"""Bounded, process-local call admission backed by the Rust budget engine.

Amounts are integer microcents (100,000,000 per USD). An exception after
admission retains its hold: an unsuccessful response is not proof of no charge.
"""

from __future__ import annotations

import inspect
import os
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import asdict, dataclass, replace
from threading import RLock
from typing import TypeVar

from .errors import CalybrisError, InputValidationError
from .finance import BudgetGuard

__all__ = [
    "AgentBudget",
    "AgentBudgetError",
    "AttemptLimitError",
    "AttemptReport",
    "AttemptStateError",
    "BudgetDeniedError",
    "BudgetOverrunError",
    "CorrectionError",
    "DuplicateAttemptError",
    "RunAccuracy",
    "RunBalance",
    "RunClosedError",
    "RunReport",
    "SETTLED_STATUSES",
]

#: Attempt statuses whose amount the ledger actually took.
#:
#: ``uncertain`` and ``overrun_unsettled`` are deliberately absent: both can carry an
#: observed cost while the ledger still holds the reservation, and counting them as
#: settled would report work the budget never completed.
SETTLED_STATUSES = frozenset({"committed", "overrun_settled", "corrected", "released"})

T = TypeVar("T")
_MAX_I64 = 2**63 - 1
_DEFAULT_DENIED_RECORDS = 1024


class AgentBudgetError(CalybrisError):
    """Base class for call admission and settlement errors."""


class BudgetDeniedError(AgentBudgetError):
    """No budget was reserved and the operation was not called."""


class DuplicateAttemptError(AgentBudgetError):
    """An attempt ID has already been admitted.

    A denied attempt never ran and never held budget, so its ID stays free: the same
    logical step may be retried once capacity exists.
    """


class AttemptLimitError(AgentBudgetError):
    """The run's bounded registry of admitted attempts is full.

    Denials do not consume this capacity, so a run is not ended by work it never did.
    """


class CorrectionError(AgentBudgetError):
    """A documented correction is incompatible with the attempt's current state."""


class AttemptStateError(AgentBudgetError):
    """A settlement is incompatible with the attempt's current state."""


class RunClosedError(AgentBudgetError):
    """The run is closed to new calls."""


class BudgetOverrunError(AgentBudgetError):
    """Observed cost exceeded its reservation; no new calls will be admitted."""

    def __init__(self, attempt_id: str, actual_microcents: int, settled: bool) -> None:
        self.attempt_id = attempt_id
        self.actual_microcents = actual_microcents
        self.settled = settled
        super().__init__(f"Attempt {attempt_id!r} exceeded its reservation; run closed")


@dataclass(frozen=True)
class AttemptReport:
    """Immutable snapshot; never contains the operation response or exception text.

    A corrected attempt keeps the cost that was originally observed in
    ``actual_microcents``; the settled amount and its justification sit beside it.
    """

    attempt_id: str
    status: str
    reserved_microcents: int
    actual_microcents: int | None = None
    corrected_microcents: int | None = None
    correction_reason: str | None = None


@dataclass(frozen=True)
class RunBalance:
    """The ledger alone, without building a record of every attempt."""

    initial_microcents: int
    remaining_microcents: int
    reserved_microcents: int
    committed_microcents: int
    closed: bool
    close_reason: str | None


@dataclass(frozen=True)
class RunReport:
    """Local accounting, not an attestation of a provider's bill.

    ``denied`` holds the most recent denials only. ``denied_total`` counts every denial
    the run has seen, so a truncated history is visible rather than silent.
    """

    initial_microcents: int
    remaining_microcents: int
    reserved_microcents: int
    committed_microcents: int
    closed: bool
    close_reason: str | None
    conservation_balanced: bool
    attempts: tuple[AttemptReport, ...]
    denied: tuple[AttemptReport, ...] = ()
    denied_total: int = 0


@dataclass(frozen=True)
class RunAccuracy:
    """What the run's own history says about the reservations it was given.

    Every number here is counted, not inferred: the engine already recorded what each
    call reserved and what it cost. ``denials_with_headroom`` is the one that usually
    matters - a refusal while the run could still have paid for the most expensive call
    it ever completed is evidence the reservation was too large, not that the budget was
    too small.
    """

    settled_attempts: int
    median_ratio_ppm: int | None
    held_unused_microcents: int
    denials_with_headroom: int
    denials_total: int
    largest_settled_microcents: int


@dataclass
class _Attempt:
    report: AttemptReport
    reservation_id: int | None


def _amount(name: str, value: int, *, positive: bool = False) -> None:
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= _MAX_I64:
        raise InputValidationError(f"{name} must be an integer in [{minimum}, {_MAX_I64}]")


def _attempt_id(value: str) -> None:
    try:
        valid = type(value) is str and 0 < len(value.encode("utf-8")) <= 256
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise InputValidationError("attempt_id must contain 1 to 256 UTF-8 bytes")


def _reason(value: str) -> None:
    try:
        valid = type(value) is str and 0 < len(value.strip()) and len(value.encode("utf-8")) <= 256
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise InputValidationError("reason must contain 1 to 256 UTF-8 bytes of text")


def _materialized(value: object) -> None:
    if inspect.isawaitable(value) or isinstance(value, (Iterator, AsyncIterator)):
        if inspect.iscoroutine(value):
            value.close()
        raise InputValidationError("Streaming or awaitable results are not completed responses")


def _async_callable(value: object) -> bool:
    return inspect.iscoroutinefunction(value) or inspect.iscoroutinefunction(
        getattr(value, "__call__", None)
    )


class AgentBudget:
    """One task's shared in-process budget, usable by threads and async tasks.

    Operations and cost callbacks run outside the accounting lock. Never create
    a new instance per call: that would create independent budgets. No automatic
    retries, timeout, checkpoint or cross-process coordination is provided.
    """

    def __init__(
        self,
        budget_microcents: int,
        *,
        max_attempts: int = 10_000,
        max_denied_records: int = _DEFAULT_DENIED_RECORDS,
    ) -> None:
        _amount("budget_microcents", budget_microcents)
        _amount("max_attempts", max_attempts, positive=True)
        _amount("max_denied_records", max_denied_records, positive=True)
        self._guard = BudgetGuard().ensure_tenant("run", budget_microcents)
        self._pid = os.getpid()
        self._lock = RLock()
        self._max_attempts = max_attempts
        self._attempts: dict[str, _Attempt] = {}
        # Denials are history, not capacity: they are kept for the report in a bounded
        # ring and counted in full, so a run is never ended by calls it refused to make.
        self._denied: deque[AttemptReport] = deque(maxlen=max_denied_records)
        self._denied_total = 0
        self._denials_with_headroom = 0
        self._largest_settled = 0
        self._closed = False
        self._close_reason: str | None = None

    def _check_process(self) -> None:
        # Check before touching a possibly inherited locked mutex after fork.
        if os.getpid() != self._pid:
            raise AgentBudgetError("AgentBudget cannot be shared across processes")

    def __getstate__(self) -> object:
        raise TypeError(
            "AgentBudget cannot be serialized; reports are snapshots, not recovery data"
        )

    def _begin(self, attempt_id: str, reserve_microcents: int) -> None:
        self._check_process()
        _attempt_id(attempt_id)
        _amount("reserve_microcents", reserve_microcents, positive=True)
        with self._lock:
            if self._closed:
                raise RunClosedError(self._close_reason or "closed")
            if attempt_id in self._attempts:
                raise DuplicateAttemptError(attempt_id)
            if len(self._attempts) >= self._max_attempts:
                raise AttemptLimitError("max_attempts reached")
            hold = self._guard.reserve("run", reserve_microcents)
            if not hold.is_reserved:
                # Nothing ran and nothing is held, so the registry keeps its capacity for
                # work that did happen and the identifier stays available for a retry.
                self._denied_total += 1
                self._denied.append(AttemptReport(attempt_id, "denied", reserve_microcents))
                # A refusal that happened while the run could still have paid for the most
                # expensive call it ever completed is evidence about the reservation, not
                # about the budget. Counted here because the comparison needs the balance
                # as it was at the refusal.
                if self._largest_settled > 0:
                    remaining = self._guard.snapshot().tenants[0].remaining_microcents
                    if remaining >= self._largest_settled:
                        self._denials_with_headroom += 1
                raise BudgetDeniedError(hold.status)
            self._attempts[attempt_id] = _Attempt(
                AttemptReport(attempt_id, "running", reserve_microcents),
                hold.reservation_id,
            )

    def _uncertain(self, attempt_id: str) -> None:
        self._check_process()
        with self._lock:
            entry = self._attempts[attempt_id]
            if entry.report.status == "running":
                entry.report = replace(entry.report, status="uncertain")

    def _settle_locked(self, entry: _Attempt, actual_microcents: int) -> None:
        assert entry.reservation_id is not None
        overrun = actual_microcents > entry.report.reserved_microcents
        if overrun:
            self._closed = True
            self._close_reason = "overrun"
        # Preserve observed cost before crossing the native settlement boundary.
        entry.report = replace(entry.report, actual_microcents=actual_microcents)
        settled = self._guard.commit(entry.reservation_id, actual_microcents)
        if settled.is_committed:
            entry.report = replace(
                entry.report, status="overrun_settled" if overrun else "committed"
            )
            entry.reservation_id = None
            self._largest_settled = max(self._largest_settled, actual_microcents)
        else:
            entry.report = replace(
                entry.report, status="overrun_unsettled" if overrun else "uncertain"
            )
            self._closed = True
            self._close_reason = "overrun" if overrun else "settlement_error"
        if overrun:
            raise BudgetOverrunError(
                entry.report.attempt_id, actual_microcents, settled.is_committed
            )
        if not settled.is_committed:
            raise AttemptStateError(f"Settlement failed: {settled.status}; run closed")

    def _finish(self, attempt_id: str, actual_microcents: int) -> None:
        self._check_process()
        _amount("actual_microcents", actual_microcents)
        with self._lock:
            self._settle_locked(self._attempts[attempt_id], actual_microcents)

    def call(
        self,
        attempt_id: str,
        reserve_microcents: int,
        operation: Callable[[], T],
        cost: Callable[[T], int],
    ) -> T:
        """Reserve, execute once, and settle; re-raise callback exceptions unchanged.

        ``cost`` must return a complete, non-negative integer cost. Disable
        hidden provider retries or reserve for all attempts they can perform.
        """
        if (
            not callable(operation)
            or not callable(cost)
            or _async_callable(operation)
            or _async_callable(cost)
        ):
            raise InputValidationError("call requires synchronous operation and cost callables")
        self._begin(attempt_id, reserve_microcents)
        try:
            result = operation()
            _materialized(result)
            actual = cost(result)
            _materialized(actual)
            self._finish(attempt_id, actual)
            return result
        except BaseException:
            self._uncertain(attempt_id)
            raise

    async def acall(
        self,
        attempt_id: str,
        reserve_microcents: int,
        operation: Callable[[], Awaitable[T]],
        cost: Callable[[T], int],
    ) -> T:
        """Async equivalent; cancellation retains the hold and propagates.

        No await occurs while the accounting lock is held. The cost callback
        is synchronous and should be short, pure, and non-blocking.
        """
        if not callable(operation) or not callable(cost) or _async_callable(cost):
            raise InputValidationError("acall requires operation and cost callables")
        self._begin(attempt_id, reserve_microcents)
        try:
            pending = operation()
            if not inspect.isawaitable(pending):
                raise InputValidationError("acall operation must return an awaitable")
            result = await pending
            _materialized(result)
            actual = cost(result)
            _materialized(actual)
            self._finish(attempt_id, actual)
            return result
        except BaseException:
            self._uncertain(attempt_id)
            raise

    def _unresolved(self, attempt_id: str) -> _Attempt:
        entry = self._attempts.get(attempt_id)
        if entry is None or entry.report.status not in ("uncertain", "overrun_unsettled"):
            raise AttemptStateError("Only an unresolved, non-running attempt can be reconciled")
        return entry

    def reconcile(self, attempt_id: str, actual_microcents: int) -> None:
        """Settle an uncertain attempt from externally verified usage.

        Previously observed cost cannot be replaced with a different value.
        A closed run stays closed after reconciliation.
        """
        self._check_process()
        _attempt_id(attempt_id)
        _amount("actual_microcents", actual_microcents)
        with self._lock:
            entry = self._unresolved(attempt_id)
            if entry.report.actual_microcents not in (None, actual_microcents):
                raise AttemptStateError("Cannot replace previously observed cost")
            self._settle_locked(entry, actual_microcents)

    def release(self, attempt_id: str, *, confirmed_no_charge: bool) -> None:
        """Release unknown usage only on an explicit caller assertion of no charge."""
        self._check_process()
        _attempt_id(attempt_id)
        if confirmed_no_charge is not True:
            raise InputValidationError("Release requires confirmed_no_charge=True")
        with self._lock:
            entry = self._unresolved(attempt_id)
            if entry.report.actual_microcents is not None:
                raise AttemptStateError("Observed cost must be reconciled, not released")
            assert entry.reservation_id is not None
            result = self._guard.release(entry.reservation_id)
            if not result.is_released:
                self._closed = True
                self._close_reason = "settlement_error"
                raise AttemptStateError(f"Release failed: {result.status}")
            entry.reservation_id = None
            entry.report = replace(entry.report, status="released", actual_microcents=0)

    def correct(self, attempt_id: str, corrected_microcents: int, *, reason: str) -> None:
        """Settle an overrun the budget could not absorb, at a documented lower amount.

        This exists for a correction the caller can defend - a provider credit, a
        corrected invoice line - not for unlocking a hold. The cost that was observed
        stays in the report beside the settled amount and the stated reason, the
        correction cannot be applied twice, and a run that closed stays closed.

        The amount must be strictly below the observed cost: a higher one is a new
        overrun, not a correction, and this method will not disguise it as one.
        """
        self._check_process()
        _attempt_id(attempt_id)
        _amount("corrected_microcents", corrected_microcents)
        _reason(reason)
        with self._lock:
            entry = self._attempts.get(attempt_id)
            if entry is None or entry.report.status != "overrun_unsettled":
                raise CorrectionError("Only an unsettled overrun can be corrected")
            observed = entry.report.actual_microcents
            assert observed is not None
            if corrected_microcents >= observed:
                raise CorrectionError(
                    f"correction must be below the observed {observed} microcents"
                )
            assert entry.reservation_id is not None
            settled = self._guard.commit(entry.reservation_id, corrected_microcents)
            if not settled.is_committed:
                raise CorrectionError(f"Correction could not be settled: {settled.status}")
            entry.reservation_id = None
            entry.report = replace(
                entry.report,
                status="corrected",
                corrected_microcents=corrected_microcents,
                correction_reason=reason,
            )

    def reservation_accuracy(self) -> RunAccuracy:
        """Reports how close the reservations were to what the calls actually cost.

        No amount is suggested: a recommendation drawn from a handful of calls would
        carry a confidence the history does not have. The distribution and the
        contradiction are reported, and the caller decides.
        """
        self._check_process()
        with self._lock:
            # An overrun the budget could not absorb has an observed cost but was
            # never taken from the ledger, and neither has an attempt whose
            # operation left the outcome uncertain. Having an amount is not the
            # same as having settled it, so the status decides membership here.
            settled = [
                entry.report
                for entry in self._attempts.values()
                if entry.report.status in SETTLED_STATUSES
                and entry.report.actual_microcents is not None
                and entry.report.reserved_microcents > 0
            ]
            ratios = sorted(
                report.actual_microcents * 1_000_000 // report.reserved_microcents
                for report in settled
                if report.actual_microcents is not None
            )
            held = sum(
                report.reserved_microcents - report.actual_microcents
                for report in settled
                if report.actual_microcents is not None
                and report.actual_microcents <= report.reserved_microcents
            )
            return RunAccuracy(
                settled_attempts=len(settled),
                median_ratio_ppm=ratios[len(ratios) // 2] if ratios else None,
                held_unused_microcents=held,
                denials_with_headroom=self._denials_with_headroom,
                denials_total=self._denied_total,
                largest_settled_microcents=self._largest_settled,
            )

    def balance(self) -> RunBalance:
        """Read the ledger without building a record of every attempt."""
        self._check_process()
        with self._lock:
            ledger = self._guard.snapshot().tenants[0]
            return RunBalance(
                ledger.initial_microcents,
                ledger.remaining_microcents,
                ledger.reserved_microcents,
                ledger.committed_microcents,
                self._closed,
                self._close_reason,
            )

    def lifecycle_report(self) -> dict[str, object]:
        """One atomic, detached JSON-ready view of existing ledger/history facts.

        The reentrant lock keeps both existing snapshots at the same instant.
        This is local accounting, not a signed provider-bill attestation. Reason
        text is user supplied and is not automatically secrets-redacted.
        """
        self._check_process()
        with self._lock:
            report = self.report()
            accuracy = self.reservation_accuracy()
            unresolved = []
            for attempt in report.attempts:
                if attempt.status in {"running", "uncertain", "overrun_unsettled"}:
                    action = "wait_for_operation"
                    if attempt.status == "uncertain":
                        action = (
                            "documented_correction"
                            if attempt.actual_microcents is not None
                            else "reconcile_or_confirm_no_charge"
                        )
                    elif attempt.status == "overrun_unsettled":
                        action = "documented_correction"
                    unresolved.append({**asdict(attempt), "next_action": action})
            return {
                "schema_version": "calybris.budget-lifecycle.v1",
                "unit": "microcents",
                "balance": {
                    key: getattr(report, key)
                    for key in (
                        "initial_microcents",
                        "remaining_microcents",
                        "reserved_microcents",
                        "committed_microcents",
                        "closed",
                        "close_reason",
                    )
                },
                "conservation_balanced": report.conservation_balanced,
                "attempts": [asdict(attempt) for attempt in report.attempts],
                "unresolved": unresolved,
                "corrections": [
                    asdict(attempt) for attempt in report.attempts if attempt.status == "corrected"
                ],
                "denied": [asdict(attempt) for attempt in report.denied],
                "denied_total": report.denied_total,
                "denied_history_truncated": report.denied_total > len(report.denied),
                "reservation_accuracy": asdict(accuracy),
            }

    def close(self) -> None:
        """Stop new admission; do not cancel in-flight work or discard its holds."""
        self._check_process()
        with self._lock:
            self._closed = True
            if self._close_reason is None:
                self._close_reason = "explicit"

    def report(self) -> RunReport:
        """Return a consistent immutable snapshot bounded by max_attempts."""
        self._check_process()
        with self._lock:
            ledger = self._guard.snapshot().tenants[0]
            return RunReport(
                ledger.initial_microcents,
                ledger.remaining_microcents,
                ledger.reserved_microcents,
                ledger.committed_microcents,
                self._closed,
                self._close_reason,
                self._guard.verify_conservation().is_balanced,
                tuple(entry.report for entry in self._attempts.values()),
                tuple(self._denied),
                self._denied_total,
            )
