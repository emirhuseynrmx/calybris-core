"""High-level Python budget and conservation helpers.

The Rust ``BudgetEngine`` remains the source of truth. ``BudgetGuard`` gives
Python callers a small, typed surface for pre-trade exposure guards, quota
systems, and any workflow that needs reserve/commit/release semantics.
"""

from __future__ import annotations

from os import PathLike
from typing import Any, Literal

from pydantic import BaseModel, Field

from . import _core
from .errors import InputValidationError
from .types import I64, SHA256_HEX, STRICT_CONFIG, U64

MICROCENTS_PER_CENT: int = _core.MICROCENTS_PER_CENT
_U64_MAX = 2**64 - 1


def _require_non_negative_i64(field: str, value: int) -> None:
    maximum = 2**63 - 1
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise InputValidationError(
            f"{field} must be an integer between 0 and {maximum}, got {value!r}"
        )


def _require_u64(field: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _U64_MAX:
        raise InputValidationError(
            f"{field} must be an integer between 0 and {_U64_MAX}, got {value!r}"
        )


def _require_tenant_id(tenant_id: str) -> None:
    if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id.encode("utf-8")) > 1024:
        raise InputValidationError(
            "tenant_id must be a non-empty UTF-8 string of at most 1024 bytes"
        )


class BudgetReservationResult(BaseModel):
    model_config = STRICT_CONFIG

    status: Literal[
        "reserved",
        "insufficient",
        "missing_tenant",
        "missing_reservation",
        "exposure_limit_exceeded",
        "overflow",
    ]
    reservation_id: U64 | None = None
    remaining_microcents: I64 | None = None
    required_microcents: I64 | None = None
    current_reserved_microcents: I64 | None = None
    max_reserved_microcents: I64 | None = None

    @property
    def is_reserved(self) -> bool:
        return self.status == "reserved" and self.reservation_id is not None


class BudgetSettlementResult(BaseModel):
    model_config = STRICT_CONFIG

    status: Literal[
        "committed",
        "released",
        "overrun",
        "invalid_amount",
        "missing_reservation",
        "missing_tenant",
        "overflow",
    ]
    remaining_microcents: I64 | None = None
    actual_microcents: I64 | None = None
    returned_microcents: I64 | None = None

    @property
    def is_committed(self) -> bool:
        return self.status == "committed"

    @property
    def is_released(self) -> bool:
        return self.status == "released"


class BudgetTopUpResult(BaseModel):
    model_config = STRICT_CONFIG

    status: Literal["topped_up", "missing_tenant", "invalid_amount", "overflow"]
    added_microcents: I64 | None = None
    new_initial_microcents: I64 | None = None
    remaining_microcents: I64 | None = None


class ConservationCheck(BaseModel):
    model_config = STRICT_CONFIG

    status: Literal["balanced", "violation", "aggregate_overflow"]
    tenant_id: str | None = None
    delta_microcents: I64 | None = None

    @property
    def is_balanced(self) -> bool:
        return self.status == "balanced"


class TenantLedger(BaseModel):
    model_config = STRICT_CONFIG

    tenant_id: str
    initial_microcents: I64
    remaining_microcents: I64
    reserved_microcents: I64
    committed_microcents: I64


class BudgetSnapshot(BaseModel):
    model_config = STRICT_CONFIG

    version: U64
    active_reservations: U64
    wal_high_watermark: U64 | None = None
    tenants: list[TenantLedger] = Field(default_factory=list)


class ConservationProof(BaseModel):
    model_config = STRICT_CONFIG

    ledger_digest_hex: SHA256_HEX
    snapshot_version: U64
    tenant_count: U64
    active_reservations: U64
    total_initial_microcents: I64
    total_committed_microcents: I64
    aggregate_totals_representable: bool


class FinancialCertificate(BaseModel):
    model_config = STRICT_CONFIG

    snapshot_version: U64
    ledger_digest_hex: SHA256_HEX
    tenant_count: U64
    active_reservations: U64
    conservation_balanced: bool
    total_initial_microcents: I64
    total_committed_microcents: I64
    aggregate_totals_representable: bool
    committed_since_last_certificate: I64


class BudgetGuard:
    """Typed Python wrapper over the Rust CAS budget engine.

    Typical path::

        guard = BudgetGuard().ensure_tenant("desk", 1_000_000_000)
        hold = guard.reserve("desk", 100_000)
        if hold.is_reserved:
            guard.commit(hold.reservation_id, 95_000)
        assert guard.verify_conservation().is_balanced
    """

    def __init__(self) -> None:
        self._engine = _core.BudgetEngine()

    def ensure_tenant(
        self,
        tenant_id: str,
        budget_microcents: int,
        *,
        max_reserved_microcents: int = 0,
    ) -> BudgetGuard:
        _require_tenant_id(tenant_id)
        _require_non_negative_i64("budget_microcents", budget_microcents)
        _require_non_negative_i64("max_reserved_microcents", max_reserved_microcents)
        self._engine.ensure_tenant(tenant_id, budget_microcents)
        if max_reserved_microcents:
            self._engine.set_max_reserved_microcents(tenant_id, max_reserved_microcents)
        return self

    def set_max_reserved_microcents(
        self,
        tenant_id: str,
        max_microcents: int,
    ) -> BudgetGuard:
        _require_tenant_id(tenant_id)
        _require_non_negative_i64("max_microcents", max_microcents)
        self._engine.set_max_reserved_microcents(tenant_id, max_microcents)
        return self

    def top_up(self, tenant_id: str, amount_microcents: int) -> BudgetTopUpResult:
        _require_tenant_id(tenant_id)
        _require_non_negative_i64("amount_microcents", amount_microcents)
        return BudgetTopUpResult.model_validate(
            self._engine.top_up_tenant(tenant_id, amount_microcents)
        )

    def reserve(self, tenant_id: str, amount_microcents: int) -> BudgetReservationResult:
        _require_tenant_id(tenant_id)
        _require_non_negative_i64("amount_microcents", amount_microcents)
        return BudgetReservationResult.model_validate(
            self._engine.try_reserve(tenant_id, amount_microcents)
        )

    def commit(
        self,
        reservation_id: int,
        actual_microcents: int,
    ) -> BudgetSettlementResult:
        _require_u64("reservation_id", reservation_id)
        _require_non_negative_i64("actual_microcents", actual_microcents)
        return BudgetSettlementResult.model_validate(
            self._engine.commit(reservation_id, actual_microcents)
        )

    def release(self, reservation_id: int) -> BudgetSettlementResult:
        _require_u64("reservation_id", reservation_id)
        return BudgetSettlementResult.model_validate(self._engine.release(reservation_id))

    def initial_microcents(self, tenant_id: str) -> int | None:
        return self._engine.initial_microcents(tenant_id)

    def remaining_microcents(self, tenant_id: str) -> int | None:
        return self._engine.remaining_microcents(tenant_id)

    def reserved_microcents(self, tenant_id: str) -> int:
        return self._engine.reserved_microcents(tenant_id)

    def committed_microcents(self, tenant_id: str) -> int | None:
        return self._engine.committed_microcents(tenant_id)

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot.model_validate(self._engine.snapshot())

    def checkpoint(
        self,
        path: str | PathLike[str],
        *,
        wal_sequence: int | None = None,
    ) -> BudgetSnapshot:
        """Persist an atomically replaced, file-fsynced snapshot.

        Parent-directory power-loss durability is platform-specific.
        """
        if wal_sequence is None:
            raw = self._engine.checkpoint(path)
        else:
            raw = self._engine.checkpoint_with_wal(path, wal_sequence)
        return BudgetSnapshot.model_validate(raw)

    def restore(self, path: str | PathLike[str]) -> BudgetSnapshot:
        """Restore a validated snapshot during exclusive recovery."""
        return BudgetSnapshot.model_validate(self._engine.restore(path))

    @staticmethod
    def migrate_legacy_snapshot_file(
        source: str | PathLike[str],
        destination: str | PathLike[str],
        trusted_next_reservation_id: int,
    ) -> BudgetSnapshot:
        """Migrate an untagged snapshot to a distinct recovery-aware file.

        The allocator fence must come from trusted durable history and be
        greater than every reservation ID previously issued. It must never be
        guessed from the legacy snapshot itself.
        """
        return BudgetSnapshot.model_validate(
            _core.BudgetEngine.migrate_legacy_snapshot_file(
                source,
                destination,
                trusted_next_reservation_id,
            )
        )

    def verify_conservation(self) -> ConservationCheck:
        return ConservationCheck.model_validate(self._engine.verify_conservation())

    def prove_conservation(self) -> ConservationProof:
        return ConservationProof.model_validate(self._engine.prove_conservation())

    def certificate(self) -> FinancialCertificate:
        return FinancialCertificate.model_validate(self._engine.certify())

    @property
    def tenant_count(self) -> int:
        return self._engine.tenant_count()

    @property
    def active_reservations(self) -> int:
        return self._engine.active_reservations()

    def as_raw_engine(self) -> Any:
        """Return the underlying Rust-backed engine for low-level integrations."""
        return self._engine

    def __repr__(self) -> str:
        return (
            f"BudgetGuard(tenants={self.tenant_count}, "
            f"active_reservations={self.active_reservations})"
        )


__all__ = [
    "MICROCENTS_PER_CENT",
    "BudgetGuard",
    "BudgetReservationResult",
    "BudgetSettlementResult",
    "BudgetTopUpResult",
    "ConservationCheck",
    "TenantLedger",
    "BudgetSnapshot",
    "ConservationProof",
    "FinancialCertificate",
]
