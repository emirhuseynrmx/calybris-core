"""High-level Python budget and conservation helpers.

The Rust ``BudgetEngine`` remains the source of truth. ``BudgetGuard`` gives
Python callers a small, typed surface for pre-trade exposure guards, quota
systems, and any workflow that needs reserve/commit/release semantics.
"""

from __future__ import annotations

from os import PathLike
from typing import Any

from pydantic import BaseModel, Field

from . import _core
from .types import STRICT_CONFIG

MICROCENTS_PER_CENT: int = _core.MICROCENTS_PER_CENT


class BudgetReservationResult(BaseModel):
    model_config = STRICT_CONFIG

    status: str
    reservation_id: int | None = None
    remaining_microcents: int | None = None
    required_microcents: int | None = None
    current_reserved_microcents: int | None = None
    max_reserved_microcents: int | None = None

    @property
    def is_reserved(self) -> bool:
        return self.status == "reserved" and self.reservation_id is not None


class BudgetSettlementResult(BaseModel):
    model_config = STRICT_CONFIG

    status: str
    remaining_microcents: int | None = None
    actual_microcents: int | None = None
    returned_microcents: int | None = None

    @property
    def is_committed(self) -> bool:
        return self.status == "committed"

    @property
    def is_released(self) -> bool:
        return self.status == "released"


class BudgetTopUpResult(BaseModel):
    model_config = STRICT_CONFIG

    status: str
    added_microcents: int | None = None
    new_initial_microcents: int | None = None
    remaining_microcents: int | None = None


class ConservationCheck(BaseModel):
    model_config = STRICT_CONFIG

    status: str
    tenant_id: str | None = None
    delta_microcents: int | None = None

    @property
    def is_balanced(self) -> bool:
        return self.status == "balanced"


class TenantLedger(BaseModel):
    model_config = STRICT_CONFIG

    tenant_id: str
    initial_microcents: int
    remaining_microcents: int
    reserved_microcents: int
    committed_microcents: int


class BudgetSnapshot(BaseModel):
    model_config = STRICT_CONFIG

    version: int
    active_reservations: int
    wal_high_watermark: int | None = None
    tenants: list[TenantLedger] = Field(default_factory=list)


class ConservationProof(BaseModel):
    model_config = STRICT_CONFIG

    ledger_digest_hex: str
    snapshot_version: int
    tenant_count: int
    active_reservations: int
    total_initial_microcents: int
    total_committed_microcents: int
    aggregate_totals_representable: bool


class FinancialCertificate(BaseModel):
    model_config = STRICT_CONFIG

    snapshot_version: int
    ledger_digest_hex: str
    tenant_count: int
    active_reservations: int
    conservation_balanced: bool
    total_initial_microcents: int
    total_committed_microcents: int
    aggregate_totals_representable: bool
    committed_since_last_certificate: int


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
        self._engine.ensure_tenant(tenant_id, budget_microcents)
        if max_reserved_microcents:
            self._engine.set_max_reserved_microcents(tenant_id, max_reserved_microcents)
        return self

    def set_max_reserved_microcents(
        self,
        tenant_id: str,
        max_microcents: int,
    ) -> BudgetGuard:
        self._engine.set_max_reserved_microcents(tenant_id, max_microcents)
        return self

    def top_up(self, tenant_id: str, amount_microcents: int) -> BudgetTopUpResult:
        return BudgetTopUpResult.model_validate(
            self._engine.top_up_tenant(tenant_id, amount_microcents)
        )

    def reserve(self, tenant_id: str, amount_microcents: int) -> BudgetReservationResult:
        return BudgetReservationResult.model_validate(
            self._engine.try_reserve(tenant_id, amount_microcents)
        )

    def commit(
        self,
        reservation_id: int,
        actual_microcents: int,
    ) -> BudgetSettlementResult:
        return BudgetSettlementResult.model_validate(
            self._engine.commit(reservation_id, actual_microcents)
        )

    def release(self, reservation_id: int) -> BudgetSettlementResult:
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
