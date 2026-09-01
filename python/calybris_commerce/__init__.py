"""calybris_commerce — fulfillment routing policy adapter over the Calybris kernel.

.. warning::

   **Preview (pre-1.0). The API may change without notice and is not covered by
   semantic versioning.** The Rust kernel underneath is the stable surface; this
   adapter is the least-settled layer in the project. Pin an exact version and
   validate against your own scenarios before relying on it. Status is exposed
   programmatically as ``calybris_commerce.ADAPTER_STATUS``.

Maps your supplier catalog and order constraints into kernel models/inputs and
returns a deterministic routing decision with an optional replay-checked audit bundle.

This module does **not** manage inventory, book carriers, or optimize multi-stop routes.
Your platform owns the catalog; Calybris evaluates the policy.

Quick start::

    from calybris_commerce import (
        SupplierPolicy, SupplierSpec, OrderInput,
        CAP_FRAGILE, REGION_TR_IST, REGION_TR_ANKARA,
    )

    engine = (
        SupplierPolicy(policy_epoch=1, catalog_epoch=1)
        .return_risk_limit(max_pct=40.0)
        .confidence_floor(min_pct=60.0)
        .add_supplier(SupplierSpec(
            supplier_id=1,
            name="Same-Day Courier",
            reliability_pct=99.2,
            risk_tolerance_pct=50.0,
            sla_hours=24,
            shipping_cost_microunits=4_500_000,
            region_mask=REGION_TR_IST | REGION_TR_ANKARA,
        ))
        .build_engine()
    )

    result = engine.route_order(OrderInput(
        order_id="ORD-123",
        order_sequence=1,
        order_value_microunits=150_000_000,
        budget_limit_microunits=10_000_000,
        return_risk_pct=5.0,
        confidence_pct=90.0,
        max_delivery_hours=48,
        required_regions=REGION_TR_IST,
    ))
    print(result.explain())
    assert result.audit_bundle.replay_valid
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

from calybris import (
    AuditBundle,
    CalybrisEngine,
    Decision,
    EngineConfig,
    InputBuilder,
    PolicyBuilder,
    PolicyValidationError,
    _core,
)
from calybris import __version__ as _calybris_version
from calybris.types import STRICT_CONFIG, DecisionTrace, ModelSpec
from pydantic import BaseModel, Field

#
# Each bit represents a cargo handling capability. Suppliers declare which
# capabilities they support; orders declare which capabilities they require.
# The kernel gates on `(supplier.capabilities & order.required) == order.required`.

CAP_STANDARD = 0  # no special requirements
CAP_HEAVY = 1 << 0  # cargo > 30 kg
CAP_FRAGILE = 1 << 1  # requires special handling
CAP_REFRIGERATED = 1 << 2  # cold chain (food, pharma)
CAP_OVERSIZED = 1 << 3  # non-standard dimensions
CAP_HAZMAT = 1 << 4  # dangerous goods / ADR
CAP_SAME_DAY = 1 << 5  # same-day delivery capable

#
# One bit per delivery zone. Suppliers declare which regions they cover;
# orders can restrict routing to specific regions.

REGION_TR_IST = 1 << 0  # Istanbul
REGION_TR_ANKARA = 1 << 1  # Ankara
REGION_TR_IZMIR = 1 << 2  # Izmir
REGION_TR_BURSA = 1 << 3  # Bursa
REGION_TR_AEGEAN = 1 << 4  # Ege (broad)
REGION_TR_CENTRAL = 1 << 5  # Iç Anadolu
REGION_TR_EASTERN = 1 << 6  # Doğu Anadolu
REGION_TR_ALL = (1 << 7) - 1  # all Turkish regions
REGION_EU = 1 << 7
REGION_US = 1 << 8
REGION_ALL = _core.ALL_REGIONS

#
# Unit convention for this adapter:
#   "microunits" are caller-defined fixed-point currency units.
#   The kernel is currency-agnostic; calybris_commerce maps "1 TL = 1_000_000 µu"
#   as an example, but any currency works as long as it's applied consistently.
#   The finance layer (BudgetGuard) uses "microcents" (1 USD cent = 1_000_000 µc)
#   as a concrete example for USD workflows — that is independent of this adapter.
#
# Cost encoding: the kernel divides cost by 1_000_000 (COST_SCALE). Using
# _ORDER_UNIT = 1_000_000 tokens per order makes shipping_cost_microunits pass
# through unchanged:
#   estimated_cost = shipping_cost × 1_000_000 / 1_000_000 = shipping_cost
#
# Latency encoding: the kernel's p95_latency_ms field stores hours here, not
# milliseconds. latency_penalty_microunits_per_ms is therefore µu per hour.
# This avoids lossy integer rounding when converting sub-ms penalties.
_ORDER_UNIT: int = 1_000_000
_MAX_SLA_HOURS: int = (1 << 32) - 1

# Re-exported for callers checking adapter maturity in their integration layer.
__version__ = _calybris_version
ADAPTER_STATUS = "preview"


def _percentage_to_bps(value: float) -> int:
    """Convert a validated percentage without binary-float truncation."""
    return int((Decimal(str(value)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


class SupplierSpec(BaseModel):
    """One fulfillment provider in the routing catalog.

    ``reliability_pct`` and ``risk_tolerance_pct`` are percentages (0–100)
    that map to kernel basis-point fields internally.

    ``sla_hours`` is stored as-is in the kernel's latency field (hours = the
    scheduling unit). The latency penalty is in microunits per hour.
    ``shipping_cost_microunits`` and ``handling_cost_microunits`` are exact:
    the kernel's per-token cost model is normalised so 1 order = 1M units.
    """

    model_config = STRICT_CONFIG

    supplier_id: int = Field(..., ge=1, description="Unique supplier identifier.")
    name: str = Field(..., description="Human-readable supplier name (for logging).")
    reliability_pct: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Historical order success rate 0–100 (99.5 → quality_bps=9950).",
    )
    risk_tolerance_pct: float = Field(
        default=95.0,
        ge=0.0,
        le=100.0,
        description="Max acceptable order return/fraud risk this supplier handles.",
    )
    sla_hours: int = Field(
        ...,
        ge=1,
        le=_MAX_SLA_HOURS,
        description=(
            "Promised p95 delivery time in hours (24 = next day). "
            f"Maximum is {_MAX_SLA_HOURS} hours."
        ),
    )
    shipping_cost_microunits: int = Field(
        ...,
        ge=0,
        description="Flat shipping cost per order in microunits (1 TL = 1_000_000).",
    )
    handling_cost_microunits: int = Field(
        default=0,
        ge=0,
        description="Additional handling cost for heavy/fragile cargo, in microunits.",
    )
    capabilities: int = Field(
        default=CAP_STANDARD,
        description="Bitmask of supported cargo types (CAP_HEAVY, CAP_FRAGILE, …).",
    )
    region_mask: int = Field(
        ...,
        ge=0,
        description="Delivery region bitmask (REGION_TR_IST | REGION_TR_ANKARA, …).",
    )
    provider_group: int = Field(
        default=0,
        ge=0,
        le=63,
        description="Supplier group slot 0–63. Use to segment courier networks.",
    )
    enabled: bool = Field(default=True, description="Disabled suppliers are skipped.")


class OrderInput(BaseModel):
    """A customer order to be routed to a fulfillment supplier.

    ``return_risk_pct`` is your best estimate of fraud/return probability
    (0 = certain delivery, 100 = certain return). ``confidence_pct`` is
    how confident you are in that estimate — low confidence tightens the
    kernel's risk gate.
    """

    model_config = STRICT_CONFIG

    order_id: str = Field(..., description="Platform order ID for tracing.")
    order_sequence: int = Field(
        ...,
        ge=0,
        description="Monotonic counter used by the kernel for digest binding.",
    )
    requested_supplier_id: int = Field(
        default=0,
        ge=0,
        description="Preferred supplier (0 = freely choose the best one).",
    )
    order_value_microunits: int = Field(
        ...,
        ge=0,
        description="Expected revenue from this order in microunits.",
    )
    budget_limit_microunits: int = Field(
        ...,
        ge=0,
        description="Maximum fulfillment spend allowed for this order.",
    )
    return_risk_pct: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Estimated return / fraud probability 0–100.",
    )
    confidence_pct: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="Confidence in the risk estimate 0–100.",
    )
    required_capabilities: int = Field(
        default=CAP_STANDARD,
        description="Required cargo handling bitmask (CAP_FRAGILE, CAP_REFRIGERATED, …).",
    )
    required_regions: int = Field(
        default=0,
        description="Required delivery region bitmask (0 = no restriction).",
    )
    minimum_reliability_pct: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Minimum acceptable supplier success rate.",
    )
    max_delivery_hours: int = Field(
        default=0,
        ge=0,
        le=_MAX_SLA_HOURS,
        description=(
            "Hard delivery deadline in hours (0 = no SLA constraint). "
            f"Maximum is {_MAX_SLA_HOURS} hours."
        ),
    )
    allowed_supplier_groups: int = Field(
        default=_core.ALL_PROVIDERS,
        description="Allowed provider group bitmask (default = all).",
    )


class RouteResult(BaseModel):
    """The routing decision for a single order.

    ``audit_bundle`` is present when the engine was called with ``audit=True``
    (the default for single-order routing). It contains SHA-256 digests of
    the policy, input, and decision — sufficient for external audit.
    """

    model_config = STRICT_CONFIG

    order_id: str
    status: Literal["accepted", "substituted", "rejected"]
    chosen_supplier_id: int
    chosen_supplier_name: str = ""
    estimated_cost_microunits: int
    reasoning: str
    rejection_summary: dict[str, int] = Field(default_factory=dict)
    evaluated_suppliers: int
    eligible_suppliers: int
    alternative_supplier_id: int
    decision: Decision
    audit_bundle: AuditBundle | None = None

    @property
    def is_fulfilled(self) -> bool:
        """True when a supplier was selected (accepted or substituted)."""
        return self.status in ("accepted", "substituted")

    @property
    def is_rejected(self) -> bool:
        """True when no supplier could handle this order."""
        return self.status == "rejected"

    def __str__(self) -> str:
        supplier = self.chosen_supplier_name or str(self.chosen_supplier_id)
        return (
            f"RouteResult(order={self.order_id}, status={self.status}, "
            f"supplier={supplier}, cost={self.estimated_cost_microunits})"
        )

    def explain(self) -> str:
        """Human-readable routing summary for logs and support tooling."""
        lines = [f"{self.order_id}: {self.status}"]
        if self.is_fulfilled:
            label = self.chosen_supplier_name or f"supplier #{self.chosen_supplier_id}"
            lines.append(f"  routed to {label}")
            lines.append(f"  cost {self.estimated_cost_microunits} microunits")
        else:
            lines.append(f"  {self.reasoning.strip()}")
            if self.rejection_summary:
                parts = ", ".join(f"{k}={v}" for k, v in sorted(self.rejection_summary.items()))
                lines.append(f"  rejection histogram: {parts}")
        if self.audit_bundle is not None:
            replay = "valid" if self.audit_bundle.replay_valid else "invalid"
            lines.append(f"  audit replay: {replay}")
        return "\n".join(lines)


class BatchRouteResult(BaseModel):
    """Routing results for a batch of orders.

    ``results`` contains one :class:`RouteResult` per order in submission order.
    ``rejection_histogram`` aggregates rejection reason counts across all orders
    and is populated only when ``trace_mode="summary"`` is passed to
    :meth:`EcomEngine.route_batch`. It is empty in the default ``"compact"`` mode.
    """

    model_config = STRICT_CONFIG

    results: list[RouteResult]
    rejection_histogram: dict[str, int] = Field(default_factory=dict)


class SupplierPolicy:
    """Builds a validated routing policy from supplier specs and risk knobs.

    Usage::

        engine = (
            SupplierPolicy(policy_epoch=1, catalog_epoch=1)
            .return_risk_limit(max_pct=40.0)
            .confidence_floor(min_pct=60.0)
            .add_supplier(SupplierSpec(...))
            .build_engine()
        )
    """

    def __init__(self, *, policy_epoch: int = 1, catalog_epoch: int = 1) -> None:
        self._policy_epoch = policy_epoch
        self._catalog_epoch = catalog_epoch
        self._max_return_risk_pct: float = 50.0
        self._min_confidence_pct: float = 50.0
        self._risk_penalty_bps: int = 3_500
        self._latency_penalty_per_hour_microunits: int = 10_000
        self._suppliers: list[SupplierSpec] = []

    def return_risk_limit(self, *, max_pct: float) -> SupplierPolicy:
        """Orders with return_risk_pct above this are always rejected."""
        self._max_return_risk_pct = max_pct
        return self

    def confidence_floor(self, *, min_pct: float) -> SupplierPolicy:
        """Orders with confidence_pct below this are always rejected."""
        self._min_confidence_pct = min_pct
        return self

    def risk_sensitivity(self, *, multiplier_bps: int) -> SupplierPolicy:
        """How aggressively return risk reduces expected utility (default 3500 bps)."""
        self._risk_penalty_bps = multiplier_bps
        return self

    def latency_cost(self, *, microunits_per_hour: int) -> SupplierPolicy:
        """Utility cost per hour of supplier SLA.

        Passed directly to the kernel as the latency penalty (µu per SLA unit).
        ``0`` disables the latency penalty entirely.
        """
        self._latency_penalty_per_hour_microunits = microunits_per_hour
        return self

    def add_supplier(self, supplier: SupplierSpec) -> SupplierPolicy:
        """Add a supplier to the catalog."""
        self._suppliers.append(supplier)
        return self

    def models(self) -> list[ModelSpec]:
        """Return the kernel model specs implied by the current supplier catalog."""
        return self._model_specs()

    def _latency_penalty_per_ms(self) -> int:
        return self._latency_penalty_per_hour_microunits

    def _model_specs(self) -> list[ModelSpec]:
        return [
            ModelSpec(
                model_id=s.supplier_id,
                provider_id=s.provider_group,
                quality_bps=_percentage_to_bps(s.reliability_pct),
                risk_ceiling_bps=_percentage_to_bps(s.risk_tolerance_pct),
                enabled=s.enabled,
                p95_latency_ms=s.sla_hours,
                capabilities=s.capabilities,
                region_mask=s.region_mask,
                # Cost encoding: 1 order = _ORDER_UNIT tokens, so cost_per_million = flat cost
                input_cost_microunits_per_million_tokens=s.shipping_cost_microunits,
                output_cost_microunits_per_million_tokens=s.handling_cost_microunits,
            )
            for s in self._suppliers
        ]

    def build(self) -> _core.PolicySnapshot:
        """Validate and return the assembled ``PolicySnapshot``.

        Raises :exc:`PolicyValidationError` for invalid configs (duplicate IDs,
        no enabled suppliers, out-of-range bps values).
        """
        if not self._suppliers:
            raise PolicyValidationError("supplier catalog is empty")
        seen_supplier_ids: set[int] = set()
        for supplier in self._suppliers:
            if supplier.supplier_id in seen_supplier_ids:
                raise PolicyValidationError(f"duplicate supplier_id {supplier.supplier_id}")
            seen_supplier_ids.add(supplier.supplier_id)
        if not any(supplier.enabled for supplier in self._suppliers):
            raise PolicyValidationError("supplier catalog has no enabled suppliers")

        config = EngineConfig(
            hard_risk_limit_bps=_percentage_to_bps(self._max_return_risk_pct),
            minimum_confidence_bps=_percentage_to_bps(self._min_confidence_pct),
            risk_penalty_multiplier_bps=self._risk_penalty_bps,
            latency_penalty_microunits_per_ms=self._latency_penalty_per_ms(),
        )

        builder = PolicyBuilder(
            config,
            policy_epoch=self._policy_epoch,
            catalog_epoch=self._catalog_epoch,
        )
        for m in self._model_specs():
            builder.add_model(m)
        return builder.build()

    def build_engine(self) -> EcomEngine:
        """Build a policy-backed engine that retains supplier display names."""
        return EcomEngine(
            self.build(),
            supplier_names={supplier.supplier_id: supplier.name for supplier in self._suppliers},
        )


class EcomEngine:
    """Routes orders to fulfillment suppliers using the Calybris kernel.

    Every call to :meth:`route_order` is deterministic: given the same policy
    and order, the kernel produces the same decision. Pass ``audit=True``
    (default) to get a cryptographic audit bundle with each result.

    For high-throughput batch routing, use :meth:`route_batch` — it releases
    the Python GIL during kernel evaluation.
    """

    def __init__(
        self,
        policy: _core.PolicySnapshot,
        *,
        supplier_names: Mapping[int, str] | None = None,
    ) -> None:
        self._engine = CalybrisEngine(policy)
        self._supplier_names = dict(supplier_names or {})

    @property
    def fingerprint(self) -> str:
        """64-char hex SHA-256 fingerprint of the current policy catalog."""
        return self._engine.fingerprint

    @property
    def supplier_count(self) -> int:
        return self._engine.model_count

    def _to_kernel_input(self, order: OrderInput) -> _core.KernelInput:
        return (
            InputBuilder(
                request_sequence=order.order_sequence,
                requested_model_id=order.requested_supplier_id,
            )
            # _ORDER_UNIT tokens × cost_per_million / 1_000_000 = flat cost
            .tokens(input=_ORDER_UNIT, output=_ORDER_UNIT)
            .budget(order.budget_limit_microunits)
            .value(order.order_value_microunits)
            .risk(
                bps=_percentage_to_bps(order.return_risk_pct),
                confidence_bps=_percentage_to_bps(order.confidence_pct),
            )
            .quality(minimum_bps=_percentage_to_bps(order.minimum_reliability_pct))
            .latency(max_p95_ms=order.max_delivery_hours)
            .capabilities(order.required_capabilities)
            .regions(order.required_regions)
            .providers(order.allowed_supplier_groups)
            .build()
        )

    def kernel_input(self, order: OrderInput) -> _core.KernelInput:
        """Convert an :class:`OrderInput` into the underlying kernel input."""
        return self._to_kernel_input(order)

    def prescribe_raw(self, order: OrderInput) -> _core.KernelDecision:
        """Return the raw kernel decision for low-level audit workflows."""
        return self._engine.prescribe(self._to_kernel_input(order))

    def verified_audit_bundle(
        self,
        order: OrderInput,
        decision: _core.KernelDecision,
    ) -> AuditBundle:
        """Build a fail-closed audit bundle for a raw kernel decision."""
        return self._engine.verified_audit_bundle(self._to_kernel_input(order), decision)

    def verified_audit_bundle_for_order(
        self,
        order: OrderInput,
        decision: _core.KernelDecision,
    ) -> AuditBundle:
        """Alias for domain-level audit workflows.

        Keeps callers on the public ``EcomEngine`` API instead of reaching into
        the wrapped core engine or the private order conversion method.
        """
        return self.verified_audit_bundle(order, decision)

    @staticmethod
    def _status(
        decision: _core.KernelDecision,
        requested_supplier_id: int,
    ) -> Literal["accepted", "substituted", "rejected"]:
        if decision.is_rejected():
            return "rejected"
        if requested_supplier_id == 0 or decision.is_requested_execution():
            return "accepted"
        return "substituted"

    @staticmethod
    def _trace_as_dict(trace: DecisionTrace | dict[str, int]) -> dict[str, int]:
        if isinstance(trace, DecisionTrace):
            return trace.model_dump()
        return trace

    @staticmethod
    def _compact_trace(trace: DecisionTrace | dict[str, int]) -> dict[str, int]:
        as_dict = EcomEngine._trace_as_dict(trace)
        return {
            key: value
            for key, value in as_dict.items()
            if value and key not in ("evaluated_models", "eligible_models")
        }

    @staticmethod
    def _reason_key(reason: str) -> str:
        mapping = {
            "budget_constraint": "budget",
            "latency_constraint": "latency",
            "non_positive_utility": "utility",
            "confidence_hard_limit": "confidence",
            "capability_constraint": "capability",
            "region_constraint": "region",
            "risk_hard_limit": "risk",
            "risk_ceiling_constraint": "risk_ceiling",
            "quality_constraint": "quality",
            "provider_constraint": "provider",
            "no_enabled_model": "disabled",
        }
        return mapping.get(reason, reason.replace("_constraint", ""))

    def _supplier_name(self, supplier_id: int) -> str:
        return self._supplier_names.get(supplier_id, "")

    @staticmethod
    def _summary_for_decision(
        decision: _core.KernelDecision,
        trace: DecisionTrace | dict[str, int],
    ) -> dict[str, int]:
        compact = EcomEngine._compact_trace(trace)
        if compact or not decision.is_rejected():
            return compact
        return {EcomEngine._reason_key(str(decision.reason)): 1}

    @staticmethod
    def _top_rejection(trace: DecisionTrace | dict[str, int]) -> str:
        as_dict = EcomEngine._trace_as_dict(trace)
        if not as_dict:
            return ""
        reason, count = max(as_dict.items(), key=lambda item: item[1])
        return f" Top rejection: {reason}={count}."

    @staticmethod
    def _reasoning(
        decision: _core.KernelDecision,
        requested_supplier_id: int,
        trace: DecisionTrace | dict[str, int] | None = None,
    ) -> str:
        trace = trace or {}
        if decision.is_rejected():
            return (
                f"Rejected - no supplier cleared all constraints: {decision.reason}."
                f"{EcomEngine._top_rejection(trace)}"
            )
        if requested_supplier_id == 0:
            return (
                f"Supplier {decision.selected_model_id} selected as the best eligible supplier "
                f"(evaluated {decision.evaluated_models} suppliers)."
            )
        if requested_supplier_id != 0 and decision.is_substitution():
            return (
                f"Requested supplier {requested_supplier_id} was not optimal; "
                f"routed to supplier {decision.selected_model_id} "
                f"({decision.reason})."
            )
        return (
            f"Supplier {decision.selected_model_id} selected "
            f"({decision.reason}, evaluated {decision.evaluated_models} suppliers)."
        )

    def route_order(self, order: OrderInput, *, audit: bool = True) -> RouteResult:
        """Route a single order and return a :class:`RouteResult`.

        When ``audit=True`` (default), the result includes a cryptographic
        :class:`AuditBundle` that proves the decision is a faithful replay of
        the current policy. Raises :exc:`VerificationError` if replay fails —
        this should never happen in normal operation.
        """
        ki = self._to_kernel_input(order)
        dec, trace = self._engine.prescribe_with_trace(ki)
        rejection_summary = self._summary_for_decision(dec, trace)

        bundle: AuditBundle | None = None
        if audit:
            bundle = self._engine.verified_audit_bundle(ki, dec)

        return RouteResult(
            order_id=order.order_id,
            status=self._status(dec, order.requested_supplier_id),
            chosen_supplier_id=dec.selected_model_id,
            chosen_supplier_name=self._supplier_name(dec.selected_model_id),
            estimated_cost_microunits=dec.estimated_cost_microunits,
            reasoning=self._reasoning(dec, order.requested_supplier_id, rejection_summary),
            rejection_summary=rejection_summary,
            evaluated_suppliers=dec.evaluated_models,
            eligible_suppliers=dec.eligible_models,
            alternative_supplier_id=dec.counterfactual_model_id,
            decision=self._engine.decision_model(dec),
            audit_bundle=bundle,
        )

    def route_batch(
        self,
        orders: list[OrderInput],
        *,
        audit: bool = False,
        trace_mode: Literal["compact", "summary"] = "compact",
    ) -> BatchRouteResult:
        """Route many orders with GIL released during kernel evaluation.

        ``audit=False`` by default — audit bundles require a sequential
        verify round-trip per order. Enable for compliance-critical batches.

        ``trace_mode`` controls rejection detail in the returned :class:`BatchRouteResult`:

        - ``"compact"`` (default): each rejected order exposes its primary rejection
          reason in ``rejection_summary`` as ``{reason: 1}``.
          ``rejection_histogram`` on the batch result is empty. Zero overhead.
        - ``"summary"``: ``rejection_histogram`` on :class:`BatchRouteResult`
          aggregates rejection reason counts across all orders. Per-order
          ``rejection_summary`` is still compact (single entry). Adds one
          ``str(decision.reason)`` per rejected order — negligible cost.

        .. note::
            Batch routing defaults to ``trace_mode="compact"`` for low-overhead
            throughput. Rejected orders expose only the primary rejection reason in
            ``rejection_summary``, not the full per-constraint histogram that
            :meth:`route_order` returns when model evaluation occurs. Use
            ``trace_mode="summary"`` for batch-level counts.
        """
        if trace_mode not in ("compact", "summary"):
            raise ValueError("trace_mode must be one of: compact, summary")

        kernel_inputs = [self._to_kernel_input(o) for o in orders]
        decisions = self._engine.prescribe_batch(kernel_inputs)

        rejection_histogram: dict[str, int] = {}
        results = []
        for order, ki, dec in zip(orders, kernel_inputs, decisions):
            bundle: AuditBundle | None = None
            if audit:
                bundle = self._engine.verified_audit_bundle(ki, dec)

            rejection_summary = self._summary_for_decision(dec, {})

            if trace_mode == "summary" and dec.is_rejected():
                key = self._reason_key(str(dec.reason))
                rejection_histogram[key] = rejection_histogram.get(key, 0) + 1

            results.append(
                RouteResult(
                    order_id=order.order_id,
                    status=self._status(dec, order.requested_supplier_id),
                    chosen_supplier_id=dec.selected_model_id,
                    chosen_supplier_name=self._supplier_name(dec.selected_model_id),
                    estimated_cost_microunits=dec.estimated_cost_microunits,
                    reasoning=self._reasoning(
                        dec,
                        order.requested_supplier_id,
                        rejection_summary,
                    ),
                    rejection_summary=rejection_summary,
                    evaluated_suppliers=dec.evaluated_models,
                    eligible_suppliers=dec.eligible_models,
                    alternative_supplier_id=dec.counterfactual_model_id,
                    decision=self._engine.decision_model(dec),
                    audit_bundle=bundle,
                )
            )
        return BatchRouteResult(results=results, rejection_histogram=rejection_histogram)

    def __repr__(self) -> str:
        return f"EcomEngine(suppliers={self.supplier_count}, fingerprint={self.fingerprint[:8]}...)"


__all__ = [
    "__version__",
    "ADAPTER_STATUS",
    # Engine & builder
    "EcomEngine",
    "SupplierPolicy",
    # Types
    "SupplierSpec",
    "OrderInput",
    "RouteResult",
    "BatchRouteResult",
    # Capability bitmasks
    "CAP_STANDARD",
    "CAP_HEAVY",
    "CAP_FRAGILE",
    "CAP_REFRIGERATED",
    "CAP_OVERSIZED",
    "CAP_HAZMAT",
    "CAP_SAME_DAY",
    # Region bitmasks
    "REGION_TR_IST",
    "REGION_TR_ANKARA",
    "REGION_TR_IZMIR",
    "REGION_TR_BURSA",
    "REGION_TR_AEGEAN",
    "REGION_TR_CENTRAL",
    "REGION_TR_EASTERN",
    "REGION_TR_ALL",
    "REGION_EU",
    "REGION_US",
    "REGION_ALL",
]
