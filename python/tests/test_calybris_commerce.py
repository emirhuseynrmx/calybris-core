"""Tests for calybris_commerce — domain adapter correctness.

Property-based tests ensure the e-commerce domain mapping preserves
Calybris's core guarantees:
- Determinism: same order → same supplier choice
- Risk gate: high-risk orders are always rejected when they exceed the limit
- Audit: every fulfilled order has a valid replay bundle
- Cost: estimated cost stays within the order's budget
"""

from __future__ import annotations

import pytest
from calybris import PolicySnapshot
from calybris.errors import PolicyValidationError, VerificationError
from calybris_commerce import (
    CAP_FRAGILE,
    CAP_REFRIGERATED,
    CAP_STANDARD,
    REGION_TR_ALL,
    REGION_TR_ANKARA,
    REGION_TR_IST,
    BatchRouteResult,
    EcomEngine,
    OrderInput,
    SupplierPolicy,
    SupplierSpec,
)
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError


def _policy_builder() -> SupplierPolicy:
    return SupplierPolicy(policy_epoch=1, catalog_epoch=1)


def test_percentage_mapping_rounds_decimal_bps_instead_of_truncating():
    policy = _policy_builder().add_supplier(
        SupplierSpec(
            supplier_id=1,
            name="Precise",
            reliability_pct=99.999,
            risk_tolerance_pct=50.005,
            sla_hours=24,
            shipping_cost_microunits=1,
            region_mask=REGION_TR_IST,
        )
    )
    model = policy.models()[0]
    assert model.quality_bps == 10_000
    assert model.risk_ceiling_bps == 5_001


def _standard_policy(**overrides) -> PolicySnapshot:
    base = dict(
        return_risk_limit_max_pct=40.0,
        confidence_floor_min_pct=60.0,
    )
    base.update(overrides)
    policy = (
        _policy_builder()
        .return_risk_limit(max_pct=base["return_risk_limit_max_pct"])
        .confidence_floor(min_pct=base["confidence_floor_min_pct"])
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Hızlı Kargo",
                reliability_pct=99.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_ALL,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Ekonomik Kargo",
                reliability_pct=95.0,
                risk_tolerance_pct=60.0,
                sla_hours=72,
                shipping_cost_microunits=2_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    return policy


def _standard_order(seq: int = 1, **overrides) -> OrderInput:
    base = dict(
        order_id=f"ORD-{seq:06d}",
        order_sequence=seq,
        order_value_microunits=150_000_000,
        budget_limit_microunits=8_000_000,
        return_risk_pct=5.0,
        confidence_pct=90.0,
        max_delivery_hours=48,
    )
    base.update(overrides)
    return OrderInput(**base)


@pytest.fixture()
def engine() -> EcomEngine:
    return EcomEngine(_standard_policy())


@pytest.fixture()
def order() -> OrderInput:
    return _standard_order()


def test_route_order_fulfilled(engine, order):
    result = engine.route_order(order)
    assert result.is_fulfilled
    assert result.chosen_supplier_id in (1, 2)


def test_route_order_status_is_accepted_or_substituted(engine, order):
    result = engine.route_order(order)
    assert result.status in ("accepted", "substituted")


def test_route_order_with_preferred_supplier(engine):
    order = _standard_order(seq=1, requested_supplier_id=2)
    result = engine.route_order(order)
    assert result.is_fulfilled


def test_route_order_cost_within_budget(engine, order):
    result = engine.route_order(order)
    assert result.is_fulfilled
    assert result.estimated_cost_microunits <= order.budget_limit_microunits


def test_route_order_reasoning_is_non_empty(engine, order):
    result = engine.route_order(order)
    assert result.reasoning


def test_build_engine_attaches_supplier_names():
    engine = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Named Courier",
                reliability_pct=99.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build_engine()
    )
    result = engine.route_order(_standard_order())
    assert result.chosen_supplier_name == "Named Courier"


def test_route_result_explain_includes_supplier_name():
    engine = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Explain Courier",
                reliability_pct=99.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build_engine()
    )
    result = engine.route_order(_standard_order())
    explanation = result.explain()
    assert "Explain Courier" in explanation
    assert result.order_id in explanation


def test_route_order_repr(engine, order):
    result = engine.route_order(order)
    r = str(result)
    assert order.order_id in r
    assert result.status in r


def test_route_order_audit_bundle_present_by_default(engine, order):
    result = engine.route_order(order, audit=True)
    assert result.audit_bundle is not None
    assert result.audit_bundle.replay_valid


def test_route_order_no_audit_bundle_when_skipped(engine, order):
    result = engine.route_order(order, audit=False)
    assert result.audit_bundle is None


def test_route_batch_audit_bundle_when_requested(engine):
    orders = [_standard_order(seq=i) for i in range(1, 4)]
    for result in engine.route_batch(orders, audit=True).results:
        assert result.audit_bundle is not None
        assert result.audit_bundle.replay_valid


def test_public_raw_audit_helpers_do_not_require_private_engine_access(engine, order):
    raw_decision = engine.prescribe_raw(order)
    bundle = engine.verified_audit_bundle_for_order(order, raw_decision)
    assert bundle.replay_valid

    wrong_order = _standard_order(seq=order.order_sequence + 1)
    with pytest.raises(VerificationError):
        engine.verified_audit_bundle_for_order(wrong_order, raw_decision)


def test_high_risk_order_is_rejected():
    engine = EcomEngine(_standard_policy(return_risk_limit_max_pct=20.0))
    risky = _standard_order(seq=1, return_risk_pct=25.0, confidence_pct=90.0)
    result = engine.route_order(risky, audit=False)
    assert result.is_rejected
    assert result.status == "rejected"


def test_low_confidence_order_is_rejected():
    engine = EcomEngine(_standard_policy(confidence_floor_min_pct=80.0))
    uncertain = _standard_order(seq=1, return_risk_pct=5.0, confidence_pct=70.0)
    result = engine.route_order(uncertain, audit=False)
    assert result.is_rejected
    assert result.rejection_summary == {"confidence": 1}


def test_zero_budget_order_is_rejected(engine):
    no_budget = _standard_order(seq=1, budget_limit_microunits=1)
    result = engine.route_order(no_budget, audit=False)
    assert result.is_rejected


def test_fragile_order_routed_to_capable_supplier():
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="General Kargo",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_STANDARD,  # no fragile capability
                region_mask=REGION_TR_ALL,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Nazik Kargo",
                reliability_pct=97.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=7_000_000,
                capabilities=CAP_FRAGILE,  # fragile capable
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    fragile_order = _standard_order(seq=1, required_capabilities=CAP_FRAGILE)
    result = engine.route_order(fragile_order, audit=False)
    assert result.is_fulfilled
    assert result.chosen_supplier_id == 2


def test_refrigerated_order_rejected_when_no_cold_chain_supplier():
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Normal Kargo",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_STANDARD,  # no refrigeration
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    cold_order = _standard_order(seq=1, required_capabilities=CAP_REFRIGERATED)
    result = engine.route_order(cold_order, audit=False)
    assert result.is_rejected
    assert result.rejection_summary["capability"] == 1
    assert "Top rejection: capability=1" in result.reasoning


def test_order_rejected_when_no_supplier_covers_required_region():
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="İstanbul Only",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_IST,  # only Istanbul
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    ankara_order = _standard_order(
        seq=1,
        required_regions=1 << 1,  # REGION_TR_ANKARA — not covered
    )
    result = engine.route_order(ankara_order, audit=False)
    assert result.is_rejected


def test_region_and_capability_constraints_must_match_same_supplier():
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Fragile Istanbul",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_IST,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Standard Ankara",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_STANDARD,
                region_mask=REGION_TR_ANKARA,
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    fragile_ankara_order = _standard_order(
        seq=1,
        required_capabilities=CAP_FRAGILE,
        required_regions=REGION_TR_ANKARA,
    )
    result = engine.route_order(fragile_ankara_order, audit=False)
    assert result.is_rejected


def test_route_batch_same_as_sequential(engine):
    orders = [_standard_order(seq=i) for i in range(1, 11)]
    batch_results = engine.route_batch(orders, audit=False).results
    seq_results = [engine.route_order(o, audit=False) for o in orders]
    for b, s in zip(batch_results, seq_results):
        assert b.status == s.status
        assert b.chosen_supplier_id == s.chosen_supplier_id
        assert b.estimated_cost_microunits == s.estimated_cost_microunits


def test_route_batch_empty_list(engine):
    assert engine.route_batch([]).results == []


def test_route_batch_empty_summary_has_empty_histogram(engine):
    result = engine.route_batch([], trace_mode="summary")
    assert result.results == []
    assert result.rejection_histogram == {}


def test_empty_supplier_catalog_raises():
    with pytest.raises(PolicyValidationError):
        _policy_builder().build()


def test_duplicate_supplier_ids_raise():
    with pytest.raises(PolicyValidationError):
        spec = SupplierSpec(
            supplier_id=1,
            name="Duplicate",
            reliability_pct=98.0,
            risk_tolerance_pct=50.0,
            sla_hours=24,
            shipping_cost_microunits=5_000_000,
            region_mask=REGION_TR_ALL,
        )
        _policy_builder().add_supplier(spec).add_supplier(spec).build()


def test_supplier_policy_models_exposes_kernel_specs_before_build():
    builder = _policy_builder().add_supplier(
        SupplierSpec(
            supplier_id=7,
            name="Inspectable",
            reliability_pct=98.5,
            risk_tolerance_pct=55.0,
            sla_hours=3,
            shipping_cost_microunits=4_000_000,
            capabilities=CAP_FRAGILE,
            region_mask=REGION_TR_ALL,
        )
    )
    models = builder.models()
    assert len(models) == 1
    assert models[0].model_id == 7
    assert models[0].quality_bps == 9_850
    assert models[0].p95_latency_ms == 3  # hours stored directly as the kernel SLA unit


def test_disabled_only_supplier_catalog_raises():
    disabled = SupplierSpec(
        supplier_id=1,
        name="Disabled",
        reliability_pct=98.0,
        risk_tolerance_pct=50.0,
        sla_hours=24,
        shipping_cost_microunits=5_000_000,
        region_mask=REGION_TR_ALL,
        enabled=False,
    )
    with pytest.raises(PolicyValidationError):
        _policy_builder().add_supplier(disabled).build()


def test_disabled_supplier_is_not_selected_when_enabled_alternative_exists():
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Disabled Cheap",
                reliability_pct=99.9,
                risk_tolerance_pct=99.0,
                sla_hours=1,
                shipping_cost_microunits=1_000_000,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_ALL,
                enabled=False,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Enabled Backup",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_ALL,
                enabled=True,
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    result = engine.route_order(
        _standard_order(seq=1, required_capabilities=CAP_FRAGILE),
        audit=False,
    )
    assert result.is_fulfilled
    assert result.chosen_supplier_id == 2


def test_supplier_policy_sla_hours_stored_as_kernel_unit():
    policy = (
        _policy_builder()
        .latency_cost(microunits_per_hour=7_200_000)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Timed Supplier",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=2,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    model = policy.models()[0]
    assert model.p95_latency_ms == 2  # hours stored directly; one kernel latency unit = one hour
    assert policy.latency_penalty_microunits_per_ms == 7_200_000  # passed through as-is (µu/hour)


def test_supplier_policy_latency_cost_zero_disables_penalty():
    policy = (
        _policy_builder()
        .latency_cost(microunits_per_hour=0)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="No Penalty",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=2,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    assert policy.latency_penalty_microunits_per_ms == 0


def test_supplier_policy_latency_cost_passed_through_as_µu_per_hour():
    policy = (
        _policy_builder()
        .latency_cost(microunits_per_hour=500_000)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Tiny Penalty",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=2,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    assert policy.latency_penalty_microunits_per_ms == 500_000


def test_supplier_sla_and_order_deadline_are_capped_to_kernel_range():
    over_limit = 1 << 32  # exceeds u32 max = _MAX_SLA_HOURS
    with pytest.raises(ValidationError):
        SupplierSpec(
            supplier_id=1,
            name="Impossible SLA",
            reliability_pct=98.0,
            risk_tolerance_pct=50.0,
            sla_hours=over_limit,
            shipping_cost_microunits=5_000_000,
            region_mask=REGION_TR_ALL,
        )
    with pytest.raises(ValidationError):
        _standard_order(seq=1, max_delivery_hours=over_limit)


@given(seq=st.integers(min_value=1, max_value=1_000_000))
@settings(max_examples=200)
def test_property_determinism(seq: int):
    """Same order always routes to the same supplier."""
    engine = EcomEngine(_standard_policy())
    order = _standard_order(seq=seq)
    r1 = engine.route_order(order, audit=False)
    r2 = engine.route_order(order, audit=False)
    assert r1.status == r2.status
    assert r1.chosen_supplier_id == r2.chosen_supplier_id
    assert r1.estimated_cost_microunits == r2.estimated_cost_microunits


@given(
    return_risk_pct=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
    confidence_pct=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
)
@settings(max_examples=200)
def test_property_risk_at_or_above_limit_rejected(return_risk_pct: float, confidence_pct: float):
    """Orders with risk_bps >= hard_limit_bps must be rejected."""
    risk_limit = 30.0
    engine = EcomEngine(_standard_policy(return_risk_limit_max_pct=risk_limit))
    order = _standard_order(
        seq=1,
        return_risk_pct=return_risk_pct,
        confidence_pct=confidence_pct,
    )
    result = engine.route_order(order, audit=False)
    risk_bps = int(return_risk_pct * 100)
    hard_limit_bps = int(risk_limit * 100)
    if risk_bps >= hard_limit_bps:
        assert result.is_rejected, (
            f"risk_bps={risk_bps} >= limit={hard_limit_bps} must be rejected, "
            f"got status={result.status}"
        )


@given(seq=st.integers(min_value=1, max_value=1_000_000))
@settings(max_examples=100)
def test_property_audit_bundle_always_valid_for_fulfilled_orders(seq: int):
    """For any fulfilled order, verified_audit_bundle must succeed."""
    engine = EcomEngine(_standard_policy())
    order = _standard_order(seq=seq)
    result = engine.route_order(order, audit=True)
    if result.is_fulfilled:
        assert result.audit_bundle is not None
        assert result.audit_bundle.replay_valid


@given(
    budget_microunits=st.integers(min_value=0, max_value=100_000_000),
    order_value=st.integers(min_value=1_000_000, max_value=1_000_000_000),
)
@settings(max_examples=150)
def test_property_cost_never_exceeds_budget(budget_microunits: int, order_value: int):
    """Estimated cost for a fulfilled order is always within the stated budget."""
    engine = EcomEngine(_standard_policy())
    order = _standard_order(
        seq=1,
        budget_limit_microunits=budget_microunits,
        order_value_microunits=order_value,
    )
    result = engine.route_order(order, audit=False)
    if result.is_fulfilled:
        assert result.estimated_cost_microunits <= budget_microunits, (
            f"Cost {result.estimated_cost_microunits} > budget {budget_microunits}"
        )


def test_cost_encoding_shipping_cost_passes_through_exactly():
    """shipping_cost_microunits is returned unchanged as estimated_cost."""
    shipping = 6_789_012
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Exact Cost",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=shipping,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(
        _standard_order(seq=1, budget_limit_microunits=shipping + 1),
        audit=False,
    )
    assert result.is_fulfilled
    assert result.estimated_cost_microunits == shipping


def test_handling_cost_adds_to_estimated_cost():
    """handling_cost_microunits is added to shipping_cost in the estimated total."""
    shipping = 5_000_000
    handling = 1_500_000
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="With Handling",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=shipping,
                handling_cost_microunits=handling,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(
        _standard_order(
            seq=1,
            budget_limit_microunits=shipping + handling + 1,
            required_capabilities=CAP_FRAGILE,
        ),
        audit=False,
    )
    assert result.is_fulfilled
    assert result.estimated_cost_microunits == shipping + handling


def test_latency_penalty_drives_faster_supplier_selection():
    """A large latency penalty causes the faster supplier to win despite higher shipping cost."""
    policy = (
        _policy_builder()
        .latency_cost(microunits_per_hour=1_000_000)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Fast Expensive",
                reliability_pct=98.0,
                risk_tolerance_pct=60.0,
                sla_hours=4,
                shipping_cost_microunits=9_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Slow Cheap",
                reliability_pct=98.0,
                risk_tolerance_pct=60.0,
                sla_hours=48,
                shipping_cost_microunits=4_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(
        _standard_order(seq=1, budget_limit_microunits=15_000_000),
        audit=False,
    )
    # latency utility: fast −4M µu vs slow −48M µu → +44M advantage for fast
    # cost disadvantage for fast: −5M µu → net +39M µu for fast supplier
    assert result.is_fulfilled
    assert result.chosen_supplier_id == 1


def test_risk_at_exact_hard_limit_is_rejected():
    """return_risk_pct at the exact limit is rejected (>= semantics)."""
    limit_pct = 35.0
    engine = EcomEngine(
        _policy_builder()
        .return_risk_limit(max_pct=limit_pct)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Test Supplier",
                reliability_pct=99.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = engine.route_order(
        _standard_order(seq=1, return_risk_pct=limit_pct),
        audit=False,
    )
    assert result.is_rejected


def test_confidence_at_floor_not_rejected():
    """confidence_pct == confidence_floor must pass (strict < gate)."""
    floor_pct = 70.0
    engine = EcomEngine(
        _policy_builder()
        .confidence_floor(min_pct=floor_pct)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Test Supplier",
                reliability_pct=99.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = engine.route_order(
        _standard_order(seq=1, return_risk_pct=5.0, confidence_pct=floor_pct),
        audit=False,
    )
    assert not result.is_rejected


def test_confidence_below_floor_is_rejected():
    """confidence_pct strictly below the floor is always rejected."""
    floor_pct = 70.0
    engine = EcomEngine(
        _policy_builder()
        .confidence_floor(min_pct=floor_pct)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Test Supplier",
                reliability_pct=99.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    # int(60.0 * 100) = 6000 < int(70.0 * 100) = 7000
    result = engine.route_order(
        _standard_order(seq=1, return_risk_pct=5.0, confidence_pct=60.0),
        audit=False,
    )
    assert result.is_rejected


def test_requested_supplier_zero_gives_accepted_status():
    """requested_supplier_id=0 always yields status='accepted' when fulfilled."""
    result = EcomEngine(_standard_policy()).route_order(
        _standard_order(seq=1, requested_supplier_id=0),
        audit=False,
    )
    assert result.is_fulfilled
    assert result.status == "accepted"


def test_preferred_supplier_substituted_when_too_slow():
    """When the preferred supplier misses the deadline a faster one is chosen."""
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Fast Supplier",
                reliability_pct=98.0,
                risk_tolerance_pct=60.0,
                sla_hours=12,
                shipping_cost_microunits=8_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Slow Supplier",
                reliability_pct=98.0,
                risk_tolerance_pct=60.0,
                sla_hours=72,
                shipping_cost_microunits=4_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(
        _standard_order(
            seq=1,
            requested_supplier_id=2,
            max_delivery_hours=24,
            budget_limit_microunits=10_000_000,
        ),
        audit=False,
    )
    assert result.is_fulfilled
    assert result.status == "substituted"
    assert result.chosen_supplier_id == 1


def test_engine_fingerprint_is_64_char_hex():
    fp = EcomEngine(_standard_policy()).fingerprint
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_engine_fingerprint_differs_between_catalogs():
    """Different supplier catalogs produce different fingerprints."""
    policy_a = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Supplier A",
                reliability_pct=98.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    policy_b = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Supplier B",
                reliability_pct=97.0,
                risk_tolerance_pct=55.0,
                sla_hours=48,
                shipping_cost_microunits=3_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    assert EcomEngine(policy_a).fingerprint != EcomEngine(policy_b).fingerprint


def test_engine_supplier_count():
    assert EcomEngine(_standard_policy()).supplier_count == 2


def test_extreme_shipping_cost_no_crash():
    """Very large shipping costs must not crash the kernel."""
    huge_cost = 2**40
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Expensive",
                reliability_pct=99.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=huge_cost,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(
        _standard_order(seq=1, budget_limit_microunits=2**62),
        audit=False,
    )
    assert result.status in ("accepted", "substituted", "rejected")


def test_evaluated_eligible_supplier_counts_consistent():
    """evaluated_suppliers >= eligible_suppliers for every order."""
    engine = EcomEngine(_standard_policy())
    for seq in range(1, 6):
        result = engine.route_order(_standard_order(seq=seq), audit=False)
        assert result.evaluated_suppliers >= result.eligible_suppliers
        assert result.eligible_suppliers >= 0


def test_rejected_explain_contains_order_id_and_reason():
    """explain() for a rejected order contains the order ID and 'reject'."""
    engine = EcomEngine(_standard_policy(return_risk_limit_max_pct=20.0))
    risky = _standard_order(seq=1, return_risk_pct=25.0, confidence_pct=90.0)
    result = engine.route_order(risky, audit=False)
    assert result.is_rejected
    explanation = result.explain()
    assert result.order_id in explanation
    assert "reject" in explanation.lower()


def test_alternative_supplier_id_is_zero_when_only_one_in_catalog():
    """Single-supplier catalog has no runner-up, so alternative_supplier_id=0."""
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Only Option",
                reliability_pct=99.0,
                risk_tolerance_pct=60.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    result = EcomEngine(policy).route_order(_standard_order(), audit=False)
    assert result.is_fulfilled
    assert result.alternative_supplier_id == 0


def test_route_batch_audit_digests_match_sequential():
    """route_batch(audit=True) produces the same digests as sequential route_order."""
    engine = EcomEngine(_standard_policy())
    orders = [_standard_order(seq=i) for i in range(1, 4)]
    batch = engine.route_batch(orders, audit=True).results
    sequential = [engine.route_order(o, audit=True) for o in orders]
    for b, s in zip(batch, sequential):
        assert b.audit_bundle is not None
        assert s.audit_bundle is not None
        assert b.audit_bundle.policy_digest_hex == s.audit_bundle.policy_digest_hex
        assert b.audit_bundle.input_digest_hex == s.audit_bundle.input_digest_hex
        assert b.audit_bundle.decision_digest_hex == s.audit_bundle.decision_digest_hex


@given(
    seqs=st.lists(
        st.integers(min_value=1, max_value=1_000_000),
        min_size=1,
        max_size=20,
        unique=True,
    )
)
@settings(max_examples=50)
def test_property_batch_matches_sequential_any_size(seqs: list[int]):
    """route_batch produces identical outcomes to sequential route_order for any batch size."""
    engine = EcomEngine(_standard_policy())
    orders = [_standard_order(seq=s) for s in seqs]
    batch = engine.route_batch(orders, audit=False).results
    seq_results = [engine.route_order(o, audit=False) for o in orders]
    for b, s in zip(batch, seq_results):
        assert b.status == s.status
        assert b.chosen_supplier_id == s.chosen_supplier_id
        assert b.estimated_cost_microunits == s.estimated_cost_microunits


@given(seq=st.integers(min_value=1, max_value=1_000_000))
@settings(max_examples=100)
def test_property_prescribe_raw_always_verifies(seq: int):
    """A freshly prescribed raw decision always passes verified_audit_bundle."""
    engine = EcomEngine(_standard_policy())
    order = _standard_order(seq=seq)
    decision = engine.prescribe_raw(order)
    bundle = engine.verified_audit_bundle_for_order(order, decision)
    assert bundle.replay_valid


@given(
    seq=st.integers(min_value=1, max_value=500_000),
    other_seq=st.integers(min_value=500_001, max_value=1_000_000),
)
@settings(max_examples=100)
def test_property_tamper_detected_for_different_order(seq: int, other_seq: int):
    """verified_audit_bundle_for_order raises when the order doesn't match the decision."""
    engine = EcomEngine(_standard_policy())
    decision = engine.prescribe_raw(_standard_order(seq=seq))
    with pytest.raises((VerificationError, Exception)):
        engine.verified_audit_bundle_for_order(_standard_order(seq=other_seq), decision)


@given(
    budget_microunits=st.integers(min_value=0, max_value=20_000_000),
    return_risk_pct=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
)
@settings(max_examples=150)
def test_property_rejected_order_cost_is_zero(budget_microunits: int, return_risk_pct: float):
    """Rejected orders always have estimated_cost_microunits=0."""
    engine = EcomEngine(_standard_policy())
    result = engine.route_order(
        _standard_order(
            seq=1,
            budget_limit_microunits=budget_microunits,
            return_risk_pct=return_risk_pct,
        ),
        audit=False,
    )
    if result.is_rejected:
        assert result.estimated_cost_microunits == 0


@given(
    n_suppliers=st.integers(min_value=2, max_value=6),
    catalog_epoch=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=50)
def test_property_multi_supplier_always_produces_decision(
    n_suppliers: int,
    catalog_epoch: int,
):
    """Any valid catalog always produces a routing decision without raising."""
    builder = SupplierPolicy(policy_epoch=1, catalog_epoch=catalog_epoch)
    for i in range(1, n_suppliers + 1):
        builder.add_supplier(
            SupplierSpec(
                supplier_id=i,
                name=f"Supplier {i}",
                reliability_pct=95.0 + i * 0.5,
                risk_tolerance_pct=60.0,
                sla_hours=24 * i,
                shipping_cost_microunits=i * 1_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
    result = EcomEngine(builder.build()).route_order(
        _standard_order(seq=1, budget_limit_microunits=20_000_000),
        audit=False,
    )
    assert result.status in ("accepted", "substituted", "rejected")


@given(
    confidence_pct=st.floats(min_value=0.0, max_value=59.99, allow_nan=False),
)
@settings(max_examples=150)
def test_property_confidence_below_floor_always_rejected(confidence_pct: float):
    """Any confidence_pct that converts below the floor bps is always rejected."""
    floor_pct = 60.0
    engine = EcomEngine(_standard_policy(confidence_floor_min_pct=floor_pct))
    result = engine.route_order(
        _standard_order(seq=1, return_risk_pct=5.0, confidence_pct=confidence_pct),
        audit=False,
    )
    confidence_bps = int(confidence_pct * 100)
    floor_bps = int(floor_pct * 100)
    if confidence_bps < floor_bps:
        assert result.is_rejected, (
            f"confidence_bps={confidence_bps} < floor={floor_bps} must be rejected"
        )


def test_route_batch_returns_batch_route_result(engine):
    """route_batch returns BatchRouteResult, not a plain list."""
    result = engine.route_batch([_standard_order(seq=1)])
    assert isinstance(result, BatchRouteResult)
    assert len(result.results) == 1


def test_route_batch_compact_has_empty_histogram(engine):
    """Default compact mode always produces an empty rejection_histogram."""
    orders = [_standard_order(seq=i) for i in range(1, 4)]
    assert engine.route_batch(orders).rejection_histogram == {}


def test_route_batch_compact_rejected_order_has_single_reason_key():
    """In compact mode a rejected order's rejection_summary has exactly one key with count 1."""
    engine = EcomEngine(_standard_policy(confidence_floor_min_pct=80.0))
    row = engine.route_batch([_standard_order(seq=1, confidence_pct=50.0)]).results[0]
    assert row.is_rejected
    assert len(row.rejection_summary) == 1
    assert list(row.rejection_summary.values()) == [1]


def test_route_batch_compact_differs_from_route_order_when_full_trace_exists():
    """route_order exposes per-constraint trace; compact batch keeps primary reason only."""
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Standard A",
                reliability_pct=98.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                capabilities=CAP_STANDARD,
                region_mask=REGION_TR_ALL,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="Standard B",
                reliability_pct=97.0,
                risk_tolerance_pct=50.0,
                sla_hours=24,
                shipping_cost_microunits=4_000_000,
                capabilities=CAP_FRAGILE,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    engine = EcomEngine(policy)
    order = _standard_order(seq=1, required_capabilities=CAP_REFRIGERATED)

    single = engine.route_order(order, audit=False)
    batch_row = engine.route_batch([order], audit=False).results[0]

    assert single.is_rejected
    assert batch_row.is_rejected
    assert single.rejection_summary.get("capability", 0) >= 1
    assert batch_row.rejection_summary == {"capability": 1}


def test_route_batch_summary_histogram_counts_rejected():
    """trace_mode='summary' populates rejection_histogram with per-reason counts."""
    engine = EcomEngine(_standard_policy(confidence_floor_min_pct=80.0))
    orders = [_standard_order(seq=i, confidence_pct=50.0) for i in range(1, 4)]
    result = engine.route_batch(orders, trace_mode="summary")
    assert result.rejection_histogram.get("confidence", 0) == 3


def test_route_batch_summary_histogram_empty_when_all_fulfilled(engine):
    """trace_mode='summary' histogram stays empty when no orders are rejected."""
    orders = [_standard_order(seq=i) for i in range(1, 4)]
    assert engine.route_batch(orders, trace_mode="summary").rejection_histogram == {}


def test_route_batch_summary_per_order_results_match_compact(engine):
    """trace_mode='summary' does not change per-order status or cost."""
    orders = [_standard_order(seq=i) for i in range(1, 4)]
    compact = engine.route_batch(orders, trace_mode="compact").results
    summary = engine.route_batch(orders, trace_mode="summary").results
    for c, s in zip(compact, summary):
        assert c.status == s.status
        assert c.chosen_supplier_id == s.chosen_supplier_id
        assert c.estimated_cost_microunits == s.estimated_cost_microunits


def test_route_batch_rejects_unknown_trace_mode(engine):
    """Unknown trace_mode values raise ValueError instead of silently defaulting."""
    with pytest.raises(ValueError, match="trace_mode"):
        engine.route_batch([_standard_order(seq=1)], trace_mode="full")
    with pytest.raises(ValueError, match="trace_mode"):
        engine.route_batch([_standard_order(seq=1)], trace_mode="banana")
