"""Targeted bug-hunt probes for 0.4.5 release surfaces.

Run: pytest python/tests/test_bug_hunt.py -v
Or with thorough hypothesis: pytest python/tests/test_bug_hunt.py -q --hypothesis-profile=thorough
"""

from __future__ import annotations

import threading

import pytest
from calybris import BudgetGuard, CalybrisEngine
from calybris.errors import VerificationError
from calybris_commerce import (
    CAP_FRAGILE,
    CAP_HEAVY,
    CAP_REFRIGERATED,
    CAP_STANDARD,
    REGION_ALL,
    REGION_TR_ALL,
    REGION_TR_ANKARA,
    REGION_TR_IST,
    EcomEngine,
    OrderInput,
    SupplierSpec,
)
from hypothesis import given, settings
from hypothesis import strategies as st
from test_calybris import _make_policy, _make_request
from test_calybris_commerce import _policy_builder, _standard_order


def _bitmask_engine(cap_supplier: int, region_supplier: int):
    policy = (
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="A",
                reliability_pct=98.0,
                risk_tolerance_pct=70.0,
                sla_hours=12,
                shipping_cost_microunits=5_000_000,
                capabilities=cap_supplier,
                region_mask=region_supplier,
            )
        )
        .add_supplier(
            SupplierSpec(
                supplier_id=2,
                name="B",
                reliability_pct=97.0,
                risk_tolerance_pct=70.0,
                sla_hours=24,
                shipping_cost_microunits=4_000_000,
                capabilities=CAP_STANDARD | CAP_HEAVY,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    return EcomEngine(policy)


@given(
    req_caps=st.integers(min_value=0, max_value=CAP_FRAGILE | CAP_HEAVY | CAP_REFRIGERATED),
    req_regions=st.sampled_from([0, REGION_TR_IST, REGION_TR_ANKARA, REGION_TR_ALL]),
)
@settings(max_examples=300)
def test_property_batch_matches_sequential_under_bitmasks(req_caps: int, req_regions: int):
    """route_batch must match route_order for capability + region combinations."""
    engine = _bitmask_engine(CAP_FRAGILE | CAP_REFRIGERATED, REGION_TR_IST | REGION_TR_ANKARA)
    order = _standard_order(
        seq=42,
        required_capabilities=req_caps,
        required_regions=req_regions,
        budget_limit_microunits=20_000_000,
    )
    batch = engine.route_batch([order], audit=False).results[0]
    single = engine.route_order(order, audit=False)
    assert batch.status == single.status
    assert batch.chosen_supplier_id == single.chosen_supplier_id
    assert batch.estimated_cost_microunits == single.estimated_cost_microunits


@given(
    return_risk=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
    confidence=st.floats(min_value=0.0, max_value=100.0, allow_nan=False),
)
@settings(max_examples=300)
def test_property_kernel_input_bps_matches_int_truncation(return_risk: float, confidence: float):
    """OrderInput float→bps mapping must match what the kernel receives."""
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="X",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    order = _standard_order(seq=7, return_risk_pct=return_risk, confidence_pct=confidence)
    ki = engine.kernel_input(order)
    assert ki.risk_bps == int(return_risk * 100)
    assert ki.confidence_bps == int(confidence * 100)


def test_route_batch_large_10k_matches_sequential():
    """10k batch: memory + correctness (CSV 'Large Batch Routing' probe)."""
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Bulk",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    orders = [_standard_order(seq=i) for i in range(1, 10_001)]
    batch = engine.route_batch(orders, audit=False)
    assert len(batch.results) == 10_000
    # spot-check every 1000th + first/last
    for idx in [0, 999, 5000, 9999]:
        single = engine.route_order(orders[idx], audit=False)
        assert batch.results[idx].chosen_supplier_id == single.chosen_supplier_id


def test_prescribe_batch_threaded_matches_main_thread():
    """GIL release: batch results identical when called from worker thread."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    requests = [_make_request(seq=i) for i in range(1, 51)]
    main = engine.prescribe_batch(requests)
    holder: list = []

    def worker():
        holder.append(CalybrisEngine(policy).prescribe_batch(requests))

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert holder[0] == main


@given(
    ops=st.lists(
        st.tuples(st.integers(0, 5), st.integers(1, 30_000_000)),
        min_size=1,
        max_size=30,
    )
)
@settings(max_examples=200)
def test_property_budget_guard_exposure_cap_conservation(ops):
    """Mixed ops with exposure cap must stay balanced."""
    cap = 50_000_000
    guard = BudgetGuard().ensure_tenant("desk", 200_000_000, max_reserved_microcents=cap)
    open_ids: list[int] = []
    for op_type, amount in ops:
        match op_type % 6:
            case 0:
                hold = guard.reserve("desk", amount)
                if hold.is_reserved and hold.reservation_id is not None:
                    open_ids.append(hold.reservation_id)
            case 1 if open_ids:
                rid = open_ids.pop(0)
                guard.commit(rid, max(1, amount % 1_000_000))
            case 2 if open_ids:
                rid = open_ids.pop(0)
                guard.release(rid)
            case 3:
                guard.top_up("desk", amount)
            case 4:
                guard.set_max_reserved_microcents("desk", max(amount, 1))
            case _:
                pass
        assert guard.verify_conservation().is_balanced
        assert guard.reserved_microcents("desk") <= cap or not open_ids


def test_verified_audit_bundle_for_order_rejects_tampered_sequence():
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Audit",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    order = _standard_order(seq=100)
    decision = engine.prescribe_raw(order)
    tampered = OrderInput(**{**order.model_dump(), "order_sequence": order.order_sequence + 1})
    with pytest.raises(VerificationError):
        engine.verified_audit_bundle_for_order(tampered, decision)


def test_verified_audit_bundle_rejects_mismatched_decision():
    """Fail-closed: decision from a different order must not verify."""
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Audit",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    order_a = _standard_order(seq=1)
    order_b = _standard_order(seq=2)
    decision_a = engine.prescribe_raw(order_a)
    with pytest.raises(VerificationError):
        engine.verified_audit_bundle_for_order(order_b, decision_a)


@given(
    seq=st.integers(min_value=0, max_value=2**32 - 1),
    budget=st.integers(min_value=0, max_value=2**62),
    max_hours=st.integers(min_value=0, max_value=(1 << 32) - 1),
)
@settings(max_examples=200)
def test_property_order_mapping_extreme_fields_no_crash(seq: int, budget: int, max_hours: int):
    """OrderInput → KernelInput must survive u32-scale sequences and large budgets."""
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="Extreme",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    order = _standard_order(
        seq=seq,
        budget_limit_microunits=budget,
        max_delivery_hours=max_hours,
        required_regions=REGION_ALL,
    )
    ki = engine.kernel_input(order)
    assert ki.request_sequence == seq
    assert ki.budget_limit_microunits == budget
    assert ki.max_p95_latency_ms == max_hours
    assert ki.required_region_mask == REGION_ALL
    dec = engine.prescribe_raw(order)
    assert dec.request_sequence == seq


def test_route_batch_audit_roundtrip_matches_single():
    """Batch audit=True must produce same replay validity as route_order."""
    engine = EcomEngine(
        _policy_builder()
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="AuditBatch",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    orders = [_standard_order(seq=i) for i in range(1, 6)]
    singles = [engine.route_order(o, audit=True) for o in orders]
    batch = engine.route_batch(orders, audit=True)
    for single, batched in zip(singles, batch.results):
        assert batched.chosen_supplier_id == single.chosen_supplier_id
        assert batched.audit_bundle is not None
        assert batched.audit_bundle.replay_valid


def test_route_batch_rejected_orders_have_reason_in_summary():
    """Batch path must surface rejection reason (not only empty trace)."""
    engine = EcomEngine(
        _policy_builder()
        .return_risk_limit(max_pct=10.0)
        .add_supplier(
            SupplierSpec(
                supplier_id=1,
                name="S",
                reliability_pct=99.0,
                risk_tolerance_pct=80.0,
                sla_hours=24,
                shipping_cost_microunits=5_000_000,
                region_mask=REGION_TR_ALL,
            )
        )
        .build()
    )
    risky = _standard_order(seq=1, return_risk_pct=50.0)
    result = engine.route_batch([risky], audit=False).results[0]
    assert result.is_rejected
    assert result.rejection_summary  # should contain reason key from decision.reason
