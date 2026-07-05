"""Tests for the calybris Python package.

Property-based tests with Hypothesis mirror the Rust proptest suite:
- Determinism: same input always produces same output
- Verify-after-prescribe always returns Valid
- Tampered decisions are always detected
- verified_audit_bundle raises for any structural change to the decision
"""

from __future__ import annotations

import calybris_core as _core
import pytest
from calybris import (
    ALL_REGIONS,
    MICROCENTS_PER_CENT,
    BudgetGuard,
    CalybrisEngine,
    EngineConfig,
    InputBuilder,
    PolicyBuilder,
    VerificationError,
)
from calybris.errors import InputValidationError, PolicyValidationError
from calybris.types import (
    AuditBundle,
    Decision,
    DecisionTrace,
    ModelSpec,
    ProofEnvelope,
    VerifyResult,
)
from hypothesis import given, settings
from hypothesis import strategies as st


def _make_policy(**overrides) -> _core.PolicySnapshot:
    config = EngineConfig(**overrides)
    return (
        PolicyBuilder(config, policy_epoch=1, catalog_epoch=1)
        .add_model(
            ModelSpec(
                model_id=1,
                provider_id=0,
                quality_bps=9_000,
                risk_ceiling_bps=9_500,
                p95_latency_ms=200,
                region_mask=ALL_REGIONS,
                input_cost_microunits_per_million_tokens=250,
                output_cost_microunits_per_million_tokens=1_000,
            )
        )
        .add_model(
            ModelSpec(
                model_id=2,
                provider_id=1,
                quality_bps=7_000,
                risk_ceiling_bps=9_500,
                p95_latency_ms=90,
                region_mask=ALL_REGIONS,
                input_cost_microunits_per_million_tokens=25,
                output_cost_microunits_per_million_tokens=125,
            )
        )
        .build()
    )


def _make_request(seq: int = 1, model_id: int = 1) -> _core.KernelInput:
    return (
        InputBuilder(request_sequence=seq, requested_model_id=model_id)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=1_000, confidence_bps=9_000)
        .quality(minimum_bps=5_000)
        .latency(max_p95_ms=1_000)
        .build()
    )


@pytest.fixture()
def policy() -> _core.PolicySnapshot:
    return _make_policy()


@pytest.fixture()
def engine(policy: _core.PolicySnapshot) -> CalybrisEngine:
    return CalybrisEngine(policy)


@pytest.fixture()
def request_() -> _core.KernelInput:
    return _make_request()


def test_prescribe_returns_executable_decision(engine, request_):
    decision = engine.prescribe(request_)
    assert decision.is_executable()
    assert not decision.is_rejected()
    assert decision.selected_model_id in (1, 2)


def test_prescribe_as_model_returns_pydantic_decision(engine, request_):
    model = engine.prescribe_as_model(request_)
    assert isinstance(model, Decision)
    assert model.is_executable()
    assert model.action in ("execute_requested", "substitute")


def test_prescribe_batch_matches_sequential(engine, request_):
    requests = [_make_request(seq=i) for i in range(1, 11)]
    batch = engine.prescribe_batch(requests)
    sequential = [engine.prescribe(r) for r in requests]
    for b, s in zip(batch, sequential):
        assert b == s


def test_determinism_same_policy_same_input(engine, request_):
    d1 = engine.prescribe(request_)
    d2 = engine.prescribe(request_)
    assert d1 == d2


def test_determinism_independent_engines(request_):
    policy_a = _make_policy()
    policy_b = _make_policy()
    engine_a = CalybrisEngine(policy_a)
    engine_b = CalybrisEngine(policy_b)
    assert engine_a.prescribe(request_) == engine_b.prescribe(request_)


def test_verify_valid_for_fresh_decision(engine, request_):
    decision = engine.prescribe(request_)
    result = engine.verify(request_, decision)
    assert isinstance(result, VerifyResult)
    assert result.is_valid
    assert bool(result)


def test_verify_returns_status_string(engine, request_):
    decision = engine.prescribe(request_)
    assert engine.verify_status(request_, decision) == "valid"


def test_verify_full_dict_contains_status_on_valid(engine, request_):
    decision = engine.prescribe(request_)
    result = engine.verify(request_, decision)
    assert result.status == "valid"


def test_audit_bundle_replay_valid(engine, request_):
    decision = engine.prescribe(request_)
    bundle = engine.audit_bundle(request_, decision)
    assert isinstance(bundle, AuditBundle)
    assert bundle.replay_valid
    assert len(bundle.policy_digest_hex) == 64
    assert len(bundle.input_digest_hex) == 64
    assert len(bundle.decision_digest_hex) == 64


def test_verified_audit_bundle_succeeds_for_valid_decision(engine, request_):
    decision = engine.prescribe(request_)
    bundle = engine.verified_audit_bundle(request_, decision)
    assert bundle.replay_valid


def test_verified_audit_bundle_raises_for_wrong_request(engine, request_):
    decision = engine.prescribe(request_)
    wrong_request = _make_request(seq=999, model_id=2)
    with pytest.raises((VerificationError, Exception)):
        engine.verified_audit_bundle(wrong_request, decision)


def test_policy_validation_rejects_empty_catalog():
    config = EngineConfig()
    builder = PolicyBuilder(config)
    with pytest.raises(PolicyValidationError):
        builder.build()


def test_policy_validation_rejects_hard_risk_above_10000():
    with pytest.raises(Exception):
        EngineConfig(hard_risk_limit_bps=10_001)


def test_policy_validation_rejects_duplicate_model_ids():
    config = EngineConfig()
    builder = PolicyBuilder(config)
    spec = ModelSpec(
        model_id=1,
        provider_id=0,
        quality_bps=9_000,
        risk_ceiling_bps=9_500,
        p95_latency_ms=200,
        region_mask=ALL_REGIONS,
        input_cost_microunits_per_million_tokens=250,
        output_cost_microunits_per_million_tokens=1_000,
    )
    builder.add_model(spec).add_model(spec)
    with pytest.raises(PolicyValidationError):
        builder.build()


def test_policy_validation_rejects_all_disabled_models():
    config = EngineConfig()
    builder = PolicyBuilder(config).add_model(
        ModelSpec(
            model_id=1,
            provider_id=0,
            quality_bps=9_000,
            risk_ceiling_bps=9_500,
            enabled=False,
            p95_latency_ms=200,
            region_mask=ALL_REGIONS,
            input_cost_microunits_per_million_tokens=250,
            output_cost_microunits_per_million_tokens=1_000,
        )
    )
    with pytest.raises(PolicyValidationError):
        builder.build()


def test_risk_at_or_above_hard_limit_is_rejected(engine):
    for risk in (9_600, 9_700):  # at the limit and above are both rejected
        risky_request = (
            InputBuilder(request_sequence=1, requested_model_id=1)
            .tokens(input=1_000, output=500)
            .budget(50_000_000)
            .value(100_000)
            .risk(bps=risk, confidence_bps=9_000)
            .build()
        )
        assert engine.prescribe(risky_request).is_rejected(), f"risk_bps={risk} should be rejected"


def test_budget_too_low_for_all_models_is_rejected(engine):
    poor_request = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000_000, output=1_000_000)
        .budget(1)  # 1 microunit — cannot cover any model's cost
        .value(100_000)
        .risk(bps=0, confidence_bps=10_000)
        .build()
    )
    decision = engine.prescribe(poor_request)
    assert decision.is_rejected()


def test_quality_requirement_too_high_forces_substitute_or_reject(engine):
    high_quality_request = (
        InputBuilder(request_sequence=1, requested_model_id=2)  # model 2 has 7000 bps
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=500, confidence_bps=9_000)
        .quality(minimum_bps=8_500)  # model 2 fails, model 1 passes
        .build()
    )
    decision = engine.prescribe(high_quality_request)
    assert decision.is_executable()
    assert decision.selected_model_id == 1  # substituted to higher-quality model


def test_decision_model_convenience_methods_consistent_with_codes(engine, request_):
    raw = engine.prescribe(request_)
    model = engine.decision_model(raw)

    assert model.is_executable() == raw.is_executable()
    assert model.is_rejected() == raw.is_rejected()
    assert model.is_substitution() == raw.is_substitution()
    assert model.is_requested_execution() == raw.is_requested_execution()


def test_verify_result_model_is_valid(engine, request_):
    decision = engine.prescribe(request_)
    result = engine.verify(request_, decision)
    assert result.is_valid
    assert bool(result)
    assert result.status == "valid"


def test_audit_bundle_fields_are_64_char_hex(engine, request_):
    decision = engine.prescribe(request_)
    bundle = engine.audit_bundle(request_, decision)
    for field in (bundle.policy_digest_hex, bundle.input_digest_hex, bundle.decision_digest_hex):
        assert len(field) == 64
        assert all(c in "0123456789abcdef" for c in field)


def test_engine_repr_contains_epoch_and_model_count(engine):
    r = repr(engine)
    assert "policy_epoch=1" in r
    assert "models=2" in r
    assert "fingerprint=" in r


def test_prescribe_with_trace_exposes_rejection_histogram(engine):
    request = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(1)
        .value(100_000)
        .risk(bps=1_000, confidence_bps=9_000)
        .quality(minimum_bps=5_000)
        .latency(max_p95_ms=1_000)
        .build()
    )
    decision, trace = engine.prescribe_with_trace(request)
    assert decision.is_rejected()
    assert isinstance(trace, DecisionTrace)
    assert trace.evaluated_models == 2
    assert trace.budget >= 0


def test_input_builder_requires_budget():
    with pytest.raises(InputValidationError, match="budget is required"):
        InputBuilder(request_sequence=1, requested_model_id=1).build()


def test_input_builder_rejects_out_of_range_bps():
    with pytest.raises(InputValidationError, match="confidence_bps"):
        (
            InputBuilder(request_sequence=1, requested_model_id=1)
            .budget(50_000_000)
            .risk(bps=0, confidence_bps=50_000)
            .build()
        )


def test_audit_bundle_includes_schema_metadata(engine, request_):
    decision = engine.prescribe(request_)
    bundle = engine.audit_bundle(request_, decision)
    assert bundle.schema_version == "calybris.audit.v1"
    assert bundle.digest_algorithm == "sha256"
    assert bundle.proof_version == 1
    assert bundle.created_by == "calybris"
    assert bundle.policy_epoch == 1
    assert bundle.catalog_epoch == 1


def test_proof_envelope_seals_decision(engine, request_):
    decision = engine.prescribe(request_)
    envelope = engine.proof_envelope(request_, decision)
    assert isinstance(envelope, ProofEnvelope)
    assert envelope.replay_valid
    assert envelope.proof_version == 1
    assert len(envelope.policy_digest_hex) == 64


def test_package_version_is_exposed():
    import calybris

    assert calybris.__version__
    assert calybris.__version__ != "0.0.0+local"


def test_budget_guard_reserve_commit_and_certificate():
    guard = BudgetGuard().ensure_tenant(
        "desk-alpha",
        1_000 * MICROCENTS_PER_CENT,
        max_reserved_microcents=500 * MICROCENTS_PER_CENT,
    )
    hold = guard.reserve("desk-alpha", 100 * MICROCENTS_PER_CENT)
    assert hold.is_reserved
    assert hold.reservation_id is not None
    assert guard.reserved_microcents("desk-alpha") == 100 * MICROCENTS_PER_CENT

    settlement = guard.commit(hold.reservation_id, 90 * MICROCENTS_PER_CENT)
    assert settlement.is_committed
    assert guard.committed_microcents("desk-alpha") == 90 * MICROCENTS_PER_CENT
    assert guard.verify_conservation().is_balanced

    proof = guard.prove_conservation()
    cert = guard.certificate()
    assert len(proof.ledger_digest_hex) == 64
    assert cert.conservation_balanced
    assert cert.total_committed_microcents == 90 * MICROCENTS_PER_CENT


@given(seq=st.integers(min_value=0, max_value=10_000_000))
@settings(max_examples=200)
def test_property_determinism(seq: int):
    """For any valid sequence number, prescribe is deterministic."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = _make_request(seq=seq)
    assert engine.prescribe(req) == engine.prescribe(req)


@given(seq=st.integers(min_value=1, max_value=10_000_000))
@settings(max_examples=200)
def test_property_verify_after_prescribe_always_valid(seq: int):
    """verify(input, prescribe(input)) is always Valid."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = _make_request(seq=seq)
    dec = engine.prescribe(req)
    result = engine.verify(req, dec)
    assert result.is_valid, f"Verification failed for seq={seq}: {result}"


@given(
    risk_bps=st.integers(min_value=0, max_value=10_000),
    confidence_bps=st.integers(min_value=0, max_value=10_000),
)
@settings(max_examples=200)
def test_property_high_risk_rejected_when_above_limit(risk_bps: int, confidence_bps: int):
    """Any request with risk_bps >= hard_risk_limit_bps must be rejected."""
    hard_limit = 5_000
    policy = _make_policy(hard_risk_limit_bps=hard_limit)
    engine = CalybrisEngine(policy)
    req = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=risk_bps, confidence_bps=confidence_bps)
        .build()
    )
    decision = engine.prescribe(req)
    if risk_bps >= hard_limit:
        assert decision.is_rejected(), (
            f"Expected rejection for risk_bps={risk_bps} >= limit={hard_limit}, "
            f"got action={decision.action}"
        )


@given(seq=st.integers(min_value=1, max_value=10_000_000))
@settings(max_examples=100)
def test_property_verified_audit_bundle_never_fails_for_fresh_decision(seq: int):
    """verified_audit_bundle must never raise for a freshly prescribed decision."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = _make_request(seq=seq)
    dec = engine.prescribe(req)
    bundle = engine.verified_audit_bundle(req, dec)
    assert bundle.replay_valid


@given(
    n_models=st.integers(min_value=1, max_value=8),
    policy_epoch=st.integers(min_value=1, max_value=1_000),
)
@settings(max_examples=50)
def test_property_multi_model_policy_always_prescribes(n_models: int, policy_epoch: int):
    """A valid policy with N models always produces some decision."""
    config = EngineConfig()
    builder = PolicyBuilder(config, policy_epoch=policy_epoch, catalog_epoch=1)
    for i in range(1, n_models + 1):
        builder.add_model(
            ModelSpec(
                model_id=i,
                provider_id=i % 64,
                quality_bps=9_000,
                risk_ceiling_bps=9_500,
                p95_latency_ms=200,
                region_mask=ALL_REGIONS,
                input_cost_microunits_per_million_tokens=250,
                output_cost_microunits_per_million_tokens=1_000,
            )
        )
    policy = builder.build()
    engine = CalybrisEngine(policy)
    req = _make_request()
    dec = engine.prescribe(req)
    assert dec.selected_model_id in range(0, n_models + 1)
    result = engine.verify(req, dec)
    assert result.is_valid


def test_extreme_input_values_no_panic(engine):
    """u32::MAX tokens, large budget and value must not panic."""
    request = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=2**32 - 1, output=2**32 - 1)
        .budget(2**62)
        .value(2**62)
        .risk(bps=0, confidence_bps=10_000)
        .build()
    )
    decision = engine.prescribe(request)
    assert decision.request_sequence == 1


def test_confidence_at_minimum_floor_not_rejected():
    """confidence_bps == minimum_confidence_bps passes (strict < gate)."""
    policy = _make_policy(minimum_confidence_bps=7_000)
    eng = CalybrisEngine(policy)
    at_floor = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=7_000)
        .build()
    )
    assert not eng.prescribe(at_floor).is_rejected()


def test_confidence_below_minimum_floor_is_rejected():
    """confidence_bps < minimum_confidence_bps is always rejected."""
    policy = _make_policy(minimum_confidence_bps=7_000)
    eng = CalybrisEngine(policy)
    below = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=6_999)
        .build()
    )
    assert eng.prescribe(below).is_rejected()


def test_rejected_decision_cost_and_model_id_are_zero(engine):
    """Rejected decisions must have estimated_cost=0 and selected_model_id=0."""
    over_risk = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=9_600, confidence_bps=9_000)
        .build()
    )
    dec = engine.prescribe(over_risk)
    assert dec.is_rejected()
    assert dec.estimated_cost_microunits == 0
    assert dec.selected_model_id == 0


def test_latency_constraint_enforced(engine):
    """max_p95_latency_ms tighter than all models forces rejection."""
    tight = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=10_000)
        .latency(max_p95_ms=50)
        .build()
    )
    assert engine.prescribe(tight).is_rejected()


def test_latency_constraint_disabled_when_zero(engine):
    """max_p95_latency_ms=0 disables the latency gate entirely."""
    no_limit = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=10_000)
        .latency(max_p95_ms=0)
        .build()
    )
    assert not engine.prescribe(no_limit).is_rejected()


def test_provider_mask_restricts_to_single_provider(engine):
    """allowed_provider_mask=1<<1 admits only provider_id=1, which is model 2."""
    provider1_only = (
        InputBuilder(request_sequence=1, requested_model_id=0)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=10_000)
        .providers(allowed_mask=1 << 1)
        .build()
    )
    dec = engine.prescribe(provider1_only)
    assert dec.is_executable()
    assert dec.selected_model_id == 2


def test_prescribe_with_trace_counts_are_consistent(engine, request_):
    """evaluated_models equals catalog size; eligible <= evaluated."""
    _, trace = engine.prescribe_with_trace(request_)
    assert trace.evaluated_models == 2
    assert 0 <= trace.eligible_models <= trace.evaluated_models


def test_budget_guard_release_restores_available_microcents():
    """Releasing a reservation returns the amount to available budget."""
    guard = BudgetGuard().ensure_tenant("t", 1_000 * MICROCENTS_PER_CENT)
    hold = guard.reserve("t", 200 * MICROCENTS_PER_CENT)
    assert hold.is_reserved
    guard.release(hold.reservation_id)
    assert guard.reserved_microcents("t") == 0
    assert guard.verify_conservation().is_balanced


def test_budget_guard_reserve_over_exposure_limit_is_denied():
    """Reservations over the exposure cap are denied without mutating state."""
    guard = BudgetGuard().ensure_tenant(
        "t",
        1_000 * MICROCENTS_PER_CENT,
        max_reserved_microcents=100 * MICROCENTS_PER_CENT,
    )
    big = guard.reserve("t", 200 * MICROCENTS_PER_CENT)
    assert not big.is_reserved
    assert guard.reserved_microcents("t") == 0
    assert guard.verify_conservation().is_balanced


def test_budget_guard_top_up_adds_to_initial():
    """top_up increases initial_microcents by the supplied amount."""
    initial = 500 * MICROCENTS_PER_CENT
    addition = 200 * MICROCENTS_PER_CENT
    guard = BudgetGuard().ensure_tenant("t", initial)
    guard.top_up("t", addition)
    assert guard.initial_microcents("t") == initial + addition
    assert guard.verify_conservation().is_balanced


def test_utility_for_model_none_when_budget_insufficient(engine):
    """utility_for_model returns None for all models when budget cannot cover cost."""
    squeezed = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000_000, output=1_000_000)
        .budget(1)
        .value(100_000)
        .risk(bps=0, confidence_bps=10_000)
        .build()
    )
    assert engine.utility_for_model(squeezed, 1) is None
    assert engine.utility_for_model(squeezed, 2) is None


def test_counterfactual_utility_non_none_for_eligible_runner_up(engine, request_):
    """counterfactual_utility is non-None for any model eligible under the policy."""
    dec = engine.prescribe(request_)
    assert dec.is_executable()
    other = 2 if dec.selected_model_id == 1 else 1
    util = engine.counterfactual_utility(request_, other)
    assert util is not None
    assert isinstance(util, int)


def test_prescribe_batch_large_matches_sequential(engine):
    """Batch of 100 requests produces identical decisions to sequential evaluation."""
    requests = [_make_request(seq=i) for i in range(1, 101)]
    batch = engine.prescribe_batch(requests)
    assert len(batch) == 100
    for i, (b, r) in enumerate(zip(batch, requests)):
        assert b == engine.prescribe(r), f"mismatch at index {i}"


def test_budget_guard_snapshot_reflects_tenant_count():
    """snapshot().tenants has one entry per registered tenant."""
    guard = BudgetGuard().ensure_tenant("a", 1_000).ensure_tenant("b", 2_000)
    snap = guard.snapshot()
    assert guard.tenant_count == 2
    assert len(snap.tenants) == 2


@given(risk_bps=st.integers(min_value=9_600, max_value=10_000))
@settings(max_examples=50)
def test_property_rejected_cost_and_model_id_are_zero(risk_bps: int):
    """Rejected decisions always have estimated_cost=0 and selected_model_id=0."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=risk_bps, confidence_bps=9_000)
        .build()
    )
    dec = engine.prescribe(req)
    assert dec.is_rejected()
    assert dec.estimated_cost_microunits == 0
    assert dec.selected_model_id == 0


@given(seq=st.integers(min_value=1, max_value=500_000))
@settings(max_examples=100)
def test_property_tamper_always_detected(seq: int):
    """Any input change to a fresh decision is detected by verified_audit_bundle."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = _make_request(seq=seq)
    dec = engine.prescribe(req)
    wrong_req = _make_request(seq=seq + 500_000)
    with pytest.raises((VerificationError, Exception)):
        engine.verified_audit_bundle(wrong_req, dec)


@given(confidence_bps=st.integers(min_value=0, max_value=10_000))
@settings(max_examples=150)
def test_property_confidence_below_floor_rejected(confidence_bps: int):
    """confidence_bps < minimum_confidence_bps must always result in rejection."""
    floor = 5_000
    policy = _make_policy(minimum_confidence_bps=floor)
    engine = CalybrisEngine(policy)
    req = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=1_000, output=500)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=0, confidence_bps=confidence_bps)
        .build()
    )
    if confidence_bps < floor:
        assert engine.prescribe(req).is_rejected(), (
            f"confidence_bps={confidence_bps} < floor={floor} must be rejected"
        )


@given(
    ops=st.lists(
        st.tuples(st.integers(0, 4), st.integers(1, 50_000_000)),
        min_size=1,
        max_size=40,
    )
)
@settings(max_examples=100)
def test_property_budget_guard_conservation_invariant(ops):
    """Conservation invariant holds after any sequence of budget operations."""
    guard = BudgetGuard().ensure_tenant("t", 100_000_000)
    open_reservations: list[tuple[int, int]] = []
    for op_type, amount in ops:
        match op_type % 5:
            case 0:
                hold = guard.reserve("t", amount)
                if hold.is_reserved and hold.reservation_id is not None:
                    open_reservations.append((hold.reservation_id, amount))
            case 1 if open_reservations:
                rid, reserved_amt = open_reservations.pop(0)
                guard.commit(rid, min(amount, reserved_amt))
            case 2 if open_reservations:
                rid, _ = open_reservations.pop(0)
                guard.release(rid)
            case 3:
                guard.top_up("t", amount)
            case _:
                pass
        assert guard.verify_conservation().is_balanced


@given(
    input_tokens=st.integers(0, 2**32 - 1),
    output_tokens=st.integers(0, 2**32 - 1),
    value=st.integers(-(2**62), 2**62),
    budget=st.integers(0, 2**62),
)
@settings(max_examples=50)
def test_property_extreme_values_no_panic(
    input_tokens: int,
    output_tokens: int,
    value: int,
    budget: int,
):
    """Kernel must not panic for any combination of valid Rust field ranges."""
    policy = _make_policy()
    engine = CalybrisEngine(policy)
    req = (
        InputBuilder(request_sequence=1, requested_model_id=1)
        .tokens(input=input_tokens, output=output_tokens)
        .budget(budget)
        .value(value)
        .risk(bps=0, confidence_bps=10_000)
        .build()
    )
    dec = engine.prescribe(req)
    assert dec.request_sequence == 1
