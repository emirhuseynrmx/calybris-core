"""The bridge a Python learner will actually stand on.

The decision engine is Rust and whatever learns from it will be Python. These
tests exist because a record shape that only exists on the Rust side is a record
nobody writes.
"""

from __future__ import annotations

import pytest

from calybris import _core


def catalog() -> list[_core.KernelModel]:
    return [
        _core.KernelModel(
            model_id=1,
            provider_id=0,
            quality_bps=9_000,
            risk_ceiling_bps=9_000,
            enabled=1,
            p95_latency_ms=200,
            capabilities=0b1,
            region_mask=0b1,
            input_cost_microunits_per_million_tokens=3_000_000,
            output_cost_microunits_per_million_tokens=15_000_000,
        ),
        _core.KernelModel(
            model_id=2,
            provider_id=1,
            quality_bps=7_000,
            risk_ceiling_bps=9_000,
            enabled=1,
            p95_latency_ms=900,
            capabilities=0b1,
            region_mask=0b1,
            input_cost_microunits_per_million_tokens=1_000_000,
            output_cost_microunits_per_million_tokens=5_000_000,
        ),
    ]


def policy() -> _core.PolicySnapshot:
    return _core.PolicySnapshot(1, 1, 9_000, 1_000, 2_000, 5, catalog())


def request(**overrides: int) -> _core.KernelInput:
    fields = {
        "request_sequence": 7,
        "requested_model_id": 1,
        "input_tokens": 1_000,
        "output_tokens": 500,
        "budget_limit_microunits": 50_000_000,
        "business_value_microunits": 5_000_000,
        "minimum_quality_bps": 0,
        "max_p95_latency_ms": 0,
        "risk_bps": 1_000,
        "confidence_bps": 9_000,
        "required_capabilities": 0b1,
        "allowed_provider_mask": _core.ALL_PROVIDERS,
        "required_region_mask": 0,
    }
    fields.update(overrides)
    return _core.KernelInput(**fields)


def measured() -> _core.Observation:
    return _core.Observation(
        realized_cost_microunits=4_100_000,
        realized_latency_ms=238,
        succeeded=True,
    )


def test_explain_reports_the_numbers_a_gate_compared() -> None:
    # A 300 ms cap puts candidate 2, at 900 ms, outside it.
    candidates = policy().explain(request(max_p95_latency_ms=300))
    by_id = {candidate.model_id: candidate for candidate in candidates}

    rejected = by_id[2]
    assert rejected.status == "rejected"
    assert rejected.gate == "Latency"
    assert (rejected.measured, rejected.limit) == (900, 300)
    # A rejected candidate was never priced, so it carries no utility.
    assert rejected.utility is None


def test_an_eligible_candidate_carries_the_terms_that_ranked_it() -> None:
    candidates = policy().explain(request())
    eligible = [c for c in candidates if c.status == "eligible"]
    assert eligible, "at least one candidate must clear every gate"

    for candidate in eligible:
        assert candidate.utility is not None and candidate.utility > 0
        assert candidate.cost_microunits is not None
        # The terms have to reconstruct the total the kernel ranked on.
        total = (
            candidate.quality_adjusted
            - candidate.risk_penalty
            - candidate.cost_microunits
            - candidate.latency_penalty
        )
        assert total == candidate.utility


def test_explain_agrees_with_the_decision() -> None:
    snapshot = policy()
    decision = snapshot.prescribe(request())
    eligible = [c for c in snapshot.explain(request()) if c.status == "eligible"]

    assert decision.selected_model_id in {c.model_id for c in eligible}
    best = max(c.utility for c in eligible)
    chosen = next(c for c in eligible if c.model_id == decision.selected_model_id)
    assert chosen.utility == best


def test_a_request_refused_at_the_hard_limits_explains_no_candidates() -> None:
    # risk at the hard limit: the catalog is never walked.
    assert policy().explain(request(risk_bps=9_000)) == []


def test_an_outcome_binds_to_its_decision() -> None:
    snapshot = policy()
    decision = snapshot.prescribe(request())
    outcome = _core.Outcome.applied(decision, 1_760_000_000_000_000, measured())

    outcome.validate()
    assert outcome.follows(decision)
    assert outcome.request_sequence == decision.request_sequence
    assert outcome.strategy == "maximise_utility"
    assert outcome.propensity_bps == _core.FULL_PROBABILITY_BPS
    assert len(outcome.digest) == 64


def test_applied_with_nothing_measured_is_refused() -> None:
    decision = policy().prescribe(request())
    outcome = _core.Outcome.applied(decision, 1, _core.Observation())

    with pytest.raises(ValueError, match="observation"):
        outcome.validate()

    # Abandoned explains the absence, so it stands.
    outcome.disposition = "abandoned"
    outcome.validate()


def test_an_explored_choice_records_its_probability() -> None:
    snapshot = policy()
    decision = snapshot.prescribe(request())
    other = 2 if decision.selected_model_id == 1 else 1

    outcome = _core.Outcome.chosen_otherwise(
        decision, 1, measured(), acted_model_id=other, propensity_bps=500
    )
    assert outcome.strategy == "explore"
    assert outcome.acted_model_id == other
    assert outcome.propensity_bps == 500


def test_an_observed_choice_cannot_have_had_no_chance_of_happening() -> None:
    decision = policy().prescribe(request())
    with pytest.raises(ValueError, match="propensity"):
        _core.Outcome.chosen_otherwise(
            decision, 1, measured(), acted_model_id=2, propensity_bps=0
        )


def test_a_missing_measurement_and_a_zero_measurement_differ() -> None:
    decision = policy().prescribe(request())
    absent = _core.Outcome.applied(
        decision, 1, _core.Observation(realized_latency_ms=1)
    )
    zero = _core.Outcome.applied(
        decision, 1, _core.Observation(realized_cost_microunits=0, realized_latency_ms=1)
    )
    assert absent.digest != zero.digest


def test_a_correction_is_a_new_revision_of_the_same_decision() -> None:
    decision = policy().prescribe(request())
    outcome = _core.Outcome.applied(decision, 1, measured())
    first = outcome.digest

    outcome.revision = 1
    outcome.observation = _core.Observation(
        realized_cost_microunits=9_900_000, realized_latency_ms=238, succeeded=True
    )

    assert outcome.digest != first
    assert outcome.follows(decision)


def test_an_unknown_disposition_is_refused() -> None:
    decision = policy().prescribe(request())
    outcome = _core.Outcome.applied(decision, 1, measured())
    with pytest.raises(ValueError, match="applied, abandoned or in_flight"):
        outcome.disposition = "probably_fine"
