"""Business decision adapter contracts against the real native kernel."""

import json

import pytest
from calybris.builder import EngineConfig
from calybris.decisions import Candidate, DecisionEngine, DecisionRequest, compare_policies


def candidates():
    return [
        Candidate(
            candidate_id=1,
            provider_id=0,
            quality_bps=9000,
            risk_ceiling_bps=9500,
            lead_time_ms=50,
            region_mask=1,
            quoted_cost_microunits=100,
        ),
        Candidate(
            candidate_id=2,
            provider_id=1,
            quality_bps=9000,
            risk_ceiling_bps=9500,
            lead_time_ms=100,
            region_mask=1,
            quoted_cost_microunits=200,
        ),
    ]


def request(**changes):
    return DecisionRequest(
        request_sequence=1, budget_microunits=500, business_value_microunits=10000, **changes
    )


def test_selection_and_native_proof_are_preserved():
    engine = DecisionEngine(candidates())
    result = engine.decide(request())
    assert result.selected_candidate_id == 1
    assert result.status == "selected"
    assert result.decision.estimated_cost_microunits == 100
    assert result.proof.replay_valid
    assert len(result.catalog_digest) == 64
    assert engine.verify(request(), result)
    assert not engine.verify(request(minimum_quality_bps=9500), result)
    assert json.loads(result.model_dump_json())["schema_version"] == "calybris.decision.v1"


def test_no_eligible_candidate_is_explicit_not_a_fake_zero_id():
    result = DecisionEngine(candidates()).decide(request(minimum_quality_bps=9500))
    assert result.status == "rejected"
    assert result.selected_candidate_id is None
    assert result.trace.quality == 2


def test_catalog_identity_ignores_input_order_but_not_quotes():
    a = DecisionEngine(candidates())
    b = DecisionEngine(list(reversed(candidates())))
    assert a.catalog_digest == b.catalog_digest
    assert a.decide(request()) == b.decide(request())
    changed = candidates()
    changed[0] = changed[0].model_copy(update={"quoted_cost_microunits": 120})
    assert DecisionEngine(changed).catalog_digest != a.catalog_digest


def test_policy_comparison_reuses_same_frozen_requests():
    before = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=0))
    after = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=9500))
    comparison = compare_policies(before, after, [request(confidence_bps=9000)])
    assert comparison.total == 1
    assert comparison.changed == 1
    assert comparison.newly_rejected == 1
    assert comparison.changes[0].before.selected_candidate_id == 1
    assert comparison.changes[0].after.selected_candidate_id is None
    assert comparison.changed_fields == ("minimum_confidence_bps",)


def test_comparison_refuses_different_catalog_and_is_bounded():
    engine = DecisionEngine(candidates())
    with pytest.raises(ValueError, match="catalog"):
        compare_policies(engine, DecisionEngine(candidates()[:1]), [])
    with pytest.raises(ValueError, match="max_requests"):
        compare_policies(engine, engine, [request(), request()], max_requests=1)


def test_strict_integer_and_immutable_candidate():
    with pytest.raises(ValueError):
        Candidate(
            candidate_id=True,
            provider_id=0,
            quality_bps=9000,
            risk_ceiling_bps=9500,
            lead_time_ms=1,
            region_mask=1,
            quoted_cost_microunits=1,
        )
    with pytest.raises(ValueError):
        candidates()[0].candidate_id = 3


def test_comparison_change_details_can_be_bounded_without_losing_totals():
    before = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=0))
    after = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=9500))
    result = compare_policies(before, after, [request(confidence_bps=9000)] * 5, max_changes=2)
    assert result.total == result.changed == result.newly_rejected == 5
    assert len(result.changes) == 2
    assert result.changes_truncated


def test_a_comparison_names_both_policies_even_when_its_details_are_truncated():
    before = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=0))
    after = DecisionEngine(candidates(), config=EngineConfig(minimum_confidence_bps=9500))
    requests = [request(confidence_bps=9000) for _ in range(5)]

    comparison = compare_policies(before, after, requests, max_changes=0)

    assert comparison.changes == ()
    assert comparison.changes_truncated
    assert comparison.changed == 5
    assert comparison.before_policy.policy_digest == before.policy_digest
    assert comparison.after_policy.policy_digest == after.policy_digest
    assert comparison.before_policy != comparison.after_policy
    assert comparison.policy_changed


def test_an_epoch_only_change_is_still_a_changed_policy():
    """Configuration equality is not policy equality.

    ``changed_fields`` compares the configured knobs and finds nothing here, which is
    correct and also not the whole answer: the caller versioned the policy and a
    reader has to be able to see that.
    """
    config = EngineConfig()
    before = DecisionEngine(candidates(), config=config, policy_epoch=1)
    after = DecisionEngine(candidates(), config=config, policy_epoch=7)

    comparison = compare_policies(before, after, [request()])

    assert comparison.changed_fields == ()
    assert comparison.policy_changed
    assert comparison.before_policy.policy_epoch == 1
    assert comparison.after_policy.policy_epoch == 7
