"""The outcome golden vectors, reproduced through the Python binding.

`tests/golden_outcome.rs` pins these from Rust. This file reads the same fixture
and rebuilds the same records through the wheel, so the two languages are pinned
to one set of bytes rather than to two that happen to agree today.

If one of these fails, the outcome format has changed. That needs a new digest
tag, never a re-pinned fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from calybris import (
    ALL_PROVIDERS,
    KernelInput,
    KernelModel,
    Observation,
    Outcome,
    PolicySnapshot,
)

# The fixture lives at the repo root, two levels up from python/tests/.
FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "calybris_outcome_v1.json"
    ).read_text(encoding="utf-8")
)

CASES = {case["label"]: case for case in FIXTURE["cases"]}

AT = 1_760_000_000_000_000
ALL_REGIONS = (1 << 64) - 1


def catalog() -> list[KernelModel]:
    return [
        KernelModel(
            model_id=1,
            provider_id=0,
            quality_bps=9_000,
            risk_ceiling_bps=9_500,
            enabled=1,
            p95_latency_ms=200,
            capabilities=0b1,
            region_mask=ALL_REGIONS,
            input_cost_microunits_per_million_tokens=3_000_000,
            output_cost_microunits_per_million_tokens=15_000_000,
        ),
        KernelModel(
            model_id=2,
            provider_id=1,
            quality_bps=8_000,
            risk_ceiling_bps=9_500,
            enabled=1,
            p95_latency_ms=100,
            capabilities=0b1,
            region_mask=ALL_REGIONS,
            input_cost_microunits_per_million_tokens=1_000_000,
            output_cost_microunits_per_million_tokens=5_000_000,
        ),
    ]


def policy() -> PolicySnapshot:
    return PolicySnapshot(1, 1, 9_000, 1_000, 2_000, 5, catalog())


def request(sequence: int, budget: int) -> KernelInput:
    return KernelInput(
        request_sequence=sequence,
        requested_model_id=1,
        input_tokens=1_000,
        output_tokens=500,
        budget_limit_microunits=budget,
        business_value_microunits=5_000_000,
        minimum_quality_bps=0,
        max_p95_latency_ms=0,
        risk_bps=1_000,
        confidence_bps=9_000,
        required_capabilities=0b1,
        allowed_provider_mask=ALL_PROVIDERS,
        required_region_mask=0,
    )


def measured() -> Observation:
    return Observation(
        realized_cost_microunits=4_100_000,
        realized_latency_ms=238,
        succeeded=True,
    )


def check(label: str, outcome: Outcome) -> None:
    """Every digest the fixture pins, not only the outcome digest."""
    case = CASES[label]
    assert outcome.input_digest == case["input_digest_hex"], f"{label}: input"
    assert outcome.decision_digest == case["decision_digest_hex"], f"{label}: decision"
    assert outcome.identity_digest == case["identity_digest_hex"], f"{label}: identity"
    assert outcome.selection_digest == case["selection_digest_hex"], f"{label}: selection"
    assert outcome.digest == case["outcome_digest_hex"], f"{label}: outcome"


def test_the_fixture_is_the_one_the_rust_tests_pin() -> None:
    assert FIXTURE["spec"] == "calybris.outcome.v1"
    assert FIXTURE["tags"] == {
        "identity": "calyidn1",
        "selection": "calysel1",
        "outcome": "calyout1",
    }
    assert len(CASES) == 7


def test_the_pinned_policy_is_the_policy_these_vectors_were_made_from() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    outcome = Outcome.applied(snapshot, asked, snapshot.prescribe(asked), AT, measured())

    assert outcome.policy_digest == FIXTURE["policy_digest_hex"]


def test_a_followed_and_fully_measured_outcome_is_reproduced() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.applied(snapshot, asked, decision, AT, measured())

    outcome.validate_against(snapshot, asked, decision)
    check("followed-applied-fully-measured", outcome)


def test_an_abandoned_outcome_is_reproduced() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.abandoned(snapshot, asked, decision, AT)

    outcome.validate_against(snapshot, asked, decision)
    check("followed-abandoned", outcome)


def test_a_partial_in_flight_outcome_is_reproduced() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.applied(
        snapshot,
        asked,
        decision,
        AT,
        Observation(realized_cost_microunits=2_000_000),
    )
    outcome.disposition = "in_flight"

    outcome.validate_against(snapshot, asked, decision)
    check("followed-in-flight-partial", outcome)


def test_an_exploration_at_one_basis_point_is_reproduced() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.chosen_otherwise(
        snapshot,
        asked,
        decision,
        AT,
        Observation(
            realized_cost_microunits=9_000_000,
            realized_latency_ms=95,
            succeeded=False,
        ),
        acted_model_id=2,
        propensity_bps=1,
    )

    check("explored-one-basis-point", outcome)


def test_a_human_choice_with_no_propensity_is_reproduced() -> None:
    """The only pinned selection digest with an absent optional field.

    If the presence byte were ever dropped on either side of the binding, this is
    the case that would disagree.
    """
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.chosen_otherwise(
        snapshot, asked, decision, AT, measured(), acted_model_id=2, human=True
    )

    assert outcome.propensity_bps is None
    check("human-no-propensity", outcome)


def test_zero_measurements_at_revision_seven_are_reproduced() -> None:
    snapshot = policy()
    asked = request(42, 50_000_000)
    decision = snapshot.prescribe(asked)
    outcome = Outcome.applied(
        snapshot,
        asked,
        decision,
        AT,
        Observation(
            realized_cost_microunits=0, realized_latency_ms=0, succeeded=False
        ),
    )
    outcome.revision = 7

    outcome.validate_against(snapshot, asked, decision)
    check("zero-measurements-revision-seven", outcome)


def test_an_abandoned_rejection_is_reproduced() -> None:
    snapshot = policy()
    asked = request(43, 1)
    decision = snapshot.prescribe(asked)
    assert decision.action == "reject"
    outcome = Outcome.abandoned(snapshot, asked, decision, AT)

    outcome.validate_against(snapshot, asked, decision)
    check("rejection-abandoned", outcome)


def test_no_two_pinned_outcomes_collide() -> None:
    digests = [case["outcome_digest_hex"] for case in FIXTURE["cases"]]
    assert len(set(digests)) == len(digests)
    assert all(len(d) == 64 for d in digests)


@pytest.mark.parametrize("label", sorted(CASES))
def test_every_pinned_case_is_exercised_by_a_test_in_this_file(label: str) -> None:
    """A fixture case nothing rebuilds is a case nothing pins.

    The Rust side covers all seven; this asserts the Python side does too, so a
    case added later cannot quietly stay Rust-only.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    assert f'check("{label}"' in source, f"{label} is pinned but never rebuilt here"
