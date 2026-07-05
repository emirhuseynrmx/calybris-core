"""CALY-PROOF v1 conformance suite (Python side).

Reads the same shared conformance fixture as the Rust suite and asserts that
the Python binding reproduces every case's digests and decision fields. This
proves cross-language conformance across the full decision-outcome matrix, not
just the single happy-path golden triple.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from calybris import ALL_PROVIDERS, ALL_REGIONS, KernelInput, KernelModel, PolicySnapshot

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "caly_proof_conformance_v1.json"
)


@pytest.fixture(scope="module")
def suite() -> dict:
    if not FIXTURE_PATH.exists():
        pytest.skip(f"conformance fixture not found at {FIXTURE_PATH}")
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def shared_policy() -> PolicySnapshot:
    return PolicySnapshot(
        7,
        42,
        9_600,
        5_500,
        3_500,
        2,
        [
            KernelModel(1, 0, 9_000, 9_500, 1, 200, 0b101, ALL_REGIONS, 250, 1_000),
            KernelModel(2, 1, 7_500, 9_500, 1, 90, 0b001, ALL_REGIONS, 25, 125),
        ],
    )


def _base(**overrides: int) -> dict:
    fields = dict(
        request_sequence=1,
        requested_model_id=1,
        input_tokens=1_000,
        output_tokens=500,
        business_value_microunits=100_000,
        budget_limit_microunits=50_000_000,
        risk_bps=1_000,
        confidence_bps=9_000,
        minimum_quality_bps=5_000,
        max_p95_latency_ms=1_000,
        required_capabilities=0b001,
        allowed_provider_mask=ALL_PROVIDERS,
        required_region_mask=0,
    )
    fields.update(overrides)
    return fields


# Must mirror the Rust generator exactly.
CASE_INPUTS = {
    "execute_requested": _base(),
    "substitute": _base(
        request_sequence=2, requested_model_id=2, business_value_microunits=5_000_000
    ),
    "reject_risk_hard_limit": _base(request_sequence=3, risk_bps=9_800),
    "reject_confidence_hard_limit": _base(request_sequence=4, confidence_bps=5_000),
    "reject_quality_constraint": _base(request_sequence=5, minimum_quality_bps=9_500),
    "reject_budget_constraint": _base(request_sequence=6, budget_limit_microunits=1),
}


def _input(label: str) -> KernelInput:
    f = CASE_INPUTS[label]
    return KernelInput(
        f["request_sequence"],
        f["requested_model_id"],
        f["input_tokens"],
        f["output_tokens"],
        f["business_value_microunits"],
        f["budget_limit_microunits"],
        f["risk_bps"],
        f["confidence_bps"],
        f["minimum_quality_bps"],
        f["max_p95_latency_ms"],
        f["required_capabilities"],
        f["allowed_provider_mask"],
        f["required_region_mask"],
    )


def test_every_conformance_case_matches_rust(suite: dict) -> None:
    policy = shared_policy()
    for case in suite["cases"]:
        label = case["label"]
        request = _input(label)
        decision = policy.prescribe(request)
        bundle = policy.audit_bundle(request, decision)

        assert bundle["input_digest_hex"] == case["input_digest_hex"], (
            f"input digest mismatch for {label}"
        )
        assert bundle["decision_digest_hex"] == case["decision_digest_hex"], (
            f"decision digest mismatch for {label}"
        )
        assert decision.selected_model_id == case["selected_model_id"], (
            f"selected model mismatch for {label}"
        )
        assert (
            decision.expected_utility_microunits
            == case["expected_utility_microunits"]
        ), f"utility mismatch for {label}"
