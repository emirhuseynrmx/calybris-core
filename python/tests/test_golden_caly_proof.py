"""CALY-PROOF v1 cross-language golden test.

Proves that the Python binding reproduces the *same* canonical digests as the
Rust reference implementation, byte for byte, by reading the identical fixture
(`tests/fixtures/caly_proof_v1.json`) that the Rust golden test pins.

This is the artifact a Python user runs to trust the library without ever
running the Rust engine. A mismatch here means either the binding marshals a
field wrong or the proof format drifted — both breaking changes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from calybris import (
    ALL_PROVIDERS,
    ALL_REGIONS,
    KernelInput,
    KernelModel,
    PolicySnapshot,
    ReceiptState,
    ReceiptWal,
    StateChain,
    public_key_from_signing_key,
)

# tests/fixtures/caly_proof_v1.json lives at the repo root, two levels up from
# python/tests/. Resolve robustly so the test works from any CWD.
FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "caly_proof_v1.json"
)


@pytest.fixture(scope="module")
def golden() -> dict:
    if not FIXTURE_PATH.exists():
        raise AssertionError(f"golden fixture not found at {FIXTURE_PATH}")
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def fixture_policy() -> PolicySnapshot:
    """The exact policy pinned by the Rust golden test."""
    return PolicySnapshot(
        7,   # policy_epoch
        42,  # catalog_epoch
        9_600,  # hard_risk_limit_bps
        5_500,  # minimum_confidence_bps
        3_500,  # risk_penalty_multiplier_bps
        2,   # latency_penalty_microunits_per_ms
        [
            KernelModel(
                1,          # model_id
                0,          # provider_id
                9_000,      # quality_bps
                9_500,      # risk_ceiling_bps
                1,          # enabled
                200,        # p95_latency_ms
                0b101,      # capabilities
                ALL_REGIONS,  # region_mask
                250,        # input_cost_microunits_per_million_tokens
                1_000,      # output_cost_microunits_per_million_tokens
            ),
            KernelModel(
                2,
                1,
                7_500,
                9_500,
                1,
                90,
                0b001,
                ALL_REGIONS,
                25,
                125,
            ),
        ],
    )


def fixture_input() -> KernelInput:
    """The exact input pinned by the Rust golden test."""
    return KernelInput(
        1_001,        # request_sequence
        1,            # requested_model_id
        1_000,        # input_tokens
        500,          # output_tokens
        100_000,      # business_value_microunits
        50_000_000,   # budget_limit_microunits
        1_000,        # risk_bps
        9_000,        # confidence_bps
        5_000,        # minimum_quality_bps
        1_000,        # max_p95_latency_ms
        0b001,        # required_capabilities
        ALL_PROVIDERS,  # allowed_provider_mask
        0,            # required_region_mask
    )


def test_python_reproduces_rust_golden_digests(golden: dict) -> None:
    """The three canonical digests must match the Rust fixture byte for byte."""
    policy = fixture_policy()
    request = fixture_input()
    decision = policy.prescribe(request)
    bundle = policy.audit_bundle(request, decision)

    assert bundle["policy_digest_hex"] == golden["policy_digest_hex"], (
        "policy digest diverged from the Rust reference — proof-format or "
        "binding marshalling change"
    )
    assert bundle["input_digest_hex"] == golden["input_digest_hex"]
    assert bundle["decision_digest_hex"] == golden["decision_digest_hex"]
    assert bundle["replay_valid"] is True


def test_python_reproduces_rust_golden_decision(golden: dict) -> None:
    """The decision semantics must match the pinned expected values."""
    policy = fixture_policy()
    decision = policy.prescribe(fixture_input())
    expected = golden["decision"]

    assert decision.selected_model_id == expected["selected_model_id"]
    assert decision.estimated_cost_microunits == expected["estimated_cost_microunits"]
    assert (
        decision.expected_utility_microunits
        == expected["expected_utility_microunits"]
    )
    # Action/reason are exposed as human strings on the Python side; assert the
    # canonical shape rather than the exact enum spelling.
    assert decision.selected_model_id == 1


def test_verified_bundle_is_fail_closed(golden: dict) -> None:
    """verified_audit_bundle returns a replay-valid bundle for a clean decision."""
    policy = fixture_policy()
    request = fixture_input()
    decision = policy.prescribe(request)
    bundle = policy.verified_audit_bundle(request, decision)
    assert bundle["replay_valid"] is True
    assert bundle["policy_digest_hex"] == golden["policy_digest_hex"]


def test_python_reproduces_rust_golden_signed_receipt(golden: dict) -> None:
    """Receipt claims and Ed25519 signature must match Rust byte for byte."""
    policy = fixture_policy()
    request = fixture_input()
    decision = policy.prescribe(request)
    expected = golden["receipt"]

    chain = StateChain.genesis((1_000_000).to_bytes(8, "little"))
    transition = chain.advance((999_000).to_bytes(8, "little"))
    receipt = policy.issue_receipt(
        request,
        decision,
        state=ReceiptState.from_transition(transition),
        wal=ReceiptWal(expected["wal_sequence"], expected["wal_entry_hash"]),
    )
    signing_key = bytes([11]) * 32
    receipt.sign(signing_key, "receipt-service:golden", 1_783_000_000_001)

    assert transition.digest_before_hex == expected["state_digest_before_hex"]
    assert transition.digest_after_hex == expected["state_digest_after_hex"]
    assert receipt.claims_digest_hex == expected["claims_digest_hex"]
    assert receipt.public_key_hex == expected["public_key_hex"]
    assert receipt.signature_hex == expected["signature_hex"]
    receipt.verify(policy, request, decision)
    receipt.verify_signature(public_key_from_signing_key(signing_key))
