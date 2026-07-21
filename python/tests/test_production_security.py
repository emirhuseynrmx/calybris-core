"""Adversarial tests for Python's production trust-boundary APIs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from calybris import (
    ALL_REGIONS,
    ArtifactValidationError,
    AuditedWal,
    BudgetGuard,
    CalybrisEngine,
    EngineConfig,
    InputBuilder,
    PersistenceError,
    PolicyBuilder,
    ProvenanceError,
    ReceiptError,
    ReceiptState,
    ReceiptWal,
    StateChain,
    StateTrajectoryError,
    WalAnchor,
    WalError,
    plan_recovery,
    public_key_from_signing_key,
    replay_verify_audited_wal,
    verify_audited_wal,
    verify_state_trajectory,
)
from calybris.types import ModelSpec

SIGNING_KEY = bytes(range(32))
TRUSTED_PUBLIC_KEY = public_key_from_signing_key(SIGNING_KEY)
WAL_KEY = b"python-production-wal-key-000001"


def _policy():
    return (
        PolicyBuilder(EngineConfig(), policy_epoch=7, catalog_epoch=3)
        .add_model(
            ModelSpec(
                model_id=1,
                provider_id=0,
                quality_bps=9_000,
                risk_ceiling_bps=9_500,
                p95_latency_ms=100,
                region_mask=ALL_REGIONS,
                input_cost_microunits_per_million_tokens=250,
                output_cost_microunits_per_million_tokens=1_000,
            )
        )
        .build()
    )


def _request(sequence: int = 1):
    return (
        InputBuilder(request_sequence=sequence, requested_model_id=1)
        .tokens(input=1_000, output=250)
        .budget(10_000_000)
        .value(500_000)
        .risk(bps=100, confidence_bps=9_500)
        .build()
    )


@pytest.fixture
def lock_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "locks"
    monkeypatch.setenv("CALYBRIS_WAL_LOCK_DIR", str(path))
    return path


def test_policy_and_receipt_require_pinned_trust_key() -> None:
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)

    signed_policy = engine.sign_policy(SIGNING_KEY, "risk-officer:test", 1_700_000_000_000)
    signed_policy.verify(engine.policy, TRUSTED_PUBLIC_KEY)
    with pytest.raises(ProvenanceError, match="pinned trust anchor"):
        signed_policy.verify(engine.policy, bytes([9]) * 32)

    receipt = engine.issue_receipt(request, decision)
    receipt.sign(SIGNING_KEY, "decision-service:test", 1_700_000_000_001)
    receipt.verify(engine.policy, request, decision)
    receipt.verify_signature(TRUSTED_PUBLIC_KEY)
    with pytest.raises(ReceiptError, match="trusted key"):
        receipt.verify_signature(public_key_from_signing_key(bytes([8]) * 32))


def test_receipt_tampering_is_detected() -> None:
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)
    receipt = engine.issue_receipt(request, decision)
    receipt.sign(SIGNING_KEY, "decision-service:test", 1_700_000_000_001)

    payload = json.loads(receipt.to_json())
    payload["policy_epoch"] += 1
    tampered = type(receipt).from_json(json.dumps(payload))

    with pytest.raises(ReceiptError):
        tampered.verify(engine.policy, request, decision)
    with pytest.raises(ReceiptError):
        tampered.verify_signature(TRUSTED_PUBLIC_KEY)


def test_receipt_full_verification_requires_all_trust_anchors() -> None:
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)
    state = ReceiptState(1, "11" * 32, "22" * 32)
    wal = ReceiptWal(9, "33" * 32)
    receipt = engine.issue_receipt(request, decision, state=state, wal=wal)
    receipt.sign(SIGNING_KEY, "decision-service:test", 1_700_000_000_001)

    receipt.verify_full(
        engine.policy,
        request,
        decision,
        TRUSTED_PUBLIC_KEY,
        state,
        wal,
    )

    incomplete = engine.issue_receipt(request, decision, state=state)
    incomplete.sign(SIGNING_KEY, "decision-service:test", 1_700_000_000_001)
    with pytest.raises(ReceiptError, match="WAL anchor mismatch"):
        incomplete.verify_full(
            engine.policy,
            request,
            decision,
            TRUSTED_PUBLIC_KEY,
            state,
            wal,
        )


def test_security_artifact_json_is_strict_and_repr_is_panic_free(tmp_path: Path) -> None:
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)

    signed = engine.sign_policy(SIGNING_KEY, "risk-officer:test", 1)
    signed_payload = json.loads(signed.to_json())
    signed_payload["approved"] = True
    with pytest.raises(ArtifactValidationError, match="unknown field"):
        type(signed).from_json(json.dumps(signed_payload))

    signed_payload.pop("approved")
    signed_payload["policy_digest_hex"] = "€"
    malformed_signed = type(signed).from_json(json.dumps(signed_payload))
    assert "digest='€...'" in repr(malformed_signed)

    receipt = engine.issue_receipt(request, decision)
    receipt_payload = json.loads(receipt.to_json())
    receipt_payload["approved"] = True
    with pytest.raises(ArtifactValidationError, match="unknown field"):
        type(receipt).from_json(json.dumps(receipt_payload))

    receipt_payload.pop("approved")
    receipt_payload["claims_digest_hex"] = "€"
    malformed_receipt = type(receipt).from_json(json.dumps(receipt_payload))
    assert "claims='€...'" in repr(malformed_receipt)

    anchor_path = tmp_path / "anchor.json"
    anchor_path.write_text(
        json.dumps(
            {
                "schema_version": "calybris.wal-anchor.v1",
                "sequence": 0,
                "last_hash": "€",
                "keyed": False,
            }
        ),
        encoding="utf-8",
    )
    malformed_anchor = WalAnchor.load(anchor_path)
    assert "last_hash='€...'" in repr(malformed_anchor)

    anchor_path.write_text(
        json.dumps(
            {
                "schema_version": "calybris.wal-anchor.v1",
                "sequence": 0,
                "last_hash": "genesis",
                "keyed": False,
                "trusted": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PersistenceError, match="unknown field"):
        WalAnchor.load(anchor_path)


def test_state_chain_is_bound_into_receipt() -> None:
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)
    chain = StateChain.genesis((1_000_000).to_bytes(8, "little"))
    transition = chain.advance((900_000).to_bytes(8, "little"))
    state = ReceiptState.from_transition(transition)

    bundle = engine.stateful_audit_bundle(request, decision, transition)
    assert bundle.step == 1
    next_request = _request(2)
    next_transition = chain.advance((800_000).to_bytes(8, "little"))
    next_bundle = engine.stateful_audit_bundle(
        next_request,
        engine.prescribe(next_request),
        next_transition,
    )
    verify_state_trajectory([bundle, next_bundle])
    with pytest.raises(StateTrajectoryError, match="does not continue"):
        verify_state_trajectory([next_bundle, bundle])
    receipt = engine.issue_receipt(request, decision, state=state)
    receipt.verify_state(
        transition.step,
        transition.digest_before_hex,
        transition.digest_after_hex,
    )
    with pytest.raises(ReceiptError, match="state anchor mismatch"):
        receipt.verify_state(
            transition.step + 1,
            transition.digest_before_hex,
            transition.digest_after_hex,
        )


def test_keyed_wal_anchor_replay_and_receipt_roundtrip(
    tmp_path: Path,
    lock_dir: Path,
) -> None:
    del lock_dir
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)
    wal_path = tmp_path / "decisions.wal"
    anchor_path = tmp_path / "trusted-anchor.json"

    with AuditedWal(wal_path, hmac_key=WAL_KEY) as wal:
        entry = wal.append_verified(
            engine.policy,
            request,
            decision,
            metadata={"tenant": "acme", "attempt": 1},
        )
        anchor = wal.anchor()
        anchor.save(anchor_path)

    loaded = WalAnchor.load(anchor_path)
    assert verify_audited_wal(wal_path, hmac_key=WAL_KEY, anchor=loaded) == (
        entry.sequence,
        entry.entry_hash,
    )
    verdicts = replay_verify_audited_wal(wal_path, engine.policy, hmac_key=WAL_KEY)
    assert verdicts == [
        {
            "sequence": 1,
            "replay_valid": True,
            "policy_digest_match": True,
            "input_digest_match": True,
            "decision_digest_match": True,
        }
    ]

    receipt = engine.issue_receipt(request, decision, wal=entry.receipt_anchor())
    receipt.verify_wal(entry.sequence, entry.entry_hash)

    snapshot_path = tmp_path / "budget-snapshot.json"
    guard = BudgetGuard().ensure_tenant("acme", 1_000_000)
    snapshot = guard.checkpoint(snapshot_path, wal_sequence=entry.sequence)
    assert snapshot.wal_high_watermark == entry.sequence
    recovery = plan_recovery(
        snapshot_path,
        wal_path,
        hmac_key=WAL_KEY,
        anchor=loaded,
    )
    assert recovery["entries_to_replay"] == 0


def test_wal_rejects_short_key_and_second_writer(
    tmp_path: Path,
    lock_dir: Path,
) -> None:
    del lock_dir
    wal_path = tmp_path / "decisions.wal"
    with pytest.raises(ArtifactValidationError, match="at least 32 bytes"):
        AuditedWal(wal_path, hmac_key=b"too-short")

    first = AuditedWal(wal_path, hmac_key=WAL_KEY)
    try:
        with pytest.raises(WalError, match="active writer"):
            AuditedWal(wal_path, hmac_key=WAL_KEY)
    finally:
        first.close()


def test_metadata_nan_is_rejected_without_advancing_wal(
    tmp_path: Path,
    lock_dir: Path,
) -> None:
    del lock_dir
    engine = CalybrisEngine(_policy())
    request = _request()
    decision = engine.prescribe(request)

    with AuditedWal(tmp_path / "decisions.wal", hmac_key=WAL_KEY) as wal:
        with pytest.raises(ArtifactValidationError, match="canonical JSON"):
            wal.append_verified(
                engine.policy,
                request,
                decision,
                metadata={"bad": float("nan")},
            )
        assert wal.sequence == 0


def test_anchor_detects_clean_suffix_truncation(
    tmp_path: Path,
    lock_dir: Path,
) -> None:
    del lock_dir
    engine = CalybrisEngine(_policy())
    wal_path = tmp_path / "decisions.wal"

    with AuditedWal(wal_path, hmac_key=WAL_KEY) as wal:
        for sequence in (1, 2):
            request = _request(sequence)
            wal.append_verified(
                engine.policy,
                request,
                engine.prescribe(request),
                metadata={"sequence": sequence},
            )
        anchor = wal.anchor()

    lines = wal_path.read_bytes().splitlines(keepends=True)
    wal_path.write_bytes(b"".join(lines[:-1]))

    assert verify_audited_wal(wal_path, hmac_key=WAL_KEY)[0] == 1
    with pytest.raises(WalError, match="anchor mismatch"):
        verify_audited_wal(wal_path, hmac_key=WAL_KEY, anchor=anchor)
