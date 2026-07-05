//! CALY-PROOF v1 golden vector tests.
//!
//! These pin the canonical digest and WAL chain byte layouts across versions
//! and platforms. If one of these assertions ever fails, the proof format
//! has changed: that is a breaking change requiring a new digest tag
//! (`calypol2\0`, …) — never re-pin the expected values.

#![cfg(feature = "wal")]

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{
    KernelAction, KernelInput, KernelModel, KernelReason, PolicySnapshot, ALL_PROVIDERS,
    ALL_REGIONS,
};
use calybris_core::verify::{verify_decision, VerifyResult};
use calybris_core::wal::WalWriter;

const FIXTURE: &str = include_str!("fixtures/caly_proof_v1.json");

fn fixture_policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
        7,
        42,
        9_600,
        5_500,
        3_500,
        2,
        vec![
            KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0b101,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1_000,
            },
            KernelModel {
                model_id: 2,
                provider_id: 1,
                quality_bps: 7_500,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 90,
                capabilities: 0b001,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 25,
                output_cost_microunits_per_million_tokens: 125,
            },
        ],
    )
    .expect("fixture policy is valid")
}

fn fixture_input() -> KernelInput {
    KernelInput {
        request_sequence: 1_001,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        business_value_microunits: 100_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        minimum_quality_bps: 5_000,
        max_p95_latency_ms: 1_000,
        required_capabilities: 0b001,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn expected(field: &str) -> String {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    fixture[field].as_str().unwrap().to_string()
}

#[test]
fn golden_digests_are_reproduced_byte_for_byte() {
    let policy = fixture_policy();
    let input = fixture_input();
    let decision = policy.prescribe(input);

    assert_eq!(
        digest_to_hex(&policy_digest(&policy)),
        expected("policy_digest_hex"),
        "policy digest layout changed — this is a breaking proof-format change"
    );
    assert_eq!(
        digest_to_hex(&input_digest(&input)),
        expected("input_digest_hex"),
        "input digest layout changed — this is a breaking proof-format change"
    );
    assert_eq!(
        digest_to_hex(&decision_digest(&decision)),
        expected("decision_digest_hex"),
        "decision digest layout changed — this is a breaking proof-format change"
    );
}

#[test]
fn golden_decision_semantics_are_stable() {
    let policy = fixture_policy();
    let input = fixture_input();
    let decision = policy.prescribe(input);

    assert_eq!(decision.action, KernelAction::ExecuteRequested);
    assert_eq!(
        decision.reason,
        KernelReason::RequestedModelMaximizesUtility
    );
    assert_eq!(decision.selected_model_id, 1);
    assert_eq!(decision.estimated_cost_microunits, 2);
    assert_eq!(decision.expected_utility_microunits, 77_098);
    assert_eq!(
        verify_decision(&policy, input, &decision),
        VerifyResult::Valid
    );
}

#[test]
fn golden_wal_chain_hashes_are_reproduced() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.wal.jsonl");

    let mut wal: WalWriter<serde_json::Value> = WalWriter::open(&path).unwrap();
    let entry_1 = wal
        .append(serde_json::json!({"k": 1_u64, "v": "alpha"}))
        .unwrap();
    let entry_2 = wal
        .append(serde_json::json!({"k": 2_u64, "v": "beta"}))
        .unwrap();

    assert_eq!(entry_1.previous_hash, "genesis");
    assert_eq!(
        entry_1.entry_hash,
        fixture["wal"]["entry_1_hash"].as_str().unwrap(),
        "WAL chain hashing changed — this is a breaking proof-format change"
    );
    assert_eq!(entry_2.previous_hash, entry_1.entry_hash);
    assert_eq!(
        entry_2.entry_hash,
        fixture["wal"]["entry_2_hash"].as_str().unwrap(),
        "WAL chain hashing changed — this is a breaking proof-format change"
    );
}
