//! Generate the CALY-PROOF v1 golden vector fixture (one-time tool).
//!
//! Run: cargo run --example gen_golden_vectors --features wal
//! Output is the JSON fixture body for tests/fixtures/caly_proof_v1.json.

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::wal::WalWriter;

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

fn main() {
    let policy = fixture_policy();
    let input = fixture_input();
    let decision = policy.prescribe(input);

    let dir = std::env::temp_dir().join("caly-golden-gen");
    std::fs::create_dir_all(&dir).unwrap();
    let wal_path = dir.join("golden.wal.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal: WalWriter<serde_json::Value> = WalWriter::open(&wal_path).unwrap();
    let e1 = wal
        .append(serde_json::json!({"k": 1_u64, "v": "alpha"}))
        .unwrap();
    let e2 = wal
        .append(serde_json::json!({"k": 2_u64, "v": "beta"}))
        .unwrap();

    println!(
        "policy_digest    = {}",
        digest_to_hex(&policy_digest(&policy))
    );
    println!(
        "input_digest     = {}",
        digest_to_hex(&input_digest(&input))
    );
    println!(
        "decision_digest  = {}",
        digest_to_hex(&decision_digest(&decision))
    );
    println!(
        "decision: action={:?} reason={:?} selected={} cost={} utility={}",
        decision.action,
        decision.reason,
        decision.selected_model_id,
        decision.estimated_cost_microunits,
        decision.expected_utility_microunits
    );
    println!("wal entry1 hash  = {}", e1.entry_hash);
    println!("wal entry2 hash  = {}", e2.entry_hash);
}
