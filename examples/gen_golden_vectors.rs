//! Generate the CALY-PROOF v1 golden vector fixture (one-time tool).
//!
//! Run: cargo run --example gen_golden_vectors --features wal,provenance
//! Output is the JSON fixture body for tests/fixtures/caly_proof_v1.json.

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::receipt::{
    issue_receipt, sign_receipt, ReceiptAnchors, ReceiptState, ReceiptWal,
};
use calybris_core::state::StateChain;
use calybris_core::wal::WalWriter;
use ed25519_dalek::SigningKey;

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

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("golden.wal.jsonl");
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

    let mut state_chain = StateChain::genesis(&1_000_000_u64.to_le_bytes());
    let transition = state_chain.advance(&999_000_u64.to_le_bytes());
    let mut receipt = issue_receipt(
        &policy,
        input,
        &decision,
        ReceiptAnchors {
            state: Some(ReceiptState {
                step: transition.step,
                state_digest_before_hex: digest_to_hex(&transition.digest_before),
                state_digest_after_hex: digest_to_hex(&transition.digest_after),
            }),
            wal: Some(ReceiptWal {
                sequence: e2.sequence,
                entry_hash: e2.entry_hash,
            }),
        },
    )
    .unwrap();
    let receipt_signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    sign_receipt(
        &mut receipt,
        &receipt_signing_key,
        "receipt-service:golden",
        1_783_000_000_001,
    )
    .unwrap();
    let signature = receipt.signature.as_ref().unwrap();
    let state = receipt.state.as_ref().unwrap();
    let wal = receipt.wal.as_ref().unwrap();
    println!("receipt state before = {}", state.state_digest_before_hex);
    println!("receipt state after  = {}", state.state_digest_after_hex);
    println!("receipt wal sequence = {}", wal.sequence);
    println!("receipt wal hash     = {}", wal.entry_hash);
    println!("receipt claims digest= {}", receipt.claims_digest_hex);
    println!("receipt public key   = {}", signature.public_key_hex);
    println!("receipt signature    = {}", signature.signature_hex);
}
