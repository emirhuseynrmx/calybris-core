#![cfg(all(feature = "wal", feature = "provenance"))]

use calybris_core::digest::bytes_to_hex;
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::receipt::{
    issue_receipt, sign_receipt, verify_receipt, verify_receipt_signature, verify_receipt_state,
    verify_receipt_wal, ReceiptAnchors, ReceiptState, ReceiptWal,
};
use calybris_core::state::StateChain;
use calybris_core::wal::{verify_wal_keyed_against_anchor, AuditedRecord, WalWriter};

#[test]
fn receipt_pipeline_binds_replay_state_wal_anchor_and_signature() {
    let policy = PolicySnapshot::try_new(
        7,
        42,
        9_600,
        5_500,
        3_500,
        2,
        vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 250,
            output_cost_microunits_per_million_tokens: 1_000,
        }],
    )
    .unwrap();
    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        business_value_microunits: 100_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        minimum_quality_bps: 5_000,
        max_p95_latency_ms: 1_000,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };
    let decision = policy.prescribe_checked(input).unwrap();

    let mut state_chain = StateChain::genesis(&50_000_000_u64.to_le_bytes());
    let transition = state_chain.advance(&49_999_000_u64.to_le_bytes());

    let directory = tempfile::tempdir().unwrap();
    let wal_path = directory.path().join("decisions.wal");
    let wal_key = [9_u8; 32];
    let mut wal = WalWriter::<AuditedRecord<&str>>::open_keyed(&wal_path, &wal_key).unwrap();
    let entry = wal
        .append_verified_audited(&policy, input, decision, "receipt-pipeline")
        .unwrap();
    wal.flush_and_sync().unwrap();
    let wal_anchor = wal.anchor();

    let mut receipt = issue_receipt(
        &policy,
        input,
        &decision,
        ReceiptAnchors {
            state: Some(ReceiptState {
                step: transition.step,
                state_digest_before_hex: bytes_to_hex(&transition.digest_before),
                state_digest_after_hex: bytes_to_hex(&transition.digest_after),
            }),
            wal: Some(ReceiptWal {
                sequence: entry.sequence,
                entry_hash: entry.entry_hash.clone(),
            }),
        },
    )
    .unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
    sign_receipt(
        &mut receipt,
        &signing_key,
        "production-receipt-service",
        1_700_000_000_000,
    )
    .unwrap();

    verify_receipt(&receipt, &policy, input, &decision).unwrap();
    verify_receipt_signature(&receipt, Some(&signing_key.verifying_key())).unwrap();
    verify_receipt_wal(&receipt, entry.sequence, &entry.entry_hash).unwrap();
    verify_receipt_state(
        &receipt,
        transition.step,
        &bytes_to_hex(&transition.digest_before),
        &bytes_to_hex(&transition.digest_after),
    )
    .unwrap();
    drop(wal);
    verify_wal_keyed_against_anchor(&wal_path, &wal_key, &wal_anchor).unwrap();
}
