//! End-to-end audit pipeline: prescribe → bundle → WAL → replay → conservation proof.
//!
//! Auditors can read this file as a single reference for the OSS security surface.

use calybris_core::budget::{BudgetEngine, ConservationStatus};
use calybris_core::finance::prove_conservation;
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
use calybris_core::wal::{replay_audited_wal_keyed, WalWriter};
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "target/test-audit-pipeline-{}-{}.jsonl",
        name,
        std::process::id()
    ))
}

fn snapshot() -> PolicySnapshot {
    PolicySnapshot::try_new(
        1,
        1,
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
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 100,
                output_cost_microunits_per_million_tokens: 400,
            },
            KernelModel {
                model_id: 2,
                provider_id: 1,
                quality_bps: 7_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 80,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 20,
                output_cost_microunits_per_million_tokens: 80,
            },
        ],
    )
    .expect("valid snapshot")
}

#[test]
fn full_audit_pipeline_with_budget_and_keyed_wal() {
    let snap = snapshot();
    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 400,
        business_value_microunits: 80_000,
        budget_limit_microunits: 5_000_000,
        risk_bps: 500,
        confidence_bps: 8_500,
        minimum_quality_bps: 5_000,
        max_p95_latency_ms: 500,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };

    let decision = snap.prescribe(input);
    assert_eq!(
        verify_decision(&snap, input, &decision),
        VerifyResult::Valid
    );

    let bundle = audit_bundle(&snap, input, &decision);
    assert!(bundle.replay_valid);
    assert_eq!(bundle.policy_digest().unwrap().len(), 32);

    let engine = BudgetEngine::new();
    engine.ensure_tenant("desk", 10_000_000);
    let (_, reservation) = engine.try_reserve("desk", 500_000);
    engine.commit(reservation.unwrap(), 450_000);
    assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    let ledger_hex = prove_conservation(&engine).expect("balanced ledger");
    assert_eq!(ledger_hex.len(), 64);

    let path = temp_path("e2e");
    let _ = std::fs::remove_file(&path);
    let key = b"audit-pipeline-key-2026";

    {
        let mut wal = WalWriter::open_keyed(&path, key).unwrap();
        wal.append_audited(&snap, input, decision, ledger_hex.clone())
            .unwrap();
        wal.sync().unwrap();
    }

    let verdicts = replay_audited_wal_keyed::<String>(&path, &snap, Some(key)).unwrap();
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].replay_valid);
    assert!(verdicts[0].policy_digest_match);
    assert!(verdicts[0].input_digest_match);
    assert!(verdicts[0].decision_digest_match);

    let _ = std::fs::remove_file(&path);
}
