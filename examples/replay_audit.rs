/// Full audit pipeline: prescribe → audit bundle → WAL → offline replay verify
///
/// ```bash
/// cargo run --example replay_audit
/// ```
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
use calybris_core::wal::{replay_audited_wal, WalWriter};
use std::path::PathBuf;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct RouteMeta {
    scenario: String,
}

fn main() {
    let models = vec![
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9500,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 450,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 250,
            output_cost_microunits_per_million_tokens: 1000,
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 7000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 90,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 25,
            output_cost_microunits_per_million_tokens: 125,
        },
    ];
    let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 2, models).unwrap();

    let path = PathBuf::from("replay_audit_demo.jsonl");
    let _ = std::fs::remove_file(&path);
    let mut wal = WalWriter::open(&path).unwrap();

    let scenarios = [
        ("high-quality", 9000_u16, 50_000_000_u64),
        ("budget-tight", 5000, 500),
    ];

    for (i, (name, min_quality, budget)) in scenarios.iter().enumerate() {
        let input = KernelInput {
            request_sequence: i as u64 + 1,
            requested_model_id: 1,
            input_tokens: 1000,
            output_tokens: 500,
            business_value_microunits: 100_000,
            budget_limit_microunits: *budget,
            risk_bps: 1000,
            confidence_bps: 9000,
            minimum_quality_bps: *min_quality,
            max_p95_latency_ms: 1000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);
        assert_eq!(
            verify_decision(&snapshot, input, &decision),
            VerifyResult::Valid
        );
        let bundle = audit_bundle(&snapshot, input, &decision);
        assert!(bundle.replay_valid);

        wal.append_audited(
            &snapshot,
            input,
            decision,
            RouteMeta {
                scenario: (*name).into(),
            },
        )
        .unwrap();
    }

    wal.flush_and_sync().unwrap();

    let verdicts = replay_audited_wal(&path, &snapshot).unwrap();
    println!("Replay audit: {} entries, all verified", verdicts.len());
    for v in &verdicts {
        println!(
            "  seq={} replay={} policy={} input={} decision={}",
            v.sequence,
            v.replay_valid,
            v.policy_digest_match,
            v.input_digest_match,
            v.decision_digest_match
        );
    }

    let _ = std::fs::remove_file(&path);
}