//! LLM routing and cost governance.
//!
//! The example models a gateway choosing among premium, fast, and budget
//! providers under quality, latency, risk, provider, and budget constraints.
//! Every decision is verified before entering the audited WAL.
//!
//! ```bash
//! cargo run --example llm_routing
//! ```

use calybris_core::kernel::*;
use calybris_core::verify::{verified_audit_bundle, verify_decision, VerifyResult};
use calybris_core::wal::{AuditedRecord, WalWriter};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
struct RoutingRecord {
    scenario: String,
    requested_model: String,
    selected_model: String,
    action: String,
    reason: String,
    estimated_cost_microunits: u64,
    eligible_models: u16,
}

fn main() {
    let models = vec![
        model(1, 0, 9_600, 9_500, 2_500_000, 10_000_000, 420),
        model(2, 0, 8_200, 9_200, 150_000, 600_000, 130),
        model(3, 1, 9_300, 9_500, 2_200_000, 8_500_000, 360),
        model(4, 1, 7_600, 9_000, 80_000, 300_000, 90),
        model(5, 2, 8_900, 9_300, 700_000, 2_000_000, 210),
        model(6, 2, 7_200, 8_800, 40_000, 120_000, 70),
    ];
    let names = [
        (1, "gpt-4o"),
        (2, "gpt-4o-mini"),
        (3, "claude-sonnet"),
        (4, "claude-haiku"),
        (5, "gemini-pro"),
        (6, "gemini-flash"),
    ];

    let snapshot = PolicySnapshot::try_new(3, 17, 9_600, 5_500, 3_500, 2, models)
        .expect("valid model catalog");

    let wal_path = PathBuf::from("llm_routing_demo.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal: WalWriter<AuditedRecord<RoutingRecord>> = WalWriter::open(&wal_path).unwrap();

    println!("Calybris - LLM Routing");
    println!("======================\n");

    let scenarios = [
        (
            "Legal review: premium quality required",
            KernelInput {
                request_sequence: 1,
                requested_model_id: 1,
                input_tokens: 12_000,
                output_tokens: 4_000,
                business_value_microunits: 2_000_000,
                budget_limit_microunits: 120_000,
                risk_bps: 1_800,
                confidence_bps: 9_300,
                minimum_quality_bps: 9_200,
                max_p95_latency_ms: 700,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            },
        ),
        (
            "Support macro: substitute away from premium",
            KernelInput {
                request_sequence: 2,
                requested_model_id: 1,
                input_tokens: 800,
                output_tokens: 200,
                business_value_microunits: 35_000,
                budget_limit_microunits: 1_000,
                risk_bps: 500,
                confidence_bps: 9_100,
                minimum_quality_bps: 7_000,
                max_p95_latency_ms: 300,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            },
        ),
        (
            "Realtime chat: latency cap dominates",
            KernelInput {
                request_sequence: 3,
                requested_model_id: 3,
                input_tokens: 1_200,
                output_tokens: 500,
                business_value_microunits: 60_000,
                budget_limit_microunits: 10_000,
                risk_bps: 700,
                confidence_bps: 9_000,
                minimum_quality_bps: 7_000,
                max_p95_latency_ms: 100,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            },
        ),
        (
            "Abuse review: hard risk reject",
            KernelInput {
                request_sequence: 4,
                requested_model_id: 1,
                input_tokens: 2_000,
                output_tokens: 1_000,
                business_value_microunits: 100_000,
                budget_limit_microunits: 100_000,
                risk_bps: 9_800,
                confidence_bps: 8_500,
                minimum_quality_bps: 7_000,
                max_p95_latency_ms: 0,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            },
        ),
    ];

    for (scenario, input) in scenarios {
        route(&snapshot, &names, scenario, input, &mut wal);
    }

    wal.flush_and_sync().unwrap();
    println!("WAL entries: {} -> {}", wal.sequence(), wal_path.display());
    let _ = std::fs::remove_file(&wal_path);
}

fn route(
    snapshot: &PolicySnapshot,
    names: &[(u32, &'static str)],
    scenario: &str,
    input: KernelInput,
    wal: &mut WalWriter<AuditedRecord<RoutingRecord>>,
) {
    let (decision, trace) = snapshot.prescribe_with_trace(input);
    assert_eq!(
        verify_decision(snapshot, input, &decision),
        VerifyResult::Valid
    );
    assert!(verified_audit_bundle(snapshot, input, &decision).is_ok());

    println!("{scenario}");
    println!("  action:    {}", decision.action);
    println!("  requested: {}", name_of(input.requested_model_id, names));
    println!(
        "  selected:  {}",
        name_of(decision.selected_model_id, names)
    );
    println!("  reason:    {}", decision.reason);
    println!(
        "  cost:      {} microunits",
        decision.estimated_cost_microunits
    );
    println!(
        "  rejects:   latency={} quality={} budget={} utility={} risk_ceiling={}",
        trace.rejections.latency,
        trace.rejections.quality,
        trace.rejections.budget,
        trace.rejections.utility,
        trace.rejections.risk_ceiling
    );
    println!(
        "  eligible:  {}/{}\n",
        trace.eligible_models, trace.evaluated_models
    );

    wal.append_verified_audited(
        snapshot,
        input,
        decision,
        RoutingRecord {
            scenario: scenario.into(),
            requested_model: name_of(input.requested_model_id, names).into(),
            selected_model: name_of(decision.selected_model_id, names).into(),
            action: decision.action.to_string(),
            reason: decision.reason.to_string(),
            estimated_cost_microunits: decision.estimated_cost_microunits,
            eligible_models: trace.eligible_models,
        },
    )
    .expect("verified WAL append");
}

fn name_of(id: u32, names: &[(u32, &'static str)]) -> &'static str {
    names
        .iter()
        .find(|(model_id, _)| *model_id == id)
        .map_or("none", |(_, name)| *name)
}

fn model(
    id: u32,
    provider: u16,
    quality: u16,
    risk_ceiling: u16,
    input_cost: u64,
    output_cost: u64,
    latency: u32,
) -> KernelModel {
    KernelModel {
        model_id: id,
        provider_id: provider,
        quality_bps: quality,
        risk_ceiling_bps: risk_ceiling,
        enabled: 1,
        p95_latency_ms: latency,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: input_cost,
        output_cost_microunits_per_million_tokens: output_cost,
    }
}
