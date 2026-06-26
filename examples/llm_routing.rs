//! Use case 1: LLM routing / cost governance
//!
//! Given candidate models and hard constraints (budget, risk, quality, latency),
//! Calybris deterministically selects, substitutes, or rejects — then records
//! an auditable WAL trail.
//!
//! ```bash
//! cargo run --example llm_routing
//! ```
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
use calybris_core::wal::WalWriter;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
struct RoutingRecord {
    scenario: String,
    action: String,
    requested_model: String,
    selected_model: String,
    reason: String,
}

fn main() {
    let models = vec![
        model(1, 0, 9500, 250, 1000, 450),
        model(2, 0, 7500, 15, 60, 120),
        model(3, 1, 9200, 300, 1500, 380),
        model(4, 1, 7000, 25, 125, 90),
        model(5, 2, 8800, 125, 500, 320),
        model(6, 2, 7200, 8, 30, 80),
    ];
    let names = [
        ("gpt-4o", 1),
        ("gpt-4o-mini", 2),
        ("claude-sonnet", 3),
        ("claude-haiku", 4),
        ("gemini-pro", 5),
        ("gemini-flash", 6),
    ];

    let snapshot =
        PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 2, models).expect("valid catalog");

    let wal_path = PathBuf::from("llm_routing_demo.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal = WalWriter::<RoutingRecord>::open(&wal_path).unwrap();

    println!("Calybris — LLM Routing");
    println!("======================\n");

    run_scenario(
        &snapshot,
        &names,
        "Compliance review (quality floor 0.90)",
        KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 4000,
            output_tokens: 2000,
            business_value_microunits: 500_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 2000,
            confidence_bps: 9000,
            minimum_quality_bps: 9000,
            max_p95_latency_ms: 1000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        },
        1,
        &mut wal,
    );

    run_scenario(
        &snapshot,
        &names,
        "Support ticket (downgrade OK)",
        KernelInput {
            request_sequence: 2,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 10_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 500,
            confidence_bps: 9000,
            minimum_quality_bps: 6000,
            max_p95_latency_ms: 500,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        },
        1,
        &mut wal,
    );

    run_scenario(
        &snapshot,
        &names,
        "Budget exhausted",
        KernelInput {
            request_sequence: 3,
            requested_model_id: 3,
            input_tokens: 8000,
            output_tokens: 4000,
            business_value_microunits: 100_000,
            budget_limit_microunits: 10,
            risk_bps: 1000,
            confidence_bps: 9000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        },
        3,
        &mut wal,
    );

    wal.flush_and_sync().unwrap();
    println!("WAL: {} entries → {}", wal.sequence(), wal_path.display());
    let _ = std::fs::remove_file(&wal_path);
}

fn run_scenario(
    snapshot: &PolicySnapshot,
    names: &[(&str, u32)],
    scenario: &str,
    input: KernelInput,
    requested_id: u32,
    wal: &mut WalWriter<RoutingRecord>,
) {
    let (decision, trace) = snapshot.prescribe_with_trace(input);
    assert_eq!(
        verify_decision(snapshot, input, &decision),
        VerifyResult::Valid
    );
    assert!(audit_bundle(snapshot, input, &decision).replay_valid);

    println!("  {scenario}");
    println!("    action:   {}", decision.action);
    println!("    requested: {}", name_of(requested_id, names));
    println!(
        "    selected:  {}",
        name_of(decision.selected_model_id, names)
    );
    println!("    reason:   {}", decision.reason);
    println!(
        "    rejections: quality={} budget={} utility={}",
        trace.rejections.quality, trace.rejections.budget, trace.rejections.utility
    );
    println!();

    wal.append(RoutingRecord {
        scenario: scenario.into(),
        action: decision.action.to_string(),
        requested_model: name_of(requested_id, names).into(),
        selected_model: name_of(decision.selected_model_id, names).into(),
        reason: decision.reason.to_string(),
    })
    .expect("WAL append must succeed");
}

fn name_of<'a>(id: u32, names: &'a [(&'a str, u32)]) -> &'a str {
    names
        .iter()
        .find(|(_, mid)| *mid == id)
        .map_or("unknown", |(n, _)| n)
}

fn model(
    id: u32,
    provider: u16,
    quality: u16,
    input_cost: u64,
    output_cost: u64,
    latency: u32,
) -> KernelModel {
    KernelModel {
        model_id: id,
        provider_id: provider,
        quality_bps: quality,
        risk_ceiling_bps: 9500,
        enabled: 1,
        p95_latency_ms: latency,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: input_cost,
        output_cost_microunits_per_million_tokens: output_cost,
    }
}
