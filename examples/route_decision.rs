/// Legacy LLM routing demo. Prefer `llm_routing` (`cargo run --example llm_routing`).
///
/// ```bash
/// cargo run --example route_decision
/// ```
use calybris_core::kernel::*;
use calybris_core::wal::WalWriter;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RoutingDecision {
    action: String,
    requested_model: String,
    selected_model: String,
    reason: String,
    estimated_cost_microunits: u64,
    expected_utility: i64,
    policy_epoch: u64,
}

fn main() {
    // Model catalog: 6 LLM providers with real-ish pricing
    let models = vec![
        model(1, "gpt-4o", 0, 9500, 250, 1000, 450),
        model(2, "gpt-4o-mini", 0, 7500, 15, 60, 120),
        model(3, "claude-sonnet", 1, 9200, 300, 1500, 380),
        model(4, "claude-haiku", 1, 7000, 25, 125, 90),
        model(5, "gemini-pro", 2, 8800, 125, 500, 320),
        model(6, "gemini-flash", 2, 7200, 8, 30, 80),
    ];
    let names: Vec<(&str, u32)> = vec![
        ("gpt-4o", 1),
        ("gpt-4o-mini", 2),
        ("claude-sonnet", 3),
        ("claude-haiku", 4),
        ("gemini-pro", 5),
        ("gemini-flash", 6),
    ];

    let snapshot =
        PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 2, models).expect("valid policy");

    // WAL for tamper-evident audit trail
    let wal_path = PathBuf::from("demo_routing.wal.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal = WalWriter::<RoutingDecision>::open(&wal_path).unwrap();

    println!("Calybris LLM Routing Demo");
    println!("=========================\n");

    // Scenario 1: High-value compliance review
    let decision = snapshot.prescribe(KernelInput {
        request_sequence: 1,
        requested_model_id: 1, // gpt-4o requested
        input_tokens: 4000,
        output_tokens: 2000,
        business_value_microunits: 500_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 2000,
        confidence_bps: 9000,
        minimum_quality_bps: 9000, // high quality floor
        max_p95_latency_ms: 1000,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    });
    print_and_log(
        &decision,
        1,
        &names,
        "Compliance review (quality=0.90)",
        &mut wal,
    );

    // Scenario 2: Simple support ticket — can be downgraded
    let decision = snapshot.prescribe(KernelInput {
        request_sequence: 2,
        requested_model_id: 1, // gpt-4o requested
        input_tokens: 500,
        output_tokens: 200,
        business_value_microunits: 10_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 500,
        confidence_bps: 9000,
        minimum_quality_bps: 6000, // low quality floor — downgrade OK
        max_p95_latency_ms: 500,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    });
    print_and_log(
        &decision,
        1,
        &names,
        "Support ticket (quality=0.60)",
        &mut wal,
    );

    // Scenario 3: Budget exhausted
    let decision = snapshot.prescribe(KernelInput {
        request_sequence: 3,
        requested_model_id: 3,
        input_tokens: 8000,
        output_tokens: 4000,
        business_value_microunits: 100_000,
        budget_limit_microunits: 10, // almost no budget
        risk_bps: 1000,
        confidence_bps: 9000,
        minimum_quality_bps: 5000,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    });
    print_and_log(
        &decision,
        3,
        &names,
        "Budget exhausted ($0.00001 left)",
        &mut wal,
    );

    // Scenario 4: Risk too high — blocked
    let decision = snapshot.prescribe(KernelInput {
        request_sequence: 4,
        requested_model_id: 1,
        input_tokens: 1000,
        output_tokens: 500,
        business_value_microunits: 200_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 9800, // above hard limit
        confidence_bps: 9000,
        minimum_quality_bps: 5000,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    });
    print_and_log(
        &decision,
        1,
        &names,
        "High-risk request (risk=0.98)",
        &mut wal,
    );

    // Verify WAL
    wal.flush_and_sync().unwrap();
    println!(
        "\nWAL: {} entries, last hash: {}...",
        wal.sequence(),
        &wal.last_hash()[..16]
    );
    println!("Audit trail: {}", wal_path.display());

    let _ = std::fs::remove_file(&wal_path);
}

fn print_and_log(
    d: &KernelDecision,
    requested_model_id: u32,
    names: &[(&str, u32)],
    scenario: &str,
    wal: &mut WalWriter<RoutingDecision>,
) {
    let requested = name_of(requested_model_id, names);
    let selected = name_of(d.selected_model_id, names);
    let action = format!("{:?}", d.action);
    let reason = format!("{:?}", d.reason);

    println!("  {scenario}");
    println!("    Action:    {action}");
    println!("    Requested: {requested}");
    println!("    Selected:  {selected}");
    println!("    Reason:    {reason}");
    println!("    Cost:      {} microunits", d.estimated_cost_microunits);
    println!("    Utility:   {}", d.expected_utility_microunits);
    println!();

    let record = RoutingDecision {
        action,
        requested_model: requested.to_string(),
        selected_model: selected.to_string(),
        reason,
        estimated_cost_microunits: d.estimated_cost_microunits,
        expected_utility: d.expected_utility_microunits,
        policy_epoch: d.policy_epoch,
    };
    wal.append(record)
        .expect("WAL append must succeed for audit trail integrity");
}

fn name_of<'a>(id: u32, names: &'a [(&'a str, u32)]) -> &'a str {
    names
        .iter()
        .find(|(_, mid)| *mid == id)
        .map_or("unknown", |(n, _)| n)
}

fn model(
    id: u32,
    _name: &str,
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
