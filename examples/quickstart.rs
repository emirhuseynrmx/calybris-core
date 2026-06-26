//! README Quick Start — copy-paste runnable demo
//!
//! ```bash
//! cargo run --example quickstart
//! ```
use calybris_core::budget::BudgetEngine;
use calybris_core::finance::prove_conservation;
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let models = vec![
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
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

    let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 2, models)?;

    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1000,
        output_tokens: 500,
        business_value_microunits: 100_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 1000,
        confidence_bps: 9000,
        minimum_quality_bps: 5000,
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

    let budget = BudgetEngine::new();
    budget.ensure_tenant("desk-1", 100_000_000);
    prove_conservation(&budget)?;

    println!("action: {}", decision.action);
    println!("selected_model_id: {}", decision.selected_model_id);
    println!("utility: {}", decision.expected_utility_microunits);
    println!("conservation: ok");

    Ok(())
}
