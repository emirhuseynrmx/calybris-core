use calybris_core::kernel::*;

fn main() {
    let models = vec![
        KernelModel {
            model_id: 0,
            provider_id: 0,
            quality_bps: 3500,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 8,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 0,
            output_cost_microunits_per_million_tokens: 0,
        },
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 7500,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 420,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 15,
            output_cost_microunits_per_million_tokens: 60,
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 9200,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 900,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 250,
            output_cost_microunits_per_million_tokens: 1000,
        },
    ];

    let snapshot =
        PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).expect("valid policy");

    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 2,
        input_tokens: 1000,
        output_tokens: 500,
        business_value_microunits: 50_000,
        budget_limit_microunits: 1_000_000,
        risk_bps: 500,
        confidence_bps: 9000,
        minimum_quality_bps: 5000,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };

    let decision = snapshot.prescribe(input);

    println!("Action:    {:?}", decision.action);
    println!("Selected:  model_id={}", decision.selected_model_id);
    println!(
        "Utility:   {} microunits",
        decision.expected_utility_microunits
    );
    println!(
        "Cost:      {} microunits",
        decision.estimated_cost_microunits
    );
    println!("Reason:    {:?}", decision.reason);
}
