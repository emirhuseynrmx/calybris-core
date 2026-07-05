//! Generate the CALY-PROOF v1 conformance vector suite (one-time tool).
//!
//! Emits a JSON object of labeled cases — one shared policy, many inputs
//! chosen to exercise each decision outcome (execute, substitute, and each
//! rejection reason) — with the byte-exact expected digests. Any conforming
//! implementation, on any platform, must reproduce every case.
//!
//! Run: cargo run --example gen_conformance_vectors --features wal > /tmp/vec.json

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};

fn shared_policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
        7,
        42,
        9_600, // hard_risk_limit_bps
        5_500, // minimum_confidence_bps
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
    .expect("shared policy is valid")
}

fn base() -> KernelInput {
    KernelInput {
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
        required_capabilities: 0b001,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn main() {
    let policy = shared_policy();
    let policy_hex = digest_to_hex(&policy_digest(&policy));

    // (label, input) — each crafted to hit a distinct decision outcome.
    let cases: Vec<(&str, KernelInput)> = vec![
        // Execute requested: model 1 is eligible and maximizes utility.
        ("execute_requested", base()),
        // Substitution: request the cheaper model 2 but let model 1 win on
        // utility (high value amortizes model 1's cost).
        (
            "substitute",
            KernelInput {
                request_sequence: 2,
                requested_model_id: 2,
                business_value_microunits: 5_000_000,
                required_capabilities: 0b001,
                ..base()
            },
        ),
        // Risk hard limit: request risk above the policy ceiling.
        (
            "reject_risk_hard_limit",
            KernelInput {
                request_sequence: 3,
                risk_bps: 9_800,
                ..base()
            },
        ),
        // Confidence hard limit: confidence below the policy floor.
        (
            "reject_confidence_hard_limit",
            KernelInput {
                request_sequence: 4,
                confidence_bps: 5_000,
                ..base()
            },
        ),
        // Quality constraint: require quality above both models.
        (
            "reject_quality_constraint",
            KernelInput {
                request_sequence: 5,
                minimum_quality_bps: 9_500,
                ..base()
            },
        ),
        // Budget constraint: budget below the cheapest eligible cost.
        (
            "reject_budget_constraint",
            KernelInput {
                request_sequence: 6,
                budget_limit_microunits: 1,
                ..base()
            },
        ),
    ];

    println!("{{");
    println!("  \"spec\": \"CALY-PROOF v1 conformance suite\",");
    println!(
        "  \"comment\": \"One shared policy, many inputs exercising each decision outcome. Any conforming implementation MUST reproduce every digest and decision field. A mismatch is a breaking proof-format change requiring a new digest tag.\","
    );
    println!("  \"policy_digest_hex\": \"{policy_hex}\",");
    println!("  \"cases\": [");
    for (i, (label, input)) in cases.iter().enumerate() {
        let decision = policy.prescribe(*input);
        let comma = if i + 1 < cases.len() { "," } else { "" };
        println!("    {{");
        println!("      \"label\": \"{label}\",");
        println!("      \"request_sequence\": {},", input.request_sequence);
        println!(
            "      \"input_digest_hex\": \"{}\",",
            digest_to_hex(&input_digest(input))
        );
        println!(
            "      \"decision_digest_hex\": \"{}\",",
            digest_to_hex(&decision_digest(&decision))
        );
        println!("      \"reason\": \"{}\",", decision.reason);
        println!(
            "      \"selected_model_id\": {},",
            decision.selected_model_id
        );
        println!(
            "      \"estimated_cost_microunits\": {},",
            decision.estimated_cost_microunits
        );
        println!(
            "      \"expected_utility_microunits\": {}",
            decision.expected_utility_microunits
        );
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}
