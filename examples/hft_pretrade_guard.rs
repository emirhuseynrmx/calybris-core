//! Use case 2: HFT-style pre-trade risk and budget guard
//!
//! **Not** an exchange, strategy engine, or market data system.
//! Demonstrates: candidate order → deterministic admit/reject → exposure hold →
//! financial certificate → conservation proof.
//!
//! ```bash
//! cargo run --example hft_pretrade_guard
//! ```
use calybris_core::budget::{BudgetEngine, BudgetSettlement, ConservationStatus};
use calybris_core::finance::{certify_ledger, prove_conservation, MICROCENTS_PER_CENT};
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};

fn main() {
    // Venue catalog: execution paths with latency/cost/risk profiles
    let venues = vec![
        venue(1, 0, 9800, 50, 200, 120), // primary — low latency
        venue(2, 1, 8500, 30, 100, 350), // backup
        venue(3, 2, 7000, 10, 40, 800),  // dark pool — cheap, slow
    ];

    let policy = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 5, venues).expect("valid");

    let budget = BudgetEngine::new();
    budget.ensure_tenant("desk-alpha", 100_000_000 * MICROCENTS_PER_CENT);

    println!("Calybris — Pre-Trade Guard");
    println!("==========================\n");

    // Candidate order: BTCUSDT buy, $250k notional (in microcents)
    let notional_microcents = 25_000_000_i64 * MICROCENTS_PER_CENT;
    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1,
        output_tokens: 1,
        business_value_microunits: notional_microcents,
        budget_limit_microunits: notional_microcents as u64,
        risk_bps: 120,
        confidence_bps: 9200,
        minimum_quality_bps: 8000,
        max_p95_latency_ms: 500,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };

    println!("Candidate order:");
    println!("  symbol:     BTCUSDT");
    println!("  side:       buy");
    println!("  notional:   {notional_microcents} microcents");
    println!("  risk_bps:   {}", input.risk_bps);
    println!("  latency cap: {} ms", input.max_p95_latency_ms);
    println!();

    let decision = policy.prescribe(input);
    assert_eq!(
        verify_decision(&policy, input, &decision),
        VerifyResult::Valid
    );
    let bundle = audit_bundle(&policy, input, &decision);
    assert!(bundle.replay_valid);

    println!("Decision:");
    println!("  action:   {}", decision.action);
    println!("  venue:    {}", decision.selected_model_id);
    println!("  reason:   {}", decision.reason);
    println!("  utility:  {}", decision.expected_utility_microunits);
    println!();

    if decision.action == KernelAction::Reject {
        println!("Order rejected — no budget hold.");
        return;
    }

    let hold = notional_microcents;
    let (_, reservation_id) = budget.try_reserve("desk-alpha", hold);
    let Some(reservation_id) = reservation_id else {
        println!("Exposure limit hit at budget layer.");
        return;
    };

    let actual = decision.estimated_cost_microunits as i64;
    match budget.commit(reservation_id, actual) {
        BudgetSettlement::Committed { .. } => {
            let cert = certify_ledger(&budget);
            let digest = prove_conservation(&budget).unwrap();
            println!("Financial certificate:");
            println!("  conservation: {}", cert.conservation_balanced);
            println!(
                "  lifetime spend: {:?} microcents",
                budget.committed_microcents("desk-alpha")
            );
            println!("  ledger digest:  {}...", &digest[..16]);
            assert_eq!(budget.verify_conservation(), ConservationStatus::Balanced);
        }
        other => println!("Settlement failed: {other:?}"),
    }
}

fn venue(
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
