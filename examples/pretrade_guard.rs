//! Pre-trade guard for an algorithmic desk: venue routing + exposure holds.
//!
//! Scenario: `desk-alpha` runs a VWAP algo at the US cash open. Each child order
//! passes through two layers before it can leave for an exchange:
//!
//! 1. **Policy gate** — pick an eligible venue under risk, latency, quality, and fee caps.
//! 2. **Exposure gate** — reserve notional against the desk budget; commit routing fees on admit.
//!
//! Calybris owns layer 1 and the conservation proof for layer 2. It is not an OMS,
//! market-data feed, or matching engine.
//!
//! ```bash
//! cargo run --example pretrade_guard
//! ```

use calybris_core::budget::{BudgetEngine, ConservationStatus};
use calybris_core::finance::{certify_ledger, prove_conservation, MICROCENTS_PER_CENT};
use calybris_core::kernel::*;
use calybris_core::verify::{verified_audit_bundle, verify_decision, VerifyResult};

const USD: i64 = 100 * MICROCENTS_PER_CENT;
/// One child order maps to one kernel "request" for flat per-order venue fees.
const ORDER_UNIT: u32 = 1_000_000;

#[derive(Clone, Copy)]
struct ChildOrder {
    client_id: &'static str,
    parent_algo: &'static str,
    symbol: &'static str,
    side: &'static str,
    requested_venue: u32,
    notional_usd: i64,
    /// Estimated adverse-selection / slippage risk in bps.
    risk_bps: u16,
    confidence_bps: u16,
    min_fill_quality_bps: u16,
    latency_cap_ms: u32,
}

fn main() {
    let venues = vec![
        // id, provider, quality, input_fee, output_fee, p95_ms
        venue(10, 0, 9_900, 8_200, 14_000, 42), // NYSE Arca lit — tight spread, fastest
        venue(20, 1, 9_400, 5_100, 9_500, 95),  // NASDAQ backup — reliable, slightly slower
        venue(30, 2, 8_600, 2_800, 4_200, 280), // IEX-style dark — cheap, higher latency
    ];
    let venue_names = [
        (10, "NYSE-Arca-lit"),
        (20, "NASDAQ-backup"),
        (30, "IEX-dark"),
    ];

    let policy =
        PolicySnapshot::try_new(7, 42, 9_600, 7_000, 4_000, 4, venues).expect("valid venue policy");

    let budget = BudgetEngine::new();
    budget.ensure_tenant("desk-alpha", 2_000_000 * USD);
    // Open exposure cap: max notional reserved but not yet filled.
    budget.set_max_reserved_microcents("desk-alpha", 500_000 * USD);

    // 09:31 ET — parent VWAP fans out five child orders in one burst.
    let orders = [
        ChildOrder {
            client_id: "CL-10041",
            parent_algo: "VWAP-AAPL",
            symbol: "AAPL",
            side: "buy",
            requested_venue: 10,
            notional_usd: 85_000,
            risk_bps: 90,
            confidence_bps: 9_400,
            min_fill_quality_bps: 9_200,
            latency_cap_ms: 80,
        },
        ChildOrder {
            client_id: "CL-10042",
            parent_algo: "VWAP-TSLA",
            symbol: "TSLA",
            side: "sell",
            requested_venue: 10,
            notional_usd: 210_000,
            risk_bps: 220,
            confidence_bps: 9_100,
            min_fill_quality_bps: 9_000,
            // Lit primary is spiking; desk still wants sub-120 ms.
            latency_cap_ms: 120,
        },
        ChildOrder {
            client_id: "CL-10043",
            parent_algo: "POV-NVDA",
            symbol: "NVDA",
            side: "buy",
            requested_venue: 30,
            notional_usd: 140_000,
            // Desk hard risk limit is 9_600 bps — this name is blocked pre-trade.
            risk_bps: 9_750,
            confidence_bps: 8_900,
            min_fill_quality_bps: 9_100,
            latency_cap_ms: 400,
        },
        ChildOrder {
            client_id: "CL-10044",
            parent_algo: "VWAP-SPY",
            symbol: "SPY",
            side: "buy",
            requested_venue: 20,
            notional_usd: 620_000,
            risk_bps: 60,
            confidence_bps: 9_600,
            min_fill_quality_bps: 9_300,
            latency_cap_ms: 150,
        },
        ChildOrder {
            client_id: "CL-10045",
            parent_algo: "VWAP-MSFT",
            symbol: "MSFT",
            side: "buy",
            requested_venue: 10,
            notional_usd: 55_000,
            risk_bps: 75,
            confidence_bps: 9_500,
            min_fill_quality_bps: 9_200,
            latency_cap_ms: 90,
        },
    ];

    println!("Calybris pre-trade guard — desk-alpha @ US cash open");
    println!("====================================================");
    println!("desk budget:        2,000,000 USD");
    println!("open exposure cap:    500,000 USD (reserved, not yet filled)");
    println!("pipeline: policy gate -> exposure hold -> fee commit -> audit\n");

    let mut admitted = 0_u32;
    let mut policy_rejects = 0_u32;
    let mut exposure_rejects = 0_u32;

    for order in orders {
        match run_child_order(&policy, &budget, &venue_names, order) {
            GateOutcome::Admitted => admitted += 1,
            GateOutcome::PolicyRejected => policy_rejects += 1,
            GateOutcome::ExposureRejected => exposure_rejects += 1,
        }
    }

    let proof = prove_conservation(&budget).expect("budget must conserve");
    let cert = certify_ledger(&budget);
    assert_eq!(budget.verify_conservation(), ConservationStatus::Balanced);
    assert!(cert.conservation_balanced);

    println!("Session summary");
    println!("  admitted:          {admitted}");
    println!("  policy rejected:   {policy_rejects}");
    println!("  exposure rejected: {exposure_rejects}");
    println!(
        "  open reserved:     {} USD",
        budget.reserved_microcents("desk-alpha") / USD
    );
    println!(
        "  committed fees:    {} microcents",
        cert.total_committed_microcents
    );
    println!("  conservation:      {}", cert.conservation_balanced);
    println!("  ledger digest:     {}...", &proof.ledger_digest_hex[..16]);
}

enum GateOutcome {
    Admitted,
    PolicyRejected,
    ExposureRejected,
}

fn run_child_order(
    policy: &PolicySnapshot,
    budget: &BudgetEngine,
    names: &[(u32, &'static str)],
    order: ChildOrder,
) -> GateOutcome {
    println!(
        "{} {} {:<4} {:>7} USD  algo={}  req={}",
        order.client_id,
        order.symbol,
        order.side,
        order.notional_usd,
        order.parent_algo,
        name_of(order.requested_venue, names),
    );

    let notional = order.notional_usd * USD;
    let input = KernelInput {
        request_sequence: hash_client_id(order.client_id),
        requested_model_id: order.requested_venue,
        input_tokens: ORDER_UNIT,
        output_tokens: ORDER_UNIT,
        business_value_microunits: notional,
        budget_limit_microunits: 45_000,
        risk_bps: order.risk_bps,
        confidence_bps: order.confidence_bps,
        minimum_quality_bps: order.min_fill_quality_bps,
        max_p95_latency_ms: order.latency_cap_ms,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };

    let (decision, trace) = policy.prescribe_with_trace(input);
    assert_eq!(
        verify_decision(policy, input, &decision),
        VerifyResult::Valid
    );
    assert!(verified_audit_bundle(policy, input, &decision).is_ok());

    println!(
        "  policy: action={} venue={} reason={}",
        decision.action,
        name_of(decision.selected_model_id, names),
        decision.reason
    );
    println!(
        "          rejections latency={} budget={} quality={} utility={} eligible={}/{}",
        trace.rejections.latency,
        trace.rejections.budget,
        trace.rejections.quality,
        trace.rejections.utility,
        trace.eligible_models,
        trace.evaluated_models
    );

    if decision.action == KernelAction::Reject {
        println!("  outcome: BLOCKED at policy gate (no venue cleared constraints)\n");
        return GateOutcome::PolicyRejected;
    }

    if decision.selected_model_id != order.requested_venue {
        println!(
            "  note:    venue failover {} -> {}",
            name_of(order.requested_venue, names),
            name_of(decision.selected_model_id, names)
        );
    }

    let (_, reservation_id) = budget.try_reserve("desk-alpha", notional);
    let Some(reservation_id) = reservation_id else {
        println!("  outcome: BLOCKED at exposure gate (open exposure cap exceeded)\n");
        return GateOutcome::ExposureRejected;
    };

    // Hold stays open until fill/cancel — routing fee is quoted, not settled here.
    let fee = decision.estimated_cost_microunits as i64;
    println!(
        "  exposure: open hold {} USD (reservation {reservation_id}), quoted routing fee {fee} microcents",
        order.notional_usd
    );
    println!("  outcome: ADMITTED (replay bundle valid)\n");
    GateOutcome::Admitted
}

fn hash_client_id(id: &str) -> u64 {
    id.bytes().fold(0_u64, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u64::from(b))
    })
}

fn name_of(id: u32, names: &[(u32, &'static str)]) -> &'static str {
    names
        .iter()
        .find(|(venue_id, _)| *venue_id == id)
        .map_or("none", |(_, name)| *name)
}

fn venue(
    id: u32,
    provider: u16,
    quality: u16,
    input_fee: u64,
    output_fee: u64,
    latency_ms: u32,
) -> KernelModel {
    KernelModel {
        model_id: id,
        provider_id: provider,
        quality_bps: quality,
        risk_ceiling_bps: 9_500,
        enabled: 1,
        p95_latency_ms: latency_ms,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: input_fee,
        output_cost_microunits_per_million_tokens: output_fee,
    }
}
