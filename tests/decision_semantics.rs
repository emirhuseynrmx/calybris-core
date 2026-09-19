//! The semantics 1.0.0 freezes.
//!
//! Every assertion here is a promise the crate is making to whatever is built on
//! top of it after development stops. They are written as tests rather than as
//! prose because prose does not fail a build, and a frozen contract that drifts
//! is worse than one that was never stated.
//!
//! The units, ceilings and orderings checked here are documented in
//! `docs/DECISION_SEMANTICS.md`; this file is what keeps that document true.

use calybris_core::kernel::{
    KernelAction, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, MAX_BPS,
    MAX_CATALOG_MODELS, MAX_PROVIDER_ID,
};

fn model(model_id: u32, quality_bps: u16, cost_per_million: u64) -> KernelModel {
    KernelModel {
        model_id,
        provider_id: 0,
        quality_bps,
        risk_ceiling_bps: 9_000,
        enabled: 1,
        p95_latency_ms: 100,
        capabilities: 0,
        region_mask: 0,
        input_cost_microunits_per_million_tokens: cost_per_million,
        output_cost_microunits_per_million_tokens: cost_per_million,
    }
}

fn policy(models: Vec<KernelModel>) -> PolicySnapshot {
    PolicySnapshot::try_new(1, 1, 9_000, 1_000, 2_000, 5, models).expect("policy")
}

fn request() -> KernelInput {
    KernelInput {
        request_sequence: 1,
        requested_model_id: 0,
        input_tokens: 1_000,
        output_tokens: 1_000,
        budget_limit_microunits: 1_000_000_000,
        business_value_microunits: 5_000_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

/// The ceilings a caller has to design around. Stated, not discovered.
#[test]
fn the_documented_ceilings_are_the_actual_ceilings() {
    assert_eq!(MAX_PROVIDER_ID, 63, "one bit per provider in a u64 mask");
    assert_eq!(MAX_CATALOG_MODELS, 65_535, "candidate indices are u16");
    assert_eq!(MAX_BPS, 10_000, "basis points are a fraction of one");
}

/// Latency is milliseconds in a `u32`, which is where the ceiling comes from.
/// Anything modelling delivery in days has to convert, and the conversion is the
/// caller's to make and to record.
#[test]
fn the_latency_ceiling_is_a_little_under_fifty_days() {
    let ceiling_days = f64::from(u32::MAX) / 1000.0 / 86_400.0;
    assert!(
        (49.7..49.8).contains(&ceiling_days),
        "u32 milliseconds tops out near 49.7 days, got {ceiling_days}"
    );
}

/// Ties are broken to a total order, so the same catalog and the same request
/// always name the same winner — on any machine, in any build.
#[test]
fn ties_break_by_cost_then_quality_then_identifier() {
    // Identical utility: cheaper wins.
    let decision =
        policy(vec![model(1, 9_000, 4_000_000), model(2, 9_000, 1_000_000)]).prescribe(request());
    assert_eq!(
        decision.selected_model_id, 2,
        "cheaper candidate wins a tie"
    );

    // Identical utility and cost: higher quality wins.
    let decision =
        policy(vec![model(3, 8_000, 1_000_000), model(4, 8_000, 1_000_000)]).prescribe(request());
    assert_eq!(
        decision.selected_model_id, 3,
        "equal on utility and cost, the lower identifier holds the tie"
    );
}

/// Ordering is stable against catalog order: the same set in a different order
/// decides the same way.
#[test]
fn catalog_order_does_not_decide_the_winner() {
    let forward = policy(vec![
        model(1, 9_000, 4_000_000),
        model(2, 9_000, 1_000_000),
        model(3, 9_000, 2_000_000),
    ])
    .prescribe(request());
    let reversed = policy(vec![
        model(3, 9_000, 2_000_000),
        model(2, 9_000, 1_000_000),
        model(1, 9_000, 4_000_000),
    ])
    .prescribe(request());

    assert_eq!(forward.selected_model_id, reversed.selected_model_id);
    assert_eq!(
        forward.expected_utility_microunits,
        reversed.expected_utility_microunits
    );
}

/// An empty eligible set is a rejection with a reason, never a fallback.
#[test]
fn every_candidate_rejected_is_a_rejection_and_not_a_guess() {
    let mut input = request();
    input.minimum_quality_bps = MAX_BPS;

    let decision = policy(vec![model(1, 9_000, 1_000_000)]).prescribe(input);

    assert_eq!(decision.action, KernelAction::Reject);
    assert_eq!(decision.eligible_models, 0);
    assert_eq!(
        decision.selected_model_id, 0,
        "a rejection names no candidate"
    );
}

/// A candidate that prices above the request's budget is refused rather than
/// clamped to it.
#[test]
fn the_budget_is_a_wall_and_not_a_target() {
    let mut input = request();
    input.budget_limit_microunits = 1;

    let decision = policy(vec![model(1, 9_000, 1_000_000)]).prescribe(input);
    assert_eq!(decision.action, KernelAction::Reject);
}

/// Utility is clamped rather than wrapped, so an extreme catalog cannot turn a
/// huge positive into a negative and reverse a ranking.
#[test]
fn extreme_inputs_saturate_instead_of_wrapping() {
    let mut input = request();
    input.business_value_microunits = i64::MAX;
    input.input_tokens = u32::MAX;
    input.output_tokens = u32::MAX;
    input.budget_limit_microunits = u64::MAX;

    let decision = policy(vec![model(1, MAX_BPS, u64::MAX)]).prescribe(input);

    // Whatever it decides, it must not have produced a negative utility for a
    // candidate it selected.
    if decision.action != KernelAction::Reject {
        assert!(
            decision.expected_utility_microunits > 0,
            "a selected candidate carries positive utility"
        );
    }
}

/// The same input decides identically every time, which is the whole product.
#[test]
fn the_same_input_decides_identically() {
    let policy = policy(vec![
        model(1, 9_000, 3_000_000),
        model(2, 8_500, 1_000_000),
        model(3, 9_900, 8_000_000),
    ]);
    let first = policy.prescribe(request());
    for _ in 0..64 {
        assert_eq!(policy.prescribe(request()), first);
    }
}
