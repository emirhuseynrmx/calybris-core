//! Outcome golden vector tests.
//!
//! `tests/specification.rs` checks that the code agrees with
//! `docs/SPECIFICATION.md`. That is necessary and not sufficient: an edit that
//! changed the layout and the document together would pass it. These are the
//! pinned bytes, and they are what makes the format actually frozen.
//!
//! If one of these assertions fails, the outcome format has changed. That is a
//! breaking change requiring a new digest tag (`calyout2\0`, `calysel2\0`,
//! `calyidn2\0`) — **never re-pin the expected values**, and never re-run
//! `examples/gen_outcome_vectors.rs` over this fixture to make a test pass.

use calybris_core::digest::{digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::outcome::{
    identity_digest, outcome_digest, selection_digest, DecisionIdentity, Disposition, Observation,
    Outcome, Selection,
};

const FIXTURE: &str = include_str!("fixtures/calybris_outcome_v1.json");

/// The fixture is flat and small, so a scanner beats a JSON dependency here.
fn field(case: &str, name: &str) -> String {
    let start = FIXTURE
        .find(&format!("\"label\": \"{case}\""))
        .unwrap_or_else(|| panic!("no case labelled {case}"));
    let rest = &FIXTURE[start..];
    let end = rest.find("    }").unwrap_or(rest.len());
    let block = &rest[..end];

    let key = format!("\"{name}\": \"");
    let at = block
        .find(&key)
        .unwrap_or_else(|| panic!("{case} has no {name}"))
        + key.len();
    let value = &block[at..];
    value[..value.find('"').expect("unterminated value")].to_string()
}

fn catalog() -> Vec<KernelModel> {
    vec![
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0b1,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 3_000_000,
            output_cost_microunits_per_million_tokens: 15_000_000,
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 8_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 100,
            capabilities: 0b1,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 1_000_000,
            output_cost_microunits_per_million_tokens: 5_000_000,
        },
    ]
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(1, 1, 9_000, 1_000, 2_000, 5, catalog()).expect("policy")
}

fn request(sequence: u64, budget: u64) -> KernelInput {
    KernelInput {
        request_sequence: sequence,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        budget_limit_microunits: budget,
        business_value_microunits: 5_000_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        required_capabilities: 0b1,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

const AT: u64 = 1_760_000_000_000_000;

fn measured() -> Observation {
    Observation {
        realized_cost_microunits: Some(4_100_000),
        realized_latency_ms: Some(238),
        succeeded: Some(true),
    }
}

/// Asserts every digest a case pins.
fn check(case: &str, outcome: &Outcome, input: &KernelInput) {
    assert_eq!(
        digest_to_hex(&input_digest(input)),
        field(case, "input_digest_hex"),
        "{case}: input digest",
    );
    assert_eq!(
        digest_to_hex(&outcome.identity.decision_digest),
        field(case, "decision_digest_hex"),
        "{case}: decision digest",
    );
    assert_eq!(
        digest_to_hex(&identity_digest(&outcome.identity)),
        field(case, "identity_digest_hex"),
        "{case}: identity digest",
    );
    assert_eq!(
        digest_to_hex(&selection_digest(&outcome.selection)),
        field(case, "selection_digest_hex"),
        "{case}: selection digest",
    );
    assert_eq!(
        digest_to_hex(&outcome_digest(outcome)),
        field(case, "outcome_digest_hex"),
        "{case}: outcome digest",
    );
}

#[test]
fn the_pinned_policy_is_the_policy_these_vectors_were_made_from() {
    let expected = FIXTURE
        .split("\"policy_digest_hex\": \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("policy digest in fixture");

    assert_eq!(digest_to_hex(&policy_digest(&policy())), expected);
}

#[test]
fn a_followed_and_fully_measured_outcome_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let outcome = Outcome::applied(&policy, &input, &decision, AT, measured());

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("followed-applied-fully-measured", &outcome, &input);
}

#[test]
fn an_abandoned_outcome_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let outcome = Outcome::abandoned(&policy, &input, &decision, AT);

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("followed-abandoned", &outcome, &input);
}

#[test]
fn a_partial_in_flight_outcome_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(2_000_000),
            realized_latency_ms: None,
            succeeded: None,
        },
    );
    outcome.disposition = Disposition::InFlight;

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("followed-in-flight-partial", &outcome, &input);
}

#[test]
fn an_exploration_at_one_basis_point_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(9_000_000),
            realized_latency_ms: Some(95),
            succeeded: Some(false),
        },
    );
    outcome.selection = Selection::explored(2, 1);

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("explored-one-basis-point", &outcome, &input);
}

/// The one case whose selection digest has an absent field. If the presence byte
/// were ever dropped, this is the vector that would catch it.
#[test]
fn a_human_choice_with_no_propensity_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, AT, measured());
    outcome.selection = Selection::human(2);

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("human-no-propensity", &outcome, &input);
}

#[test]
fn zero_measurements_at_revision_seven_are_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(0),
            realized_latency_ms: Some(0),
            succeeded: Some(false),
        },
    );
    outcome.revision = 7;

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("zero-measurements-revision-seven", &outcome, &input);
}

#[test]
fn an_abandoned_rejection_is_reproduced_byte_for_byte() {
    let policy = policy();
    let input = request(43, 1);
    let decision = policy.prescribe(input);
    let outcome = Outcome::abandoned(&policy, &input, &decision, AT);

    outcome
        .validate_against(&policy, &input, &decision)
        .expect("the pinned case is a valid record");
    check("rejection-abandoned", &outcome, &input);
}

/// Every pinned outcome digest is distinct. Seven records that differ only in
/// their disposition, revision or selection must not collide, and a collision
/// here would mean a field had stopped reaching the hash at all.
#[test]
fn the_pinned_outcomes_are_all_different_from_each_other() {
    let labels = [
        "followed-applied-fully-measured",
        "followed-abandoned",
        "followed-in-flight-partial",
        "explored-one-basis-point",
        "human-no-propensity",
        "zero-measurements-revision-seven",
        "rejection-abandoned",
    ];

    let digests: Vec<String> = labels
        .iter()
        .map(|label| field(label, "outcome_digest_hex"))
        .collect();

    for (i, a) in digests.iter().enumerate() {
        assert_eq!(a.len(), 64, "{}", labels[i]);
        for (j, b) in digests.iter().enumerate().skip(i + 1) {
            assert_ne!(a, b, "{} collides with {}", labels[i], labels[j]);
        }
    }
}

/// The identity in a pinned record has to be rebuildable from the policy, the
/// input and the decision — otherwise the vector pins a value a second
/// implementation could not arrive at.
#[test]
fn every_pinned_identity_is_rebuildable_from_its_three_parts() {
    let policy = policy();
    for (sequence, budget) in [(42, 50_000_000), (43, 1)] {
        let input = request(sequence, budget);
        let decision = policy.prescribe(input);
        let rebuilt = DecisionIdentity::of(&policy, &input, &decision);

        assert_eq!(
            digest_to_hex(&identity_digest(&rebuilt)),
            field(
                if sequence == 43 {
                    "rejection-abandoned"
                } else {
                    "followed-abandoned"
                },
                "identity_digest_hex",
            ),
        );
    }
}
