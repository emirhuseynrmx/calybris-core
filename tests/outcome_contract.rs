//! The outcome record has to refuse the shapes a later learner would misread.

use calybris_core::digest::decision_digest;
use calybris_core::kernel::{
    KernelAction, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS,
};
use calybris_core::outcome::{
    outcome_digest, DecisionIdentity, Disposition, IdentityField, Observation, Outcome,
    OutcomeError, Selection, SelectionStrategy, FULL_PROBABILITY_BPS,
};

fn models() -> Vec<KernelModel> {
    vec![
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_000,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0b1,
            region_mask: 0b1,
            input_cost_microunits_per_million_tokens: 3_000_000,
            output_cost_microunits_per_million_tokens: 15_000_000,
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 8_000,
            risk_ceiling_bps: 9_000,
            enabled: 1,
            p95_latency_ms: 100,
            capabilities: 0b1,
            region_mask: 0b1,
            input_cost_microunits_per_million_tokens: 1_000_000,
            output_cost_microunits_per_million_tokens: 5_000_000,
        },
    ]
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(1, 1, 9_000, 1_000, 2_000, 5, models()).expect("policy")
}

fn request() -> KernelInput {
    KernelInput {
        request_sequence: 42,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        budget_limit_microunits: 50_000_000,
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

fn measured() -> Observation {
    Observation {
        realized_cost_microunits: Some(4_100_000),
        realized_latency_ms: Some(238),
        succeeded: Some(true),
    }
}

#[test]
fn an_outcome_binds_to_the_policy_the_input_and_the_decision() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let outcome = Outcome::applied(
        &policy,
        &input,
        &decision,
        1_760_000_000_000_000,
        measured(),
    );

    assert!(outcome.follows(&decision));
    assert_eq!(outcome.identity.decision_digest, decision_digest(&decision));
    assert_eq!(outcome.identity.request_sequence, decision.request_sequence);
    outcome
        .validate_against(&policy, &input, &decision)
        .expect("a followed, measured outcome is valid");
}

/// The reason the identity is three digests rather than one: a policy change that
/// happens not to change this decision still changes what the record means.
#[test]
fn the_same_decision_under_a_different_policy_is_not_the_same_outcome() {
    let input = request();
    let before = policy();
    let after = PolicySnapshot::try_new(1, 1, 9_500, 1_000, 2_000, 5, models()).expect("policy");

    let decision_before = before.prescribe(input);
    let decision_after = after.prescribe(input);
    assert_eq!(
        decision_digest(&decision_before),
        decision_digest(&decision_after),
        "this test is only meaningful while the two policies decide identically",
    );

    let outcome = Outcome::applied(&before, &input, &decision_before, 1, measured());

    assert_eq!(
        outcome.validate_against(&after, &input, &decision_after),
        Err(OutcomeError::IdentityMismatch(IdentityField::Policy)),
    );
}

/// Likewise for the request: two requests can decide the same way and still be
/// different evidence.
#[test]
fn a_different_request_that_decides_the_same_way_is_not_the_same_outcome() {
    let policy = policy();
    let asked = request();
    let mut otherwise = request();
    otherwise.max_p95_latency_ms = 100_000; // slack nothing here comes near

    let decision = policy.prescribe(asked);
    let decision_otherwise = policy.prescribe(otherwise);
    assert_eq!(
        decision_digest(&decision),
        decision_digest(&decision_otherwise),
        "this test is only meaningful while the two requests decide identically",
    );

    let outcome = Outcome::applied(&policy, &asked, &decision, 1, measured());

    assert_eq!(
        outcome.validate_against(&policy, &otherwise, &decision_otherwise),
        Err(OutcomeError::IdentityMismatch(IdentityField::Input)),
    );
}

#[test]
fn maximise_utility_must_record_certainty() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.selection.propensity_bps = Some(7_500);

    assert_eq!(
        outcome.validate(),
        Err(OutcomeError::DeterministicPropensity(7_500)),
    );
}

#[test]
fn exploration_must_record_the_probability_it_cannot_recover_later() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.selection = Selection {
        strategy: SelectionStrategy::Explore,
        acted_model_id: 2,
        propensity_bps: None,
    };

    assert_eq!(
        outcome.validate(),
        Err(OutcomeError::MissingPropensity(SelectionStrategy::Explore)),
    );

    outcome.selection = Selection::explored(2, 1_500);
    outcome
        .validate_against(&policy, &input, &decision)
        .expect("a deliberate exploration with a stated probability is a valid record");
}

/// A person's reasons are not a distribution. Recording a number here would make
/// the record look causally usable when it is not.
#[test]
fn a_human_choice_records_no_probability() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());

    outcome.selection = Selection::human(2);
    outcome
        .validate_against(&policy, &input, &decision)
        .expect("a human override is a valid record without a propensity");

    outcome.selection.propensity_bps = Some(FULL_PROBABILITY_BPS);
    assert_eq!(outcome.validate(), Err(OutcomeError::UnknowablePropensity));
}

#[test]
fn an_observed_event_cannot_have_had_no_chance_of_happening() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.selection = Selection {
        strategy: SelectionStrategy::Explore,
        acted_model_id: 2,
        propensity_bps: Some(0),
    };

    assert_eq!(
        outcome.validate(),
        Err(OutcomeError::PropensityOutOfRange(0)),
    );
}

#[test]
fn applied_without_a_measurement_is_refused() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.observation = Observation::default();

    assert_eq!(outcome.validate(), Err(OutcomeError::EmptyObservation));
}

/// The mirror of the rule above: nothing ran, so nothing can have been measured,
/// and a zero here would later read as a free success.
#[test]
fn abandoned_with_a_measurement_is_refused() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::abandoned(&policy, &input, &decision, 1);
    outcome
        .validate_against(&policy, &input, &decision)
        .expect("an abandoned recommendation with nothing measured is valid");

    outcome.observation.realized_cost_microunits = Some(0);
    assert_eq!(
        outcome.validate(),
        Err(OutcomeError::ObservationOnAbandoned),
    );
}

#[test]
fn in_flight_cannot_claim_it_already_finished() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.disposition = Disposition::InFlight;

    assert_eq!(outcome.validate(), Err(OutcomeError::CompletedInFlight));

    outcome.observation.succeeded = None;
    outcome
        .validate_against(&policy, &input, &decision)
        .expect("cost and latency so far are fine while the work is still running");
}

#[test]
fn a_rejection_cannot_have_been_carried_out() {
    let policy = policy();
    let mut input = request();
    input.budget_limit_microunits = 1;
    let decision = policy.prescribe(input);
    assert_eq!(decision.action, KernelAction::Reject);

    let outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    assert_eq!(
        outcome.validate_against(&policy, &input, &decision),
        Err(OutcomeError::ActedOnRejection),
    );

    Outcome::abandoned(&policy, &input, &decision, 1)
        .validate_against(&policy, &input, &decision)
        .expect("abandoning a rejection is the only thing that can have happened");
}

#[test]
fn following_the_ranking_means_acting_on_what_it_ranked() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    let selected = decision.selected_model_id;
    outcome.selection.acted_model_id = selected + 1;

    assert_eq!(
        outcome.validate_against(&policy, &input, &decision),
        Err(OutcomeError::ActedModelNotSelected {
            acted: selected + 1,
            selected,
        }),
    );
}

#[test]
fn an_outcome_for_a_model_outside_the_catalog_is_refused() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let mut outcome = Outcome::applied(&policy, &input, &decision, 1, measured());
    outcome.selection = Selection::explored(9_999, 1_000);

    assert_eq!(
        outcome.validate_against(&policy, &input, &decision),
        Err(OutcomeError::ActedModelNotInCatalog(9_999)),
    );
}

#[test]
fn the_digest_separates_a_missing_measurement_from_a_zero_one() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);

    let absent = Outcome::applied(
        &policy,
        &input,
        &decision,
        1,
        Observation {
            realized_cost_microunits: None,
            realized_latency_ms: Some(10),
            succeeded: Some(true),
        },
    );
    let mut zero = absent;
    zero.observation.realized_cost_microunits = Some(0);

    assert_ne!(outcome_digest(&absent), outcome_digest(&zero));
}

#[test]
fn the_digest_separates_an_unknowable_probability_from_a_recorded_one() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let base = Outcome::applied(&policy, &input, &decision, 1, measured());

    let mut human = base;
    human.selection = Selection::human(decision.selected_model_id);
    let mut certain = base;
    certain.selection = Selection {
        strategy: SelectionStrategy::Human,
        acted_model_id: decision.selected_model_id,
        propensity_bps: Some(FULL_PROBABILITY_BPS),
    };

    assert_ne!(outcome_digest(&human), outcome_digest(&certain));
}

#[test]
fn a_correction_is_visible_as_a_correction() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);
    let first = Outcome::applied(&policy, &input, &decision, 1, measured());
    let mut second = first;
    second.revision = 1;

    assert_ne!(outcome_digest(&first), outcome_digest(&second));
}

#[test]
fn the_identity_is_computed_the_same_way_wherever_it_is_built() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);

    assert_eq!(
        Outcome::applied(&policy, &input, &decision, 1, measured()).identity,
        DecisionIdentity::of(&policy, &input, &decision),
    );
}
