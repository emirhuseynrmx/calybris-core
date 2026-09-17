//! The outcome record has to refuse the shapes a later learner would misread.

use calybris_core::digest::decision_digest;
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS};
use calybris_core::outcome::{
    outcome_digest, Disposition, Observation, Outcome, OutcomeError, Selection, SelectionStrategy,
    FULL_PROBABILITY_BPS,
};

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
        1,
        1,
        9_000,
        1_000,
        2_000,
        5,
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
        ],
    )
    .expect("policy")
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
fn an_outcome_binds_to_the_decision_it_followed() {
    let decision = policy().prescribe(request());
    let outcome = Outcome::applied(&decision, 1_760_000_000_000_000, measured());

    assert!(outcome.follows(&decision));
    assert_eq!(outcome.decision_digest, decision_digest(&decision));
    assert_eq!(outcome.request_sequence, decision.request_sequence);
    outcome
        .validate()
        .expect("a followed, measured outcome is valid");
}

#[test]
fn the_same_request_under_a_different_policy_does_not_inherit_the_outcome() {
    let decision = policy().prescribe(request());
    let outcome = Outcome::applied(&decision, 1, measured());

    // Same request sequence, different policy epoch: a different decision.
    let other = PolicySnapshot::try_new(2, 1, 9_000, 1_000, 2_000, 5, policy().models().to_vec())
        .expect("policy");
    let other_decision = other.prescribe(request());

    assert_eq!(outcome.request_sequence, other_decision.request_sequence);
    assert!(
        !outcome.follows(&other_decision),
        "binding by sequence alone would have accepted this"
    );
}

#[test]
fn applied_without_a_measurement_is_refused() {
    let decision = policy().prescribe(request());
    let mut outcome = Outcome::applied(&decision, 1, Observation::default());

    assert_eq!(outcome.validate(), Err(OutcomeError::EmptyObservation));

    // Abandoned explains the absence, so it stands.
    outcome.disposition = Disposition::Abandoned;
    outcome
        .validate()
        .expect("an abandoned recommendation measures nothing");
}

#[test]
fn a_deterministic_strategy_cannot_claim_it_might_have_chosen_otherwise() {
    let selection = Selection {
        strategy: SelectionStrategy::MaximiseUtility,
        acted_model_id: 1,
        propensity_bps: 4_000,
    };
    assert_eq!(
        selection.validate(),
        Err(OutcomeError::DeterministicPropensity(4_000))
    );
}

#[test]
fn an_observed_choice_cannot_have_had_no_chance_of_happening() {
    for propensity in [0, FULL_PROBABILITY_BPS + 1] {
        let selection = Selection {
            strategy: SelectionStrategy::Explore,
            acted_model_id: 2,
            propensity_bps: propensity,
        };
        assert_eq!(
            selection.validate(),
            Err(OutcomeError::PropensityOutOfRange(propensity)),
            "propensity {propensity} must be refused"
        );
    }
}

#[test]
fn an_absent_measurement_and_a_zero_measurement_are_different_records() {
    let decision = policy().prescribe(request());

    let absent = Outcome::applied(
        &decision,
        1,
        Observation {
            realized_cost_microunits: None,
            realized_latency_ms: Some(1),
            succeeded: None,
        },
    );
    let zero = Outcome::applied(
        &decision,
        1,
        Observation {
            realized_cost_microunits: Some(0),
            realized_latency_ms: Some(1),
            succeeded: None,
        },
    );

    assert_ne!(
        outcome_digest(&absent),
        outcome_digest(&zero),
        "a missing cost must not hash the same as a cost of zero"
    );
}

#[test]
fn a_correction_supersedes_rather_than_overwrites() {
    let decision = policy().prescribe(request());
    let first = Outcome::applied(&decision, 1, measured());

    let mut corrected = first;
    corrected.revision = 1;
    corrected.observation.realized_cost_microunits = Some(9_900_000);

    assert_ne!(
        outcome_digest(&first),
        outcome_digest(&corrected),
        "a revision must be distinguishable from what it replaces"
    );
    assert_eq!(first.decision_digest, corrected.decision_digest);
}

#[test]
fn an_explored_choice_records_the_candidate_that_was_actually_taken() {
    let decision = policy().prescribe(request());
    let runner_up = decision.counterfactual_model_id;

    let outcome = Outcome {
        selection: Selection {
            strategy: SelectionStrategy::Explore,
            acted_model_id: runner_up,
            propensity_bps: 500,
        },
        ..Outcome::applied(&decision, 1, measured())
    };

    outcome.validate().expect("an exploring caller is valid");
    assert_ne!(
        outcome.selection.acted_model_id, decision.selected_model_id,
        "this record exists precisely because the ranking was not followed"
    );
}
