//! `explain` must never disagree with the decision it explains.
//!
//! The two share `first_failed_gate` and `Pricing`, so agreement is structural
//! rather than coincidental. These tests are here because "structural" is a claim
//! about today's code, and the next person to optimise the hot loop needs the
//! claim checked rather than commented.

use calybris_core::kernel::{
    CandidateVerdict, KernelAction, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS,
};
use proptest::prelude::*;

/// A catalog entry with every field set, so no gate is accidentally untested.
fn model(
    model_id: u32,
    provider_id: u16,
    quality_bps: u16,
    p95_latency_ms: u32,
    risk_ceiling_bps: u16,
    enabled: u8,
) -> KernelModel {
    KernelModel {
        model_id,
        provider_id,
        quality_bps,
        risk_ceiling_bps,
        p95_latency_ms,
        enabled,
        capabilities: 0b111,
        region_mask: 0b11,
        input_cost_microunits_per_million_tokens: 3_000_000,
        output_cost_microunits_per_million_tokens: 15_000_000,
    }
}

fn request(
    budget_limit_microunits: u64,
    minimum_quality_bps: u16,
    max_p95_latency_ms: u32,
    risk_bps: u16,
) -> KernelInput {
    KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        budget_limit_microunits,
        business_value_microunits: 5_000_000,
        minimum_quality_bps,
        max_p95_latency_ms,
        risk_bps,
        confidence_bps: 9_000,
        required_capabilities: 0b1,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
        1,
        1,
        9_000,
        1_000,
        2_000,
        5,
        vec![
            model(1, 0, 9_000, 400, 5_000, 1),
            model(2, 1, 7_500, 900, 2_000, 1),
            model(3, 2, 9_900, 120, 9_000, 1),
            model(4, 3, 6_000, 200, 9_000, 0),
            model(5, 7, 9_500, 150, 9_000, 1),
        ],
    )
    .expect("policy")
}

#[test]
fn every_gate_reports_the_numbers_it_compared() {
    let policy = policy();
    // Quality floor above model 2, and provider 7 is outside the allowed mask.
    let mut input = request(50_000_000, 8_000, 300, 1_000);
    input.allowed_provider_mask = 0b1111;
    let explanation = policy.explain(input);

    let verdicts: Vec<_> = explanation
        .candidates
        .iter()
        .map(|candidate| (candidate.model_id, candidate.verdict))
        .collect();

    for (model_id, verdict) in verdicts {
        match (model_id, verdict) {
            (
                2,
                CandidateVerdict::Rejected {
                    measured, limit, ..
                },
            ) => {
                // Reported against the first gate it fails, which is quality.
                assert_eq!((measured, limit), (7_500, 8_000));
            }
            (4, CandidateVerdict::Rejected { gate, .. }) => {
                assert_eq!(format!("{gate:?}"), "Disabled");
            }
            (
                5,
                CandidateVerdict::Rejected {
                    gate,
                    measured,
                    limit,
                },
            ) => {
                assert_eq!(format!("{gate:?}"), "ProviderNotAllowed");
                assert_eq!((measured, limit), (7, 0b1111));
            }
            _ => {}
        }
    }
}

#[test]
fn a_request_refused_at_the_hard_limits_invents_no_candidate_reasons() {
    let policy = policy();
    // risk_bps at the hard limit: the catalog is never walked.
    let explanation = policy.explain(request(50_000_000, 0, 0, 9_000));

    assert_eq!(explanation.decision.action, KernelAction::Reject);
    assert!(
        explanation.candidates.is_empty(),
        "no candidate was examined, so none may carry a verdict"
    );
}

#[test]
fn the_chosen_candidate_is_reported_eligible() {
    let policy = policy();
    let explanation = policy.explain(request(50_000_000, 0, 0, 1_000));
    let chosen = explanation.decision.selected_model_id;

    let verdict = explanation
        .candidates
        .iter()
        .find(|candidate| candidate.model_id == chosen)
        .map(|candidate| candidate.verdict)
        .expect("the chosen candidate must appear in the explanation");

    assert!(matches!(verdict, CandidateVerdict::Eligible(_)));
}

proptest! {
    /// The eligible set and the decision cannot disagree, at any request.
    #[test]
    fn explain_and_prescribe_never_disagree(
        budget in 0_u64..80_000_000,
        min_quality in 0_u16..10_000,
        max_latency in 0_u32..1_500,
        risk in 0_u16..8_999,
    ) {
        let policy = policy();
        let input = request(budget, min_quality, max_latency, risk);

        let decision = policy.prescribe(input);
        let explanation = policy.explain(input);

        prop_assert_eq!(explanation.decision, decision);

        let eligible: Vec<u32> = explanation.eligible().map(|c| c.model_id).collect();
        prop_assert_eq!(
            eligible.len(),
            usize::from(decision.eligible_models),
            "explain counted a different eligible set than prescribe ranked"
        );

        if decision.action == KernelAction::Reject {
            prop_assert!(
                eligible.is_empty(),
                "a rejection cannot coexist with an eligible candidate"
            );
        } else {
            prop_assert!(
                eligible.contains(&decision.selected_model_id),
                "the selected candidate must be one explain calls eligible"
            );
            // The winner must hold the highest utility explain reports.
            let best = explanation
                .eligible()
                .filter_map(|c| match c.verdict {
                    CandidateVerdict::Eligible(terms) => Some(terms.utility),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            let chosen = explanation
                .eligible()
                .find(|c| c.model_id == decision.selected_model_id)
                .and_then(|c| match c.verdict {
                    CandidateVerdict::Eligible(terms) => Some(terms.utility),
                    _ => None,
                })
                .unwrap_or(-1);
            prop_assert_eq!(chosen, best, "the ranked winner is not the highest utility");
        }
    }
}
