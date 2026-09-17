//! An outcome record is written by whatever sits above the kernel.
//!
//! The property: decoding never panics, validation never panics, and a record
//! that validation accepts really does satisfy the rules the format promises.
//! A learner downstream reads these to make causal claims, so an accepted
//! record that breaks the rules is worse than a rejected one.

#![no_main]

use calybris_core::outcome::{
    outcome_digest, Disposition, Outcome, SelectionStrategy, FULL_PROBABILITY_BPS,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(outcome) = serde_json::from_slice::<Outcome>(data) else {
        return;
    };

    // Digesting arbitrary field values must not panic or overflow.
    let _ = outcome_digest(&outcome);

    if outcome.validate().is_err() {
        return;
    }

    // Everything below is what `validate` returning Ok is supposed to mean.
    match outcome.selection.strategy {
        SelectionStrategy::MaximiseUtility => {
            assert_eq!(outcome.selection.propensity_bps, Some(FULL_PROBABILITY_BPS));
        }
        SelectionStrategy::Explore => {
            let bps = outcome.selection.propensity_bps.expect("explore has one");
            assert!(bps >= 1 && bps <= FULL_PROBABILITY_BPS);
        }
        SelectionStrategy::Human => {
            assert_eq!(outcome.selection.propensity_bps, None);
        }
    }

    match outcome.disposition {
        Disposition::Applied => assert!(!outcome.observation.is_empty()),
        Disposition::Abandoned => assert!(outcome.observation.is_empty()),
        Disposition::InFlight => assert!(outcome.observation.succeeded.is_none()),
    }
});
