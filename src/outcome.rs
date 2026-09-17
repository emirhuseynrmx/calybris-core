//! What happened after a decision, and how the decision was reached.
//!
//! The kernel decides and, until now, forgot. Everything downstream of a
//! decision — did anyone act on it, what did it actually cost, was it overridden
//! — lived outside the crate with no agreed shape, which meant no two callers
//! could record it the same way and nothing could later learn from it.
//!
//! This module is that shape and nothing more. **The kernel does not learn from
//! these records.** It stores no history, updates no estimate, and changes no
//! decision because of one. It defines how an outcome is written down and how it
//! binds to the decision it followed; what to do with a pile of them is a
//! question for whatever sits above.
//!
//! ## Why the selection strategy is recorded here
//!
//! A later learner reading these records faces the problem that only the taken
//! action has an observed outcome. Estimating what the other candidates would
//! have done is valid only when the probability of each choice is known — which
//! has to be written at decision time, because it cannot be recovered
//! afterwards. [`Selection`] is that field. A log without it can be read, but
//! nothing causal can honestly be concluded from it.
//!
//! Recording it costs nothing today and is impossible to add retroactively,
//! which is the only reason it is in the core rather than above it.

use crate::digest::decision_digest;
use crate::kernel::KernelDecision;
use sha2::{Digest, Sha256};

/// Outcome record format version.
pub const OUTCOME_DIGEST_TAG: &[u8] = b"calyout1\0";
/// Selection record format version.
pub const SELECTION_DIGEST_TAG: &[u8] = b"calysel1\0";

/// Basis points, as everywhere else in the kernel: 10,000 = 100%.
pub const FULL_PROBABILITY_BPS: u16 = 10_000;

/// How the acted-on candidate came to be chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SelectionStrategy {
    /// The kernel's own ranking: the eligible candidate with the highest utility,
    /// every time. Propensity is always 10,000.
    MaximiseUtility = 0,
    /// A caller deliberately took something other than the top-ranked candidate,
    /// to learn what it would do. The caller states the probability with which it
    /// would have made this choice.
    Explore = 1,
    /// A person chose, for reasons the system does not hold.
    Human = 2,
}

/// How a candidate came to be acted on, and with what probability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Selection {
    /// Which mechanism produced the choice.
    pub strategy: SelectionStrategy,
    /// The candidate that was actually acted on. Equal to the decision's selected
    /// model when the kernel's ranking was followed.
    pub acted_model_id: u32,
    /// The probability, in basis points, that this mechanism would choose this
    /// candidate for this request. [`SelectionStrategy::MaximiseUtility`] is
    /// deterministic and therefore 10,000.
    pub propensity_bps: u16,
}

/// Rejected because a record that cannot be trusted is worse than no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OutcomeError {
    /// A probability outside 1..=10,000. Zero is refused as well: an event that
    /// was observed cannot have had no chance of happening.
    #[error("propensity must be 1..={FULL_PROBABILITY_BPS} basis points, got {0}")]
    PropensityOutOfRange(u16),
    /// A deterministic strategy claiming it might have chosen otherwise.
    #[error("MaximiseUtility is deterministic and must record {FULL_PROBABILITY_BPS}, got {0}")]
    DeterministicPropensity(u16),
    /// An observation that says nothing.
    #[error(
        "an outcome must carry at least one observation or a disposition that explains its absence"
    )]
    EmptyObservation,
}

impl Selection {
    /// The ordinary case: the kernel ranked, the caller followed.
    #[must_use]
    pub fn followed(decision: &KernelDecision) -> Self {
        Self {
            strategy: SelectionStrategy::MaximiseUtility,
            acted_model_id: decision.selected_model_id,
            propensity_bps: FULL_PROBABILITY_BPS,
        }
    }

    /// Requires a usable probability, and refuses a deterministic strategy that
    /// claims otherwise.
    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.propensity_bps == 0 || self.propensity_bps > FULL_PROBABILITY_BPS {
            return Err(OutcomeError::PropensityOutOfRange(self.propensity_bps));
        }
        if self.strategy == SelectionStrategy::MaximiseUtility
            && self.propensity_bps != FULL_PROBABILITY_BPS
        {
            return Err(OutcomeError::DeterministicPropensity(self.propensity_bps));
        }
        Ok(())
    }
}

/// What became of the recommendation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Disposition {
    /// Carried out, and the observation below describes it.
    Applied = 0,
    /// Never carried out. Nothing was observed, and nothing should be inferred:
    /// an abandoned recommendation is not a failed one.
    Abandoned = 1,
    /// Carried out, and still running when this record was written. A later
    /// revision replaces it.
    InFlight = 2,
}

/// The numbers that came back.
///
/// Each is optional because a real pipeline learns them at different times and a
/// missing measurement must not be readable as a zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Observation {
    /// What it actually cost, against the decision's estimate.
    pub realized_cost_microunits: Option<u64>,
    /// What it actually took, against the candidate's p95.
    pub realized_latency_ms: Option<u32>,
    /// Whether the work succeeded. Separate from the numbers: a cheap, fast
    /// failure is still a failure.
    pub succeeded: Option<bool>,
}

impl Observation {
    /// Whether anything at all was measured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.realized_cost_microunits.is_none()
            && self.realized_latency_ms.is_none()
            && self.succeeded.is_none()
    }
}

/// One decision, what was done about it, and what came back.
///
/// Bound to the decision by digest rather than by sequence number: a sequence
/// identifies a request, and the same request re-run under a different policy is
/// a different decision that must not inherit this outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Outcome {
    /// The decision this followed.
    pub decision_digest: [u8; 32],
    /// Carried alongside the digest so a record can be found without recomputing
    /// every digest in a log.
    pub request_sequence: u64,
    /// When the observation was made, in microseconds since the Unix epoch. The
    /// caller supplies it; the kernel reads no clock, because a decision record
    /// that depends on when it is replayed is not replayable.
    pub observed_at_micros: u64,
    /// Starts at zero and increases. A later revision supersedes an earlier one
    /// for the same decision rather than overwriting it, so a correction is
    /// visible as a correction.
    pub revision: u32,
    /// How the acted-on candidate was chosen.
    pub selection: Selection,
    /// What became of the recommendation.
    pub disposition: Disposition,
    /// What was measured.
    pub observation: Observation,
}

impl Outcome {
    /// Builds a record for a decision that was followed and completed.
    #[must_use]
    pub fn applied(
        decision: &KernelDecision,
        observed_at_micros: u64,
        observation: Observation,
    ) -> Self {
        Self {
            decision_digest: decision_digest(decision),
            request_sequence: decision.request_sequence,
            observed_at_micros,
            revision: 0,
            selection: Selection::followed(decision),
            disposition: Disposition::Applied,
            observation,
        }
    }

    /// Requires a usable selection, and an observation where one is claimed.
    ///
    /// `Applied` without a measurement is refused: it asserts that something
    /// happened while recording nothing about it, which is the shape a learner
    /// would later read as a silent success.
    pub fn validate(&self) -> Result<(), OutcomeError> {
        self.selection.validate()?;
        if self.disposition == Disposition::Applied && self.observation.is_empty() {
            return Err(OutcomeError::EmptyObservation);
        }
        Ok(())
    }

    /// Whether this record describes `decision`.
    #[must_use]
    pub fn follows(&self, decision: &KernelDecision) -> bool {
        self.decision_digest == decision_digest(decision)
    }
}

/// Canonical digest of a selection record.
#[must_use]
pub fn selection_digest(selection: &Selection) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SELECTION_DIGEST_TAG);
    hasher.update([selection.strategy as u8]);
    hasher.update(selection.acted_model_id.to_le_bytes());
    hasher.update(selection.propensity_bps.to_le_bytes());
    hasher.finalize().into()
}

/// Canonical digest of an outcome record, over every field.
///
/// Optional measurements are written as a presence byte followed by the value,
/// so an absent measurement and a zero measurement produce different digests.
#[must_use]
pub fn outcome_digest(outcome: &Outcome) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OUTCOME_DIGEST_TAG);
    hasher.update(outcome.decision_digest);
    hasher.update(outcome.request_sequence.to_le_bytes());
    hasher.update(outcome.observed_at_micros.to_le_bytes());
    hasher.update(outcome.revision.to_le_bytes());
    hasher.update(selection_digest(&outcome.selection));
    hasher.update([outcome.disposition as u8]);

    let observation = &outcome.observation;
    match observation.realized_cost_microunits {
        Some(cost) => {
            hasher.update([1_u8]);
            hasher.update(cost.to_le_bytes());
        }
        None => hasher.update([0_u8]),
    }
    match observation.realized_latency_ms {
        Some(latency) => {
            hasher.update([1_u8]);
            hasher.update(latency.to_le_bytes());
        }
        None => hasher.update([0_u8]),
    }
    match observation.succeeded {
        Some(succeeded) => {
            hasher.update([1_u8]);
            hasher.update([u8::from(succeeded)]);
        }
        None => hasher.update([0_u8]),
    }
    hasher.finalize().into()
}
