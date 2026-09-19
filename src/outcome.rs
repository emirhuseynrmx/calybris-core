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
//!
//! ## Why the binding is three digests and not one
//!
//! A decision digest identifies a decision but not the world that produced it.
//! The same catalog under a changed policy, or a different request that happens
//! to decide the same way, would both pass a single-digest check. Since these
//! records exist to support causal claims, the claim has to be pinned to the
//! exact policy and the exact request as well; [`DecisionIdentity`] is that pin,
//! and [`Outcome::validate_against`] is where it is enforced.

use crate::digest::{decision_digest, input_digest, policy_digest};
use crate::kernel::{KernelAction, KernelDecision, KernelInput, PolicySnapshot};
use sha2::{Digest, Sha256};

/// Decision identity format version.
pub const IDENTITY_DIGEST_TAG: &[u8] = b"calyidn1\0";
/// Outcome record format version.
pub const OUTCOME_DIGEST_TAG: &[u8] = b"calyout1\0";
/// Selection record format version.
pub const SELECTION_DIGEST_TAG: &[u8] = b"calysel1\0";

/// Basis points, as everywhere else in the kernel: 10,000 = 100%.
pub const FULL_PROBABILITY_BPS: u16 = 10_000;

/// Everything needed to say *which* decision this record is about.
///
/// All four are carried rather than recomputed, because the record outlives the
/// snapshot and the input that produced it. [`Outcome::validate_against`] is how
/// they are checked when those are still on hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DecisionIdentity {
    /// The policy and catalog in force. Without it, an outcome logged before a
    /// price change is indistinguishable from one logged after.
    pub policy_digest: [u8; 32],
    /// The request as it was asked.
    pub input_digest: [u8; 32],
    /// The decision that came back.
    pub decision_digest: [u8; 32],
    /// Carried in the clear so a record can be found in a log without recomputing
    /// every digest in it.
    pub request_sequence: u64,
}

impl DecisionIdentity {
    /// Computes the identity of a decision from the three things that produced it.
    #[must_use]
    pub fn of(snapshot: &PolicySnapshot, input: &KernelInput, decision: &KernelDecision) -> Self {
        Self {
            policy_digest: policy_digest(snapshot),
            input_digest: input_digest(input),
            decision_digest: decision_digest(decision),
            request_sequence: decision.request_sequence,
        }
    }

    /// The first field that disagrees, in the order a reader would want to know:
    /// wrong world, wrong question, wrong answer, wrong request.
    fn disagreement(&self, other: &Self) -> Option<IdentityField> {
        if self.policy_digest != other.policy_digest {
            Some(IdentityField::Policy)
        } else if self.input_digest != other.input_digest {
            Some(IdentityField::Input)
        } else if self.decision_digest != other.decision_digest {
            Some(IdentityField::Decision)
        } else if self.request_sequence != other.request_sequence {
            Some(IdentityField::RequestSequence)
        } else {
            None
        }
    }
}

/// Which part of a [`DecisionIdentity`] failed to match.
///
/// Exhaustive on purpose: an identity has exactly these four parts, and a fifth
/// would be a change to the record format rather than a new error case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityField {
    /// The policy snapshot in force differs.
    Policy,
    /// The request differs.
    Input,
    /// The decision differs.
    Decision,
    /// The sequence number differs.
    RequestSequence,
}

impl std::fmt::Display for IdentityField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy => write!(f, "policy"),
            Self::Input => write!(f, "input"),
            Self::Decision => write!(f, "decision"),
            Self::RequestSequence => write!(f, "request sequence"),
        }
    }
}

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
    /// A person chose, for reasons the system does not hold. The probability is
    /// not merely unrecorded but unknowable, and must be absent rather than
    /// guessed.
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
    /// candidate for this request, or `None` where no such probability exists.
    ///
    /// Absent means *not causally evaluable*, and a record carrying `None` must be
    /// excluded from an off-policy estimate rather than defaulted into one. It is
    /// required for [`SelectionStrategy::MaximiseUtility`] and
    /// [`SelectionStrategy::Explore`], and forbidden for
    /// [`SelectionStrategy::Human`].
    pub propensity_bps: Option<u16>,
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
    /// A strategy that has a probability did not record one. It cannot be
    /// recovered later, so the record is refused now rather than silently
    /// excluded from every estimate built on it.
    #[error("{0:?} must record a propensity, and it cannot be recovered afterwards")]
    MissingPropensity(SelectionStrategy),
    /// A probability attached to a choice that does not have one.
    #[error("Human selection has no propensity to record; leave it absent")]
    UnknowablePropensity,
    /// An observation that says nothing.
    #[error(
        "an outcome must carry at least one observation or a disposition that explains its absence"
    )]
    EmptyObservation,
    /// Something was measured about work that was never carried out.
    #[error("Abandoned means nothing was carried out, so nothing can have been observed")]
    ObservationOnAbandoned,
    /// Work reported as both still running and already finished.
    #[error("InFlight cannot record success or failure; revise the record when it finishes")]
    CompletedInFlight,
    /// A rejection that someone claims to have carried out.
    #[error("the decision was a rejection, so there was nothing to carry out")]
    ActedOnRejection,
    /// The kernel's ranking was claimed, but something else was acted on.
    #[error("MaximiseUtility acted on model {acted}, but the decision selected {selected}")]
    ActedModelNotSelected {
        /// What the record says was acted on.
        acted: u32,
        /// What the decision selected.
        selected: u32,
    },
    /// An outcome for a model the policy does not contain.
    #[error("model {0} is not in this policy's catalog")]
    ActedModelNotInCatalog(u32),
    /// The record describes a different decision than the one it was checked
    /// against.
    #[error("this outcome does not follow that decision: the {0} differs")]
    IdentityMismatch(IdentityField),
}

impl Selection {
    /// The ordinary case: the kernel ranked, the caller followed.
    #[must_use]
    pub fn followed(decision: &KernelDecision) -> Self {
        Self {
            strategy: SelectionStrategy::MaximiseUtility,
            acted_model_id: decision.selected_model_id,
            propensity_bps: Some(FULL_PROBABILITY_BPS),
        }
    }

    /// A caller took something other than the top-ranked candidate, and states
    /// how likely it was to do so.
    #[must_use]
    pub fn explored(acted_model_id: u32, propensity_bps: u16) -> Self {
        Self {
            strategy: SelectionStrategy::Explore,
            acted_model_id,
            propensity_bps: Some(propensity_bps),
        }
    }

    /// A person chose. No probability is recorded, because none exists.
    #[must_use]
    pub fn human(acted_model_id: u32) -> Self {
        Self {
            strategy: SelectionStrategy::Human,
            acted_model_id,
            propensity_bps: None,
        }
    }

    /// Checks the probability against the strategy that claims it.
    ///
    /// | Strategy | Propensity |
    /// |---|---|
    /// | `MaximiseUtility` | exactly 10,000 |
    /// | `Explore` | 1..=10,000 |
    /// | `Human` | absent |
    pub fn validate(&self) -> Result<(), OutcomeError> {
        match (self.strategy, self.propensity_bps) {
            (SelectionStrategy::Human, Some(_)) => Err(OutcomeError::UnknowablePropensity),
            (SelectionStrategy::Human, None) => Ok(()),
            (strategy, None) => Err(OutcomeError::MissingPropensity(strategy)),
            (strategy, Some(bps)) => {
                if bps == 0 || bps > FULL_PROBABILITY_BPS {
                    return Err(OutcomeError::PropensityOutOfRange(bps));
                }
                if strategy == SelectionStrategy::MaximiseUtility && bps != FULL_PROBABILITY_BPS {
                    return Err(OutcomeError::DeterministicPropensity(bps));
                }
                Ok(())
            }
        }
    }
}

/// What became of the recommendation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Disposition {
    /// Carried out and finished. The observation describes it, and must say
    /// something.
    Applied = 0,
    /// Never carried out. Nothing was observed, and nothing should be inferred:
    /// an abandoned recommendation is not a failed one.
    Abandoned = 1,
    /// Carried out, and still running when this record was written. Cost and
    /// latency so far may be recorded; success may not, because it is not yet
    /// known. A later revision replaces it.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Outcome {
    /// Which decision this followed, and under which policy and request.
    pub identity: DecisionIdentity,
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
        snapshot: &PolicySnapshot,
        input: &KernelInput,
        decision: &KernelDecision,
        observed_at_micros: u64,
        observation: Observation,
    ) -> Self {
        Self {
            identity: DecisionIdentity::of(snapshot, input, decision),
            observed_at_micros,
            revision: 0,
            selection: Selection::followed(decision),
            disposition: Disposition::Applied,
            observation,
        }
    }

    /// Builds a record for a decision nobody acted on.
    ///
    /// There is no observation parameter: an abandoned recommendation has nothing
    /// to measure, and [`validate`](Self::validate) refuses one that carries a
    /// measurement anyway.
    #[must_use]
    pub fn abandoned(
        snapshot: &PolicySnapshot,
        input: &KernelInput,
        decision: &KernelDecision,
        observed_at_micros: u64,
    ) -> Self {
        Self {
            identity: DecisionIdentity::of(snapshot, input, decision),
            observed_at_micros,
            revision: 0,
            selection: Selection::followed(decision),
            disposition: Disposition::Abandoned,
            observation: Observation::default(),
        }
    }

    /// Requires a usable selection, and a disposition consistent with what was
    /// measured.
    ///
    /// | Disposition | Observation |
    /// |---|---|
    /// | `Applied` | at least one field |
    /// | `Abandoned` | none at all |
    /// | `InFlight` | cost and latency so far; never `succeeded` |
    ///
    /// `Applied` without a measurement is refused because it asserts that
    /// something happened while recording nothing about it, which is the shape a
    /// learner would later read as a silent success. `Abandoned` with one is
    /// refused for the mirror reason.
    ///
    /// This checks the record against itself.
    /// [`validate_against`](Self::validate_against) checks it against the
    /// decision it claims to follow, and is the stronger of the two wherever the
    /// decision is still on hand.
    pub fn validate(&self) -> Result<(), OutcomeError> {
        self.selection.validate()?;
        match self.disposition {
            Disposition::Applied => {
                if self.observation.is_empty() {
                    return Err(OutcomeError::EmptyObservation);
                }
            }
            Disposition::Abandoned => {
                if !self.observation.is_empty() {
                    return Err(OutcomeError::ObservationOnAbandoned);
                }
            }
            Disposition::InFlight => {
                if self.observation.succeeded.is_some() {
                    return Err(OutcomeError::CompletedInFlight);
                }
            }
        }
        Ok(())
    }

    /// Everything [`validate`](Self::validate) checks, plus everything that can
    /// only be checked with the decision in hand.
    ///
    /// - The identity matches all three digests and the sequence number
    /// - A rejection was not acted on: [`KernelAction::Reject`] admits only
    ///   [`Disposition::Abandoned`], because there was nothing to carry out
    /// - [`SelectionStrategy::MaximiseUtility`] acted on the model the kernel
    ///   actually selected
    /// - The acted-on model exists in this policy's catalog
    pub fn validate_against(
        &self,
        snapshot: &PolicySnapshot,
        input: &KernelInput,
        decision: &KernelDecision,
    ) -> Result<(), OutcomeError> {
        self.validate()?;

        let expected = DecisionIdentity::of(snapshot, input, decision);
        if let Some(field) = self.identity.disagreement(&expected) {
            return Err(OutcomeError::IdentityMismatch(field));
        }

        if decision.action == KernelAction::Reject && self.disposition != Disposition::Abandoned {
            return Err(OutcomeError::ActedOnRejection);
        }

        if self.selection.strategy == SelectionStrategy::MaximiseUtility
            && self.selection.acted_model_id != decision.selected_model_id
        {
            return Err(OutcomeError::ActedModelNotSelected {
                acted: self.selection.acted_model_id,
                selected: decision.selected_model_id,
            });
        }

        // A rejection selects nothing, so there is no acted-on model to find.
        if decision.action != KernelAction::Reject
            && !snapshot
                .models()
                .iter()
                .any(|model| model.model_id == self.selection.acted_model_id)
        {
            return Err(OutcomeError::ActedModelNotInCatalog(
                self.selection.acted_model_id,
            ));
        }

        Ok(())
    }

    /// The cheap check: does this record name the same decision?
    ///
    /// Compares the decision digest and the sequence number only, for scanning a
    /// log where the policy and input are not at hand. It does not establish that
    /// the record is *valid* for that decision — use
    /// [`validate_against`](Self::validate_against) for that.
    #[must_use]
    pub fn follows(&self, decision: &KernelDecision) -> bool {
        self.identity.decision_digest == decision_digest(decision)
            && self.identity.request_sequence == decision.request_sequence
    }
}

/// Canonical digest of a decision identity.
#[must_use]
pub fn identity_digest(identity: &DecisionIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DIGEST_TAG);
    hasher.update(identity.policy_digest);
    hasher.update(identity.input_digest);
    hasher.update(identity.decision_digest);
    hasher.update(identity.request_sequence.to_le_bytes());
    hasher.finalize().into()
}

/// Canonical digest of a selection record.
///
/// The propensity is written as a presence byte followed by the value, so an
/// unknowable probability and a recorded one never collide.
#[must_use]
pub fn selection_digest(selection: &Selection) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SELECTION_DIGEST_TAG);
    hasher.update([selection.strategy as u8]);
    hasher.update(selection.acted_model_id.to_le_bytes());
    match selection.propensity_bps {
        Some(bps) => {
            hasher.update([1_u8]);
            hasher.update(bps.to_le_bytes());
        }
        None => hasher.update([0_u8]),
    }
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
    hasher.update(identity_digest(&outcome.identity));
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
