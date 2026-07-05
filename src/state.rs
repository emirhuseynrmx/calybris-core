//! Stateful decision proofs: bind decisions to a state trajectory.
//!
//! [`crate::kernel::PolicySnapshot::prescribe`] is memoryless — each decision
//! is independently replayable. Real deployments carry state between
//! decisions: accumulated exposure, budget, open positions. This module makes
//! the *trajectory* provable: every decision records a digest of the domain
//! state before and after it, chained so that a verifier can confirm not just
//! each decision but the whole sequence — no state transition can be
//! inserted, dropped, or reordered without breaking the chain.
//!
//! The caller supplies the canonical byte encoding of its state (integer
//! fields in a fixed order; see the float rule in `docs/CALY_PROOF.md` §5.1).
//! The digest layout is specified in `docs/CALY_PROOF.md` §6.
//!
//! ```
//! use calybris_core::state::{StateChain, verify_trajectory};
//! # use calybris_core::kernel::*;
//! # use calybris_core::state::stateful_audit_bundle;
//! # let policy = PolicySnapshot::try_new(1, 1, 9_600, 5_500, 3_500, 2, vec![KernelModel {
//! #     model_id: 1, provider_id: 0, quality_bps: 9_000, risk_ceiling_bps: 9_500, enabled: 1,
//! #     p95_latency_ms: 200, capabilities: 0, region_mask: ALL_REGIONS,
//! #     input_cost_microunits_per_million_tokens: 250,
//! #     output_cost_microunits_per_million_tokens: 1_000 }]).unwrap();
//! # let input = KernelInput { request_sequence: 1, requested_model_id: 1, input_tokens: 100,
//! #     output_tokens: 50, business_value_microunits: 10_000, budget_limit_microunits: 1_000_000,
//! #     risk_bps: 100, confidence_bps: 9_000, minimum_quality_bps: 0, max_p95_latency_ms: 0,
//! #     required_capabilities: 0, allowed_provider_mask: ALL_PROVIDERS, required_region_mask: 0 };
//!
//! // Domain state: e.g. remaining budget as canonical little-endian bytes.
//! let mut chain = StateChain::genesis(&1_000_000_u64.to_le_bytes());
//!
//! let decision = policy.prescribe(input);
//! let transition = chain.advance(&999_000_u64.to_le_bytes());
//! let proof = stateful_audit_bundle(&policy, input, &decision, &transition).unwrap();
//!
//! verify_trajectory(std::slice::from_ref(&proof)).unwrap();
//! ```

use sha2::{Digest, Sha256};

use crate::digest::digest_to_hex;
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{verified_audit_bundle, AuditBundle, VerifyError};

/// State transition digest format version (see `docs/CALY_PROOF.md` §6).
pub const STATE_DIGEST_TAG: &[u8] = b"calystt1\0";

/// Canonical digest of a domain state at a given trajectory step.
pub fn state_digest(step: u64, state_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_TAG);
    hasher.update(step.to_le_bytes());
    hasher.update(state_bytes);
    hasher.finalize().into()
}

/// One step of the state trajectory: digests before and after a decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateTransition {
    /// 1-based step index of the transition.
    pub step: u64,
    pub digest_before: [u8; 32],
    pub digest_after: [u8; 32],
}

/// Tracks the digest trajectory of a caller-owned state machine.
///
/// The chain owns no domain state — only step counter and last digest — so
/// it can be rebuilt deterministically during replay from the same state
/// byte sequence.
#[derive(Clone, Debug)]
pub struct StateChain {
    step: u64,
    last_digest: [u8; 32],
}

impl StateChain {
    /// Anchor the chain at step 0 with the initial state.
    pub fn genesis(initial_state_bytes: &[u8]) -> Self {
        Self {
            step: 0,
            last_digest: state_digest(0, initial_state_bytes),
        }
    }

    /// Record a transition to the next state. Returns the proof material to
    /// embed in the decision's audit bundle.
    pub fn advance(&mut self, next_state_bytes: &[u8]) -> StateTransition {
        let step = self.step.saturating_add(1);
        let digest_before = self.last_digest;
        let digest_after = state_digest(step, next_state_bytes);
        self.step = step;
        self.last_digest = digest_after;
        StateTransition {
            step,
            digest_before,
            digest_after,
        }
    }

    pub fn step(&self) -> u64 {
        self.step
    }

    pub fn last_digest(&self) -> [u8; 32] {
        self.last_digest
    }
}

/// An [`AuditBundle`] extended with the state trajectory of the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StatefulAuditBundle {
    /// The stateless decision proof (policy/input/decision digests + replay).
    pub audit: AuditBundle,
    /// 1-based trajectory step.
    pub step: u64,
    /// Hex digest of the domain state before this decision.
    pub state_digest_before_hex: String,
    /// Hex digest of the domain state after this decision.
    pub state_digest_after_hex: String,
}

/// Fail-closed constructor: returns a stateful proof only when the decision
/// replays exactly (same contract as [`verified_audit_bundle`]).
pub fn stateful_audit_bundle(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
    transition: &StateTransition,
) -> Result<StatefulAuditBundle, VerifyError> {
    let audit = verified_audit_bundle(snapshot, input, decision)?;
    Ok(StatefulAuditBundle {
        audit,
        step: transition.step,
        state_digest_before_hex: digest_to_hex(&transition.digest_before),
        state_digest_after_hex: digest_to_hex(&transition.digest_after),
    })
}

/// Why a trajectory failed verification.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TrajectoryError {
    #[error("step {found} does not continue from step {expected}")]
    NonMonotonicStep { expected: u64, found: u64 },
    #[error(
        "state chain broken at step {step}: before-digest does not match previous after-digest"
    )]
    BrokenChain { step: u64 },
    #[error("bundle at step {step} carries replay_valid=false")]
    ReplayInvalid { step: u64 },
}

/// Verify the linkage of a sequence of stateful proofs: steps increase by
/// one, every `before` digest equals the previous `after` digest, and no
/// bundle carries a failed replay flag.
///
/// This checks trajectory *linkage*. Recomputing the underlying decision and
/// state digests additionally requires the policy artifact and the state
/// byte encodings, exactly as in stateless verification.
pub fn verify_trajectory(bundles: &[StatefulAuditBundle]) -> Result<(), TrajectoryError> {
    let mut previous: Option<&StatefulAuditBundle> = None;
    for bundle in bundles {
        if !bundle.audit.replay_valid {
            return Err(TrajectoryError::ReplayInvalid { step: bundle.step });
        }
        if let Some(previous) = previous {
            let expected = previous.step.saturating_add(1);
            if bundle.step != expected {
                return Err(TrajectoryError::NonMonotonicStep {
                    expected,
                    found: bundle.step,
                });
            }
            if bundle.state_digest_before_hex != previous.state_digest_after_hex {
                return Err(TrajectoryError::BrokenChain { step: bundle.step });
            }
        }
        previous = Some(bundle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelModel, ALL_PROVIDERS, ALL_REGIONS};

    fn policy() -> PolicySnapshot {
        PolicySnapshot::try_new(
            1,
            1,
            9_600,
            5_500,
            3_500,
            2,
            vec![KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1_000,
            }],
        )
        .unwrap()
    }

    fn input(sequence: u64) -> KernelInput {
        KernelInput {
            request_sequence: sequence,
            requested_model_id: 1,
            input_tokens: 1_000,
            output_tokens: 500,
            business_value_microunits: 100_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 1_000,
            confidence_bps: 9_000,
            minimum_quality_bps: 5_000,
            max_p95_latency_ms: 1_000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        }
    }

    fn trajectory(states: &[u64]) -> Vec<StatefulAuditBundle> {
        let snapshot = policy();
        let mut chain = StateChain::genesis(&states[0].to_le_bytes());
        states[1..]
            .iter()
            .enumerate()
            .map(|(i, state)| {
                let request = input(i as u64 + 1);
                let decision = snapshot.prescribe(request);
                let transition = chain.advance(&state.to_le_bytes());
                stateful_audit_bundle(&snapshot, request, &decision, &transition).unwrap()
            })
            .collect()
    }

    #[test]
    fn valid_trajectory_verifies() {
        let bundles = trajectory(&[1_000_000, 999_000, 998_000, 990_000]);
        assert_eq!(bundles.len(), 3);
        verify_trajectory(&bundles).unwrap();
    }

    #[test]
    fn dropped_step_breaks_the_chain() {
        let bundles = trajectory(&[1_000_000, 999_000, 998_000, 990_000]);
        let gappy = vec![bundles[0].clone(), bundles[2].clone()];
        assert_eq!(
            verify_trajectory(&gappy),
            Err(TrajectoryError::NonMonotonicStep {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn reordered_steps_break_the_chain() {
        let bundles = trajectory(&[1_000_000, 999_000, 998_000, 990_000]);
        let reordered = vec![bundles[1].clone(), bundles[2].clone(), bundles[0].clone()];
        assert!(verify_trajectory(&reordered).is_err());
    }

    #[test]
    fn tampered_state_digest_breaks_the_chain() {
        let mut bundles = trajectory(&[1_000_000, 999_000, 998_000]);
        bundles[1].state_digest_before_hex = digest_to_hex(&state_digest(1, b"forged"));
        assert_eq!(
            verify_trajectory(&bundles),
            Err(TrajectoryError::BrokenChain { step: 2 })
        );
    }

    #[test]
    fn same_state_bytes_at_different_steps_have_different_digests() {
        let bytes = 42_u64.to_le_bytes();
        assert_ne!(state_digest(1, &bytes), state_digest(2, &bytes));
    }

    #[test]
    fn state_chain_is_deterministic_for_replay() {
        let states = [7_u64, 8, 9];
        let run = |states: &[u64]| {
            let mut chain = StateChain::genesis(&states[0].to_le_bytes());
            states[1..]
                .iter()
                .map(|s| chain.advance(&s.to_le_bytes()))
                .collect::<Vec<_>>()
        };
        assert_eq!(run(&states), run(&states));
    }
}
