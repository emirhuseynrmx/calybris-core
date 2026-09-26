//! Keyed, replayable exploration among near-best candidates.
//!
//! The kernel is deterministic: for the same policy and request it selects the
//! same candidate every time. That is what makes a decision replayable, and it
//! is also why a system that only ever follows the kernel can never learn what
//! the second-best candidate would have done. Credit scoring has a name for the
//! damage — a model retrained only on the applicants it approved grows more
//! confident while it grows worse at refusing — and the remedy that works is to
//! take a small, deliberate share of other choices and record the probability of
//! each one.
//!
//! This module does that without touching the kernel. The kernel decides as it
//! always does; then, among the eligible candidates whose utility is within a
//! stated window of the winner, a keyed draw either keeps the winner or picks
//! one of the others uniformly. The draw is `HMAC-SHA256(key, "calyexp1" ‖
//! policy digest ‖ input digest)`, so:
//!
//! - it is fixed by the policy, the request and the key — anyone holding the key
//!   can replay it and get the same choice, which [`verify`] does;
//! - a requester without the key cannot predict or steer it;
//! - the probability of the candidate that was acted on is exact and recorded,
//!   which is what an off-policy estimate needs and cannot recover afterwards.
//!
//! What it does not do: an HMAC is checkable only by someone who holds the key.
//! A draw that anyone can check without a secret needs a verifiable random
//! function (RFC 9381); that is not here.
//!
//! The record binds under the digest tag `calyexp1`, which no earlier artifact
//! uses, and [`ExplorationRecord::selection`] converts it into the
//! [`Selection`] an [`Outcome`](crate::outcome::Outcome)
//! already carries.
//!
//! Why exploration is needed at all: Scarone et al., "The Illusion of
//! Improvement: Reject Inference Strategies in Credit Scoring", arXiv:2606.18479.
//! The logged-propensity design: Li et al., arXiv:1003.0146.

use crate::digest::{input_digest, policy_digest};
use crate::kernel::{CandidateVerdict, KernelDecision, KernelInput, PolicySnapshot, BASIS_POINTS};
use crate::outcome::Selection;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Domain tag for the draw and for [`ExplorationRecord::digest`].
pub const EXPLORATION_TAG: &[u8; 8] = b"calyexp1";

/// The shortest key accepted, the same floor as a keyed WAL.
pub const MIN_EXPLORATION_KEY_BYTES: usize = 32;

/// How much to explore, and among which candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExplorationConfig {
    /// The share of requests, in basis points, on which a candidate other than
    /// the winner may be taken. `200` is two percent.
    pub rate_bps: u16,
    /// Only candidates whose utility is at least `winner − window` are eligible
    /// to be explored, in the kernel's utility unit (microunits). A window of
    /// zero explores only exact ties.
    pub window_microunits: u64,
}

/// Why exploration refused to run or a record did not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExplorationError {
    #[error("exploration key must be at least {MIN_EXPLORATION_KEY_BYTES} bytes, found {0}")]
    ShortKey(usize),
    #[error("rate_bps must be <= 10000, got {0}")]
    RateOutOfRange(u16),
    #[error("the record does not match a replay under this policy, request and key")]
    Mismatch,
}

/// What was acted on, and exactly how likely that was.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExplorationRecord {
    /// The kernel's decision, unchanged.
    pub decision: KernelDecision,
    pub config: ExplorationConfig,
    /// The candidate to act on. Equal to the decision's selected model unless
    /// `explored` is true; `0` when the kernel selected nothing.
    pub acted_model_id: u32,
    /// Whether the draw took a candidate other than the winner.
    pub explored: bool,
    /// How many candidates were within the window, the winner included.
    pub window_size: u32,
    /// The exact probability that this mechanism acts on `acted_model_id` for
    /// this request: `propensity_numerator / propensity_denominator`.
    pub propensity_numerator: u64,
    pub propensity_denominator: u64,
}

impl ExplorationRecord {
    /// The exact probability of this choice, for off-policy estimates
    /// ([`crate::ope::evaluate_exact`]). `None` only for a record whose
    /// fraction is not a probability, which [`explore`] never writes.
    #[must_use]
    pub fn propensity(&self) -> Option<crate::ope::Propensity> {
        crate::ope::Propensity::new(self.propensity_numerator, self.propensity_denominator)
    }

    /// The probability in basis points, rounded to the nearest and never below
    /// one, as [`Selection`] holds it. Lossy below a basis point and between
    /// whole ones: estimate from [`ExplorationRecord::propensity`] instead.
    #[must_use]
    pub fn propensity_bps(&self) -> u16 {
        let bps = (u128::from(self.propensity_numerator) * u128::from(BASIS_POINTS)
            + u128::from(self.propensity_denominator) / 2)
            / u128::from(self.propensity_denominator.max(1));
        bps.clamp(1, u128::from(BASIS_POINTS)) as u16
    }

    /// The [`Selection`] to record in an [`Outcome`](crate::outcome::Outcome):
    /// the kernel's ranking when the winner was kept, exploration otherwise.
    /// `None` when the kernel selected nothing, so nothing was acted on.
    #[must_use]
    pub fn selection(&self) -> Option<Selection> {
        if !self.decision.is_executable() {
            return None;
        }
        Some(if self.explored {
            Selection::explored(self.acted_model_id, self.propensity_bps())
        } else if self.propensity_numerator == self.propensity_denominator {
            // Nothing else could have been taken: a lone winner, or a zero rate.
            Selection::followed(&self.decision)
        } else {
            // The winner was kept, but it could have been otherwise: the
            // probability is below one and has to be recorded as such.
            Selection::explored(self.acted_model_id, self.propensity_bps())
        })
    }

    /// `SHA-256("calyexp1" ‖ decision fields ‖ config ‖ choice ‖ propensity)`,
    /// every integer big-endian.
    #[must_use]
    pub fn digest(&self, policy: &PolicySnapshot, input: &KernelInput) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(EXPLORATION_TAG);
        h.update(policy_digest(policy));
        h.update(input_digest(input));
        h.update(crate::digest::decision_digest(&self.decision));
        h.update(self.config.rate_bps.to_be_bytes());
        h.update(self.config.window_microunits.to_be_bytes());
        h.update(self.acted_model_id.to_be_bytes());
        h.update([u8::from(self.explored)]);
        h.update(self.window_size.to_be_bytes());
        h.update(self.propensity_numerator.to_be_bytes());
        h.update(self.propensity_denominator.to_be_bytes());
        h.finalize().into()
    }
}

/// Decides, then draws.
pub fn explore(
    policy: &PolicySnapshot,
    input: KernelInput,
    config: ExplorationConfig,
    key: &[u8],
) -> Result<ExplorationRecord, ExplorationError> {
    if key.len() < MIN_EXPLORATION_KEY_BYTES {
        return Err(ExplorationError::ShortKey(key.len()));
    }
    if u64::from(config.rate_bps) > BASIS_POINTS {
        return Err(ExplorationError::RateOutOfRange(config.rate_bps));
    }
    let explanation = policy.explain(input);
    let decision = explanation.decision;
    if !decision.is_executable() {
        return Ok(ExplorationRecord {
            decision,
            config,
            acted_model_id: 0,
            explored: false,
            window_size: 0,
            propensity_numerator: 1,
            propensity_denominator: 1,
        });
    }
    let best = decision.expected_utility_microunits;
    let floor = i128::from(best) - i128::from(config.window_microunits);
    // The others in the window, in catalog order, which the policy digest fixes.
    let others: Vec<u32> = explanation
        .candidates
        .iter()
        .filter(|c| c.model_id != decision.selected_model_id)
        .filter_map(|c| match c.verdict {
            CandidateVerdict::Eligible(t) if i128::from(t.utility) >= floor => Some(c.model_id),
            _ => None,
        })
        .collect();
    let k = others.len() as u64 + 1;
    let rate = u64::from(config.rate_bps);
    let den = BASIS_POINTS * k;

    let draw = draw(policy, &input, key);
    let roll = u64::from_be_bytes(draw[0..8].try_into().expect("8 bytes")) % BASIS_POINTS;
    let pick = u64::from_be_bytes(draw[8..16].try_into().expect("8 bytes")) % k;

    // With probability `rate`, choose uniformly among all k (the winner
    // included); otherwise keep the winner. So the winner has probability
    // (1 − rate) + rate/k and each other candidate rate/k.
    let explore_now = k > 1 && roll < rate;
    let (acted, explored) = if explore_now && pick > 0 {
        (others[(pick - 1) as usize], true)
    } else {
        (decision.selected_model_id, false)
    };
    let num = if k == 1 {
        den
    } else if explored {
        rate
    } else {
        (BASIS_POINTS - rate) * k + rate
    };
    Ok(ExplorationRecord {
        decision,
        config,
        acted_model_id: acted,
        explored,
        window_size: k as u32,
        propensity_numerator: num,
        propensity_denominator: den,
    })
}

/// Replays [`explore`] and checks that it produces exactly `record`.
pub fn verify(
    policy: &PolicySnapshot,
    input: KernelInput,
    key: &[u8],
    record: &ExplorationRecord,
) -> Result<(), ExplorationError> {
    let replay = explore(policy, input, record.config, key)?;
    if &replay == record {
        Ok(())
    } else {
        Err(ExplorationError::Mismatch)
    }
}

fn draw(policy: &PolicySnapshot, input: &KernelInput, key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(EXPLORATION_TAG);
    mac.update(&policy_digest(policy));
    mac.update(&input_digest(input));
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelModel, ALL_PROVIDERS, ALL_REGIONS};
    use crate::outcome::SelectionStrategy;

    const KEY: [u8; 32] = [7; 32];

    fn model(id: u32, quality: u16) -> KernelModel {
        KernelModel {
            model_id: id,
            provider_id: 0,
            quality_bps: quality,
            risk_ceiling_bps: 10_000,
            enabled: 1,
            p95_latency_ms: 10,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 1_000,
            output_cost_microunits_per_million_tokens: 1_000,
        }
    }

    fn policy() -> PolicySnapshot {
        PolicySnapshot::try_new(
            1,
            1,
            9_000,
            0,
            0,
            0,
            vec![
                model(1, 9_000),
                model(2, 8_990),
                model(3, 8_980),
                model(4, 1_000),
            ],
        )
        .unwrap()
    }

    fn input(seq: u64) -> KernelInput {
        KernelInput {
            request_sequence: seq,
            requested_model_id: 1,
            input_tokens: 100,
            output_tokens: 100,
            business_value_microunits: 10_000_000,
            budget_limit_microunits: 1_000_000_000,
            risk_bps: 0,
            confidence_bps: 10_000,
            minimum_quality_bps: 0,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        }
    }

    fn cfg(rate: u16, window: u64) -> ExplorationConfig {
        ExplorationConfig {
            rate_bps: rate,
            window_microunits: window,
        }
    }

    #[test]
    fn replays_exactly_and_a_changed_record_fails() {
        let p = policy();
        for seq in 0..200 {
            let r = explore(&p, input(seq), cfg(5_000, 50_000), &KEY).unwrap();
            verify(&p, input(seq), &KEY, &r).unwrap();
            let mut forged = r.clone();
            forged.explored = !forged.explored;
            assert_eq!(
                verify(&p, input(seq), &KEY, &forged),
                Err(ExplorationError::Mismatch)
            );
            let mut forged = r.clone();
            forged.propensity_numerator += 1;
            assert!(verify(&p, input(seq), &KEY, &forged).is_err());
        }
    }

    #[test]
    fn another_key_draws_differently_somewhere() {
        let p = policy();
        let other = [9_u8; 32];
        let differs = (0..200).any(|s| {
            explore(&p, input(s), cfg(5_000, 50_000), &KEY)
                .unwrap()
                .acted_model_id
                != explore(&p, input(s), cfg(5_000, 50_000), &other)
                    .unwrap()
                    .acted_model_id
        });
        assert!(differs);
    }

    #[test]
    fn only_candidates_inside_the_window_are_ever_taken() {
        let p = policy();
        let window = explain_gap(&p, 2) + 1; // admits model 2, not 3
        for seq in 0..500 {
            let r = explore(&p, input(seq), cfg(10_000, window), &KEY).unwrap();
            assert!(r.acted_model_id == 1 || r.acted_model_id == 2, "{r:?}");
            assert_eq!(r.window_size, 2);
        }
    }

    fn explain_gap(p: &PolicySnapshot, id: u32) -> u64 {
        let e = p.explain(input(0));
        let best = e.decision.expected_utility_microunits;
        let u = e
            .candidates
            .iter()
            .find(|c| c.model_id == id)
            .and_then(|c| match c.verdict {
                CandidateVerdict::Eligible(t) => Some(t.utility),
                _ => None,
            })
            .unwrap();
        (best - u) as u64
    }

    #[test]
    fn propensities_sum_to_one_over_the_window() {
        let p = policy();
        let r = explore(&p, input(1), cfg(300, 1_000_000), &KEY).unwrap();
        let k = u64::from(r.window_size);
        let winner = (BASIS_POINTS - 300) * k + 300;
        let each_other = 300;
        assert_eq!(winner + each_other * (k - 1), r.propensity_denominator);
    }

    #[test]
    fn the_observed_exploration_rate_is_close_to_the_stated_one() {
        let p = policy();
        let n = 20_000;
        let explored = (0..n)
            .filter(|&s| {
                explore(&p, input(s), cfg(2_000, 1_000_000), &KEY)
                    .unwrap()
                    .explored
            })
            .count() as f64;
        // rate 20% over k=3 candidates: an other is taken with probability 0.2 * 2/3.
        let expected = n as f64 * 0.2 * 2.0 / 3.0;
        assert!(
            (explored - expected).abs() < 4.0 * expected.sqrt(),
            "{explored} vs {expected}"
        );
    }

    #[test]
    fn zero_rate_or_a_lone_winner_never_explores_and_records_certainty() {
        let p = policy();
        for seq in 0..100 {
            let r = explore(&p, input(seq), cfg(0, 1_000_000), &KEY).unwrap();
            assert!(!r.explored);
            let r = explore(&p, input(seq), cfg(10_000, 0), &KEY).unwrap();
            assert!(!r.explored);
            assert_eq!(r.window_size, 1);
            assert_eq!(r.propensity_numerator, r.propensity_denominator);
            assert_eq!(
                r.selection().unwrap().strategy,
                SelectionStrategy::MaximiseUtility
            );
        }
    }

    #[test]
    fn the_selection_it_produces_is_one_an_outcome_accepts() {
        let p = policy();
        for seq in 0..200 {
            let r = explore(&p, input(seq), cfg(5_000, 1_000_000), &KEY).unwrap();
            let s = r.selection().unwrap();
            s.validate().unwrap();
            assert_eq!(s.acted_model_id, r.acted_model_id);
        }
    }

    #[test]
    fn short_keys_and_bad_rates_are_refused() {
        let p = policy();
        assert_eq!(
            explore(&p, input(0), cfg(1, 0), &[0; 31]),
            Err(ExplorationError::ShortKey(31))
        );
        assert_eq!(
            explore(&p, input(0), cfg(10_001, 0), &KEY),
            Err(ExplorationError::RateOutOfRange(10_001))
        );
    }

    #[test]
    fn the_kernel_decision_is_never_changed() {
        let p = policy();
        for seq in 0..100 {
            let r = explore(&p, input(seq), cfg(10_000, 1_000_000), &KEY).unwrap();
            assert_eq!(r.decision, p.prescribe(input(seq)));
        }
    }

    #[test]
    fn the_digest_is_tagged_and_changes_with_the_choice() {
        let p = policy();
        let r = explore(&p, input(3), cfg(5_000, 1_000_000), &KEY).unwrap();
        let mut other = r.clone();
        other.acted_model_id ^= 1;
        assert_ne!(r.digest(&p, &input(3)), other.digest(&p, &input(3)));
    }

    #[test]
    fn a_refused_request_acts_on_nothing_and_records_no_selection() {
        let p = policy();
        let x = KernelInput {
            risk_bps: 9_000,
            ..input(1)
        };
        let r = explore(&p, x, cfg(5_000, 1_000_000), &KEY).unwrap();
        assert_eq!((r.acted_model_id, r.window_size, r.explored), (0, 0, false));
        assert!(r.selection().is_none());
        verify(&p, x, &KEY, &r).unwrap();
    }
}
