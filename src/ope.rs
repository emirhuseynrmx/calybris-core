//! Off-policy estimates: what a different policy would have *achieved*.
//!
//! `compare_policies` replays requests under two policies and says which
//! decisions would change. It cannot say whether the changes would have been
//! better, because the outcomes of choices that were never made were never
//! observed. This module estimates that from outcomes that *were* observed,
//! using the probability with which each acted-on candidate was chosen.
//!
//! The estimators are the standard ones:
//!
//! - **IPS** (inverse propensity scoring): the mean of `w · reward`, where `w` is
//!   `1 / propensity` when the target policy would act on the same candidate the
//!   log acted on, and `0` otherwise. Unbiased when every candidate the target
//!   could choose had a non-zero chance of being logged.
//! - **SNIPS** (self-normalised IPS): `Σ w·reward / Σ w`. Slightly biased, much
//!   steadier when weights are large.
//!
//! with an approximate 95% interval for IPS from the normal approximation, and
//! the effective sample size `(Σw)² / Σw²`.
//!
//! **Use the exact propensity.** [`Selection`](crate::outcome::Selection)
//! stores a probability in whole basis points, rounded to the nearest and
//! never below one. That is exact for the kernel's own choices (one) and for
//! probabilities that happen to be whole basis points, and it can be far off
//! otherwise: at an exploration rate of 1 bp over 22 near-best candidates, an
//! alternative's true probability is about 0.045 bp and is recorded as 1 bp,
//! so its IPS weight comes out 22 times too small. [`evaluate`] reads the
//! recorded basis points and inherits that error; [`evaluate_exact`] takes the
//! exact fraction from [`crate::exploration::ExplorationRecord::propensity`]
//! and does not.
//!
//! The honest limit, stated in the result rather than in a footnote: a log
//! written entirely by the kernel's own ranking has propensity one for the
//! winner and zero for everything else. A target policy that would have chosen
//! differently on such a record is choosing something the log could never have
//! shown, and no estimator can say what that would have done. Those records
//! are counted in [`Estimate::unsupported`]. When it is not zero, the estimate
//! describes only the requests on which the two policies agree, and the remedy
//! is exploration ([`crate::exploration`]), not a cleverer formula.
//!
//! The estimators trust their inputs. [`evaluate`] checks that each outcome
//! names the request it is paired with, and nothing more: verify outcomes and
//! the decision log (`verify`, the WAL, receipts) before estimating from them.
//!
//! Estimates are floating point and offline. Nothing here is on the decision
//! path, which stays integer-only.
//!
//! Doubly robust estimation: Dudík, Langford and Li, arXiv:1103.4601. Offline
//! evaluation from logged propensities: Li et al., arXiv:1003.5956. Estimation
//! when the logging policy is deterministic: Narita et al., arXiv:2212.01925.

use crate::digest::input_digest;
use crate::kernel::{KernelInput, PolicySnapshot, BASIS_POINTS};
use crate::outcome::Outcome;

/// A probability as an exact fraction `numerator / denominator`, with
/// `0 < numerator ≤ denominator`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerializedPropensity"))]
pub struct Propensity {
    numerator: u64,
    denominator: u64,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct SerializedPropensity {
    numerator: u64,
    denominator: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<SerializedPropensity> for Propensity {
    type Error = &'static str;

    fn try_from(value: SerializedPropensity) -> Result<Self, Self::Error> {
        Self::new(value.numerator, value.denominator)
            .ok_or("propensity must satisfy 0 < numerator <= denominator")
    }
}

impl Propensity {
    /// Certainty.
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// `None` unless `0 < numerator ≤ denominator`.
    #[must_use]
    pub fn new(numerator: u64, denominator: u64) -> Option<Self> {
        (numerator > 0 && numerator <= denominator).then_some(Self {
            numerator,
            denominator,
        })
    }

    /// A probability recorded in basis points. `None` outside 1..=10,000.
    #[must_use]
    pub fn from_bps(bps: u16) -> Option<Self> {
        Self::new(u64::from(bps), BASIS_POINTS)
    }

    #[must_use]
    pub fn numerator(self) -> u64 {
        self.numerator
    }

    #[must_use]
    pub fn denominator(self) -> u64 {
        self.denominator
    }

    #[must_use]
    pub fn is_one(self) -> bool {
        self.numerator == self.denominator
    }

    /// `1 / p`, the inverse propensity weight.
    #[must_use]
    pub fn weight(self) -> f64 {
        self.denominator as f64 / self.numerator as f64
    }

    /// The basis points a [`Selection`](crate::outcome::Selection) records
    /// for this probability: rounded to the nearest, never below one.
    #[must_use]
    pub fn to_bps(self) -> u16 {
        let bps = (u128::from(self.numerator) * u128::from(BASIS_POINTS)
            + u128::from(self.denominator) / 2)
            / u128::from(self.denominator);
        bps.clamp(1, u128::from(BASIS_POINTS)) as u16
    }
}

/// One logged choice, reduced to what an estimator reads.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoggedChoice {
    /// What the log acted on.
    pub acted_model_id: u32,
    /// How likely the logging mechanism was to act on it.
    pub propensity: Propensity,
    /// What came back, in whatever unit the caller scores outcomes.
    pub reward: f64,
    /// What the target policy would act on for the same request; `0` when it
    /// would select nothing.
    pub target_model_id: u32,
}

/// Why no estimate was produced.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum OpeError {
    /// A clip must be a positive, finite weight.
    #[error("clip {0} is not a positive, finite weight")]
    InvalidClip(f64),
    #[error("no record could be used")]
    NoUsableRecords,
    /// Finite inputs overflowed the estimator's floating-point arithmetic.
    #[error("OPE arithmetic overflow; rescale rewards or choose an explicit weight clip")]
    NumericOverflow,
}

/// An estimate of the target policy's mean reward per request.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Estimate {
    /// Records the estimate was computed from.
    pub used: u64,
    /// Records set aside: no propensity (a person chose), no reward, a
    /// propensity of zero, an outcome that does not belong to the request it
    /// was paired with, or an exact propensity the outcome did not record.
    pub excluded: u64,
    /// Used records on which the target would have acted on the same candidate.
    pub matched: u64,
    /// Used records on which the target would have chosen differently and the
    /// log could never have chosen that way (propensity one). See the module
    /// documentation: when this is not zero, the estimate is not an estimate of
    /// the target policy's value.
    pub unsupported: u64,
    pub ips: f64,
    /// Approximate 95% interval for `ips`, from the normal approximation.
    pub ips_ci95: (f64, f64),
    /// `None` when no record matched.
    pub snips: Option<f64>,
    pub effective_sample_size: f64,
    /// The largest weight used, after clipping.
    pub max_weight: f64,
    /// The clip that was applied, if any.
    pub clip: Option<f64>,
}

/// Diagnostics, not a deployment approval or a confidence guarantee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpeWarning {
    LowSampleSize,
    LowEffectiveSampleSize,
    UnsupportedPolicy,
    ClippedWeights,
}

impl Estimate {
    /// Flags fewer than 30 usable records, ESS below 10, unsupported target
    /// choices, and clipping. These are conservative defaults; callers still
    /// need domain-specific evidence requirements and independent outcomes.
    #[must_use]
    pub fn warnings(&self) -> Vec<OpeWarning> {
        let mut out = Vec::new();
        if self.used < 30 {
            out.push(OpeWarning::LowSampleSize);
        }
        if self.effective_sample_size < 10.0 {
            out.push(OpeWarning::LowEffectiveSampleSize);
        }
        if self.unsupported > 0 {
            out.push(OpeWarning::UnsupportedPolicy);
        }
        if self.clip.is_some() {
            out.push(OpeWarning::ClippedWeights);
        }
        out
    }
}

/// Estimates from reduced records. `clip` caps each weight (biased, steadier)
/// and must be positive and finite; `None` leaves the weights as they are.
pub fn estimate(records: &[LoggedChoice], clip: Option<f64>) -> Result<Estimate, OpeError> {
    if let Some(c) = clip {
        if !(c.is_finite() && c > 0.0) {
            return Err(OpeError::InvalidClip(c));
        }
    }
    let mut used = 0_u64;
    let mut excluded = 0_u64;
    let mut matched = 0_u64;
    let mut unsupported = 0_u64;
    let mut terms = Vec::with_capacity(records.len());
    let (mut sum_w, mut sum_w2, mut sum_wr, mut max_w) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
    for r in records {
        if !r.reward.is_finite() {
            excluded += 1;
            continue;
        }
        used += 1;
        let same = r.target_model_id != 0 && r.target_model_id == r.acted_model_id;
        let mut w = if same {
            matched += 1;
            r.propensity.weight()
        } else {
            if r.propensity.is_one() && r.target_model_id != 0 {
                unsupported += 1;
            }
            0.0
        };
        if let Some(c) = clip {
            w = w.min(c);
        }
        max_w = max_w.max(w);
        sum_w += w;
        sum_w2 += w * w;
        sum_wr += w * r.reward;
        if !sum_w.is_finite() || !sum_w2.is_finite() || !sum_wr.is_finite() {
            return Err(OpeError::NumericOverflow);
        }
        terms.push(w * r.reward);
    }
    if used == 0 {
        return Err(OpeError::NoUsableRecords);
    }
    let n = used as f64;
    let ips = sum_wr / n;
    let var = if used > 1 {
        terms.iter().map(|t| (t - ips) * (t - ips)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let half = 1.96 * (var / n).sqrt();
    let result = Estimate {
        used,
        excluded,
        matched,
        unsupported,
        ips,
        ips_ci95: (ips - half, ips + half),
        snips: (sum_w > 0.0).then(|| sum_wr / sum_w),
        effective_sample_size: if sum_w2 > 0.0 {
            sum_w * sum_w / sum_w2
        } else {
            0.0
        },
        max_weight: max_w,
        clip,
    };
    if !var.is_finite()
        || !result.ips.is_finite()
        || !result.ips_ci95.0.is_finite()
        || !result.ips_ci95.1.is_finite()
        || !result.effective_sample_size.is_finite()
        || result.snips.is_some_and(|value| !value.is_finite())
    {
        return Err(OpeError::NumericOverflow);
    }
    Ok(result)
}

fn target_choice(target: &PolicySnapshot, input: KernelInput) -> u32 {
    let d = target.prescribe(input);
    if d.is_executable() {
        d.selected_model_id
    } else {
        0
    }
}

/// Whether an outcome may be estimated from: it validates, and it names the
/// request it is paired with.
fn usable(input: &KernelInput, outcome: &Outcome) -> bool {
    outcome.validate().is_ok() && outcome.identity.input_digest == input_digest(input)
}

/// Estimates `target`'s mean reward from logged `(request, outcome)` pairs,
/// using the propensity each outcome recorded in basis points.
///
/// Exact when every recorded propensity is a whole number of basis points,
/// which holds for the kernel's own choices; for exploration logs use
/// [`evaluate_exact`] (see the module documentation). The target's choice is
/// whatever `target.prescribe(request)` selects. An outcome is used only if
/// it validates ([`Outcome::validate`]), its recorded input digest matches the
/// request it is paired with, it has a propensity (a person's choice has
/// none), and `reward` returns a value.
pub fn evaluate(
    target: &PolicySnapshot,
    logs: &[(KernelInput, Outcome)],
    reward: impl Fn(&Outcome) -> Option<f64>,
    clip: Option<f64>,
) -> Result<Estimate, OpeError> {
    let mut records = Vec::with_capacity(logs.len());
    let mut excluded = 0_u64;
    for (input, outcome) in logs {
        let propensity = outcome
            .selection
            .propensity_bps
            .and_then(Propensity::from_bps);
        let (Some(p), Some(r)) = (propensity, reward(outcome)) else {
            excluded += 1;
            continue;
        };
        if !usable(input, outcome) {
            excluded += 1;
            continue;
        }
        records.push(LoggedChoice {
            acted_model_id: outcome.selection.acted_model_id,
            propensity: p,
            reward: r,
            target_model_id: target_choice(target, *input),
        });
    }
    let mut e = estimate(&records, clip)?;
    e.excluded += excluded;
    Ok(e)
}

/// [`evaluate`] with the exact propensity of each record, from
/// [`crate::exploration::ExplorationRecord::propensity`], in place of the
/// basis points the outcome rounded it to.
///
/// A record whose exact propensity does not round to what its outcome
/// recorded is excluded. Agreement is only a consistency check: many exact
/// fractions round to the same basis points. Authenticate the exact fraction
/// together with its exploration record before calling this function.
pub fn evaluate_exact(
    target: &PolicySnapshot,
    logs: &[(KernelInput, Outcome, Propensity)],
    reward: impl Fn(&Outcome) -> Option<f64>,
    clip: Option<f64>,
) -> Result<Estimate, OpeError> {
    let mut records = Vec::with_capacity(logs.len());
    let mut excluded = 0_u64;
    for (input, outcome, propensity) in logs {
        let recorded = outcome.selection.propensity_bps;
        let Some(r) = reward(outcome) else {
            excluded += 1;
            continue;
        };
        if recorded != Some(propensity.to_bps()) || !usable(input, outcome) {
            excluded += 1;
            continue;
        }
        records.push(LoggedChoice {
            acted_model_id: outcome.selection.acted_model_id,
            propensity: *propensity,
            reward: r,
            target_model_id: target_choice(target, *input),
        });
    }
    let mut e = estimate(&records, clip)?;
    e.excluded += excluded;
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_inputs_cannot_produce_a_nonfinite_estimate() {
        let extreme = LoggedChoice {
            acted_model_id: 1,
            propensity: Propensity::new(1, u64::MAX).unwrap(),
            reward: f64::MAX,
            target_model_id: 1,
        };
        assert!(estimate(&[extreme; 30], None).is_err());
        assert!(estimate(&[rec(1, 10_000, 1e200, 1), rec(1, 10_000, -1e200, 1)], None).is_err());
        let clipped = estimate(
            &[LoggedChoice {
                reward: 1.0,
                ..extreme
            }; 30],
            Some(100.0),
        )
        .unwrap();
        assert!(clipped.ips.is_finite());
    }

    #[test]
    fn estimates_report_weak_evidence_without_hiding_it() {
        let e = estimate(&[rec(1, 1, 1.0, 1), rec(2, 10_000, 0.0, 1)], Some(10.0)).unwrap();
        let warnings = e.warnings();
        assert!(warnings.contains(&OpeWarning::LowSampleSize));
        assert!(warnings.contains(&OpeWarning::LowEffectiveSampleSize));
        assert!(warnings.contains(&OpeWarning::UnsupportedPolicy));
        assert!(warnings.contains(&OpeWarning::ClippedWeights));
        assert!(estimate(&vec![rec(1, 10_000, 1.0, 1); 100], None)
            .unwrap()
            .warnings()
            .is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialization_cannot_bypass_propensity_invariants() {
        for value in [
            serde_json::json!({"numerator": 0, "denominator": 0}),
            serde_json::json!({"numerator": 1, "denominator": 0}),
            serde_json::json!({"numerator": 0, "denominator": 5}),
            serde_json::json!({"numerator": 6, "denominator": 5}),
        ] {
            assert!(
                serde_json::from_value::<Propensity>(value.clone()).is_err(),
                "{value}"
            );
            let choice = serde_json::json!({
                "acted_model_id": 1, "propensity": value, "reward": 1.0, "target_model_id": 1
            });
            assert!(serde_json::from_value::<LoggedChoice>(choice).is_err());
        }
        for p in [
            Propensity::ONE,
            Propensity::new(1, 220_000).unwrap(),
            Propensity::new(u64::MAX - 1, u64::MAX).unwrap(),
        ] {
            let encoded = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<Propensity>(&encoded).unwrap(), p);
            assert!(p.weight().is_finite());
            assert!(p.to_bps() > 0);
        }
    }

    fn rec(acted: u32, p: u16, reward: f64, target: u32) -> LoggedChoice {
        LoggedChoice {
            acted_model_id: acted,
            propensity: Propensity::from_bps(p).unwrap(),
            reward,
            target_model_id: target,
        }
    }

    #[test]
    fn a_target_identical_to_a_deterministic_logger_recovers_the_mean() {
        let r: Vec<_> = (0..100)
            .map(|i| rec(1, 10_000, f64::from(i % 10), 1))
            .collect();
        let e = estimate(&r, None).unwrap();
        assert!((e.ips - 4.5).abs() < 1e-12);
        assert_eq!(e.snips, Some(4.5));
        assert_eq!(e.unsupported, 0);
        assert_eq!(e.matched, 100);
    }

    #[test]
    fn a_deterministic_log_cannot_speak_for_a_different_choice() {
        let r: Vec<_> = (0..50).map(|_| rec(1, 10_000, 1.0, 2)).collect();
        let e = estimate(&r, None).unwrap();
        assert_eq!(e.unsupported, 50);
        assert_eq!(e.matched, 0);
        assert_eq!(e.snips, None);
    }

    #[test]
    fn ips_is_unbiased_on_a_uniformly_explored_log() {
        // Two arms, logged uniformly at 50%. Arm 1 pays 1.0, arm 2 pays 0.0.
        // A target that always takes arm 1 is worth 1.0 per request.
        let mut r = Vec::new();
        for i in 0..10_000 {
            let acted = if i % 2 == 0 { 1 } else { 2 };
            let reward = if acted == 1 { 1.0 } else { 0.0 };
            r.push(rec(acted, 5_000, reward, 1));
        }
        let e = estimate(&r, None).unwrap();
        assert!((e.ips - 1.0).abs() < 1e-9, "{}", e.ips);
        assert!(e.ips_ci95.0 <= 1.0 && 1.0 <= e.ips_ci95.1);
        assert_eq!(e.unsupported, 0);
    }

    #[test]
    fn clipping_caps_the_weights() {
        let r = vec![rec(1, 1, 1.0, 1), rec(1, 10_000, 1.0, 1)];
        let e = estimate(&r, Some(10.0)).unwrap();
        assert_eq!(e.max_weight, 10.0);
        assert_eq!(e.clip, Some(10.0));
    }

    /// The review finding: a clip that is not a positive, finite weight used
    /// to be applied as given, and a negative one produced negative weights.
    #[test]
    fn a_clip_that_is_not_a_positive_finite_weight_is_refused() {
        let r = vec![rec(1, 5_000, 1.0, 1)];
        for bad in [-1.0, 0.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                matches!(estimate(&r, Some(bad)), Err(OpeError::InvalidClip(_))),
                "clip {bad}"
            );
        }
        assert!(estimate(&r, Some(0.5)).is_ok());
    }

    #[test]
    fn unusable_records_are_counted_not_defaulted() {
        let r = vec![rec(1, 10_000, f64::NAN, 1), rec(1, 10_000, 2.0, 1)];
        let e = estimate(&r, None).unwrap();
        assert_eq!(e.used, 1);
        assert_eq!(e.excluded, 1);
        assert_eq!(
            estimate(&[rec(1, 10_000, f64::NAN, 1)], None),
            Err(OpeError::NoUsableRecords)
        );
        assert_eq!(estimate(&[], None), Err(OpeError::NoUsableRecords));
    }

    #[test]
    fn a_target_that_selects_nothing_earns_nothing_and_is_not_unsupported() {
        let e = estimate(&[rec(1, 10_000, 5.0, 0)], None).unwrap();
        assert_eq!(e.ips, 0.0);
        assert_eq!(e.unsupported, 0);
    }

    #[test]
    fn a_propensity_is_a_fraction_in_zero_one() {
        assert!(Propensity::new(0, 5).is_none());
        assert!(Propensity::new(6, 5).is_none());
        assert!(Propensity::from_bps(0).is_none());
        assert!(Propensity::from_bps(10_001).is_none());
        assert!(Propensity::ONE.is_one());
        assert_eq!(Propensity::new(1, 3).unwrap().to_bps(), 3_333);
        assert_eq!(Propensity::new(3, 20).unwrap().to_bps(), 1_500);
        // Far under a basis point, recorded as one.
        let tiny = Propensity::new(1, 220_000).unwrap();
        assert_eq!(tiny.to_bps(), 1);
        assert!((tiny.weight() - 220_000.0).abs() < 1e-6);
    }
}
