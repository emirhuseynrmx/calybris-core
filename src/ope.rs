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
//! with an approximate 95% interval for IPS and the effective sample size
//! `(Σw)² / Σw²`.
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
//! # What the interval assumes
//!
//! `ips_ci95` is `ips ± 1.96 · s / √n`, with `s` the sample standard deviation
//! of the per-record terms `w · reward`. It is an approximate 95% interval
//! only when the records are independent draws from one logging policy, the
//! propensities are the true ones, and `n` is large enough for the normal
//! approximation to hold for terms that are heavy-tailed whenever some weight
//! is large. It does not account for clipping, which biases the estimate
//! downward by an unknown amount, and SNIPS has no interval here.
//! [`Estimate::warnings`] names the conditions under which it should not be
//! read as one.
//!
//! # What the estimators trust
//!
//! An outcome is excluded, and counted in [`Estimate::excluded`], when it does
//! not validate ([`Outcome::validate`]), has no propensity (a person chose) or
//! no reward, or names a different request than the one it is paired with.
//! Nothing here checks that the outcome, the request or the exploration record
//! is the one that was logged: verify them first (the WAL, receipts,
//! [`crate::exploration::verify`]). An estimate is as trustworthy as its inputs.
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
#[cfg_attr(
    feature = "serde",
    serde(try_from = "PropensityParts", into = "PropensityParts")
)]
pub struct Propensity {
    numerator: u64,
    denominator: u64,
}

/// The wire form of a [`Propensity`], checked on the way in.
#[cfg(feature = "serde")]
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
struct PropensityParts {
    numerator: u64,
    denominator: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<PropensityParts> for Propensity {
    type Error = &'static str;
    fn try_from(p: PropensityParts) -> Result<Self, Self::Error> {
        Self::new(p.numerator, p.denominator)
            .ok_or("a propensity needs 0 < numerator <= denominator")
    }
}

#[cfg(feature = "serde")]
impl From<Propensity> for PropensityParts {
    fn from(p: Propensity) -> Self {
        Self {
            numerator: p.numerator,
            denominator: p.denominator,
        }
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
    /// for this probability: rounded to the nearest, never below one. The
    /// same rounding as [`crate::exploration::ExplorationRecord::propensity_bps`].
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
    /// A clip must be a positive, finite weight. A negative one would turn
    /// weights negative, and NaN would pass every comparison.
    #[error("clip {0} is not a positive, finite weight")]
    InvalidClip(f64),
    #[error("no record could be used")]
    NoUsableRecords,
}

/// An estimate of the target policy's mean reward per request.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Estimate {
    /// Records the estimate was computed from.
    pub used: u64,
    /// Records set aside: an outcome that does not validate, no propensity
    /// (a person chose), no reward or a non-finite one, an outcome that does
    /// not belong to the request it was paired with, or an exact propensity
    /// that is not the one the outcome recorded.
    pub excluded: u64,
    /// Used records on which the target would have acted on the same candidate.
    pub matched: u64,
    /// Used records on which the target would have chosen differently and the
    /// log could never have chosen that way (propensity one). See the module
    /// documentation: when this is not zero, the estimate is not an estimate of
    /// the target policy's value.
    pub unsupported: u64,
    pub ips: f64,
    /// Approximate 95% interval for `ips`; see the module documentation for
    /// what it assumes.
    pub ips_ci95: (f64, f64),
    /// `None` when no record matched.
    pub snips: Option<f64>,
    pub effective_sample_size: f64,
    /// The largest weight used, after clipping.
    pub max_weight: f64,
    /// The clip that was applied, if any.
    pub clip: Option<f64>,
}

/// Below this many used records the normal approximation behind `ips_ci95`
/// is not to be relied on. A rule of thumb, not a theorem.
pub const MIN_RECORDS: u64 = 30;

/// Below this effective sample size a handful of heavily weighted records
/// decide the estimate. A rule of thumb, as [`MIN_RECORDS`].
pub const MIN_EFFECTIVE_SAMPLE_SIZE: f64 = 30.0;

/// A reason not to take an [`Estimate`] at face value.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum EstimateWarning {
    /// Fewer than [`MIN_RECORDS`] records were used.
    FewRecords { used: u64 },
    /// The effective sample size is below [`MIN_EFFECTIVE_SAMPLE_SIZE`].
    LowEffectiveSampleSize { effective: f64 },
    /// No used record was one the target would have taken: the estimate is
    /// zero for want of evidence, not because the target earns nothing.
    NoMatches,
    /// The target would have chosen something the log could never show;
    /// see [`Estimate::unsupported`].
    Unsupported { records: u64 },
    /// At least one weight reached the clip, so the estimate is biased
    /// downward by an amount the interval does not show.
    Clipped { clip: f64 },
}

impl Estimate {
    /// The conditions under which this estimate, or its interval, should not
    /// be read as what it claims to be. Empty when none holds.
    #[must_use]
    pub fn warnings(&self) -> Vec<EstimateWarning> {
        let mut out = Vec::new();
        if self.used < MIN_RECORDS {
            out.push(EstimateWarning::FewRecords { used: self.used });
        }
        if self.effective_sample_size < MIN_EFFECTIVE_SAMPLE_SIZE {
            out.push(EstimateWarning::LowEffectiveSampleSize {
                effective: self.effective_sample_size,
            });
        }
        if self.matched == 0 {
            out.push(EstimateWarning::NoMatches);
        }
        if self.unsupported > 0 {
            out.push(EstimateWarning::Unsupported {
                records: self.unsupported,
            });
        }
        if let Some(c) = self.clip {
            if self.max_weight >= c {
                out.push(EstimateWarning::Clipped { clip: c });
            }
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
    Ok(Estimate {
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
    })
}

fn target_choice(target: &PolicySnapshot, input: KernelInput) -> u32 {
    let d = target.prescribe(input);
    if d.is_executable() {
        d.selected_model_id
    } else {
        0
    }
}

/// The reward of an outcome that may be used, or `None` when it may not:
/// it does not validate, names another request, or has no reward.
fn usable(
    input: &KernelInput,
    outcome: &Outcome,
    reward: &impl Fn(&Outcome) -> Option<f64>,
) -> Option<f64> {
    if outcome.validate().is_err() || outcome.identity.input_digest != input_digest(input) {
        return None;
    }
    reward(outcome)
}

/// Estimates `target`'s mean reward from logged `(request, outcome)` pairs,
/// using the propensity each outcome recorded in basis points.
///
/// Exact when every recorded propensity is a whole number of basis points,
/// which holds for the kernel's own choices; for exploration logs use
/// [`evaluate_exact`] (see the module documentation). The target's choice is
/// whatever `target.prescribe(request)` selects. See the module documentation
/// for which outcomes are excluded.
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
        let (Some(p), Some(r)) = (propensity, usable(input, outcome, &reward)) else {
            excluded += 1;
            continue;
        };
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
/// recorded is excluded: the two were not written for the same choice.
pub fn evaluate_exact(
    target: &PolicySnapshot,
    logs: &[(KernelInput, Outcome, Propensity)],
    reward: impl Fn(&Outcome) -> Option<f64>,
    clip: Option<f64>,
) -> Result<Estimate, OpeError> {
    let mut records = Vec::with_capacity(logs.len());
    let mut excluded = 0_u64;
    for (input, outcome, propensity) in logs {
        let Some(r) = usable(input, outcome, &reward) else {
            excluded += 1;
            continue;
        };
        if outcome.selection.propensity_bps != Some(propensity.to_bps()) {
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
        assert!(e.warnings().is_empty(), "{:?}", e.warnings());
    }

    #[test]
    fn a_deterministic_log_cannot_speak_for_a_different_choice() {
        let r: Vec<_> = (0..50).map(|_| rec(1, 10_000, 1.0, 2)).collect();
        let e = estimate(&r, None).unwrap();
        assert_eq!(e.unsupported, 50);
        assert_eq!(e.matched, 0);
        assert_eq!(e.snips, None);
        let w = e.warnings();
        assert!(w.contains(&EstimateWarning::NoMatches));
        assert!(w.contains(&EstimateWarning::Unsupported { records: 50 }));
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
    fn clipping_caps_the_weights_and_says_so() {
        let r = vec![rec(1, 1, 1.0, 1), rec(1, 10_000, 1.0, 1)];
        let e = estimate(&r, Some(10.0)).unwrap();
        assert_eq!(e.max_weight, 10.0);
        assert_eq!(e.clip, Some(10.0));
        assert!(e
            .warnings()
            .contains(&EstimateWarning::Clipped { clip: 10.0 }));
        // A clip no weight reaches changes nothing and warns of nothing.
        let e = estimate(&r, Some(1e9)).unwrap();
        assert!(!e
            .warnings()
            .iter()
            .any(|w| matches!(w, EstimateWarning::Clipped { .. })));
    }

    /// A clip that is not a positive, finite weight used to be applied as
    /// given, and a negative one produced negative weights.
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
        let r = vec![
            rec(1, 10_000, f64::NAN, 1),
            rec(1, 10_000, f64::INFINITY, 1),
            rec(1, 10_000, 2.0, 1),
        ];
        let e = estimate(&r, None).unwrap();
        assert_eq!(e.used, 1);
        assert_eq!(e.excluded, 2);
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
    fn few_records_and_a_few_heavy_weights_are_flagged() {
        let e = estimate(&[rec(1, 10_000, 1.0, 1); 5], None).unwrap();
        assert!(e
            .warnings()
            .contains(&EstimateWarning::FewRecords { used: 5 }));
        // 1,000 records, one of them weighted 10,000: the effective sample
        // size is about one.
        let mut r = vec![rec(2, 10_000, 1.0, 1); 999];
        r.push(rec(1, 1, 1.0, 1));
        let e = estimate(&r, None).unwrap();
        assert!(e.effective_sample_size < 2.0);
        assert!(e
            .warnings()
            .iter()
            .any(|w| matches!(w, EstimateWarning::LowEffectiveSampleSize { .. })));
    }

    #[test]
    fn a_propensity_is_a_fraction_in_zero_one() {
        assert!(Propensity::new(0, 5).is_none());
        assert!(Propensity::new(6, 5).is_none());
        assert!(Propensity::new(0, 0).is_none());
        assert!(Propensity::from_bps(0).is_none());
        assert!(Propensity::from_bps(10_001).is_none());
        assert!(Propensity::ONE.is_one());
        assert!(Propensity::new(7, 7).unwrap().is_one());
        assert_eq!(Propensity::new(1, 3).unwrap().to_bps(), 3_333);
        assert_eq!(Propensity::new(3, 20).unwrap().to_bps(), 1_500);
        assert_eq!(Propensity::ONE.to_bps(), 10_000);
        // Far under a basis point, recorded as one.
        let tiny = Propensity::new(1, 220_000).unwrap();
        assert_eq!(tiny.to_bps(), 1);
        assert!((tiny.weight() - 220_000.0).abs() < 1e-6);
        // The extremes of u64 neither overflow nor divide by zero.
        let edge = Propensity::new(1, u64::MAX).unwrap();
        assert_eq!(edge.to_bps(), 1);
        assert!(edge.weight().is_finite());
        assert_eq!(
            Propensity::new(u64::MAX, u64::MAX).unwrap().to_bps(),
            10_000
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_propensity_read_from_json_is_checked() {
        let p = Propensity::new(3, 20).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, r#"{"numerator":3,"denominator":20}"#);
        assert_eq!(serde_json::from_str::<Propensity>(&json).unwrap(), p);
        for bad in [
            r#"{"numerator":0,"denominator":20}"#,
            r#"{"numerator":21,"denominator":20}"#,
            r#"{"numerator":0,"denominator":0}"#,
        ] {
            assert!(serde_json::from_str::<Propensity>(bad).is_err(), "{bad}");
        }
    }
}
