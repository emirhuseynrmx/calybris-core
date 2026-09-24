//! Off-policy estimates: what a different policy would have *achieved*.
//!
//! `compare_policies` replays requests under two policies and says which
//! decisions would change. It cannot say whether the changes would have been
//! better, because the outcomes of choices that were never made were never
//! observed. This module estimates that from outcomes that *were* observed,
//! using the probability with which each acted-on candidate was chosen — the
//! number [`Selection`](crate::outcome::Selection) records and that cannot be
//! recovered afterwards.
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
//! The honest limit, stated in the result rather than in a footnote: a log
//! written entirely by the kernel's own ranking has propensity one for the
//! winner and zero for everything else. A target policy that would have chosen
//! differently on such a record is choosing something the log could never have
//! shown, and no estimator can say what that would have done. Those records
//! are counted in [`Estimate::unsupported`]. When it is not zero, the estimate
//! describes only the requests on which the two policies agree, and the remedy
//! is exploration ([`crate::exploration`]), not a cleverer formula.
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

/// One logged choice, reduced to what an estimator reads.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LoggedChoice {
    /// What the log acted on.
    pub acted_model_id: u32,
    /// How likely the logging mechanism was to act on it, in basis points.
    pub propensity_bps: u16,
    /// What came back, in whatever unit the caller scores outcomes.
    pub reward: f64,
    /// What the target policy would act on for the same request; `0` when it
    /// would select nothing.
    pub target_model_id: u32,
}

/// An estimate of the target policy's mean reward per request.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Estimate {
    /// Records the estimate was computed from.
    pub used: u64,
    /// Records set aside: no propensity (a person chose), no reward, a
    /// propensity of zero, or an outcome that does not belong to the request
    /// it was paired with.
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

/// Estimates from reduced records. `clip` caps each weight (biased, steadier);
/// `None` leaves them as they are. Returns `None` when no record is usable.
#[must_use]
pub fn estimate(records: &[LoggedChoice], clip: Option<f64>) -> Option<Estimate> {
    let mut used = 0_u64;
    let mut excluded = 0_u64;
    let mut matched = 0_u64;
    let mut unsupported = 0_u64;
    let mut terms = Vec::with_capacity(records.len());
    let (mut sum_w, mut sum_w2, mut sum_wr, mut max_w) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
    for r in records {
        if r.propensity_bps == 0
            || u64::from(r.propensity_bps) > BASIS_POINTS
            || !r.reward.is_finite()
        {
            excluded += 1;
            continue;
        }
        used += 1;
        let same = r.target_model_id != 0 && r.target_model_id == r.acted_model_id;
        let mut w = if same {
            matched += 1;
            BASIS_POINTS as f64 / f64::from(r.propensity_bps)
        } else {
            if u64::from(r.propensity_bps) == BASIS_POINTS && r.target_model_id != 0 {
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
        return None;
    }
    let n = used as f64;
    let ips = sum_wr / n;
    let var = if used > 1 {
        terms.iter().map(|t| (t - ips) * (t - ips)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let half = 1.96 * (var / n).sqrt();
    Some(Estimate {
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

/// Estimates `target`'s mean reward from logged `(request, outcome)` pairs.
///
/// The target's choice is whatever `target.prescribe(request)` selects. An
/// outcome is used only if its recorded input digest matches the request it is
/// paired with, it has a propensity (a person's choice has none), and `reward`
/// returns a value for it.
#[must_use]
pub fn evaluate(
    target: &PolicySnapshot,
    logs: &[(KernelInput, Outcome)],
    reward: impl Fn(&Outcome) -> Option<f64>,
    clip: Option<f64>,
) -> Option<Estimate> {
    let mut records = Vec::with_capacity(logs.len());
    let mut mismatched = 0_u64;
    for (input, outcome) in logs {
        let (Some(p), Some(r)) = (outcome.selection.propensity_bps, reward(outcome)) else {
            mismatched += 1;
            continue;
        };
        if outcome.identity.input_digest != input_digest(input) {
            mismatched += 1;
            continue;
        }
        let d = target.prescribe(*input);
        records.push(LoggedChoice {
            acted_model_id: outcome.selection.acted_model_id,
            propensity_bps: p,
            reward: r,
            target_model_id: if d.is_executable() {
                d.selected_model_id
            } else {
                0
            },
        });
    }
    let mut e = estimate(&records, clip)?;
    e.excluded += mismatched;
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(acted: u32, p: u16, reward: f64, target: u32) -> LoggedChoice {
        LoggedChoice {
            acted_model_id: acted,
            propensity_bps: p,
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

    #[test]
    fn unusable_records_are_counted_not_defaulted() {
        let r = vec![
            rec(1, 0, 1.0, 1),
            rec(1, 10_000, f64::NAN, 1),
            rec(1, 10_000, 2.0, 1),
        ];
        let e = estimate(&r, None).unwrap();
        assert_eq!(e.used, 1);
        assert_eq!(e.excluded, 2);
        assert!(estimate(&[rec(1, 0, 1.0, 1)], None).is_none());
    }

    #[test]
    fn a_target_that_selects_nothing_earns_nothing_and_is_not_unsupported() {
        let e = estimate(&[rec(1, 10_000, 5.0, 0)], None).unwrap();
        assert_eq!(e.ips, 0.0);
        assert_eq!(e.unsupported, 0);
    }
}
