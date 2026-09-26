//! The off-policy estimators against a reference written from their
//! definitions, on data drawn from several distributions.
//!
//! The reference is deliberately plain: one pass per quantity, in a different
//! order from the crate's, with the weight computed from the fraction as the
//! textbooks write it. Agreement to within floating-point rounding says the
//! crate computes the estimators it documents; the population tests in
//! `tests/preview.rs` say those estimators are unbiased with exact
//! propensities.

#![cfg(feature = "preview")]

use calybris_core::ope::{estimate, LoggedChoice, OpeError, Propensity};
use proptest::prelude::*;

struct Reference {
    ips: f64,
    half_width: f64,
    snips: Option<f64>,
    ess: f64,
    matched: u64,
    unsupported: u64,
}

fn reference(records: &[LoggedChoice], clip: Option<f64>) -> Reference {
    let weight = |r: &LoggedChoice| {
        let w = if r.target_model_id != 0 && r.target_model_id == r.acted_model_id {
            r.propensity.denominator() as f64 / r.propensity.numerator() as f64
        } else {
            0.0
        };
        clip.map_or(w, |c| w.min(c))
    };
    let n = records.len() as f64;
    let terms: Vec<f64> = records.iter().rev().map(|r| weight(r) * r.reward).collect();
    let ips = terms.iter().sum::<f64>() / n;
    let var = if records.len() > 1 {
        terms.iter().map(|t| (t - ips).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let sum_w: f64 = records.iter().rev().map(weight).sum();
    let sum_w2: f64 = records.iter().rev().map(|r| weight(r).powi(2)).sum();
    Reference {
        ips,
        half_width: 1.96 * (var / n).sqrt(),
        snips: (sum_w > 0.0).then(|| terms.iter().sum::<f64>() / sum_w),
        ess: if sum_w2 > 0.0 {
            sum_w * sum_w / sum_w2
        } else {
            0.0
        },
        matched: records
            .iter()
            .filter(|r| r.target_model_id != 0 && r.target_model_id == r.acted_model_id)
            .count() as u64,
        unsupported: records
            .iter()
            .filter(|r| {
                r.target_model_id != 0
                    && r.target_model_id != r.acted_model_id
                    && r.propensity.is_one()
            })
            .count() as u64,
    }
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-9 * (1.0 + a.abs().max(b.abs()))
}

/// Propensities from three regimes: certainty, whole basis points, and the
/// sub-basis-point fractions exploration produces over large windows.
fn propensity() -> impl Strategy<Value = Propensity> {
    prop_oneof![
        Just(Propensity::ONE),
        (1_u16..=10_000).prop_map(|b| Propensity::from_bps(b).unwrap()),
        (1_u64..=10_000, 1_u64..=1_000)
            .prop_map(|(rate, k)| Propensity::new(rate, 10_000 * k).unwrap()),
        (1_u64..=u64::from(u32::MAX))
            .prop_flat_map(|den| (1..=den, Just(den)))
            .prop_map(|(num, den)| Propensity::new(num, den).unwrap()),
    ]
}

/// Rewards: binary, bounded and continuous, and wide with either sign.
fn reward() -> impl Strategy<Value = f64> {
    prop_oneof![
        prop_oneof![Just(0.0), Just(1.0)],
        0.0..1.0_f64,
        -1e6..1e6_f64,
    ]
}

fn record() -> impl Strategy<Value = LoggedChoice> {
    (1_u32..=4, propensity(), reward(), 0_u32..=4).prop_map(
        |(acted_model_id, propensity, reward, target_model_id)| LoggedChoice {
            acted_model_id,
            propensity,
            reward,
            target_model_id,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn estimates_agree_with_the_reference(
        records in prop::collection::vec(record(), 1..200),
        clip in prop::option::of(1e-3..1e7_f64),
    ) {
        let e = estimate(&records, clip).unwrap();
        let r = reference(&records, clip);
        prop_assert_eq!(e.used, records.len() as u64);
        prop_assert_eq!(e.excluded, 0);
        prop_assert_eq!(e.matched, r.matched);
        prop_assert_eq!(e.unsupported, r.unsupported);
        prop_assert!(close(e.ips, r.ips), "ips {} vs {}", e.ips, r.ips);
        prop_assert!(close(e.ips_ci95.1 - e.ips, r.half_width));
        prop_assert!(close(e.ips - e.ips_ci95.0, r.half_width));
        prop_assert!(close(e.effective_sample_size, r.ess));
        match (e.snips, r.snips) {
            (Some(a), Some(b)) => prop_assert!(close(a, b), "snips {} vs {}", a, b),
            (None, None) => {}
            other => prop_assert!(false, "snips {:?}", other),
        }
        prop_assert!(e.effective_sample_size <= e.used as f64 * (1.0 + 1e-12));
        if let Some(c) = clip {
            prop_assert!(e.max_weight <= c);
        }
    }

    /// Without clipping, a record's weight is exactly the inverse of its
    /// probability, however small, and never the inverse of a rounding.
    #[test]
    fn a_lone_matched_record_is_weighted_by_its_exact_inverse(p in propensity()) {
        let r = LoggedChoice { acted_model_id: 1, propensity: p, reward: 1.0, target_model_id: 1 };
        let e = estimate(&[r], None).unwrap();
        prop_assert_eq!(e.max_weight, p.denominator() as f64 / p.numerator() as f64);
        prop_assert_eq!(e.ips, e.max_weight);
    }

    #[test]
    fn a_clip_is_refused_unless_positive_and_finite(clip in any::<f64>()) {
        let r = [LoggedChoice {
            acted_model_id: 1,
            propensity: Propensity::ONE,
            reward: 1.0,
            target_model_id: 1,
        }];
        let result = estimate(&r, Some(clip));
        if clip.is_finite() && clip > 0.0 {
            prop_assert!(result.is_ok());
        } else {
            // NaN is not equal to itself, so compare the variant, not the value.
            prop_assert!(matches!(result, Err(OpeError::InvalidClip(_))), "{:?}", result);
        }
    }
}
