//! What would have to change for a decision to come out differently.
//!
//! [`PolicySnapshot::explain`] says why each candidate ended where it did. This
//! module answers the next question a person asks: *what would it have taken?*
//!
//! - [`what_would_win`]: for a candidate that was not selected, the smallest
//!   change to one of its own levers — quality, p95 latency, price, risk
//!   ceiling, or being switched on — after which the kernel selects it.
//! - [`decision_margin`]: for the candidate that was selected, how far each of
//!   its levers can move before it stops being selected.
//!
//! Both are computed by running the real kernel on a copy of the policy with one
//! field of one candidate changed, and searching for the boundary. There is no
//! second formula here that could drift away from [`PolicySnapshot::prescribe`]:
//! the gate order, the utility terms and the tie-break are whatever the kernel
//! does. The search relies on one property, and it holds for every lever
//! listed: moving a lever in its favourable direction never makes the candidate
//! less attractive to the kernel while everything else stays fixed.
//!
//! Every answer is about **one lever at a time**, with all other candidates and
//! the request unchanged. A candidate that could win only by moving two levers
//! together has no single-lever answer, and the lever is left out rather than
//! guessed at. Nothing here changes a decision or a digest.
//!
//! Counterfactual explanations as a way to state recourse without opening the
//! model: Wachter, Mittelstadt and Russell, arXiv:1711.00399. Exact recourse
//! for linear, integer-scored decisions: Ustun, Spangher and Liu, arXiv:1809.06514.

use crate::kernel::{KernelDecision, KernelInput, KernelModel, KernelReason, PolicySnapshot};

/// One-millionth, the unit of [`Lever::PriceScalePpm`].
pub const PPM: u64 = 1_000_000;

/// How far a price may be scaled up when looking for a winner's margin: a
/// thousand times its current price. A winner that survives that is reported
/// with no price boundary rather than searched for without end.
pub const MAX_PRICE_SCALE_PPM: u64 = 1_000 * PPM;

/// A property of one candidate that a counterfactual may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Lever {
    /// `quality_bps`, in basis points. Higher is better.
    QualityBps,
    /// `p95_latency_ms`, in milliseconds. Lower is better.
    P95LatencyMs,
    /// Both token prices scaled together, in parts per million of the current
    /// price: `1_000_000` is the price today, `900_000` is ten percent cheaper.
    /// Lower is better.
    PriceScalePpm,
    /// `risk_ceiling_bps`, in basis points. Higher is better.
    RiskCeilingBps,
    /// `enabled`, `0` or `1`.
    Enabled,
}

/// Where one lever would have to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Requirement {
    pub lever: Lever,
    /// The lever's value in the policy as it is.
    pub current: u64,
    /// For [`what_would_win`]: the value closest to `current` at which the
    /// candidate is selected. For [`decision_margin`]: the value furthest from
    /// `current` at which it is still selected; one step beyond, it is not.
    pub boundary: u64,
    /// For a price lever, what the candidate would cost for this request at
    /// `boundary`, in microunits, as the kernel prices it. `None` otherwise.
    pub cost_at_boundary_microunits: Option<u64>,
}

/// What a candidate that was not selected would need in order to be selected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Counterfactual {
    pub model_id: u32,
    /// The decision as it stands.
    pub decision: KernelDecision,
    /// Set when the request was refused before any candidate was looked at
    /// (risk at or above the hard limit, or confidence below the floor). No
    /// change to a candidate can help then, and `levers` is empty.
    pub blocked_by_request: Option<KernelReason>,
    /// One entry per lever that can make this candidate win on its own, in the
    /// order of [`Lever`]. Empty when the candidate is already selected.
    pub levers: Vec<Requirement>,
}

/// How far the selected candidate's levers can move before it loses.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Margin {
    pub model_id: u32,
    pub decision: KernelDecision,
    /// One entry per lever that has a boundary inside its range. A lever
    /// missing from this list cannot make the winner lose on its own: quality
    /// could fall to zero, or the price could rise a thousandfold, and it would
    /// still be selected.
    pub levers: Vec<Requirement>,
}

/// The smallest single-lever change after which `model_id` is selected.
///
/// Returns `None` when `model_id` is not in the catalog.
#[must_use]
pub fn what_would_win(
    policy: &PolicySnapshot,
    input: KernelInput,
    model_id: u32,
) -> Option<Counterfactual> {
    let index = policy
        .models()
        .iter()
        .position(|m| m.model_id == model_id)?;
    let decision = policy.prescribe(input);
    let blocked_by_request = request_block(decision.reason);
    let mut out = Counterfactual {
        model_id,
        decision,
        blocked_by_request,
        levers: Vec::new(),
    };
    if blocked_by_request.is_some() || selected(&decision, model_id) {
        return Some(out);
    }
    let model = policy.models()[index];
    let wins = |candidate: KernelModel| {
        selected(
            &with_model(policy, index, candidate).prescribe(input),
            model_id,
        )
    };

    if model.enabled == 0 {
        let on = KernelModel {
            enabled: 1,
            ..model
        };
        if wins(on) {
            out.levers.push(plain(Lever::Enabled, 0, 1));
        }
        // Every other lever is measured on the candidate as it is, switched
        // off, and cannot make it win.
        return Some(out);
    }

    // Quality: the lowest value at or above today's at which it wins.
    let q = u64::from(model.quality_bps);
    if let Some(b) = lowest_true(q, u64::from(crate::kernel::MAX_BPS), |v| {
        wins(KernelModel {
            quality_bps: v as u16,
            ..model
        })
    }) {
        out.levers.push(plain(Lever::QualityBps, q, b));
    }

    // Latency: the highest value at or below today's at which it wins.
    let l = u64::from(model.p95_latency_ms);
    if let Some(b) = highest_true(0, l, |v| {
        wins(KernelModel {
            p95_latency_ms: v as u32,
            ..model
        })
    }) {
        out.levers.push(plain(Lever::P95LatencyMs, l, b));
    }

    // Price: the highest scale at or below today's at which it wins.
    if let Some(b) = highest_true(0, PPM, |s| wins(scaled(model, s))) {
        out.levers.push(priced(policy, index, input, model, b));
    }

    // Risk ceiling: the lowest value at or above today's at which it wins.
    let r = u64::from(model.risk_ceiling_bps);
    if let Some(b) = lowest_true(r, u64::from(crate::kernel::MAX_BPS), |v| {
        wins(KernelModel {
            risk_ceiling_bps: v as u16,
            ..model
        })
    }) {
        out.levers.push(plain(Lever::RiskCeilingBps, r, b));
    }
    Some(out)
}

/// How far the selected candidate's levers can move before it stops winning.
///
/// Returns `None` when the decision selected nothing.
#[must_use]
pub fn decision_margin(policy: &PolicySnapshot, input: KernelInput) -> Option<Margin> {
    let decision = policy.prescribe(input);
    if !decision.is_executable() {
        return None;
    }
    let model_id = decision.selected_model_id;
    let index = policy
        .models()
        .iter()
        .position(|m| m.model_id == model_id)?;
    let model = policy.models()[index];
    let wins = |candidate: KernelModel| {
        selected(
            &with_model(policy, index, candidate).prescribe(input),
            model_id,
        )
    };
    let mut levers = Vec::new();

    // Quality: the lowest value at which it still wins. No boundary if it
    // survives all the way down to zero.
    let q = u64::from(model.quality_bps);
    if !wins(KernelModel {
        quality_bps: 0,
        ..model
    }) {
        if let Some(b) = lowest_true(0, q, |v| {
            wins(KernelModel {
                quality_bps: v as u16,
                ..model
            })
        }) {
            levers.push(plain(Lever::QualityBps, q, b));
        }
    }

    // Latency: the highest value at which it still wins.
    let l = u64::from(model.p95_latency_ms);
    if !wins(KernelModel {
        p95_latency_ms: u32::MAX,
        ..model
    }) {
        if let Some(b) = highest_true(l, u64::from(u32::MAX), |v| {
            wins(KernelModel {
                p95_latency_ms: v as u32,
                ..model
            })
        }) {
            levers.push(plain(Lever::P95LatencyMs, l, b));
        }
    }

    // Price: the highest scale at which it still wins, up to the cap.
    if !wins(scaled(model, MAX_PRICE_SCALE_PPM)) {
        if let Some(b) = highest_true(PPM, MAX_PRICE_SCALE_PPM, |s| wins(scaled(model, s))) {
            levers.push(priced(policy, index, input, model, b));
        }
    }

    // Risk ceiling: the lowest value at which it still wins.
    let r = u64::from(model.risk_ceiling_bps);
    if !wins(KernelModel {
        risk_ceiling_bps: 0,
        ..model
    }) {
        if let Some(b) = lowest_true(0, r, |v| {
            wins(KernelModel {
                risk_ceiling_bps: v as u16,
                ..model
            })
        }) {
            levers.push(plain(Lever::RiskCeilingBps, r, b));
        }
    }

    Some(Margin {
        model_id,
        decision,
        levers,
    })
}

fn selected(decision: &KernelDecision, model_id: u32) -> bool {
    decision.is_executable() && decision.selected_model_id == model_id
}

fn request_block(reason: KernelReason) -> Option<KernelReason> {
    matches!(
        reason,
        KernelReason::RiskHardLimit | KernelReason::ConfidenceHardLimit
    )
    .then_some(reason)
}

/// The policy with one candidate replaced, everything else identical.
fn with_model(policy: &PolicySnapshot, index: usize, model: KernelModel) -> PolicySnapshot {
    let mut models = policy.models().to_vec();
    models[index] = model;
    PolicySnapshot::new_unchecked(
        policy.policy_epoch,
        policy.catalog_epoch,
        policy.hard_risk_limit_bps,
        policy.minimum_confidence_bps,
        policy.risk_penalty_multiplier_bps,
        policy.latency_penalty_microunits_per_ms,
        models,
    )
}

/// Both token prices multiplied by `scale_ppm / 1_000_000`, rounded down and
/// saturating at `u64::MAX`.
fn scaled(model: KernelModel, scale_ppm: u64) -> KernelModel {
    let scale = |price: u64| {
        let v = u128::from(price) * u128::from(scale_ppm) / u128::from(PPM);
        u64::try_from(v).unwrap_or(u64::MAX)
    };
    KernelModel {
        input_cost_microunits_per_million_tokens: scale(
            model.input_cost_microunits_per_million_tokens,
        ),
        output_cost_microunits_per_million_tokens: scale(
            model.output_cost_microunits_per_million_tokens,
        ),
        ..model
    }
}

fn plain(lever: Lever, current: u64, boundary: u64) -> Requirement {
    Requirement {
        lever,
        current,
        boundary,
        cost_at_boundary_microunits: None,
    }
}

fn priced(
    policy: &PolicySnapshot,
    index: usize,
    input: KernelInput,
    model: KernelModel,
    scale_ppm: u64,
) -> Requirement {
    let moved = scaled(model, scale_ppm);
    let explanation = with_model(policy, index, moved).explain(input);
    let cost = explanation
        .candidates
        .iter()
        .find(|c| c.model_id == model.model_id)
        .and_then(|c| match c.verdict {
            crate::kernel::CandidateVerdict::Eligible(t)
            | crate::kernel::CandidateVerdict::NonPositiveUtility(t) => Some(t.cost_microunits),
            crate::kernel::CandidateVerdict::OverBudget {
                cost_microunits, ..
            } => Some(cost_microunits),
            crate::kernel::CandidateVerdict::Rejected { .. } => None,
        });
    Requirement {
        lever: Lever::PriceScalePpm,
        current: PPM,
        boundary: scale_ppm,
        cost_at_boundary_microunits: cost,
    }
}

/// The smallest `v` in `[lo, hi]` with `pred(v)`, for a `pred` that is false
/// and then true as `v` rises. `None` when `pred(hi)` is false.
pub(crate) fn lowest_true(lo: u64, hi: u64, pred: impl Fn(u64) -> bool) -> Option<u64> {
    if lo > hi || !pred(hi) {
        return None;
    }
    let (mut lo, mut hi) = (lo, hi);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(lo)
}

/// The largest `v` in `[lo, hi]` with `pred(v)`, for a `pred` that is true and
/// then false as `v` rises. `None` when `pred(lo)` is false.
pub(crate) fn highest_true(lo: u64, hi: u64, pred: impl Fn(u64) -> bool) -> Option<u64> {
    if lo > hi || !pred(lo) {
        return None;
    }
    let (mut lo, mut hi) = (lo, hi);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if pred(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{ALL_PROVIDERS, ALL_REGIONS};

    fn model(id: u32, quality: u16, latency: u32, price: u64) -> KernelModel {
        KernelModel {
            model_id: id,
            provider_id: 0,
            quality_bps: quality,
            risk_ceiling_bps: 10_000,
            enabled: 1,
            p95_latency_ms: latency,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: price,
            output_cost_microunits_per_million_tokens: price,
        }
    }

    fn policy(models: Vec<KernelModel>) -> PolicySnapshot {
        PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 1_000, models).unwrap()
    }

    fn input() -> KernelInput {
        KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 1_000,
            output_tokens: 1_000,
            business_value_microunits: 10_000_000,
            budget_limit_microunits: 1_000_000_000,
            risk_bps: 100,
            confidence_bps: 10_000,
            minimum_quality_bps: 0,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        }
    }

    fn lever(levers: &[Requirement], lever: Lever) -> Option<Requirement> {
        levers.iter().copied().find(|r| r.lever == lever)
    }

    fn with(p: &PolicySnapshot, id: u32, f: impl Fn(KernelModel) -> KernelModel) -> PolicySnapshot {
        let i = p.models().iter().position(|m| m.model_id == id).unwrap();
        with_model(p, i, f(p.models()[i]))
    }

    #[test]
    fn each_boundary_is_exact_one_step_short_loses() {
        let p = policy(vec![
            model(1, 9_000, 100, 1_000_000),
            model(2, 8_000, 300, 1_000_000),
        ]);
        let x = input();
        assert_eq!(p.prescribe(x).selected_model_id, 1);
        let cf = what_would_win(&p, x, 2).unwrap();
        assert!(!cf.levers.is_empty());
        for r in &cf.levers {
            let at = |v: u64| match r.lever {
                Lever::QualityBps => with(&p, 2, |m| KernelModel {
                    quality_bps: v as u16,
                    ..m
                }),
                Lever::P95LatencyMs => with(&p, 2, |m| KernelModel {
                    p95_latency_ms: v as u32,
                    ..m
                }),
                Lever::PriceScalePpm => with(&p, 2, |m| scaled(m, v)),
                Lever::RiskCeilingBps => with(&p, 2, |m| KernelModel {
                    risk_ceiling_bps: v as u16,
                    ..m
                }),
                Lever::Enabled => unreachable!(),
            };
            assert_eq!(
                at(r.boundary).prescribe(x).selected_model_id,
                2,
                "{r:?} wins at the boundary"
            );
            let short = match r.lever {
                Lever::QualityBps | Lever::RiskCeilingBps => r.boundary - 1,
                _ => r.boundary + 1,
            };
            assert_ne!(
                at(short).prescribe(x).selected_model_id,
                2,
                "{r:?} one step short still loses"
            );
        }
    }

    #[test]
    fn the_selected_candidate_needs_nothing() {
        let p = policy(vec![
            model(1, 9_000, 100, 1_000_000),
            model(2, 8_000, 300, 1_000_000),
        ]);
        assert!(what_would_win(&p, input(), 1).unwrap().levers.is_empty());
    }

    #[test]
    fn a_request_refused_at_the_hard_limit_has_no_lever() {
        let p = policy(vec![
            model(1, 9_000, 100, 1_000_000),
            model(2, 8_000, 300, 1_000_000),
        ]);
        let x = KernelInput {
            risk_bps: 9_000,
            ..input()
        };
        let cf = what_would_win(&p, x, 2).unwrap();
        assert_eq!(cf.blocked_by_request, Some(KernelReason::RiskHardLimit));
        assert!(cf.levers.is_empty());
    }

    #[test]
    fn a_switched_off_candidate_is_offered_only_the_switch() {
        let mut off = model(2, 9_900, 10, 1);
        off.enabled = 0;
        let p = policy(vec![model(1, 9_000, 100, 1_000_000), off]);
        let cf = what_would_win(&p, input(), 2).unwrap();
        assert_eq!(cf.levers, vec![plain(Lever::Enabled, 0, 1)]);
    }

    #[test]
    fn the_margin_is_exact_one_step_beyond_loses() {
        let p = policy(vec![
            model(1, 9_000, 100, 1_000_000),
            model(2, 8_000, 300, 1_000_000),
        ]);
        let x = input();
        let m = decision_margin(&p, x).unwrap();
        assert_eq!(m.model_id, 1);
        let q = lever(&m.levers, Lever::QualityBps).expect("quality has a boundary");
        let at = |v: u16| {
            with(&p, 1, |m| KernelModel {
                quality_bps: v,
                ..m
            })
            .prescribe(x)
            .selected_model_id
        };
        assert_eq!(at(q.boundary as u16), 1);
        assert_ne!(at(q.boundary as u16 - 1), 1);
        let l = lever(&m.levers, Lever::P95LatencyMs).expect("latency has a boundary");
        let at = |v: u32| {
            with(&p, 1, |m| KernelModel {
                p95_latency_ms: v,
                ..m
            })
            .prescribe(x)
            .selected_model_id
        };
        assert_eq!(at(l.boundary as u32), 1);
        assert_ne!(at(l.boundary as u32 + 1), 1);
    }

    #[test]
    fn a_winner_with_no_rival_has_no_quality_boundary_above_zero_utility() {
        // Alone in the catalog, the winner loses only when its own utility
        // stops clearing zero, so the boundary is where that happens.
        let p = policy(vec![model(1, 9_000, 100, 1_000_000)]);
        let m = decision_margin(&p, input()).unwrap();
        if let Some(q) = lever(&m.levers, Lever::QualityBps) {
            assert!(q.boundary <= q.current);
        }
    }

    #[test]
    fn nothing_here_changes_the_decision() {
        let p = policy(vec![
            model(1, 9_000, 100, 1_000_000),
            model(2, 8_000, 300, 1_000_000),
        ]);
        let x = input();
        let before = p.prescribe(x);
        let _ = what_would_win(&p, x, 2);
        let _ = decision_margin(&p, x);
        assert_eq!(p.prescribe(x), before);
    }

    #[test]
    fn an_unknown_candidate_is_none() {
        let p = policy(vec![model(1, 9_000, 100, 1_000_000)]);
        assert!(what_would_win(&p, input(), 99).is_none());
    }

    #[test]
    fn the_searches_find_the_edge() {
        assert_eq!(lowest_true(0, 100, |v| v >= 37), Some(37));
        assert_eq!(lowest_true(0, 100, |_| false), None);
        assert_eq!(highest_true(0, 100, |v| v <= 37), Some(37));
        assert_eq!(highest_true(0, 100, |_| false), None);
        assert_eq!(highest_true(5, 5, |_| true), Some(5));
    }
}
