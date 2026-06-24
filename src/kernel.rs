//! Allocation-free prescriptive decision kernel.
//!
//! This module deliberately contains no HTTP, JSON, UUID, WAL, clock, or floating-point work.
//! Snapshots may allocate when they are built; `PolicySnapshot::prescribe` does not allocate.

use std::sync::Arc;

pub const BASIS_POINTS: u64 = 10_000;
const SCALED_BASIS_POINTS: u64 = BASIS_POINTS * BASIS_POINTS;
const COST_SCALE: u64 = 1_000_000;
const COST_ROUNDING: u64 = COST_SCALE - 1;
pub const ALL_PROVIDERS: u64 = u64::MAX;
pub const ALL_REGIONS: u64 = u64::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelModel {
    pub model_id: u32,
    pub provider_id: u16,
    pub quality_bps: u16,
    pub risk_ceiling_bps: u16,
    pub enabled: u8,
    pub p95_latency_ms: u32,
    pub capabilities: u64,
    pub region_mask: u64,
    pub input_cost_microunits_per_million_tokens: u64,
    pub output_cost_microunits_per_million_tokens: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelInput {
    pub request_sequence: u64,
    pub requested_model_id: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub business_value_microunits: i64,
    pub budget_limit_microunits: u64,
    pub risk_bps: u16,
    pub confidence_bps: u16,
    pub minimum_quality_bps: u16,
    pub max_p95_latency_ms: u32,
    pub required_capabilities: u64,
    pub allowed_provider_mask: u64,
    pub required_region_mask: u64,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAction {
    ExecuteRequested = 1,
    Substitute = 2,
    Reject = 3,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelReason {
    RequestedModelMaximizesUtility = 1,
    AlternativeMaximizesUtility = 2,
    RiskHardLimit = 100,
    ConfidenceHardLimit = 101,
    NoEnabledModel = 102,
    QualityConstraint = 103,
    LatencyConstraint = 104,
    CapabilityConstraint = 105,
    ProviderConstraint = 106,
    RegionConstraint = 107,
    BudgetConstraint = 108,
    NonPositiveUtility = 109,
    RiskCeilingConstraint = 110,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelDecision {
    pub request_sequence: u64,
    pub action: KernelAction,
    pub reason: KernelReason,
    pub selected_model_id: u32,
    pub selected_model_index: u16,
    pub estimated_cost_microunits: u64,
    pub expected_utility_microunits: i64,
    pub counterfactual_model_id: u32,
    pub counterfactual_utility_microunits: i64,
    pub evaluated_models: u16,
    pub eligible_models: u16,
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
    pub hard_risk_limit_bps: u16,
    pub minimum_confidence_bps: u16,
    pub risk_penalty_multiplier_bps: u16,
    pub latency_penalty_microunits_per_ms: u64,
    max_quality_bps: u16,
    max_p95_latency_ms: u32,
    max_input_cost: u64,
    max_output_cost: u64,
    models: Arc<[KernelModel]>,
}

#[derive(Clone, Copy)]
struct Candidate {
    model_id: u32,
    model_index: u16,
    quality_bps: u16,
    cost: u64,
    utility: i64,
}

#[derive(Default)]
struct RejectionCounts {
    disabled: u16,
    quality: u16,
    risk_ceiling: u16,
    latency: u16,
    capability: u16,
    provider: u16,
    region: u16,
    budget: u16,
    utility: u16,
}

impl PolicySnapshot {
    pub fn new(
        policy_epoch: u64,
        catalog_epoch: u64,
        hard_risk_limit_bps: u16,
        minimum_confidence_bps: u16,
        risk_penalty_multiplier_bps: u16,
        latency_penalty_microunits_per_ms: u64,
        models: Vec<KernelModel>,
    ) -> Self {
        let max_quality_bps = models
            .iter()
            .map(|model| model.quality_bps)
            .max()
            .unwrap_or_default();
        let max_p95_latency_ms = models
            .iter()
            .map(|model| model.p95_latency_ms)
            .max()
            .unwrap_or_default();
        let max_input_cost = models
            .iter()
            .map(|model| model.input_cost_microunits_per_million_tokens)
            .max()
            .unwrap_or_default();
        let max_output_cost = models
            .iter()
            .map(|model| model.output_cost_microunits_per_million_tokens)
            .max()
            .unwrap_or_default();
        Self {
            policy_epoch,
            catalog_epoch,
            hard_risk_limit_bps,
            minimum_confidence_bps,
            risk_penalty_multiplier_bps,
            latency_penalty_microunits_per_ms,
            max_quality_bps,
            max_p95_latency_ms,
            max_input_cost,
            max_output_cost,
            models: Arc::from(models),
        }
    }

    pub fn models(&self) -> &[KernelModel] {
        &self.models
    }

    pub fn prescribe(&self, input: KernelInput) -> KernelDecision {
        if input.risk_bps >= self.hard_risk_limit_bps {
            return self.reject(input, KernelReason::RiskHardLimit, 0, 0);
        }
        if input.confidence_bps < self.minimum_confidence_bps {
            return self.reject(input, KernelReason::ConfidenceHardLimit, 0, 0);
        }

        let mut best: Option<Candidate> = None;
        let mut second: Option<Candidate> = None;
        let mut eligible_models = 0_u16;
        let mut rejected = RejectionCounts::default();

        let value = input.business_value_microunits.max(0) as u64;
        let confidence_bps = u64::from(input.confidence_bps);
        let quality_prefix = value.checked_mul(confidence_bps).filter(|prefix| {
            prefix
                .checked_mul(u64::from(self.max_quality_bps))
                .is_some()
        });
        let risk_penalty = scaled_term_exact(
            value,
            u64::from(input.risk_bps),
            u64::from(self.risk_penalty_multiplier_bps),
        );
        let all_costs_fit = self.all_costs_fit_u64(input.input_tokens, input.output_tokens);
        let all_latencies_fit = u64::from(self.max_p95_latency_ms)
            .checked_mul(self.latency_penalty_microunits_per_ms)
            .is_some();

        let check_provider = input.allowed_provider_mask != ALL_PROVIDERS;
        let check_region = input.required_region_mask != 0;
        let check_latency = input.max_p95_latency_ms > 0;
        let latency_pen_per_ms = self.latency_penalty_microunits_per_ms;

        for (index, model) in self.models.iter().enumerate() {
            // Fast reject chain — ordered by cheapest check first
            if model.enabled == 0 {
                rejected.disabled += 1;
                continue;
            }
            if model.quality_bps < input.minimum_quality_bps {
                rejected.quality += 1;
                continue;
            }
            if check_latency && model.p95_latency_ms > input.max_p95_latency_ms {
                rejected.latency += 1;
                continue;
            }
            if model.capabilities & input.required_capabilities != input.required_capabilities {
                rejected.capability += 1;
                continue;
            }
            // Provider fence: provider_id >= 64 is always unrepresentable in a
            // 64-bit mask, so reject unconditionally regardless of ALL_PROVIDERS.
            if model.provider_id >= 64 {
                rejected.provider += 1;
                continue;
            }
            if check_provider && input.allowed_provider_mask & (1_u64 << model.provider_id) == 0 {
                rejected.provider += 1;
                continue;
            }
            if check_region && model.region_mask & input.required_region_mask == 0 {
                rejected.region += 1;
                continue;
            }
            if input.risk_bps > model.risk_ceiling_bps {
                rejected.risk_ceiling += 1;
                continue;
            }

            let cost = if all_costs_fit {
                model_cost_fast(model, input.input_tokens, input.output_tokens)
            } else {
                model_cost_reference(model, input.input_tokens, input.output_tokens)
            };
            if cost > input.budget_limit_microunits {
                rejected.budget += 1;
                continue;
            }

            let quality_adjusted = quality_prefix.map_or_else(
                || scaled_term_reference(value, confidence_bps, u64::from(model.quality_bps)),
                |prefix| {
                    // `quality_prefix` is admitted only after proving this product fits.
                    i128::from(
                        prefix.wrapping_mul(u64::from(model.quality_bps)) / SCALED_BASIS_POINTS,
                    )
                },
            );
            let latency_penalty = if all_latencies_fit {
                i128::from(u64::from(model.p95_latency_ms).wrapping_mul(latency_pen_per_ms))
            } else {
                i128::from(model.p95_latency_ms) * i128::from(latency_pen_per_ms)
            };
            let utility = clamp_i128_to_i64(
                quality_adjusted - risk_penalty - i128::from(cost) - latency_penalty,
            );

            if utility <= 0 {
                rejected.utility += 1;
                continue;
            }
            eligible_models = eligible_models.saturating_add(1);

            let candidate = Candidate {
                model_id: model.model_id,
                model_index: u16::try_from(index).unwrap_or(u16::MAX),
                quality_bps: model.quality_bps,
                cost,
                utility,
            };
            match best {
                None => best = Some(candidate),
                Some(current) if candidate_better(candidate, current) => {
                    second = best;
                    best = Some(candidate);
                }
                _ => {
                    if second.is_none_or(|s| candidate_better(candidate, s)) {
                        second = Some(candidate);
                    }
                }
            }
        }

        let evaluated_models = u16::try_from(self.models.len()).unwrap_or(u16::MAX);
        let Some(best) = best else {
            return self.reject(
                input,
                dominant_rejection_reason(&rejected),
                evaluated_models,
                eligible_models,
            );
        };
        let action = if best.model_id == input.requested_model_id {
            KernelAction::ExecuteRequested
        } else {
            KernelAction::Substitute
        };
        KernelDecision {
            request_sequence: input.request_sequence,
            action,
            reason: if action == KernelAction::ExecuteRequested {
                KernelReason::RequestedModelMaximizesUtility
            } else {
                KernelReason::AlternativeMaximizesUtility
            },
            selected_model_id: best.model_id,
            selected_model_index: best.model_index,
            estimated_cost_microunits: best.cost,
            expected_utility_microunits: best.utility,
            counterfactual_model_id: second.map_or(0, |candidate| candidate.model_id),
            counterfactual_utility_microunits: second.map_or(0, |candidate| candidate.utility),
            evaluated_models,
            eligible_models,
            policy_epoch: self.policy_epoch,
            catalog_epoch: self.catalog_epoch,
        }
    }

    #[inline]
    fn all_costs_fit_u64(&self, input_tokens: u32, output_tokens: u32) -> bool {
        let input = u64::from(input_tokens)
            .checked_mul(self.max_input_cost)
            .and_then(|value| value.checked_add(COST_ROUNDING));
        let output = u64::from(output_tokens)
            .checked_mul(self.max_output_cost)
            .and_then(|value| value.checked_add(COST_ROUNDING));
        input
            .zip(output)
            .is_some_and(|(input, output)| input.checked_add(output).is_some())
    }

    fn reject(
        &self,
        input: KernelInput,
        reason: KernelReason,
        evaluated_models: u16,
        eligible_models: u16,
    ) -> KernelDecision {
        KernelDecision {
            request_sequence: input.request_sequence,
            action: KernelAction::Reject,
            reason,
            selected_model_id: 0,
            selected_model_index: u16::MAX,
            estimated_cost_microunits: 0,
            expected_utility_microunits: 0,
            counterfactual_model_id: 0,
            counterfactual_utility_microunits: 0,
            evaluated_models,
            eligible_models,
            policy_epoch: self.policy_epoch,
            catalog_epoch: self.catalog_epoch,
        }
    }
}

#[inline(always)]
fn model_cost_fast(model: &KernelModel, input_tokens: u32, output_tokens: u32) -> u64 {
    let input = u64::from(input_tokens)
        .wrapping_mul(model.input_cost_microunits_per_million_tokens)
        .wrapping_add(COST_ROUNDING)
        / COST_SCALE;
    let output = u64::from(output_tokens)
        .wrapping_mul(model.output_cost_microunits_per_million_tokens)
        .wrapping_add(COST_ROUNDING)
        / COST_SCALE;
    input.wrapping_add(output)
}

fn model_cost_reference(model: &KernelModel, input_tokens: u32, output_tokens: u32) -> u64 {
    let input = u128::from(input_tokens)
        .saturating_mul(u128::from(model.input_cost_microunits_per_million_tokens))
        .saturating_add(u128::from(COST_ROUNDING))
        / u128::from(COST_SCALE);
    let output = u128::from(output_tokens)
        .saturating_mul(u128::from(model.output_cost_microunits_per_million_tokens))
        .saturating_add(u128::from(COST_ROUNDING))
        / u128::from(COST_SCALE);
    u64::try_from(input.saturating_add(output)).unwrap_or(u64::MAX)
}

#[inline]
fn scaled_term_exact(value: u64, first_bps: u64, second_bps: u64) -> i128 {
    value
        .checked_mul(first_bps)
        .and_then(|value| value.checked_mul(second_bps))
        .map_or_else(
            || scaled_term_reference(value, first_bps, second_bps),
            |numerator| i128::from(numerator / SCALED_BASIS_POINTS),
        )
}

#[inline]
fn scaled_term_reference(value: u64, first_bps: u64, second_bps: u64) -> i128 {
    i128::from(value) * i128::from(first_bps) * i128::from(second_bps)
        / i128::from(SCALED_BASIS_POINTS)
}

#[inline(always)]
fn candidate_better(left: Candidate, right: Candidate) -> bool {
    left.utility > right.utility
        || (left.utility == right.utility && left.cost < right.cost)
        || (left.utility == right.utility
            && left.cost == right.cost
            && left.quality_bps > right.quality_bps)
        || (left.utility == right.utility
            && left.cost == right.cost
            && left.quality_bps == right.quality_bps
            && left.model_id < right.model_id)
}

fn dominant_rejection_reason(counts: &RejectionCounts) -> KernelReason {
    let candidates = [
        (counts.capability, KernelReason::CapabilityConstraint),
        (counts.region, KernelReason::RegionConstraint),
        (counts.provider, KernelReason::ProviderConstraint),
        (counts.quality, KernelReason::QualityConstraint),
        (counts.risk_ceiling, KernelReason::RiskCeilingConstraint),
        (counts.latency, KernelReason::LatencyConstraint),
        (counts.budget, KernelReason::BudgetConstraint),
        (counts.utility, KernelReason::NonPositiveUtility),
        (counts.disabled, KernelReason::NoEnabledModel),
    ];
    candidates
        .into_iter()
        .max_by_key(|(count, _)| *count)
        .filter(|(count, _)| *count > 0)
        .map_or(KernelReason::NoEnabledModel, |(_, reason)| reason)
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, time::Instant};

    use proptest::prelude::*;

    use super::*;

    const TOOLS: u64 = 1 << 0;
    const REGION_EU: u64 = 1 << 0;

    fn snapshot() -> PolicySnapshot {
        PolicySnapshot::new(
            7,
            11,
            9_600,
            5_500,
            10_000,
            2,
            vec![
                KernelModel {
                    model_id: 10,
                    provider_id: 0,
                    quality_bps: 7_500,
                    risk_ceiling_bps: 9_500,
                    enabled: 1,
                    p95_latency_ms: 180,
                    capabilities: TOOLS,
                    region_mask: REGION_EU,
                    input_cost_microunits_per_million_tokens: 150_000,
                    output_cost_microunits_per_million_tokens: 600_000,
                },
                KernelModel {
                    model_id: 20,
                    provider_id: 1,
                    quality_bps: 9_500,
                    risk_ceiling_bps: 9_500,
                    enabled: 1,
                    p95_latency_ms: 450,
                    capabilities: TOOLS,
                    region_mask: REGION_EU,
                    input_cost_microunits_per_million_tokens: 2_500_000,
                    output_cost_microunits_per_million_tokens: 10_000_000,
                },
            ],
        )
    }

    fn input() -> KernelInput {
        KernelInput {
            request_sequence: 1,
            requested_model_id: 20,
            input_tokens: 2_000,
            output_tokens: 500,
            business_value_microunits: 100_000_000,
            budget_limit_microunits: 20_000_000,
            risk_bps: 1_000,
            confidence_bps: 9_000,
            minimum_quality_bps: 7_000,
            max_p95_latency_ms: 1_000,
            required_capabilities: TOOLS,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: REGION_EU,
        }
    }

    fn prescribe_reference(snapshot: &PolicySnapshot, input: KernelInput) -> KernelDecision {
        if input.risk_bps >= snapshot.hard_risk_limit_bps {
            return snapshot.reject(input, KernelReason::RiskHardLimit, 0, 0);
        }
        if input.confidence_bps < snapshot.minimum_confidence_bps {
            return snapshot.reject(input, KernelReason::ConfidenceHardLimit, 0, 0);
        }

        let mut best: Option<Candidate> = None;
        let mut second: Option<Candidate> = None;
        let mut eligible_models = 0_u16;
        let mut rejected = RejectionCounts::default();
        let value = input.business_value_microunits.max(0) as u64;
        let risk_penalty = scaled_term_reference(
            value,
            u64::from(input.risk_bps),
            u64::from(snapshot.risk_penalty_multiplier_bps),
        );

        for (index, model) in snapshot.models.iter().enumerate() {
            if model.enabled == 0 {
                rejected.disabled += 1;
                continue;
            }
            if model.quality_bps < input.minimum_quality_bps {
                rejected.quality += 1;
                continue;
            }
            if input.max_p95_latency_ms > 0 && model.p95_latency_ms > input.max_p95_latency_ms {
                rejected.latency += 1;
                continue;
            }
            if model.capabilities & input.required_capabilities != input.required_capabilities {
                rejected.capability += 1;
                continue;
            }
            if input.allowed_provider_mask != ALL_PROVIDERS
                && (model.provider_id >= 64
                    || input.allowed_provider_mask & (1_u64 << model.provider_id) == 0)
            {
                rejected.provider += 1;
                continue;
            }
            if input.required_region_mask != 0
                && model.region_mask & input.required_region_mask == 0
            {
                rejected.region += 1;
                continue;
            }
            if input.risk_bps > model.risk_ceiling_bps {
                rejected.risk_ceiling += 1;
                continue;
            }

            let cost = model_cost_reference(model, input.input_tokens, input.output_tokens);
            if cost > input.budget_limit_microunits {
                rejected.budget += 1;
                continue;
            }
            let quality_adjusted = scaled_term_reference(
                value,
                u64::from(input.confidence_bps),
                u64::from(model.quality_bps),
            );
            let latency_penalty = i128::from(model.p95_latency_ms)
                * i128::from(snapshot.latency_penalty_microunits_per_ms);
            let utility = clamp_i128_to_i64(
                quality_adjusted - risk_penalty - i128::from(cost) - latency_penalty,
            );
            if utility <= 0 {
                rejected.utility += 1;
                continue;
            }
            eligible_models = eligible_models.saturating_add(1);
            let candidate = Candidate {
                model_id: model.model_id,
                model_index: u16::try_from(index).unwrap_or(u16::MAX),
                quality_bps: model.quality_bps,
                cost,
                utility,
            };
            if best.is_none_or(|current| candidate_better(candidate, current)) {
                second = best;
                best = Some(candidate);
            } else if second.is_none_or(|current| candidate_better(candidate, current)) {
                second = Some(candidate);
            }
        }

        let evaluated_models = u16::try_from(snapshot.models.len()).unwrap_or(u16::MAX);
        let Some(best) = best else {
            return snapshot.reject(
                input,
                dominant_rejection_reason(&rejected),
                evaluated_models,
                eligible_models,
            );
        };
        let action = if best.model_id == input.requested_model_id {
            KernelAction::ExecuteRequested
        } else {
            KernelAction::Substitute
        };
        KernelDecision {
            request_sequence: input.request_sequence,
            action,
            reason: if action == KernelAction::ExecuteRequested {
                KernelReason::RequestedModelMaximizesUtility
            } else {
                KernelReason::AlternativeMaximizesUtility
            },
            selected_model_id: best.model_id,
            selected_model_index: best.model_index,
            estimated_cost_microunits: best.cost,
            expected_utility_microunits: best.utility,
            counterfactual_model_id: second.map_or(0, |candidate| candidate.model_id),
            counterfactual_utility_microunits: second.map_or(0, |candidate| candidate.utility),
            evaluated_models,
            eligible_models,
            policy_epoch: snapshot.policy_epoch,
            catalog_epoch: snapshot.catalog_epoch,
        }
    }

    #[test]
    fn prescribes_maximum_utility_not_minimum_price() {
        let decision = snapshot().prescribe(input());
        assert_eq!(decision.action, KernelAction::ExecuteRequested);
        assert_eq!(decision.selected_model_id, 20);
        assert_eq!(decision.counterfactual_model_id, 10);
        assert!(decision.expected_utility_microunits > decision.counterfactual_utility_microunits);
    }

    #[test]
    fn hard_budget_can_prescribe_substitution() {
        let mut request = input();
        request.budget_limit_microunits = 1_000;
        let decision = snapshot().prescribe(request);
        assert_eq!(decision.action, KernelAction::Substitute);
        assert_eq!(decision.selected_model_id, 10);
    }

    #[test]
    fn hard_constraints_fail_closed() {
        let mut request = input();
        request.risk_bps = 9_900;
        let decision = snapshot().prescribe(request);
        assert_eq!(decision.action, KernelAction::Reject);
        assert_eq!(decision.reason, KernelReason::RiskHardLimit);

        request.risk_bps = 1_000;
        request.required_capabilities = 1 << 9;
        let decision = snapshot().prescribe(request);
        assert_eq!(decision.action, KernelAction::Reject);
        assert_eq!(decision.reason, KernelReason::CapabilityConstraint);
    }

    #[test]
    fn extreme_inputs_saturate_without_panicking() {
        let mut request = input();
        request.input_tokens = u32::MAX;
        request.output_tokens = u32::MAX;
        request.business_value_microunits = i64::MAX;
        request.budget_limit_microunits = u64::MAX;
        let decision = snapshot().prescribe(request);
        assert_eq!(decision.request_sequence, request.request_sequence);
    }

    #[test]
    fn exact_fast_path_preserves_single_rounding_step() {
        assert_eq!(scaled_term_reference(2, 5_001, 9_999), 1);
        assert_eq!(scaled_term_exact(2, 5_001, 9_999), 1);
    }

    proptest! {
        #[test]
        fn optimized_scaled_term_matches_i128_reference(
            value in any::<u64>(),
            first_bps in any::<u16>(),
            second_bps in any::<u16>(),
        ) {
            prop_assert_eq!(
                scaled_term_exact(value, u64::from(first_bps), u64::from(second_bps)),
                scaled_term_reference(value, u64::from(first_bps), u64::from(second_bps)),
            );
        }

        #[test]
        fn optimized_cost_matches_u128_reference_when_guard_admits(
            input_tokens in any::<u32>(),
            output_tokens in any::<u32>(),
            input_price in any::<u64>(),
            output_price in any::<u64>(),
        ) {
            let model = KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 10_000,
                risk_ceiling_bps: u16::MAX,
                enabled: 1,
                p95_latency_ms: 1,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: input_price,
                output_cost_microunits_per_million_tokens: output_price,
            };
            let snapshot = PolicySnapshot::new(1, 1, u16::MAX, 0, 0, 0, vec![model]);
            if snapshot.all_costs_fit_u64(input_tokens, output_tokens) {
                prop_assert_eq!(
                    model_cost_fast(&model, input_tokens, output_tokens),
                    model_cost_reference(&model, input_tokens, output_tokens),
                );
            }
        }

        #[test]
        fn optimized_kernel_matches_reference_decision(
            input_tokens in any::<u32>(),
            output_tokens in any::<u32>(),
            value in any::<i64>(),
            budget in any::<u64>(),
            risk in any::<u16>(),
            confidence in any::<u16>(),
            minimum_quality in any::<u16>(),
            maximum_latency in any::<u32>(),
            provider_mask in any::<u64>(),
            region_mask in any::<u64>(),
        ) {
            let mut request = input();
            request.input_tokens = input_tokens;
            request.output_tokens = output_tokens;
            request.business_value_microunits = value;
            request.budget_limit_microunits = budget;
            request.risk_bps = risk;
            request.confidence_bps = confidence;
            request.minimum_quality_bps = minimum_quality;
            request.max_p95_latency_ms = maximum_latency;
            request.allowed_provider_mask = provider_mask;
            request.required_region_mask = region_mask;
            let snapshot = snapshot();
            prop_assert_eq!(snapshot.prescribe(request), prescribe_reference(&snapshot, request));
        }

        #[test]
        fn arbitrary_inputs_never_bypass_provider_fence(
            input_tokens in any::<u32>(),
            output_tokens in any::<u32>(),
            value in any::<i64>(),
            budget in any::<u64>(),
            risk in any::<u16>(),
            confidence in any::<u16>(),
        ) {
            let mut request = input();
            request.input_tokens = input_tokens;
            request.output_tokens = output_tokens;
            request.business_value_microunits = value;
            request.budget_limit_microunits = budget;
            request.risk_bps = risk;
            request.confidence_bps = confidence;
            request.allowed_provider_mask = 0;
            let decision = snapshot().prescribe(request);
            prop_assert_eq!(decision.action, KernelAction::Reject);
        }
    }

    #[test]
    fn provider_id_above_64_rejected_even_with_all_providers() {
        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 65,
            quality_bps: 9500,
            risk_ceiling_bps: 10000,
            enabled: 1,
            p95_latency_ms: 500,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::new(1, 1, 9600, 5500, 3500, 0, models);
        let mut request = input();
        request.allowed_provider_mask = ALL_PROVIDERS;
        let decision = snapshot.prescribe(request);
        assert_eq!(
            decision.action,
            KernelAction::Reject,
            "provider_id >= 64 must be rejected even when mask is ALL_PROVIDERS"
        );
    }

    #[test]
    fn provider_id_below_64_accepted_with_all_providers() {
        let mut request = input();
        request.allowed_provider_mask = ALL_PROVIDERS;
        let decision = snapshot().prescribe(request);
        assert_ne!(
            decision.action,
            KernelAction::Reject,
            "provider_id < 64 with ALL_PROVIDERS should not be rejected by provider fence"
        );
    }

    #[test]
    #[ignore = "release-only kernel guard"]
    fn prescriptive_kernel_latency_guard() {
        let snapshot = snapshot();
        let base = input();
        let iterations = 1_000_000_u64;
        let started = Instant::now();
        for sequence in 0..iterations {
            let mut request = base;
            request.request_sequence = sequence;
            request.input_tokens = 1_000 + (sequence % 1_024) as u32;
            black_box(snapshot.prescribe(black_box(request)));
        }
        let average_ns = started.elapsed().as_nanos() / u128::from(iterations);
        assert!(
            average_ns < 2_000,
            "prescriptive kernel exceeded 2us average guard: {average_ns}ns"
        );
    }
}
