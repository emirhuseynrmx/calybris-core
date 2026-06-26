//! Allocation-free prescriptive decision kernel.
//!
//! This module deliberately contains no HTTP, JSON, UUID, WAL, clock, or floating-point work.
//! Snapshots may allocate when they are built; [`PolicySnapshot::prescribe`] does not allocate.
//!
//! # Performance
//!
//! 8.6M decisions/sec on a single core (115ns per decision, 22-model catalog).
//! All arithmetic is `u64`/`i64`/`i128` — no `f64` anywhere in the hot path.
//!
//! # Safety
//!
//! 11 constraint gates are evaluated per decision. If no model passes all gates
//! with positive utility, the request is rejected (fail-closed).

use std::sync::Arc;

/// One basis point = 1/10,000. Used for quality, risk, and confidence values.
pub const BASIS_POINTS: u64 = 10_000;
const SCALED_BASIS_POINTS: u64 = BASIS_POINTS * BASIS_POINTS;
const COST_SCALE: u64 = 1_000_000;
const COST_ROUNDING: u64 = COST_SCALE - 1;
/// Bitmask that admits all providers (all 64 bits set).
pub const ALL_PROVIDERS: u64 = u64::MAX;
/// Bitmask that admits all regions (all 64 bits set).
pub const ALL_REGIONS: u64 = u64::MAX;
/// Maximum representable provider ID. IDs >= 64 are unconditionally rejected.
pub const MAX_PROVIDER_ID: u16 = 63;

/// A candidate model in the decision catalog.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelModel {
    /// Unique identifier for this model.
    pub model_id: u32,
    /// Provider index (0–63). IDs > [`MAX_PROVIDER_ID`] are rejected.
    pub provider_id: u16,
    /// Quality score in basis points (0–10,000).
    pub quality_bps: u16,
    /// Maximum risk this model can handle, in basis points.
    pub risk_ceiling_bps: u16,
    /// 1 = enabled, 0 = disabled (skipped during evaluation).
    pub enabled: u8,
    /// 95th-percentile latency in milliseconds.
    pub p95_latency_ms: u32,
    /// Bitmask of capabilities this model supports.
    pub capabilities: u64,
    /// Bitmask of regions where this model is available.
    pub region_mask: u64,
    /// Input cost per million tokens, in microunits (1 cent = 1,000,000).
    pub input_cost_microunits_per_million_tokens: u64,
    /// Output cost per million tokens, in microunits.
    pub output_cost_microunits_per_million_tokens: u64,
}

/// A decision request to be evaluated against the policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelInput {
    /// Monotonic sequence number for this request.
    pub request_sequence: u64,
    /// The model the caller originally requested.
    pub requested_model_id: u32,
    /// Number of input tokens.
    pub input_tokens: u32,
    /// Number of output tokens.
    pub output_tokens: u32,
    /// Expected business value of this request, in microunits.
    pub business_value_microunits: i64,
    /// Maximum cost allowed, in microunits.
    pub budget_limit_microunits: u64,
    /// Risk level of this request, in basis points (0 = safe, 10,000 = max).
    pub risk_bps: u16,
    /// Confidence in the risk estimate, in basis points.
    pub confidence_bps: u16,
    /// Minimum acceptable quality, in basis points.
    pub minimum_quality_bps: u16,
    /// Maximum acceptable p95 latency (0 = no limit).
    pub max_p95_latency_ms: u32,
    /// Required capability bitmask (all bits must match).
    pub required_capabilities: u64,
    /// Allowed provider bitmask ([`ALL_PROVIDERS`] = any).
    pub allowed_provider_mask: u64,
    /// Required region bitmask (0 = no constraint).
    pub required_region_mask: u64,
}

/// The action the kernel decided to take.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KernelAction {
    /// The requested model was selected (it maximized utility).
    ExecuteRequested = 1,
    /// A different model was selected (it had higher utility).
    Substitute = 2,
    /// No model passed all constraints with positive utility.
    Reject = 3,
}

impl std::fmt::Display for KernelAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecuteRequested => write!(f, "execute_requested"),
            Self::Substitute => write!(f, "substitute"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

/// Why the kernel made this decision.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KernelReason {
    /// The requested model had the highest utility.
    RequestedModelMaximizesUtility = 1,
    /// A substitute model had higher utility.
    AlternativeMaximizesUtility = 2,
    /// Request risk exceeded the hard limit.
    RiskHardLimit = 100,
    /// Request confidence was below the minimum.
    ConfidenceHardLimit = 101,
    /// No enabled models in the catalog.
    NoEnabledModel = 102,
    /// All models failed the quality floor.
    QualityConstraint = 103,
    /// All models exceeded the latency cap.
    LatencyConstraint = 104,
    /// No model had the required capabilities.
    CapabilityConstraint = 105,
    /// No model matched the allowed provider mask.
    ProviderConstraint = 106,
    /// No model matched the required region mask.
    RegionConstraint = 107,
    /// All models exceeded the budget limit.
    BudgetConstraint = 108,
    /// All eligible models had non-positive utility.
    NonPositiveUtility = 109,
    /// Request risk exceeded the model's risk ceiling.
    RiskCeilingConstraint = 110,
}

impl std::fmt::Display for KernelReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestedModelMaximizesUtility => write!(f, "requested_model_maximizes_utility"),
            Self::AlternativeMaximizesUtility => write!(f, "alternative_maximizes_utility"),
            Self::RiskHardLimit => write!(f, "risk_hard_limit"),
            Self::ConfidenceHardLimit => write!(f, "confidence_hard_limit"),
            Self::NoEnabledModel => write!(f, "no_enabled_model"),
            Self::QualityConstraint => write!(f, "quality_constraint"),
            Self::LatencyConstraint => write!(f, "latency_constraint"),
            Self::CapabilityConstraint => write!(f, "capability_constraint"),
            Self::ProviderConstraint => write!(f, "provider_constraint"),
            Self::RegionConstraint => write!(f, "region_constraint"),
            Self::BudgetConstraint => write!(f, "budget_constraint"),
            Self::NonPositiveUtility => write!(f, "non_positive_utility"),
            Self::RiskCeilingConstraint => write!(f, "risk_ceiling_constraint"),
        }
    }
}

/// The result of evaluating a [`KernelInput`] against a [`PolicySnapshot`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelDecision {
    /// Echoed from the input.
    pub request_sequence: u64,
    /// What to do: execute, substitute, or reject.
    pub action: KernelAction,
    /// Why this action was chosen.
    pub reason: KernelReason,
    /// The model that was selected (0 if rejected).
    pub selected_model_id: u32,
    /// Index of the selected model in the catalog.
    pub selected_model_index: u16,
    /// Estimated cost of the selected model, in microunits.
    pub estimated_cost_microunits: u64,
    /// Expected utility of the selected model.
    pub expected_utility_microunits: i64,
    /// The second-best model (for counterfactual analysis).
    pub counterfactual_model_id: u32,
    /// Utility of the counterfactual model.
    pub counterfactual_utility_microunits: i64,
    /// How many models were evaluated.
    pub evaluated_models: u16,
    /// How many models passed all constraints.
    pub eligible_models: u16,
    /// Policy version used for this decision.
    pub policy_epoch: u64,
    /// Catalog version used for this decision.
    pub catalog_epoch: u64,
}

/// An immutable snapshot of the decision policy and model catalog.
///
/// Create with [`PolicySnapshot::try_new`] (validated) or [`PolicySnapshot::new_unchecked`],
/// then call [`prescribe`](PolicySnapshot::prescribe)
/// for each request. The snapshot is `Clone` and can be shared across threads via `Arc`.
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

/// Per-constraint rejection counts from a single prescribe evaluation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RejectionHistogram {
    /// Models skipped because `enabled == 0`.
    pub disabled: u16,
    /// Models below `minimum_quality_bps`.
    pub quality: u16,
    /// Models where request risk exceeds model risk ceiling.
    pub risk_ceiling: u16,
    /// Models above latency cap.
    pub latency: u16,
    /// Models missing required capabilities.
    pub capability: u16,
    /// Models filtered by provider mask or unrepresentable provider id.
    pub provider: u16,
    /// Models filtered by region mask.
    pub region: u16,
    /// Models above budget limit.
    pub budget: u16,
    /// Eligible models with non-positive utility.
    pub utility: u16,
}

/// Explainability snapshot for a prescribe call (alloc-free alongside decision).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DecisionTrace {
    pub rejections: RejectionHistogram,
    pub evaluated_models: u16,
    pub eligible_models: u16,
}

/// Maximum basis-points value accepted by policy validation (100%).
pub const MAX_BPS: u16 = 10_000;

/// Upper bound for [`PolicySnapshot::risk_penalty_multiplier_bps`] validation.
pub const MAX_RISK_PENALTY_MULTIPLIER_BPS: u16 = 50_000;

/// Policy catalog validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("model catalog is empty")]
    EmptyCatalog,
    #[error("duplicate model_id {model_id}")]
    DuplicateModelId { model_id: u32 },
    #[error("model_id {model_id} has provider_id {provider_id} > MAX_PROVIDER_ID")]
    InvalidProviderId { model_id: u32, provider_id: u16 },
    #[error("no enabled models in catalog")]
    NoEnabledModels,
    #[error("{field} must be <= {max}, got {value}")]
    OutOfRangeBps {
        field: &'static str,
        value: u16,
        max: u16,
    },
}

type RejectionCounts = RejectionHistogram;

impl PolicySnapshot {
    /// Creates a policy snapshot without validation.
    ///
    /// Prefer [`try_new`](Self::try_new) for production traffic. This constructor
    /// may produce invalid policy parameters or catalog invariants.
    pub fn new_unchecked(
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

    /// Creates a new policy snapshot from a model catalog (alias for [`new_unchecked`](Self::new_unchecked)).
    #[deprecated(
        since = "0.3.9",
        note = "use PolicySnapshot::try_new for validated snapshots or new_unchecked for tests"
    )]
    pub fn new(
        policy_epoch: u64,
        catalog_epoch: u64,
        hard_risk_limit_bps: u16,
        minimum_confidence_bps: u16,
        risk_penalty_multiplier_bps: u16,
        latency_penalty_microunits_per_ms: u64,
        models: Vec<KernelModel>,
    ) -> Self {
        Self::new_unchecked(
            policy_epoch,
            catalog_epoch,
            hard_risk_limit_bps,
            minimum_confidence_bps,
            risk_penalty_multiplier_bps,
            latency_penalty_microunits_per_ms,
            models,
        )
    }

    /// Returns the model catalog.
    pub fn models(&self) -> &[KernelModel] {
        &self.models
    }

    /// Validate catalog and basis-point invariants before serving traffic.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.hard_risk_limit_bps > MAX_BPS {
            return Err(PolicyError::OutOfRangeBps {
                field: "hard_risk_limit_bps",
                value: self.hard_risk_limit_bps,
                max: MAX_BPS,
            });
        }
        if self.minimum_confidence_bps > MAX_BPS {
            return Err(PolicyError::OutOfRangeBps {
                field: "minimum_confidence_bps",
                value: self.minimum_confidence_bps,
                max: MAX_BPS,
            });
        }
        if self.risk_penalty_multiplier_bps > MAX_RISK_PENALTY_MULTIPLIER_BPS {
            return Err(PolicyError::OutOfRangeBps {
                field: "risk_penalty_multiplier_bps",
                value: self.risk_penalty_multiplier_bps,
                max: MAX_RISK_PENALTY_MULTIPLIER_BPS,
            });
        }
        if self.models.is_empty() {
            return Err(PolicyError::EmptyCatalog);
        }
        let mut seen = std::collections::HashSet::new();
        let mut any_enabled = false;
        for model in self.models.iter() {
            if !seen.insert(model.model_id) {
                return Err(PolicyError::DuplicateModelId {
                    model_id: model.model_id,
                });
            }
            if model.provider_id > MAX_PROVIDER_ID {
                return Err(PolicyError::InvalidProviderId {
                    model_id: model.model_id,
                    provider_id: model.provider_id,
                });
            }
            if model.quality_bps > MAX_BPS {
                return Err(PolicyError::OutOfRangeBps {
                    field: "model.quality_bps",
                    value: model.quality_bps,
                    max: MAX_BPS,
                });
            }
            if model.risk_ceiling_bps > MAX_BPS {
                return Err(PolicyError::OutOfRangeBps {
                    field: "model.risk_ceiling_bps",
                    value: model.risk_ceiling_bps,
                    max: MAX_BPS,
                });
            }
            if model.enabled != 0 {
                any_enabled = true;
            }
        }
        if !any_enabled {
            return Err(PolicyError::NoEnabledModels);
        }
        Ok(())
    }

    /// Build a snapshot and validate the catalog.
    pub fn try_new(
        policy_epoch: u64,
        catalog_epoch: u64,
        hard_risk_limit_bps: u16,
        minimum_confidence_bps: u16,
        risk_penalty_multiplier_bps: u16,
        latency_penalty_microunits_per_ms: u64,
        models: Vec<KernelModel>,
    ) -> Result<Self, PolicyError> {
        let snapshot = Self::new_unchecked(
            policy_epoch,
            catalog_epoch,
            hard_risk_limit_bps,
            minimum_confidence_bps,
            risk_penalty_multiplier_bps,
            latency_penalty_microunits_per_ms,
            models,
        );
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Evaluate many inputs. Allocates the output vector only.
    pub fn prescribe_batch(&self, inputs: &[KernelInput]) -> Vec<KernelDecision> {
        inputs.iter().map(|&input| self.prescribe(input)).collect()
    }

    /// Evaluate `input` and return decision plus rejection histogram.
    pub fn prescribe_with_trace(&self, input: KernelInput) -> (KernelDecision, DecisionTrace) {
        let (decision, rejections) = self.prescribe_inner(input);
        let trace = DecisionTrace {
            rejections,
            evaluated_models: decision.evaluated_models,
            eligible_models: decision.eligible_models,
        };
        (decision, trace)
    }

    /// Evaluate `input` against the policy and return the optimal decision.
    ///
    /// The kernel checks 11 constraint gates per candidate, computes utility as
    /// `quality_adjusted_value - risk_penalty - cost - latency_penalty`,
    /// and selects the candidate with the highest positive utility.
    ///
    /// If no candidate has positive utility, the request is rejected (fail-closed).
    /// The decision also records the counterfactual (second-best) candidate.
    ///
    /// **This function does not allocate.**
    #[must_use]
    pub fn prescribe(&self, input: KernelInput) -> KernelDecision {
        self.prescribe_inner(input).0
    }

    fn prescribe_inner(&self, input: KernelInput) -> (KernelDecision, RejectionHistogram) {
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
            if model.provider_id > MAX_PROVIDER_ID {
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
        (
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
            },
            rejected,
        )
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
    ) -> (KernelDecision, RejectionHistogram) {
        (
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
            },
            RejectionHistogram::default(),
        )
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

/// Tie-breaking order: utility > lower cost > higher quality > lower model_id.
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
        PolicySnapshot::new_unchecked(
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
            return snapshot.reject(input, KernelReason::RiskHardLimit, 0, 0).0;
        }
        if input.confidence_bps < snapshot.minimum_confidence_bps {
            return snapshot
                .reject(input, KernelReason::ConfidenceHardLimit, 0, 0)
                .0;
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
            if model.provider_id > MAX_PROVIDER_ID {
                rejected.provider += 1;
                continue;
            }
            if input.allowed_provider_mask != ALL_PROVIDERS
                && input.allowed_provider_mask & (1_u64 << model.provider_id) == 0
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
            return snapshot
                .reject(
                    input,
                    dominant_rejection_reason(&rejected),
                    evaluated_models,
                    eligible_models,
                )
                .0;
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

    fn base_model(model_id: u32, enabled: u8) -> KernelModel {
        KernelModel {
            model_id,
            provider_id: 0,
            quality_bps: 8_000,
            risk_ceiling_bps: 9_500,
            enabled,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }
    }

    #[test]
    fn policy_error_empty_catalog() {
        let snap = PolicySnapshot::new_unchecked(1, 1, 9_600, 5_500, 3_500, 0, vec![]);
        assert_eq!(snap.validate(), Err(PolicyError::EmptyCatalog));
        assert!(matches!(
            PolicySnapshot::try_new(1, 1, 9_600, 5_500, 3_500, 0, vec![]),
            Err(PolicyError::EmptyCatalog)
        ));
    }

    #[test]
    fn policy_error_duplicate_model_id() {
        let snap = PolicySnapshot::new_unchecked(
            1,
            1,
            9_600,
            5_500,
            3_500,
            0,
            vec![base_model(1, 1), base_model(1, 1)],
        );
        assert_eq!(
            snap.validate(),
            Err(PolicyError::DuplicateModelId { model_id: 1 })
        );
    }

    #[test]
    fn policy_error_invalid_provider_id() {
        let mut model = base_model(1, 1);
        model.provider_id = MAX_PROVIDER_ID + 1;
        let snap = PolicySnapshot::new_unchecked(1, 1, 9_600, 5_500, 3_500, 0, vec![model]);
        assert_eq!(
            snap.validate(),
            Err(PolicyError::InvalidProviderId {
                model_id: 1,
                provider_id: MAX_PROVIDER_ID + 1,
            })
        );
    }

    #[test]
    fn policy_error_no_enabled_models() {
        let snap = PolicySnapshot::new_unchecked(
            1,
            1,
            9_600,
            5_500,
            3_500,
            0,
            vec![base_model(1, 0), base_model(2, 0)],
        );
        assert_eq!(snap.validate(), Err(PolicyError::NoEnabledModels));
    }

    #[test]
    fn policy_error_out_of_range_bps() {
        let models = vec![base_model(1, 1)];
        assert!(matches!(
            PolicySnapshot::try_new(1, 1, 10_001, 5_500, 3_500, 0, models.clone()),
            Err(PolicyError::OutOfRangeBps { .. })
        ));
        assert!(matches!(
            PolicySnapshot::try_new(1, 1, 9_600, 10_001, 3_500, 0, models.clone()),
            Err(PolicyError::OutOfRangeBps { .. })
        ));
        assert!(matches!(
            PolicySnapshot::try_new(1, 1, 9_600, 5_500, 50_001, 0, models.clone()),
            Err(PolicyError::OutOfRangeBps { .. })
        ));
        let mut bad_quality = base_model(2, 1);
        bad_quality.quality_bps = 10_001;
        assert!(matches!(
            PolicySnapshot::try_new(1, 1, 9_600, 5_500, 3_500, 0, vec![bad_quality]),
            Err(PolicyError::OutOfRangeBps { .. })
        ));
    }

    #[test]
    fn prescribe_batch_matches_individual() {
        let snap = snapshot();
        let inputs = [
            input(),
            KernelInput {
                request_sequence: 2,
                requested_model_id: 10,
                input_tokens: 500,
                output_tokens: 100,
                business_value_microunits: 50_000_000,
                budget_limit_microunits: 5_000_000,
                risk_bps: 500,
                confidence_bps: 9_500,
                minimum_quality_bps: 7_000,
                max_p95_latency_ms: 500,
                required_capabilities: TOOLS,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: REGION_EU,
            },
        ];
        let batch = snap.prescribe_batch(&inputs);
        assert_eq!(batch.len(), inputs.len());
        for (i, &inp) in inputs.iter().enumerate() {
            assert_eq!(batch[i], snap.prescribe(inp));
        }
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
            let snapshot = PolicySnapshot::new_unchecked(1, 1, u16::MAX, 0, 0, 0, vec![model]);
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
        let snapshot = PolicySnapshot::new_unchecked(1, 1, 9600, 5500, 3500, 0, models);
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
