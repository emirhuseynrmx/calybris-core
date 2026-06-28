//! Builder ergonomics for [`KernelInput`] and [`PolicySnapshot`].
//!
//! Makes it hard to forget a required field — the compiler enforces it.
//! Optional fields have safe defaults.

use crate::kernel::*;

/// Builder for [`KernelInput`] with safe defaults for optional fields.
///
/// ```
/// use calybris_core::builder::InputBuilder;
/// use calybris_core::kernel::ALL_PROVIDERS;
///
/// let input = InputBuilder::new(1, 1)
///     .tokens(1000, 500)
///     .business_value(100_000)
///     .budget_limit(50_000_000)
///     .risk(1000, 9000)
///     .minimum_quality(5000)
///     .build();
///
/// assert_eq!(input.request_sequence, 1);
/// assert_eq!(input.allowed_provider_mask, ALL_PROVIDERS);
/// ```
pub struct InputBuilder {
    input: KernelInput,
}

impl InputBuilder {
    /// Start building an input. `sequence` and `model_id` are required.
    #[must_use]
    pub fn new(request_sequence: u64, requested_model_id: u32) -> Self {
        Self {
            input: KernelInput {
                request_sequence,
                requested_model_id,
                input_tokens: 0,
                output_tokens: 0,
                business_value_microunits: 0,
                budget_limit_microunits: u64::MAX,
                risk_bps: 0,
                confidence_bps: BASIS_POINTS as u16,
                minimum_quality_bps: 0,
                max_p95_latency_ms: 0,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            },
        }
    }

    #[must_use]
    pub fn tokens(mut self, input: u32, output: u32) -> Self {
        self.input.input_tokens = input;
        self.input.output_tokens = output;
        self
    }

    #[must_use]
    pub fn business_value(mut self, microunits: i64) -> Self {
        self.input.business_value_microunits = microunits;
        self
    }

    #[must_use]
    pub fn budget_limit(mut self, microunits: u64) -> Self {
        self.input.budget_limit_microunits = microunits;
        self
    }

    /// Set risk and confidence in basis points.
    #[must_use]
    pub fn risk(mut self, risk_bps: u16, confidence_bps: u16) -> Self {
        self.input.risk_bps = risk_bps;
        self.input.confidence_bps = confidence_bps;
        self
    }

    #[must_use]
    pub fn minimum_quality(mut self, bps: u16) -> Self {
        self.input.minimum_quality_bps = bps;
        self
    }

    #[must_use]
    pub fn max_latency(mut self, ms: u32) -> Self {
        self.input.max_p95_latency_ms = ms;
        self
    }

    #[must_use]
    pub fn capabilities(mut self, mask: u64) -> Self {
        self.input.required_capabilities = mask;
        self
    }

    #[must_use]
    pub fn providers(mut self, mask: u64) -> Self {
        self.input.allowed_provider_mask = mask;
        self
    }

    #[must_use]
    pub fn regions(mut self, mask: u64) -> Self {
        self.input.required_region_mask = mask;
        self
    }

    /// Consume the builder and return a [`KernelInput`].
    #[must_use]
    pub fn build(self) -> KernelInput {
        self.input
    }
}

/// Builder for [`KernelModel`] with safe defaults.
///
/// ```
/// use calybris_core::builder::ModelBuilder;
///
/// let model = ModelBuilder::new(1, 0)
///     .quality(9000)
///     .latency(200)
///     .cost(250, 1000)
///     .build();
///
/// assert_eq!(model.model_id, 1);
/// assert_eq!(model.enabled, 1);
/// ```
pub struct ModelBuilder {
    model: KernelModel,
}

impl ModelBuilder {
    /// Start building a model. `model_id` and `provider_id` are required.
    #[must_use]
    pub fn new(model_id: u32, provider_id: u16) -> Self {
        Self {
            model: KernelModel {
                model_id,
                provider_id,
                quality_bps: 8_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 0,
                output_cost_microunits_per_million_tokens: 0,
            },
        }
    }

    #[must_use]
    pub fn quality(mut self, bps: u16) -> Self {
        self.model.quality_bps = bps;
        self
    }

    #[must_use]
    pub fn risk_ceiling(mut self, bps: u16) -> Self {
        self.model.risk_ceiling_bps = bps;
        self
    }

    #[must_use]
    pub fn enabled(mut self, yes: bool) -> Self {
        self.model.enabled = u8::from(yes);
        self
    }

    #[must_use]
    pub fn latency(mut self, p95_ms: u32) -> Self {
        self.model.p95_latency_ms = p95_ms;
        self
    }

    #[must_use]
    pub fn capabilities(mut self, mask: u64) -> Self {
        self.model.capabilities = mask;
        self
    }

    #[must_use]
    pub fn regions(mut self, mask: u64) -> Self {
        self.model.region_mask = mask;
        self
    }

    /// Set input and output cost per million tokens (microunits).
    #[must_use]
    pub fn cost(mut self, input_per_m: u64, output_per_m: u64) -> Self {
        self.model.input_cost_microunits_per_million_tokens = input_per_m;
        self.model.output_cost_microunits_per_million_tokens = output_per_m;
        self
    }

    /// Consume the builder and return a [`KernelModel`].
    #[must_use]
    pub fn build(self) -> KernelModel {
        self.model
    }
}

/// Errors from [`PolicyBuilder::build`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("policy error: {0}")]
    Policy(#[from] crate::kernel::PolicyError),
    #[error("catalog too large: {len} models exceeds max_catalog_size {max}")]
    CatalogTooLarge { len: usize, max: usize },
}

/// Build a [`PolicySnapshot`] from config + models with validation.
///
/// ```
/// use calybris_core::builder::{PolicyBuilder, ModelBuilder};
/// use calybris_core::config::EngineConfig;
///
/// let snapshot = PolicyBuilder::new(EngineConfig::new())
///     .epochs(1, 1)
///     .model(ModelBuilder::new(1, 0).quality(9000).cost(250, 1000).build())
///     .model(ModelBuilder::new(2, 1).quality(7000).cost(25, 125).build())
///     .build()
///     .unwrap();
///
/// assert_eq!(snapshot.models().len(), 2);
/// ```
pub struct PolicyBuilder {
    config: crate::config::EngineConfig,
    policy_epoch: u64,
    catalog_epoch: u64,
    models: Vec<KernelModel>,
}

impl PolicyBuilder {
    /// Start building a policy from an [`EngineConfig`].
    #[must_use]
    pub fn new(config: crate::config::EngineConfig) -> Self {
        Self {
            config,
            policy_epoch: 1,
            catalog_epoch: 1,
            models: Vec::new(),
        }
    }

    /// Set policy and catalog epochs.
    #[must_use]
    pub fn epochs(mut self, policy: u64, catalog: u64) -> Self {
        self.policy_epoch = policy;
        self.catalog_epoch = catalog;
        self
    }

    /// Add a model to the catalog.
    #[must_use]
    pub fn model(mut self, model: KernelModel) -> Self {
        self.models.push(model);
        self
    }

    /// Add multiple models.
    #[must_use]
    pub fn models(mut self, models: impl IntoIterator<Item = KernelModel>) -> Self {
        self.models.extend(models);
        self
    }

    /// Build and validate the snapshot.
    ///
    /// Validates config, enforces `max_catalog_size`, then delegates to
    /// [`PolicySnapshot::try_new`] for policy-level validation.
    pub fn build(self) -> Result<PolicySnapshot, BuildError> {
        self.config.validate()?;
        if self.models.len() > self.config.max_catalog_size {
            return Err(BuildError::CatalogTooLarge {
                len: self.models.len(),
                max: self.config.max_catalog_size,
            });
        }
        Ok(PolicySnapshot::try_new(
            self.policy_epoch,
            self.catalog_epoch,
            self.config.hard_risk_limit_bps,
            self.config.minimum_confidence_bps,
            self.config.risk_penalty_multiplier_bps,
            self.config.latency_penalty_microunits_per_ms,
            self.models,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_builder_defaults() {
        let input = InputBuilder::new(1, 10).tokens(500, 200).build();
        assert_eq!(input.request_sequence, 1);
        assert_eq!(input.requested_model_id, 10);
        assert_eq!(input.input_tokens, 500);
        assert_eq!(input.allowed_provider_mask, ALL_PROVIDERS);
        assert_eq!(input.required_region_mask, 0);
        assert_eq!(input.budget_limit_microunits, u64::MAX);
    }

    #[test]
    fn model_builder_defaults() {
        let model = ModelBuilder::new(1, 0).cost(100, 400).build();
        assert_eq!(model.model_id, 1);
        assert_eq!(model.enabled, 1);
        assert_eq!(model.quality_bps, 8_000);
        assert_eq!(model.risk_ceiling_bps, 9_500);
    }

    #[test]
    fn policy_builder_roundtrip() {
        let config = crate::config::EngineConfig::new();
        let snap = PolicyBuilder::new(config)
            .epochs(7, 11)
            .model(
                ModelBuilder::new(1, 0)
                    .quality(9000)
                    .cost(250, 1000)
                    .build(),
            )
            .model(ModelBuilder::new(2, 1).quality(7000).cost(25, 125).build())
            .build()
            .unwrap();
        assert_eq!(snap.policy_epoch, 7);
        assert_eq!(snap.models().len(), 2);
    }

    #[test]
    fn builder_integrates_with_prescribe() {
        let config = crate::config::EngineConfig::new();
        let snap = PolicyBuilder::new(config)
            .model(ModelBuilder::new(1, 0).quality(9000).cost(100, 400).build())
            .build()
            .unwrap();
        let input = InputBuilder::new(1, 1)
            .tokens(1000, 500)
            .business_value(100_000)
            .risk(1000, 9000)
            .minimum_quality(5000)
            .build();
        let decision = snap.prescribe(input);
        assert!(decision.is_executable());
    }

    #[test]
    fn disabled_model_via_builder() {
        let model = ModelBuilder::new(1, 0).enabled(false).build();
        assert_eq!(model.enabled, 0);
    }

    #[test]
    fn catalog_too_large_rejected() {
        let config = crate::config::EngineConfig::new().max_catalog_size(1);
        let result = PolicyBuilder::new(config)
            .model(ModelBuilder::new(1, 0).cost(100, 400).build())
            .model(ModelBuilder::new(2, 1).cost(10, 40).build())
            .build();
        assert!(matches!(result, Err(BuildError::CatalogTooLarge { .. })));
    }

    #[test]
    fn invalid_config_rejected_at_build() {
        let config = crate::config::EngineConfig::new().hard_risk_limit(10_001);
        let result = PolicyBuilder::new(config)
            .model(ModelBuilder::new(1, 0).cost(100, 400).build())
            .build();
        assert!(matches!(result, Err(BuildError::Config(_))));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn builder_prescribe_never_panics(
            seq in any::<u64>(),
            model_id in 1_u32..=2,
            input_tokens in any::<u32>(),
            output_tokens in any::<u32>(),
            value in any::<i64>(),
            risk in any::<u16>(),
            confidence in any::<u16>(),
        ) {
            let config = crate::config::EngineConfig::new();
            let snap = PolicyBuilder::new(config)
                .model(ModelBuilder::new(1, 0).quality(9000).cost(100, 400).build())
                .model(ModelBuilder::new(2, 1).quality(7000).cost(10, 40).build())
                .build()
                .unwrap();
            let input = InputBuilder::new(seq, model_id)
                .tokens(input_tokens, output_tokens)
                .business_value(value)
                .risk(risk, confidence)
                .build();
            let _ = snap.prescribe(input);
        }
    }
}
