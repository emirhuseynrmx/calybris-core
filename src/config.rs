//! Runtime configuration for policy tuning and budget limits.
//!
//! [`crate::config::EngineConfig`] centralizes knobs that operators adjust without recompiling:
//! latency penalty, exposure caps, WAL durability, and policy bounds.

use crate::kernel::{MAX_BPS, MAX_RISK_PENALTY_MULTIPLIER_BPS};

/// Runtime configuration for the decision engine.
///
/// All fields have safe defaults via [`Default`]. Use the builder methods
/// to override only what you need:
///
/// ```
/// use calybris_core::config::EngineConfig;
///
/// let config = EngineConfig::new()
///     .latency_penalty(5)
///     .default_exposure_cap(500_000_000)
///     .wal_sync_on_append(true);
/// ```
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Latency penalty in microunits per millisecond of p95 latency.
    pub latency_penalty_microunits_per_ms: u64,
    /// Hard risk limit in basis points (requests at or above this are rejected).
    pub hard_risk_limit_bps: u16,
    /// Minimum confidence in basis points (requests below this are rejected).
    pub minimum_confidence_bps: u16,
    /// Risk penalty multiplier in basis points.
    pub risk_penalty_multiplier_bps: u16,
    /// Default per-tenant exposure cap in microcents (0 = unlimited).
    pub default_exposure_cap_microcents: i64,
    /// Whether WAL should fsync after every append (durability vs throughput).
    pub wal_sync_on_append: bool,
    /// Maximum models in a single catalog (sanity bound).
    pub max_catalog_size: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            latency_penalty_microunits_per_ms: 2,
            hard_risk_limit_bps: 9_600,
            minimum_confidence_bps: 5_500,
            risk_penalty_multiplier_bps: 3_500,
            default_exposure_cap_microcents: 0,
            wal_sync_on_append: false,
            max_catalog_size: 1_024,
        }
    }
}

/// Validation errors for [`EngineConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{field} = {value} exceeds max {max}")]
    OutOfRange {
        field: &'static str,
        value: u16,
        max: u16,
    },
    #[error("max_catalog_size must be > 0")]
    ZeroCatalogSize,
    #[error("default_exposure_cap_microcents must be >= 0")]
    NegativeExposureCap,
}

impl EngineConfig {
    /// Create a config with safe defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set latency penalty (microunits per ms).
    #[must_use]
    pub fn latency_penalty(mut self, microunits_per_ms: u64) -> Self {
        self.latency_penalty_microunits_per_ms = microunits_per_ms;
        self
    }

    /// Set hard risk limit (basis points, max 10_000).
    #[must_use]
    pub fn hard_risk_limit(mut self, bps: u16) -> Self {
        self.hard_risk_limit_bps = bps;
        self
    }

    /// Set minimum confidence (basis points, max 10_000).
    #[must_use]
    pub fn minimum_confidence(mut self, bps: u16) -> Self {
        self.minimum_confidence_bps = bps;
        self
    }

    /// Set risk penalty multiplier (basis points, max 50_000).
    #[must_use]
    pub fn risk_penalty_multiplier(mut self, bps: u16) -> Self {
        self.risk_penalty_multiplier_bps = bps;
        self
    }

    /// Set default per-tenant exposure cap (0 = unlimited).
    #[must_use]
    pub fn default_exposure_cap(mut self, microcents: i64) -> Self {
        self.default_exposure_cap_microcents = microcents;
        self
    }

    /// Enable fsync after every WAL append.
    #[must_use]
    pub fn wal_sync_on_append(mut self, sync: bool) -> Self {
        self.wal_sync_on_append = sync;
        self
    }

    /// Set maximum catalog size.
    #[must_use]
    pub fn max_catalog_size(mut self, size: usize) -> Self {
        self.max_catalog_size = size;
        self
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hard_risk_limit_bps > MAX_BPS {
            return Err(ConfigError::OutOfRange {
                field: "hard_risk_limit_bps",
                value: self.hard_risk_limit_bps,
                max: MAX_BPS,
            });
        }
        if self.minimum_confidence_bps > MAX_BPS {
            return Err(ConfigError::OutOfRange {
                field: "minimum_confidence_bps",
                value: self.minimum_confidence_bps,
                max: MAX_BPS,
            });
        }
        if self.risk_penalty_multiplier_bps > MAX_RISK_PENALTY_MULTIPLIER_BPS {
            return Err(ConfigError::OutOfRange {
                field: "risk_penalty_multiplier_bps",
                value: self.risk_penalty_multiplier_bps,
                max: MAX_RISK_PENALTY_MULTIPLIER_BPS,
            });
        }
        if self.max_catalog_size == 0 {
            return Err(ConfigError::ZeroCatalogSize);
        }
        if self.default_exposure_cap_microcents < 0 {
            return Err(ConfigError::NegativeExposureCap);
        }
        Ok(())
    }

    /// Initialize a tenant on a [`crate::budget::BudgetEngine`] with config-driven defaults.
    ///
    /// Applies `default_exposure_cap_microcents` if set (> 0).
    pub fn ensure_tenant(
        &self,
        budget: &crate::budget::BudgetEngine,
        tenant_id: &str,
        initial_microcents: i64,
    ) {
        budget.ensure_tenant(tenant_id, initial_microcents);
        if self.default_exposure_cap_microcents > 0 {
            budget.set_max_reserved_microcents(tenant_id, self.default_exposure_cap_microcents);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        EngineConfig::new().validate().unwrap();
    }

    #[test]
    fn builder_chain_works() {
        let config = EngineConfig::new()
            .latency_penalty(10)
            .hard_risk_limit(9_000)
            .minimum_confidence(6_000)
            .risk_penalty_multiplier(5_000)
            .default_exposure_cap(1_000_000)
            .wal_sync_on_append(true)
            .max_catalog_size(512);
        config.validate().unwrap();
        assert_eq!(config.latency_penalty_microunits_per_ms, 10);
        assert_eq!(config.hard_risk_limit_bps, 9_000);
        assert!(config.wal_sync_on_append);
    }

    #[test]
    fn ensure_tenant_applies_exposure_cap() {
        let config = EngineConfig::new().default_exposure_cap(500_000);
        let budget = crate::budget::BudgetEngine::new();
        config.ensure_tenant(&budget, "desk", 1_000_000);
        assert_eq!(budget.remaining_microcents("desk"), Some(1_000_000));
        let (_, id) = budget.try_reserve("desk", 500_001);
        assert!(id.is_none());
    }

    #[test]
    fn rejects_out_of_range_bps() {
        let config = EngineConfig::new().hard_risk_limit(10_001);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::OutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_zero_catalog() {
        let config = EngineConfig::new().max_catalog_size(0);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ZeroCatalogSize)
        ));
    }

    #[test]
    fn rejects_negative_exposure_cap() {
        let config = EngineConfig::new().default_exposure_cap(-1);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::NegativeExposureCap)
        ));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_valid_configs_always_validate(
            latency in 0_u64..1_000_000,
            risk in 0_u16..=10_000,
            conf in 0_u16..=10_000,
            penalty in 0_u16..=50_000,
            cap in 0_i64..i64::MAX,
            catalog in 1_usize..10_000,
        ) {
            let config = EngineConfig::new()
                .latency_penalty(latency)
                .hard_risk_limit(risk)
                .minimum_confidence(conf)
                .risk_penalty_multiplier(penalty)
                .default_exposure_cap(cap)
                .max_catalog_size(catalog);
            prop_assert!(config.validate().is_ok());
        }

        #[test]
        fn config_roundtrips_through_builder(
            latency in any::<u64>(),
            risk in any::<u16>(),
        ) {
            let config = EngineConfig::new()
                .latency_penalty(latency)
                .hard_risk_limit(risk);
            prop_assert_eq!(config.latency_penalty_microunits_per_ms, latency);
            prop_assert_eq!(config.hard_risk_limit_bps, risk);
        }
    }
}
