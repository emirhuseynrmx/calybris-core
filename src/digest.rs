//! Canonical SHA-256 digests for cross-platform audit binding.
//!
//! Digests use a versioned byte layout (not JSON) so fingerprints are stable
//! across machines and serde field order.

use std::fmt::Write;

use crate::kernel::{KernelDecision, KernelInput, KernelModel, PolicySnapshot};
use sha2::{Digest, Sha256};

/// Policy snapshot digest format version.
pub const POLICY_DIGEST_TAG: &[u8] = b"calypol1\0";
/// Decision input digest format version.
pub const INPUT_DIGEST_TAG: &[u8] = b"calyinp1\0";
/// Decision output digest format version.
pub const DECISION_DIGEST_TAG: &[u8] = b"calydcn1\0";
/// Budget ledger digest format version.
pub const LEDGER_DIGEST_TAG: &[u8] = b"calyldg1\0";

#[inline]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[inline]
pub fn digest_to_hex(digest: &[u8; 32]) -> String {
    bytes_to_hex(digest)
}

#[inline]
fn finish(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

#[inline]
fn update_model(hasher: &mut Sha256, model: &KernelModel) {
    hasher.update(model.model_id.to_le_bytes());
    hasher.update(model.provider_id.to_le_bytes());
    hasher.update(model.quality_bps.to_le_bytes());
    hasher.update(model.risk_ceiling_bps.to_le_bytes());
    hasher.update(model.enabled.to_le_bytes());
    hasher.update(model.p95_latency_ms.to_le_bytes());
    hasher.update(model.capabilities.to_le_bytes());
    hasher.update(model.region_mask.to_le_bytes());
    hasher.update(model.input_cost_microunits_per_million_tokens.to_le_bytes());
    hasher.update(
        model
            .output_cost_microunits_per_million_tokens
            .to_le_bytes(),
    );
}

/// Canonical SHA-256 digest of a policy snapshot.
///
/// Models are hashed in ascending `model_id` order for determinism.
pub fn policy_digest(snapshot: &PolicySnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DIGEST_TAG);
    hasher.update(snapshot.policy_epoch.to_le_bytes());
    hasher.update(snapshot.catalog_epoch.to_le_bytes());
    hasher.update(snapshot.hard_risk_limit_bps.to_le_bytes());
    hasher.update(snapshot.minimum_confidence_bps.to_le_bytes());
    hasher.update(snapshot.risk_penalty_multiplier_bps.to_le_bytes());
    hasher.update(snapshot.latency_penalty_microunits_per_ms.to_le_bytes());

    let mut models: Vec<&KernelModel> = snapshot.models().iter().collect();
    models.sort_by_key(|m| m.model_id);
    for model in models {
        update_model(&mut hasher, model);
    }
    finish(hasher)
}

/// Canonical SHA-256 digest of a decision input.
pub fn input_digest(input: &KernelInput) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INPUT_DIGEST_TAG);
    hasher.update(input.request_sequence.to_le_bytes());
    hasher.update(input.requested_model_id.to_le_bytes());
    hasher.update(input.input_tokens.to_le_bytes());
    hasher.update(input.output_tokens.to_le_bytes());
    hasher.update(input.business_value_microunits.to_le_bytes());
    hasher.update(input.budget_limit_microunits.to_le_bytes());
    hasher.update(input.risk_bps.to_le_bytes());
    hasher.update(input.confidence_bps.to_le_bytes());
    hasher.update(input.minimum_quality_bps.to_le_bytes());
    hasher.update(input.max_p95_latency_ms.to_le_bytes());
    hasher.update(input.required_capabilities.to_le_bytes());
    hasher.update(input.allowed_provider_mask.to_le_bytes());
    hasher.update(input.required_region_mask.to_le_bytes());
    finish(hasher)
}

/// Canonical SHA-256 digest of a kernel decision (all fields).
pub fn decision_digest(decision: &KernelDecision) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DECISION_DIGEST_TAG);
    hasher.update(decision.request_sequence.to_le_bytes());
    hasher.update([decision.action as u8]);
    hasher.update((decision.reason as u16).to_le_bytes());
    hasher.update(decision.selected_model_id.to_le_bytes());
    hasher.update(decision.selected_model_index.to_le_bytes());
    hasher.update(decision.estimated_cost_microunits.to_le_bytes());
    hasher.update(decision.expected_utility_microunits.to_le_bytes());
    hasher.update(decision.counterfactual_model_id.to_le_bytes());
    hasher.update(decision.counterfactual_utility_microunits.to_le_bytes());
    hasher.update(decision.evaluated_models.to_le_bytes());
    hasher.update(decision.eligible_models.to_le_bytes());
    hasher.update(decision.policy_epoch.to_le_bytes());
    hasher.update(decision.catalog_epoch.to_le_bytes());
    finish(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::*;

    fn snap() -> PolicySnapshot {
        PolicySnapshot::new(
            1,
            2,
            9600,
            5500,
            3500,
            2,
            vec![
                KernelModel {
                    model_id: 2,
                    provider_id: 0,
                    quality_bps: 7000,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 100,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 10,
                    output_cost_microunits_per_million_tokens: 40,
                },
                KernelModel {
                    model_id: 1,
                    provider_id: 0,
                    quality_bps: 9000,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 200,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 20,
                    output_cost_microunits_per_million_tokens: 80,
                },
            ],
        )
    }

    #[test]
    fn policy_digest_order_independent() {
        let a = snap();
        let b = PolicySnapshot::new(
            1,
            2,
            9600,
            5500,
            3500,
            2,
            vec![
                KernelModel {
                    model_id: 1,
                    provider_id: 0,
                    quality_bps: 9000,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 200,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 20,
                    output_cost_microunits_per_million_tokens: 80,
                },
                KernelModel {
                    model_id: 2,
                    provider_id: 0,
                    quality_bps: 7000,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 100,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 10,
                    output_cost_microunits_per_million_tokens: 40,
                },
            ],
        );
        assert_eq!(policy_digest(&a), policy_digest(&b));
    }

    #[test]
    fn digests_are_deterministic() {
        let snap = snap();
        let input = KernelInput {
            request_sequence: 7,
            requested_model_id: 1,
            input_tokens: 100,
            output_tokens: 50,
            business_value_microunits: 10_000,
            budget_limit_microunits: 1_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snap.prescribe(input);
        assert_eq!(policy_digest(&snap), policy_digest(&snap));
        assert_eq!(input_digest(&input), input_digest(&input));
        assert_eq!(decision_digest(&decision), decision_digest(&decision));
    }

    #[test]
    fn input_digest_sensitive_to_single_field_change() {
        let snap = snap();
        let mut input = KernelInput {
            request_sequence: 7,
            requested_model_id: 1,
            input_tokens: 100,
            output_tokens: 50,
            business_value_microunits: 10_000,
            budget_limit_microunits: 1_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let base = input_digest(&input);
        input.input_tokens += 1;
        assert_ne!(input_digest(&input), base);
        let decision = snap.prescribe(input);
        let mut other = decision;
        other.request_sequence = decision.request_sequence.wrapping_add(1);
        assert_ne!(decision_digest(&other), decision_digest(&decision));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn digests_stable_under_repeat(seq in any::<u64>()) {
            let snap = snap();
            let input = KernelInput {
                request_sequence: seq,
                requested_model_id: 1,
                input_tokens: 100,
                output_tokens: 50,
                business_value_microunits: 10_000,
                budget_limit_microunits: 1_000_000,
                risk_bps: 500,
                confidence_bps: 8000,
                minimum_quality_bps: 5000,
                max_p95_latency_ms: 0,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            };
            let d1 = input_digest(&input);
            let d2 = input_digest(&input);
            prop_assert_eq!(d1, d2);
            let decision = snap.prescribe(input);
            prop_assert_eq!(policy_digest(&snap), policy_digest(&snap));
            prop_assert_eq!(decision_digest(&decision), decision_digest(&decision));
        }
    }
}
