//! Decision verification and replay.
//!
//! Provides tools to independently verify that a [`KernelDecision`] was
//! correctly produced from a given [`PolicySnapshot`] and [`KernelInput`].
//!
//! This is the open-core implementation of Level 1 proof (correctness check).

use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use sha2::{Digest, Sha256};

/// Result of verifying a decision against its inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// The decision is correct: replaying the same input produces the same output.
    Valid,
    /// The decision does not match what the policy would produce.
    Mismatch {
        expected_action: crate::kernel::KernelAction,
        expected_model: u32,
        actual_action: crate::kernel::KernelAction,
        actual_model: u32,
    },
}

/// Verify that `decision` is the correct output of `snapshot.prescribe(input)`.
///
/// This is a deterministic replay check: given the same policy and input,
/// the kernel must produce the same decision. If it doesn't, the decision
/// was either tampered with or produced by a different policy version.
///
/// ```rust,no_run
/// use calybris_core::verify::verify_decision;
/// // let result = verify_decision(&snapshot, input, &decision);
/// // assert_eq!(result, VerifyResult::Valid);
/// ```
pub fn verify_decision(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> VerifyResult {
    let replayed = snapshot.prescribe(input);
    if replayed.action == decision.action
        && replayed.selected_model_id == decision.selected_model_id
        && replayed.reason == decision.reason
        && replayed.estimated_cost_microunits == decision.estimated_cost_microunits
        && replayed.expected_utility_microunits == decision.expected_utility_microunits
        && replayed.policy_epoch == decision.policy_epoch
        && replayed.catalog_epoch == decision.catalog_epoch
    {
        VerifyResult::Valid
    } else {
        VerifyResult::Mismatch {
            expected_action: replayed.action,
            expected_model: replayed.selected_model_id,
            actual_action: decision.action,
            actual_model: decision.selected_model_id,
        }
    }
}

/// Compute a fingerprint of a policy snapshot for audit binding.
///
/// The fingerprint is a SHA-256 hash of the policy parameters and model catalog.
/// Two snapshots with the same models and parameters produce the same fingerprint.
pub fn snapshot_fingerprint(snapshot: &PolicySnapshot) -> String {
    let mut hasher = Sha256::new();
    hasher.update(snapshot.policy_epoch.to_le_bytes());
    hasher.update(snapshot.catalog_epoch.to_le_bytes());
    hasher.update(snapshot.hard_risk_limit_bps.to_le_bytes());
    hasher.update(snapshot.minimum_confidence_bps.to_le_bytes());
    hasher.update(snapshot.risk_penalty_multiplier_bps.to_le_bytes());
    hasher.update(snapshot.latency_penalty_microunits_per_ms.to_le_bytes());
    for model in snapshot.models() {
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
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A correctness certificate binding a decision to its policy and input.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CorrectnessCertificate {
    /// SHA-256 fingerprint of the policy snapshot.
    pub policy_fingerprint: String,
    /// The decision that was made.
    pub decision_sequence: u64,
    /// Selected model ID.
    pub selected_model_id: u32,
    /// Action taken.
    pub action: String,
    /// Reason for the action.
    pub reason: String,
    /// Whether replay verification passed.
    pub replay_valid: bool,
    /// Number of models evaluated.
    pub evaluated_models: u16,
    /// Number of eligible models.
    pub eligible_models: u16,
    /// Counterfactual model (second-best).
    pub counterfactual_model_id: u32,
}

/// Generate a correctness certificate for a decision.
///
/// This binds the decision to its policy via fingerprint and includes
/// the replay verification result.
pub fn certify_decision(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> CorrectnessCertificate {
    let fingerprint = snapshot_fingerprint(snapshot);
    let replay = verify_decision(snapshot, input, decision);
    CorrectnessCertificate {
        policy_fingerprint: fingerprint,
        decision_sequence: decision.request_sequence,
        selected_model_id: decision.selected_model_id,
        action: format!("{}", decision.action),
        reason: format!("{}", decision.reason),
        replay_valid: replay == VerifyResult::Valid,
        evaluated_models: decision.evaluated_models,
        eligible_models: decision.eligible_models,
        counterfactual_model_id: decision.counterfactual_model_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::*;

    fn test_snapshot() -> PolicySnapshot {
        PolicySnapshot::new(
            1,
            1,
            9600,
            5500,
            3500,
            2,
            vec![
                KernelModel {
                    model_id: 1,
                    provider_id: 0,
                    quality_bps: 9500,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 450,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 250,
                    output_cost_microunits_per_million_tokens: 1000,
                },
                KernelModel {
                    model_id: 2,
                    provider_id: 1,
                    quality_bps: 7000,
                    risk_ceiling_bps: 9500,
                    enabled: 1,
                    p95_latency_ms: 90,
                    capabilities: 0,
                    region_mask: ALL_REGIONS,
                    input_cost_microunits_per_million_tokens: 25,
                    output_cost_microunits_per_million_tokens: 125,
                },
            ],
        )
    }

    fn test_input() -> KernelInput {
        KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 1000,
            output_tokens: 500,
            business_value_microunits: 100_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 1000,
            confidence_bps: 9000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 1000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        }
    }

    #[test]
    fn valid_decision_verifies() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        assert_eq!(
            verify_decision(&snap, input, &decision),
            VerifyResult::Valid
        );
    }

    #[test]
    fn tampered_decision_detected() {
        let snap = test_snapshot();
        let input = test_input();
        let mut decision = snap.prescribe(input);
        decision.selected_model_id = 99;
        assert_ne!(
            verify_decision(&snap, input, &decision),
            VerifyResult::Valid
        );
    }

    #[test]
    fn fingerprint_deterministic() {
        let snap = test_snapshot();
        assert_eq!(snapshot_fingerprint(&snap), snapshot_fingerprint(&snap));
        assert_eq!(snapshot_fingerprint(&snap).len(), 64);
    }

    #[test]
    fn certificate_generated() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let cert = certify_decision(&snap, input, &decision);
        assert!(cert.replay_valid);
        assert_eq!(cert.decision_sequence, 1);
        assert_eq!(cert.policy_fingerprint.len(), 64);
    }
}
