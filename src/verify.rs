//! Decision verification, replay, and correctness certificates.
//!
//! Level 2 proof: policy digest + input digest + full decision digest + replay.

use crate::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, KernelReason, PolicySnapshot};

/// Result of verifying a decision against its inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// The decision is correct: replaying the same input produces the same output.
    Valid,
    /// The decision does not match what the policy would produce.
    Mismatch {
        expected: KernelDecision,
        actual: KernelDecision,
    },
    /// Decision digest does not match the canonical digest of the decision fields.
    DigestMismatch {
        expected_hex: String,
        actual_hex: String,
    },
}

/// Error decoding a hex-encoded digest from an [`AuditBundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestDecodeError {
    /// A non-hex character was found.
    InvalidHexCharacter { digit: u8, index: usize },
    /// Hex string has odd length.
    OddLength,
    /// Decoded length is not 32 bytes (expected 64 hex chars).
    InvalidStringLength,
}

impl std::fmt::Display for DigestDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHexCharacter { digit, index } => {
                write!(f, "invalid hex digit 0x{digit:02x} at index {index}")
            }
            Self::OddLength => write!(f, "odd hex string length"),
            Self::InvalidStringLength => write!(f, "expected 64 hex characters"),
        }
    }
}

impl std::error::Error for DigestDecodeError {}

/// Binds a decision to its policy and input via canonical SHA-256 digests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditBundle {
    /// Hex-encoded canonical policy digest.
    pub policy_digest_hex: String,
    /// Hex-encoded canonical input digest.
    pub input_digest_hex: String,
    /// Hex-encoded canonical decision digest.
    pub decision_digest_hex: String,
    /// Whether `snapshot.prescribe(input)` equals `decision` on all fields.
    pub replay_valid: bool,
}

impl AuditBundle {
    /// Raw 32-byte policy digest.
    pub fn policy_digest(&self) -> Result<[u8; 32], DigestDecodeError> {
        decode_hex32(&self.policy_digest_hex)
    }

    /// Raw 32-byte input digest.
    pub fn input_digest(&self) -> Result<[u8; 32], DigestDecodeError> {
        decode_hex32(&self.input_digest_hex)
    }

    /// Raw 32-byte decision digest.
    pub fn decision_digest(&self) -> Result<[u8; 32], DigestDecodeError> {
        decode_hex32(&self.decision_digest_hex)
    }
}

/// Build an [`AuditBundle`] for a decision.
pub fn audit_bundle(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> AuditBundle {
    let policy = policy_digest(snapshot);
    let input_d = input_digest(&input);
    let decision_d = decision_digest(decision);
    let replayed = snapshot.prescribe(input);
    AuditBundle {
        policy_digest_hex: digest_to_hex(&policy),
        input_digest_hex: digest_to_hex(&input_d),
        decision_digest_hex: digest_to_hex(&decision_d),
        replay_valid: replayed == *decision,
    }
}

/// Verify that `decision` is the correct output of `snapshot.prescribe(input)`.
///
/// Checks full structural equality and canonical decision digest binding.
pub fn verify_decision(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> VerifyResult {
    let replayed = snapshot.prescribe(input);
    let expected_d = decision_digest(&replayed);
    let actual_d = decision_digest(decision);

    if expected_d != actual_d {
        return VerifyResult::DigestMismatch {
            expected_hex: digest_to_hex(&expected_d),
            actual_hex: digest_to_hex(&actual_d),
        };
    }

    if replayed == *decision {
        VerifyResult::Valid
    } else {
        VerifyResult::Mismatch {
            expected: replayed,
            actual: *decision,
        }
    }
}

/// Compute a fingerprint of a policy snapshot for audit binding.
///
/// Returns the hex-encoded canonical policy digest (models sorted by `model_id`).
pub fn snapshot_fingerprint(snapshot: &PolicySnapshot) -> String {
    digest_to_hex(&policy_digest(snapshot))
}

/// A correctness certificate binding a decision to its policy and input.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CorrectnessCertificate {
    /// Hex-encoded canonical policy digest.
    pub policy_fingerprint: String,
    /// Hex-encoded canonical input digest.
    pub input_fingerprint: String,
    /// Hex-encoded canonical decision digest.
    pub decision_fingerprint: String,
    pub decision_sequence: u64,
    pub selected_model_id: u32,
    pub action: String,
    pub reason: String,
    pub replay_valid: bool,
    pub evaluated_models: u16,
    pub eligible_models: u16,
    pub counterfactual_model_id: u32,
    pub counterfactual_utility_microunits: i64,
}

/// Generate a correctness certificate for a decision.
pub fn certify_decision(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> CorrectnessCertificate {
    let bundle = audit_bundle(snapshot, input, decision);
    CorrectnessCertificate {
        policy_fingerprint: bundle.policy_digest_hex,
        input_fingerprint: bundle.input_digest_hex,
        decision_fingerprint: bundle.decision_digest_hex,
        decision_sequence: decision.request_sequence,
        selected_model_id: decision.selected_model_id,
        action: format!("{}", decision.action),
        reason: format!("{}", decision.reason),
        replay_valid: bundle.replay_valid,
        evaluated_models: decision.evaluated_models,
        eligible_models: decision.eligible_models,
        counterfactual_model_id: decision.counterfactual_model_id,
        counterfactual_utility_microunits: decision.counterfactual_utility_microunits,
    }
}

/// Counterfactual utility if a specific model had been forced.
///
/// Returns `None` if the model is absent, disabled, or fails constraints.
pub fn counterfactual_utility(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    alt_model_id: u32,
) -> Option<i64> {
    let mut forced = input;
    forced.requested_model_id = alt_model_id;
    let decision = snapshot.prescribe(forced);
    if decision.selected_model_id == alt_model_id
        && decision.reason != KernelReason::NoEnabledModel
        && decision.reason != KernelReason::CapabilityConstraint
        && decision.reason != KernelReason::ProviderConstraint
        && decision.reason != KernelReason::RegionConstraint
        && decision.reason != KernelReason::QualityConstraint
        && decision.reason != KernelReason::LatencyConstraint
        && decision.reason != KernelReason::BudgetConstraint
        && decision.reason != KernelReason::RiskCeilingConstraint
        && decision.reason != KernelReason::NonPositiveUtility
    {
        Some(decision.expected_utility_microunits)
    } else if decision.counterfactual_model_id == alt_model_id {
        Some(decision.counterfactual_utility_microunits)
    } else {
        None
    }
}

fn decode_hex32(hex: &str) -> Result<[u8; 32], DigestDecodeError> {
    if hex.len() % 2 != 0 {
        return Err(DigestDecodeError::OddLength);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = from_hex_digit(bytes[i], i)?;
        let lo = from_hex_digit(bytes[i + 1], i + 1)?;
        out.push((hi << 4) | lo);
    }
    if out.len() != 32 {
        return Err(DigestDecodeError::InvalidStringLength);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&out);
    Ok(digest)
}

fn from_hex_digit(byte: u8, index: usize) -> Result<u8, DigestDecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DigestDecodeError::InvalidHexCharacter { digit: byte, index }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::*;

    fn test_snapshot() -> PolicySnapshot {
        PolicySnapshot::try_new(
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
        .expect("valid snapshot")
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
    fn tampered_counterfactual_detected() {
        let snap = test_snapshot();
        let input = test_input();
        let mut decision = snap.prescribe(input);
        decision.counterfactual_utility_microunits += 1;
        assert!(matches!(
            verify_decision(&snap, input, &decision),
            VerifyResult::DigestMismatch { .. } | VerifyResult::Mismatch { .. }
        ));
    }

    #[test]
    fn audit_bundle_binds_input() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let bundle = audit_bundle(&snap, input, &decision);
        assert!(bundle.replay_valid);
        assert_eq!(bundle.policy_digest_hex.len(), 64);
        assert_eq!(bundle.input_digest_hex.len(), 64);
        assert_eq!(bundle.decision_digest_hex.len(), 64);
    }

    #[test]
    fn fingerprint_matches_policy_digest() {
        let snap = test_snapshot();
        assert_eq!(
            snapshot_fingerprint(&snap),
            digest_to_hex(&policy_digest(&snap))
        );
    }

    #[test]
    fn audit_bundle_decodes_digests() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let bundle = audit_bundle(&snap, input, &decision);
        assert_eq!(bundle.policy_digest().unwrap().len(), 32);
        assert_eq!(bundle.input_digest().unwrap().len(), 32);
        assert_eq!(bundle.decision_digest().unwrap().len(), 32);
    }

    #[test]
    fn certificate_includes_input_fingerprint() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let cert = certify_decision(&snap, input, &decision);
        assert!(cert.replay_valid);
        assert_eq!(cert.input_fingerprint.len(), 64);
        assert_eq!(cert.decision_fingerprint.len(), 64);
    }
}
