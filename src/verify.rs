//! Decision verification, replay, and correctness certificates.
//!
//! Level 2 proof: policy digest + input digest + full decision digest + replay.

use crate::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};

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

/// Error returned by fail-closed verification helpers.
///
/// This wrapper keeps `Result<_, VerifyError>` compact while preserving the
/// full [`VerifyResult`] for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    result: Box<VerifyResult>,
}

impl VerifyError {
    /// Create a verification error from a non-valid [`VerifyResult`].
    #[must_use]
    pub fn new(result: VerifyResult) -> Self {
        Self {
            result: Box::new(result),
        }
    }

    /// Inspect the underlying verification result.
    #[must_use]
    pub fn result(&self) -> &VerifyResult {
        &self.result
    }

    /// Consume the wrapper and return the underlying verification result.
    #[must_use]
    pub fn into_result(self) -> VerifyResult {
        *self.result
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decision verification failed: {:?}", self.result)
    }
}

impl std::error::Error for VerifyError {}

/// Audit bundle schema identifier (stable across releases).
pub const AUDIT_SCHEMA_VERSION: &str = "calybris.audit.v1";
/// Digest algorithm used for all bundle fields.
pub const AUDIT_DIGEST_ALGORITHM: &str = "sha256";
/// Proof envelope version carried alongside digests.
pub const AUDIT_PROOF_VERSION: u16 = 1;
/// Producer label for externally stored audit artifacts.
pub const AUDIT_CREATED_BY: &str = "calybris";

/// Binds a decision to its policy and input via canonical SHA-256 digests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditBundle {
    /// Stable schema tag for long-term audit storage.
    pub schema_version: String,
    /// Digest algorithm (always SHA-256 for current releases).
    pub digest_algorithm: String,
    /// Proof format version.
    pub proof_version: u16,
    /// Policy epoch at decision time.
    pub policy_epoch: u64,
    /// Catalog epoch at decision time.
    pub catalog_epoch: u64,
    /// Producer label (`calybris` for kernel-generated bundles).
    pub created_by: String,
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
        schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        digest_algorithm: AUDIT_DIGEST_ALGORITHM.to_string(),
        proof_version: AUDIT_PROOF_VERSION,
        policy_epoch: snapshot.policy_epoch,
        catalog_epoch: snapshot.catalog_epoch,
        created_by: AUDIT_CREATED_BY.to_string(),
        policy_digest_hex: digest_to_hex(&policy),
        input_digest_hex: digest_to_hex(&input_d),
        decision_digest_hex: digest_to_hex(&decision_d),
        replay_valid: replayed == *decision,
    }
}

/// Verify a decision and return its [`AuditBundle`] only if it replays exactly.
///
/// This is the recommended helper at audit boundaries where a caller wants a
/// fail-closed proof package rather than an [`AuditBundle`] with
/// `replay_valid == false`.
pub fn verified_audit_bundle(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> Result<AuditBundle, VerifyError> {
    match verify_decision(snapshot, input, decision) {
        VerifyResult::Valid => Ok(audit_bundle(snapshot, input, decision)),
        error => Err(VerifyError::new(error)),
    }
}

/// Verify that `decision` is the correct output of `snapshot.prescribe(input)`.
///
/// Checks full structural equality first (human-readable mismatch on failure),
/// then confirms the stored decision digest is internally consistent.
pub fn verify_decision(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> VerifyResult {
    let replayed = snapshot.prescribe(input);
    if replayed != *decision {
        return VerifyResult::Mismatch {
            expected: replayed,
            actual: *decision,
        };
    }
    // Decisions match on all fields; verify digest consistency as a safety net.
    let expected_d = decision_digest(&replayed);
    let actual_d = decision_digest(decision);
    if expected_d != actual_d {
        return VerifyResult::DigestMismatch {
            expected_hex: digest_to_hex(&expected_d),
            actual_hex: digest_to_hex(&actual_d),
        };
    }
    VerifyResult::Valid
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

/// Utility for a specific catalog model if it passes all constraint gates.
///
/// Delegates to [`PolicySnapshot::utility_for_model`] — does **not** infer utility from
/// [`prescribe`](PolicySnapshot::prescribe) winner/runner-up fields.
///
/// Returns `None` if the model is absent, disabled, or fails any gate.
pub fn counterfactual_utility(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    alt_model_id: u32,
) -> Option<i64> {
    snapshot.utility_for_model(input, alt_model_id)
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
    fn verified_audit_bundle_returns_bundle_for_valid_decision() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let bundle = verified_audit_bundle(&snap, input, &decision).unwrap();
        assert!(bundle.replay_valid);
        assert_eq!(bundle.policy_digest_hex.len(), 64);
        assert_eq!(bundle.input_digest_hex.len(), 64);
        assert_eq!(bundle.decision_digest_hex.len(), 64);
    }

    #[test]
    fn verified_audit_bundle_rejects_tampered_decision() {
        let snap = test_snapshot();
        let input = test_input();
        let mut decision = snap.prescribe(input);
        decision.selected_model_id = 999;
        let result = verified_audit_bundle(&snap, input, &decision);
        let error = result.unwrap_err();
        assert!(matches!(
            error.result(),
            VerifyResult::DigestMismatch { .. } | VerifyResult::Mismatch { .. }
        ));
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

    fn audit_bundle_stub(
        policy_digest_hex: String,
        input_digest_hex: String,
        decision_digest_hex: String,
        replay_valid: bool,
    ) -> AuditBundle {
        AuditBundle {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            digest_algorithm: AUDIT_DIGEST_ALGORITHM.to_string(),
            proof_version: AUDIT_PROOF_VERSION,
            policy_epoch: 1,
            catalog_epoch: 1,
            created_by: AUDIT_CREATED_BY.to_string(),
            policy_digest_hex,
            input_digest_hex,
            decision_digest_hex,
            replay_valid,
        }
    }

    #[test]
    fn audit_bundle_includes_schema_metadata() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let bundle = audit_bundle(&snap, input, &decision);
        assert_eq!(bundle.schema_version, AUDIT_SCHEMA_VERSION);
        assert_eq!(bundle.digest_algorithm, AUDIT_DIGEST_ALGORITHM);
        assert_eq!(bundle.proof_version, AUDIT_PROOF_VERSION);
        assert_eq!(bundle.created_by, AUDIT_CREATED_BY);
        assert_eq!(bundle.policy_epoch, snap.policy_epoch);
        assert_eq!(bundle.catalog_epoch, snap.catalog_epoch);
    }

    #[test]
    fn decode_hex32_rejects_odd_length() {
        let bundle = audit_bundle_stub("abc".into(), "00".repeat(32), "00".repeat(32), true);
        assert_eq!(bundle.policy_digest(), Err(DigestDecodeError::OddLength));
    }

    #[test]
    fn decode_hex32_rejects_invalid_characters() {
        let bundle = audit_bundle_stub(
            format!("{}g", "a".repeat(63)),
            "00".repeat(32),
            "00".repeat(32),
            true,
        );
        assert!(matches!(
            bundle.policy_digest(),
            Err(DigestDecodeError::InvalidHexCharacter { .. })
        ));
    }

    #[test]
    fn decode_hex32_rejects_wrong_length() {
        let bundle = audit_bundle_stub("00".repeat(30), "00".repeat(32), "00".repeat(32), true);
        assert_eq!(
            bundle.policy_digest(),
            Err(DigestDecodeError::InvalidStringLength)
        );
    }

    #[test]
    fn counterfactual_utility_for_eligible_model() {
        let snap = test_snapshot();
        let input = test_input();
        let utility = counterfactual_utility(&snap, input, 2);
        assert!(utility.is_some());
        assert!(utility.unwrap() > 0);
    }

    #[test]
    fn counterfactual_utility_none_for_missing_model() {
        let snap = test_snapshot();
        let input = test_input();
        assert!(counterfactual_utility(&snap, input, 999).is_none());
    }

    #[test]
    fn verify_decision_wrong_policy_epoch() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let mut other = snap.clone();
        other.policy_epoch = snap.policy_epoch + 1;
        assert_ne!(
            verify_decision(&other, input, &decision),
            VerifyResult::Valid
        );
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn decode_hex32_rejects_non_hex_strings(s in "[^0-9a-fA-F]{1,20}") {
            let bundle = audit_bundle_stub(
                s,
                "00".repeat(32),
                "00".repeat(32),
                true,
            );
            prop_assert!(bundle.policy_digest().is_err());
        }
    }
}
