//! Production decision receipts.
//!
//! A [`DecisionReceipt`](crate::receipt::DecisionReceipt) binds the
//! replay-verified decision to optional state and WAL evidence through one
//! canonical claims digest. With the `provenance` feature,
//! [`sign_receipt`](crate::receipt::sign_receipt) signs that digest so none of
//! the attached claims can be changed without invalidating the receipt.

use sha2::{Digest, Sha256};

use crate::digest::{bytes_to_hex, decision_digest, input_digest, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{verify_decision, VerifyResult};

/// Stable receipt schema.
pub const RECEIPT_SCHEMA: &str = "calybris.receipt.v1";
/// Domain-separation tag for the canonical receipt claims digest.
pub const RECEIPT_DIGEST_TAG: &[u8] = b"calyrcp1\0";
/// Domain-separation tag for receipt signatures.
pub const RECEIPT_SIGNATURE_CONTEXT: &[u8] = b"calyrcs1\0";

/// State evidence attached to a decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptState {
    pub step: u64,
    pub state_digest_before_hex: String,
    pub state_digest_after_hex: String,
}

/// WAL evidence attached to a decision receipt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptWal {
    pub sequence: u64,
    pub entry_hash: String,
}

/// Optional evidence attached when issuing a receipt.
#[derive(Clone, Debug, Default)]
pub struct ReceiptAnchors {
    pub state: Option<ReceiptState>,
    pub wal: Option<ReceiptWal>,
}

/// Ed25519 signature over a receipt's complete claims digest.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSignature {
    pub signer_id: String,
    pub signed_at_epoch_ms: u64,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Replay-verified decision receipt with optional state and WAL evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub schema_version: String,
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
    pub policy_digest_hex: String,
    pub input_digest_hex: String,
    pub decision_digest_hex: String,
    pub replay_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ReceiptState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal: Option<ReceiptWal>,
    /// Canonical digest over every claim above, including optional anchors.
    pub claims_digest_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReceiptSignature>,
}

/// Why receipt verification failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("unknown receipt schema: {0}")]
    UnknownSchema(String),
    #[error("receipt asserts replay_valid=false")]
    ReplayFlagFalse,
    #[error("policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("input digest mismatch")]
    InputDigestMismatch,
    #[error("decision digest mismatch")]
    DecisionDigestMismatch,
    #[error("decision does not replay under the disclosed policy")]
    ReplayInvalid,
    #[error("malformed {field}: {reason}")]
    Malformed { field: &'static str, reason: String },
    #[error("receipt claims digest mismatch")]
    ClaimsDigestMismatch,
    #[error("receipt has no signature")]
    MissingSignature,
    #[error("receipt signature verification failed")]
    BadSignature,
    #[error("receipt signer does not match the trusted key")]
    UntrustedKey,
    #[error("receipt WAL anchor mismatch")]
    WalAnchorMismatch,
    #[error("receipt state anchor mismatch")]
    StateAnchorMismatch,
}

fn parse_hex<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N], ReceiptError> {
    if value.len() != N * 2 {
        return Err(ReceiptError::Malformed {
            field,
            reason: format!("expected {} hex chars, found {}", N * 2, value.len()),
        });
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = nibble(pair[0]).ok_or_else(|| ReceiptError::Malformed {
            field,
            reason: format!("invalid hex at offset {}", index * 2),
        })?;
        let low = nibble(pair[1]).ok_or_else(|| ReceiptError::Malformed {
            field,
            reason: format!("invalid hex at offset {}", index * 2 + 1),
        })?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hash_optional_state(
    hasher: &mut Sha256,
    state: Option<&ReceiptState>,
) -> Result<(), ReceiptError> {
    match state {
        Some(state) => {
            if state.step == 0 {
                return Err(ReceiptError::Malformed {
                    field: "state.step",
                    reason: "must be at least 1".to_string(),
                });
            }
            hasher.update([1]);
            hasher.update(state.step.to_le_bytes());
            hasher.update(parse_hex::<32>(
                "state_digest_before_hex",
                &state.state_digest_before_hex,
            )?);
            hasher.update(parse_hex::<32>(
                "state_digest_after_hex",
                &state.state_digest_after_hex,
            )?);
        }
        None => hasher.update([0]),
    }
    Ok(())
}

fn hash_optional_wal(hasher: &mut Sha256, wal: Option<&ReceiptWal>) -> Result<(), ReceiptError> {
    match wal {
        Some(wal) => {
            if wal.sequence == 0 {
                return Err(ReceiptError::Malformed {
                    field: "wal.sequence",
                    reason: "must be at least 1".to_string(),
                });
            }
            hasher.update([1]);
            hasher.update(wal.sequence.to_le_bytes());
            hasher.update(parse_hex::<32>("wal.entry_hash", &wal.entry_hash)?);
        }
        None => hasher.update([0]),
    }
    Ok(())
}

/// Recompute the canonical digest over every receipt claim.
pub fn receipt_claims_digest(receipt: &DecisionReceipt) -> Result<[u8; 32], ReceiptError> {
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_DIGEST_TAG);
    let schema_len =
        u64::try_from(receipt.schema_version.len()).map_err(|_| ReceiptError::Malformed {
            field: "schema_version",
            reason: "length does not fit u64".to_string(),
        })?;
    hasher.update(schema_len.to_le_bytes());
    hasher.update(receipt.schema_version.as_bytes());
    hasher.update(receipt.policy_epoch.to_le_bytes());
    hasher.update(receipt.catalog_epoch.to_le_bytes());
    hasher.update(parse_hex::<32>(
        "policy_digest_hex",
        &receipt.policy_digest_hex,
    )?);
    hasher.update(parse_hex::<32>(
        "input_digest_hex",
        &receipt.input_digest_hex,
    )?);
    hasher.update(parse_hex::<32>(
        "decision_digest_hex",
        &receipt.decision_digest_hex,
    )?);
    hasher.update([u8::from(receipt.replay_valid)]);
    hash_optional_state(&mut hasher, receipt.state.as_ref())?;
    hash_optional_wal(&mut hasher, receipt.wal.as_ref())?;
    Ok(hasher.finalize().into())
}

/// Issue an unsigned receipt only after exact decision replay succeeds.
pub fn issue_receipt(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
    anchors: ReceiptAnchors,
) -> Result<DecisionReceipt, ReceiptError> {
    if verify_decision(snapshot, input, decision) != VerifyResult::Valid {
        return Err(ReceiptError::ReplayInvalid);
    }

    let mut receipt = DecisionReceipt {
        schema_version: RECEIPT_SCHEMA.to_string(),
        policy_epoch: decision.policy_epoch,
        catalog_epoch: decision.catalog_epoch,
        policy_digest_hex: bytes_to_hex(&policy_digest(snapshot)),
        input_digest_hex: bytes_to_hex(&input_digest(&input)),
        decision_digest_hex: bytes_to_hex(&decision_digest(decision)),
        replay_valid: true,
        state: anchors.state,
        wal: anchors.wal,
        claims_digest_hex: String::new(),
        signature: None,
    };
    receipt.claims_digest_hex = bytes_to_hex(&receipt_claims_digest(&receipt)?);
    Ok(receipt)
}

/// Verify all receipt claims against the disclosed policy, input, and decision.
pub fn verify_receipt(
    receipt: &DecisionReceipt,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> Result<(), ReceiptError> {
    if receipt.schema_version != RECEIPT_SCHEMA {
        return Err(ReceiptError::UnknownSchema(receipt.schema_version.clone()));
    }
    if !receipt.replay_valid {
        return Err(ReceiptError::ReplayFlagFalse);
    }
    if receipt.policy_epoch != decision.policy_epoch
        || receipt.catalog_epoch != decision.catalog_epoch
    {
        return Err(ReceiptError::ReplayInvalid);
    }
    if receipt.policy_digest_hex != bytes_to_hex(&policy_digest(snapshot)) {
        return Err(ReceiptError::PolicyDigestMismatch);
    }
    if receipt.input_digest_hex != bytes_to_hex(&input_digest(&input)) {
        return Err(ReceiptError::InputDigestMismatch);
    }
    if receipt.decision_digest_hex != bytes_to_hex(&decision_digest(decision)) {
        return Err(ReceiptError::DecisionDigestMismatch);
    }
    if verify_decision(snapshot, input, decision) != VerifyResult::Valid {
        return Err(ReceiptError::ReplayInvalid);
    }
    let claims = receipt_claims_digest(receipt)?;
    if receipt.claims_digest_hex != bytes_to_hex(&claims) {
        return Err(ReceiptError::ClaimsDigestMismatch);
    }
    Ok(())
}

/// Confirm that a receipt points at the expected WAL position and entry hash.
pub fn verify_receipt_wal(
    receipt: &DecisionReceipt,
    sequence: u64,
    entry_hash: &str,
) -> Result<(), ReceiptError> {
    match &receipt.wal {
        Some(wal) if wal.sequence == sequence && wal.entry_hash == entry_hash => Ok(()),
        _ => Err(ReceiptError::WalAnchorMismatch),
    }
}

/// Confirm that a receipt carries the expected state transition.
pub fn verify_receipt_state(
    receipt: &DecisionReceipt,
    step: u64,
    state_digest_before_hex: &str,
    state_digest_after_hex: &str,
) -> Result<(), ReceiptError> {
    match &receipt.state {
        Some(state)
            if state.step == step
                && state.state_digest_before_hex == state_digest_before_hex
                && state.state_digest_after_hex == state_digest_after_hex =>
        {
            Ok(())
        }
        _ => Err(ReceiptError::StateAnchorMismatch),
    }
}

#[cfg(feature = "provenance")]
fn receipt_signing_message(
    claims_digest: &[u8; 32],
    signed_at_epoch_ms: u64,
    signer_id: &str,
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(RECEIPT_SIGNATURE_CONTEXT.len() + 32 + 8 + signer_id.len());
    message.extend_from_slice(RECEIPT_SIGNATURE_CONTEXT);
    message.extend_from_slice(claims_digest);
    message.extend_from_slice(&signed_at_epoch_ms.to_le_bytes());
    message.extend_from_slice(signer_id.as_bytes());
    message
}

/// Sign a receipt's complete canonical claims digest.
#[cfg(feature = "provenance")]
pub fn sign_receipt(
    receipt: &mut DecisionReceipt,
    signing_key: &ed25519_dalek::SigningKey,
    signer_id: &str,
    signed_at_epoch_ms: u64,
) -> Result<(), ReceiptError> {
    use ed25519_dalek::Signer;

    let claims_digest = receipt_claims_digest(receipt)?;
    if receipt.claims_digest_hex != bytes_to_hex(&claims_digest) {
        return Err(ReceiptError::ClaimsDigestMismatch);
    }
    let message = receipt_signing_message(&claims_digest, signed_at_epoch_ms, signer_id);
    let signature = signing_key.sign(&message);
    receipt.signature = Some(ReceiptSignature {
        signer_id: signer_id.to_string(),
        signed_at_epoch_ms,
        public_key_hex: bytes_to_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: bytes_to_hex(&signature.to_bytes()),
    });
    Ok(())
}

/// Verify the receipt signature, optionally pinning it to a trusted key.
#[cfg(feature = "provenance")]
pub fn verify_receipt_signature(
    receipt: &DecisionReceipt,
    trusted_key: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<(), ReceiptError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let signature = receipt
        .signature
        .as_ref()
        .ok_or(ReceiptError::MissingSignature)?;
    let claims_digest = receipt_claims_digest(receipt)?;
    if receipt.claims_digest_hex != bytes_to_hex(&claims_digest) {
        return Err(ReceiptError::ClaimsDigestMismatch);
    }
    let key_bytes = parse_hex::<32>("signature.public_key_hex", &signature.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|error| ReceiptError::Malformed {
            field: "signature.public_key_hex",
            reason: error.to_string(),
        })?;
    if trusted_key.is_some_and(|trusted| trusted != &verifying_key) {
        return Err(ReceiptError::UntrustedKey);
    }
    let signature_bytes = parse_hex::<64>("signature.signature_hex", &signature.signature_hex)?;
    let signature_value = Signature::from_bytes(&signature_bytes);
    let message = receipt_signing_message(
        &claims_digest,
        signature.signed_at_epoch_ms,
        &signature.signer_id,
    );
    verifying_key
        .verify(&message, &signature_value)
        .map_err(|_| ReceiptError::BadSignature)
}

/// Verify the complete production receipt contract in one fail-closed call.
///
/// This combines decision replay, canonical claim integrity, trusted-key
/// signature verification, and the caller's expected state and WAL anchors.
/// Use this at trust boundaries instead of treating signature verification as
/// proof that the disclosed state or log position is the expected one.
#[cfg(feature = "provenance")]
pub fn verify_receipt_full(
    receipt: &DecisionReceipt,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
    trusted_key: &ed25519_dalek::VerifyingKey,
    expected_state: &ReceiptState,
    expected_wal: &ReceiptWal,
) -> Result<(), ReceiptError> {
    verify_receipt(receipt, snapshot, input, decision)?;
    verify_receipt_signature(receipt, Some(trusted_key))?;
    verify_receipt_state(
        receipt,
        expected_state.step,
        &expected_state.state_digest_before_hex,
        &expected_state.state_digest_after_hex,
    )?;
    verify_receipt_wal(receipt, expected_wal.sequence, &expected_wal.entry_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelModel, ALL_PROVIDERS, ALL_REGIONS};

    fn fixture() -> (PolicySnapshot, KernelInput, KernelDecision) {
        let snapshot = PolicySnapshot::try_new(
            7,
            42,
            9_600,
            5_500,
            3_500,
            2,
            vec![KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1_000,
            }],
        )
        .unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 1_000,
            output_tokens: 500,
            business_value_microunits: 100_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 1_000,
            confidence_bps: 9_000,
            minimum_quality_bps: 5_000,
            max_p95_latency_ms: 1_000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);
        (snapshot, input, decision)
    }

    fn anchors() -> ReceiptAnchors {
        ReceiptAnchors {
            state: Some(ReceiptState {
                step: 1,
                state_digest_before_hex: "11".repeat(32),
                state_digest_after_hex: "22".repeat(32),
            }),
            wal: Some(ReceiptWal {
                sequence: 9,
                entry_hash: "33".repeat(32),
            }),
        }
    }

    #[test]
    fn receipt_verifies_and_binds_all_anchors() {
        let (snapshot, input, decision) = fixture();
        let receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        assert_eq!(
            receipt.claims_digest_hex,
            "8ea14ca3b379ca424b4421ce975cab459d607275652ba25e570de6c9d252ffd8"
        );
        verify_receipt(&receipt, &snapshot, input, &decision).unwrap();
        verify_receipt_wal(&receipt, 9, &"33".repeat(32)).unwrap();
        verify_receipt_state(&receipt, 1, &"11".repeat(32), &"22".repeat(32)).unwrap();
    }

    #[test]
    fn tampered_state_or_wal_claim_fails() {
        let (snapshot, input, decision) = fixture();
        let mut receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        receipt.state.as_mut().unwrap().step = 2;
        assert_eq!(
            verify_receipt(&receipt, &snapshot, input, &decision),
            Err(ReceiptError::ClaimsDigestMismatch)
        );

        let mut receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        receipt.schema_version = "calybris.receipt.v2".to_string();
        assert_eq!(
            verify_receipt(&receipt, &snapshot, input, &decision),
            Err(ReceiptError::UnknownSchema(
                "calybris.receipt.v2".to_string()
            ))
        );

        let mut receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        receipt.wal.as_mut().unwrap().sequence = 10;
        assert_eq!(
            verify_receipt(&receipt, &snapshot, input, &decision),
            Err(ReceiptError::ClaimsDigestMismatch)
        );
    }

    #[test]
    fn unicode_hex_input_is_rejected_without_panicking() {
        let (snapshot, input, decision) = fixture();
        let mut receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        receipt.policy_digest_hex = format!("{}x", "€".repeat(21));
        assert!(matches!(
            receipt_claims_digest(&receipt),
            Err(ReceiptError::Malformed {
                field: "policy_digest_hex",
                ..
            })
        ));
    }

    #[test]
    fn malformed_anchors_are_rejected_during_issuance_without_panicking() {
        let (snapshot, input, decision) = fixture();
        let malformed_state = ReceiptAnchors {
            state: Some(ReceiptState {
                step: 1,
                state_digest_before_hex: format!("{}x", "€".repeat(21)),
                state_digest_after_hex: "22".repeat(32),
            }),
            wal: None,
        };
        assert!(matches!(
            issue_receipt(&snapshot, input, &decision, malformed_state),
            Err(ReceiptError::Malformed {
                field: "state_digest_before_hex",
                ..
            })
        ));

        let malformed_wal = ReceiptAnchors {
            state: None,
            wal: Some(ReceiptWal {
                sequence: 1,
                entry_hash: "short".to_string(),
            }),
        };
        assert!(matches!(
            issue_receipt(&snapshot, input, &decision, malformed_wal),
            Err(ReceiptError::Malformed {
                field: "wal.entry_hash",
                ..
            })
        ));
    }

    #[test]
    fn zero_state_or_wal_positions_are_rejected() {
        let (snapshot, input, decision) = fixture();
        let mut invalid = anchors();
        invalid.state.as_mut().unwrap().step = 0;
        assert!(matches!(
            issue_receipt(&snapshot, input, &decision, invalid),
            Err(ReceiptError::Malformed {
                field: "state.step",
                ..
            })
        ));

        let mut invalid = anchors();
        invalid.wal.as_mut().unwrap().sequence = 0;
        assert!(matches!(
            issue_receipt(&snapshot, input, &decision, invalid),
            Err(ReceiptError::Malformed {
                field: "wal.sequence",
                ..
            })
        ));
    }

    #[test]
    fn receipt_json_rejects_unknown_fields() {
        let (snapshot, input, decision) = fixture();
        let receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        let mut value = serde_json::to_value(receipt).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("approved".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<DecisionReceipt>(value).is_err());
    }

    #[test]
    #[cfg(feature = "provenance")]
    fn signed_receipt_rejects_claim_and_signer_tampering() {
        let (snapshot, input, decision) = fixture();
        let mut receipt = issue_receipt(&snapshot, input, &decision, anchors()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        sign_receipt(&mut receipt, &key, "receipt-service", 1_700_000_000_000).unwrap();
        verify_receipt_signature(&receipt, Some(&key.verifying_key())).unwrap();

        let mut tampered_claim = receipt.clone();
        tampered_claim.wal.as_mut().unwrap().entry_hash = "44".repeat(32);
        assert_eq!(
            verify_receipt_signature(&tampered_claim, Some(&key.verifying_key())),
            Err(ReceiptError::ClaimsDigestMismatch)
        );

        let mut tampered_schema = receipt.clone();
        tampered_schema.schema_version = "calybris.receipt.v2".to_string();
        assert_eq!(
            verify_receipt_signature(&tampered_schema, Some(&key.verifying_key())),
            Err(ReceiptError::ClaimsDigestMismatch)
        );

        let mut tampered_signer = receipt;
        tampered_signer.signature.as_mut().unwrap().signer_id = "attacker".to_string();
        assert_eq!(
            verify_receipt_signature(&tampered_signer, Some(&key.verifying_key())),
            Err(ReceiptError::BadSignature)
        );
    }

    #[test]
    #[cfg(feature = "provenance")]
    fn full_verification_requires_replay_signature_state_and_wal() {
        let (snapshot, input, decision) = fixture();
        let expected = anchors();
        let expected_state = expected.state.clone().unwrap();
        let expected_wal = expected.wal.clone().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]);
        let mut receipt = issue_receipt(&snapshot, input, &decision, expected).unwrap();
        sign_receipt(&mut receipt, &key, "receipt-service", 1_700_000_000_000).unwrap();

        verify_receipt_full(
            &receipt,
            &snapshot,
            input,
            &decision,
            &key.verifying_key(),
            &expected_state,
            &expected_wal,
        )
        .unwrap();

        let mut missing_wal = issue_receipt(
            &snapshot,
            input,
            &decision,
            ReceiptAnchors {
                state: Some(expected_state.clone()),
                wal: None,
            },
        )
        .unwrap();
        sign_receipt(&mut missing_wal, &key, "receipt-service", 1_700_000_000_000).unwrap();
        assert_eq!(
            verify_receipt_full(
                &missing_wal,
                &snapshot,
                input,
                &decision,
                &key.verifying_key(),
                &expected_state,
                &expected_wal,
            ),
            Err(ReceiptError::WalAnchorMismatch)
        );
    }
}
