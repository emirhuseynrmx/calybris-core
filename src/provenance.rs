//! Signed policy provenance (feature `provenance`).
//!
//! Binds a policy snapshot to an accountable signer: *"this decision was made
//! under policy P, signed by officer X at time T — here is the proof."*
//!
//! The signature covers a domain-separated message over the canonical policy
//! digest, the signing timestamp, and the signer identity, so a signature for
//! one policy (or one signer, or one time) can never be replayed for another:
//!
//! ```text
//! message = "calysig1\0" || policy_digest(32 bytes)
//!        || LE(signed_at_epoch_ms: u64)
//!        || signer_id_utf8
//! signature = Ed25519(signing_key, message)
//! ```
//!
//! The timestamp is supplied by the caller — the core stays clock-free and
//! deterministic.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::digest::{bytes_to_hex, policy_digest};
use crate::kernel::PolicySnapshot;

/// Domain-separation context for policy signatures.
pub const POLICY_SIGNATURE_CONTEXT: &[u8] = b"calysig1\0";

/// A policy digest signed by an accountable identity.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SignedPolicy {
    /// Hex canonical policy digest (see `docs/CALY_PROOF.md` §1).
    pub policy_digest_hex: String,
    /// Accountable signer identity (e.g. "risk-officer:ayse").
    pub signer_id: String,
    /// Caller-supplied signing time (Unix epoch milliseconds).
    pub signed_at_epoch_ms: u64,
    /// Hex Ed25519 verifying (public) key, 32 bytes.
    pub public_key_hex: String,
    /// Hex Ed25519 signature, 64 bytes.
    pub signature_hex: String,
}

/// Why a signed policy failed verification.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProvenanceError {
    #[error("policy digest mismatch: artifact signs {signed}, snapshot digests to {actual}")]
    PolicyDigestMismatch { signed: String, actual: String },
    #[error("malformed {field}: {reason}")]
    Malformed { field: &'static str, reason: String },
    #[error("signature verification failed")]
    BadSignature,
    #[error("verifying key does not match the pinned trust anchor")]
    UntrustedKey,
}

fn signing_message(policy_digest: &[u8; 32], signed_at_epoch_ms: u64, signer_id: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(POLICY_SIGNATURE_CONTEXT.len() + 32 + 8 + signer_id.len());
    message.extend_from_slice(POLICY_SIGNATURE_CONTEXT);
    message.extend_from_slice(policy_digest);
    message.extend_from_slice(&signed_at_epoch_ms.to_le_bytes());
    message.extend_from_slice(signer_id.as_bytes());
    message
}

fn parse_hex<const N: usize>(field: &'static str, hex: &str) -> Result<[u8; N], ProvenanceError> {
    let malformed = |reason: String| ProvenanceError::Malformed { field, reason };
    if hex.len() != N * 2 {
        return Err(malformed(format!(
            "expected {} hex chars, found {}",
            N * 2,
            hex.len()
        )));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = nibble(pair[0])
            .ok_or_else(|| malformed(format!("invalid hex at offset {}", index * 2)))?;
        let low = nibble(pair[1])
            .ok_or_else(|| malformed(format!("invalid hex at offset {}", index * 2 + 1)))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

/// Sign a policy snapshot. The caller owns key custody and the timestamp.
pub fn sign_policy(
    snapshot: &PolicySnapshot,
    signing_key: &SigningKey,
    signer_id: &str,
    signed_at_epoch_ms: u64,
) -> SignedPolicy {
    let digest = policy_digest(snapshot);
    let message = signing_message(&digest, signed_at_epoch_ms, signer_id);
    let signature = signing_key.sign(&message);
    SignedPolicy {
        policy_digest_hex: bytes_to_hex(&digest),
        signer_id: signer_id.to_string(),
        signed_at_epoch_ms,
        public_key_hex: bytes_to_hex(signing_key.verifying_key().as_bytes()),
        signature_hex: bytes_to_hex(&signature.to_bytes()),
    }
}

/// Verify that `signed` is a valid signature over exactly this snapshot.
///
/// Trusts the key embedded in the artifact. To also pin the key to a known
/// trust anchor, use [`verify_signed_policy_with_key`].
pub fn verify_signed_policy(
    snapshot: &PolicySnapshot,
    signed: &SignedPolicy,
) -> Result<(), ProvenanceError> {
    let digest = policy_digest(snapshot);
    let actual_hex = bytes_to_hex(&digest);
    if signed.policy_digest_hex != actual_hex {
        return Err(ProvenanceError::PolicyDigestMismatch {
            signed: signed.policy_digest_hex.clone(),
            actual: actual_hex,
        });
    }

    let key_bytes: [u8; 32] = parse_hex("public_key_hex", &signed.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|error| ProvenanceError::Malformed {
            field: "public_key_hex",
            reason: error.to_string(),
        })?;
    let signature_bytes: [u8; 64] = parse_hex("signature_hex", &signed.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);

    let message = signing_message(&digest, signed.signed_at_epoch_ms, &signed.signer_id);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| ProvenanceError::BadSignature)
}

/// Verify signature validity AND that the signing key is the expected trust
/// anchor (e.g. the organization's registered policy-officer key).
pub fn verify_signed_policy_with_key(
    snapshot: &PolicySnapshot,
    signed: &SignedPolicy,
    trusted_key: &VerifyingKey,
) -> Result<(), ProvenanceError> {
    if signed.public_key_hex != bytes_to_hex(trusted_key.as_bytes()) {
        return Err(ProvenanceError::UntrustedKey);
    }
    verify_signed_policy(snapshot, signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelModel, ALL_REGIONS};

    fn policy(policy_epoch: u64) -> PolicySnapshot {
        PolicySnapshot::try_new(
            policy_epoch,
            1,
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
        .unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let snapshot = policy(1);
        let signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1_783_000_000_000);
        verify_signed_policy(&snapshot, &signed).unwrap();
        verify_signed_policy_with_key(&snapshot, &signed, &key(7).verifying_key()).unwrap();
    }

    #[test]
    fn signature_does_not_transfer_to_a_different_policy() {
        let signed = sign_policy(&policy(1), &key(7), "risk-officer:ayse", 1);
        let other = policy(2);
        assert!(matches!(
            verify_signed_policy(&other, &signed),
            Err(ProvenanceError::PolicyDigestMismatch { .. })
        ));
    }

    #[test]
    fn tampered_signer_id_fails() {
        let snapshot = policy(1);
        let mut signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        signed.signer_id = "risk-officer:mallory".to_string();
        assert_eq!(
            verify_signed_policy(&snapshot, &signed),
            Err(ProvenanceError::BadSignature)
        );
    }

    #[test]
    fn tampered_timestamp_fails() {
        let snapshot = policy(1);
        let mut signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        signed.signed_at_epoch_ms = 2;
        assert_eq!(
            verify_signed_policy(&snapshot, &signed),
            Err(ProvenanceError::BadSignature)
        );
    }

    #[test]
    fn unexpected_key_is_rejected_by_the_trust_anchor_check() {
        let snapshot = policy(1);
        let signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        assert_eq!(
            verify_signed_policy_with_key(&snapshot, &signed, &key(8).verifying_key()),
            Err(ProvenanceError::UntrustedKey)
        );
    }

    #[test]
    fn unicode_public_key_is_rejected_without_panicking() {
        let snapshot = policy(1);
        let mut signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        signed.public_key_hex = format!("{}x", "€".repeat(21));
        assert!(matches!(
            verify_signed_policy(&snapshot, &signed),
            Err(ProvenanceError::Malformed {
                field: "public_key_hex",
                ..
            })
        ));
    }

    #[test]
    fn signed_policy_rejects_uppercase_noncanonical_hex_encoding() {
        let snapshot = policy(1);
        let mut signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        signed.signature_hex = signed.signature_hex.to_ascii_uppercase();

        assert!(matches!(
            verify_signed_policy(&snapshot, &signed),
            Err(ProvenanceError::Malformed {
                field: "signature_hex",
                ..
            })
        ));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn signed_policy_json_rejects_unknown_fields() {
        let snapshot = policy(1);
        let signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        let mut value = serde_json::to_value(signed).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("approved".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SignedPolicy>(value).is_err());
    }

    #[test]
    fn forged_signature_fails() {
        let snapshot = policy(1);
        let mut signed = sign_policy(&snapshot, &key(7), "risk-officer:ayse", 1);
        let forged = sign_policy(&snapshot, &key(9), "risk-officer:ayse", 1);
        signed.signature_hex = forged.signature_hex;
        assert_eq!(
            verify_signed_policy(&snapshot, &signed),
            Err(ProvenanceError::BadSignature)
        );
    }
}
