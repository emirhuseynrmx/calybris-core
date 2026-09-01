//! Decision certificates — one verifiable envelope per decision.
//!
//! 0.5.0 introduced three proof surfaces separately: the audit bundle
//! (policy/input/decision digests + replay), the state trajectory
//! (`state`), and signed policy provenance (`provenance`). A decision
//! certificate groups them into a **single canonically-serializable object**
//! that an auditor can store per decision. The optional legacy signature
//! proves policy provenance only; it does not sign the certificate's input,
//! decision, state, or WAL fields. Use [`crate::receipt::DecisionReceipt`] and
//! [`crate::receipt::verify_receipt_full`] when one signature must bind the
//! complete decision evidence.
//!
//! Certificates are fail-closed: [`crate::certificate::issue_certificate`] returns one only when
//! the decision replays exactly. Verification recomputes every digest from
//! the disclosed policy/input/decision — the certificate never asks to be
//! trusted on its word.
//!
//! Signature verification lives behind the `provenance` feature; digest,
//! replay, and state-linkage verification are always available (including on
//! `wasm32`).

use crate::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{verify_decision, VerifyError, VerifyResult};

/// Certificate schema tag for long-term storage.
pub const CERTIFICATE_SCHEMA: &str = "calybris-certificate-v1";

/// State-trajectory anchor carried in a certificate (see `state` module).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CertificateState {
    pub step: u64,
    pub state_digest_before_hex: String,
    pub state_digest_after_hex: String,
}

/// WAL anchor carried in a certificate: where the decision was durably logged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CertificateWal {
    pub sequence: u64,
    pub entry_hash: String,
}

/// Accountable-signer fields (mirror of `provenance::SignedPolicy`, flattened
/// so the base certificate needs no Ed25519 dependency).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CertificateSignature {
    pub signer_id: String,
    pub signed_at_epoch_ms: u64,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// CALY-PROOF v1 compatibility envelope for a decision and optional anchors.
///
/// The optional signer authenticates the policy digest, signer identity, and
/// signing timestamp only. It is not a signature over the full certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DecisionCertificate {
    pub schema_version: String,
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
    pub policy_digest_hex: String,
    pub input_digest_hex: String,
    pub decision_digest_hex: String,
    pub replay_valid: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub state: Option<CertificateState>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub wal: Option<CertificateWal>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub signature: Option<CertificateSignature>,
}

/// Optional anchors to attach when issuing a certificate.
#[derive(Clone, Debug, Default)]
pub struct CertificateAnchors {
    pub state: Option<CertificateState>,
    pub wal: Option<CertificateWal>,
    pub signature: Option<CertificateSignature>,
}

/// Issue a fail-closed certificate: returns `Err` unless the decision is the
/// exact output of `snapshot.prescribe(input)`.
pub fn issue_certificate(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
    anchors: CertificateAnchors,
) -> Result<DecisionCertificate, VerifyError> {
    match verify_decision(snapshot, input, decision) {
        VerifyResult::Valid => {}
        error => return Err(VerifyError::new(error)),
    }
    Ok(DecisionCertificate {
        schema_version: CERTIFICATE_SCHEMA.to_string(),
        policy_epoch: decision.policy_epoch,
        catalog_epoch: decision.catalog_epoch,
        policy_digest_hex: digest_to_hex(&policy_digest(snapshot)),
        input_digest_hex: digest_to_hex(&input_digest(&input)),
        decision_digest_hex: digest_to_hex(&decision_digest(decision)),
        replay_valid: true,
        state: anchors.state,
        wal: anchors.wal,
        signature: anchors.signature,
    })
}

/// Why a certificate failed verification.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateError {
    #[error("unknown certificate schema: {0}")]
    UnknownSchema(String),
    #[error("policy digest mismatch")]
    PolicyDigestMismatch,
    #[error("input digest mismatch")]
    InputDigestMismatch,
    #[error("decision digest mismatch")]
    DecisionDigestMismatch,
    #[error("decision does not replay under the disclosed policy")]
    ReplayInvalid,
    #[error("certificate asserts replay_valid=false")]
    ReplayFlagFalse,
}

/// Verify a certificate against the disclosed policy, input, and decision:
/// recomputes all three digests, binds the disclosed policy/catalog epochs,
/// confirms the decision replays, and checks the stored `replay_valid` flag.
/// Signature verification is separate (see `verify_certificate_signature`).
pub fn verify_certificate(
    certificate: &DecisionCertificate,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> Result<(), CertificateError> {
    if certificate.schema_version != CERTIFICATE_SCHEMA {
        return Err(CertificateError::UnknownSchema(
            certificate.schema_version.clone(),
        ));
    }
    if !certificate.replay_valid {
        return Err(CertificateError::ReplayFlagFalse);
    }
    if certificate.policy_epoch != decision.policy_epoch
        || certificate.catalog_epoch != decision.catalog_epoch
    {
        return Err(CertificateError::ReplayInvalid);
    }
    if certificate.policy_digest_hex != digest_to_hex(&policy_digest(snapshot)) {
        return Err(CertificateError::PolicyDigestMismatch);
    }
    if certificate.input_digest_hex != digest_to_hex(&input_digest(&input)) {
        return Err(CertificateError::InputDigestMismatch);
    }
    if certificate.decision_digest_hex != digest_to_hex(&decision_digest(decision)) {
        return Err(CertificateError::DecisionDigestMismatch);
    }
    if verify_decision(snapshot, input, decision) != VerifyResult::Valid {
        return Err(CertificateError::ReplayInvalid);
    }
    Ok(())
}

/// Why scoped certificate verification failed.
///
/// Unlike [`CertificateError`], this surface also binds the optional state and
/// WAL anchors to caller-trusted values. The compatibility verifier
/// [`verify_certificate`] intentionally verifies only policy/input/decision
/// replay evidence.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CertificateScopedError {
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    #[error("state anchor mismatch")]
    StateAnchorMismatch,
    #[error("WAL anchor mismatch")]
    WalAnchorMismatch,
}

/// Verify replay evidence and bind state/WAL anchors to trusted expectations.
///
/// Passing `None` requires the corresponding certificate anchor to be absent;
/// an embedded anchor is never treated as self-authenticating evidence.
pub fn verify_certificate_scoped(
    certificate: &DecisionCertificate,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
    expected_state: Option<&CertificateState>,
    expected_wal: Option<&CertificateWal>,
) -> Result<(), CertificateScopedError> {
    verify_certificate(certificate, snapshot, input, decision)?;
    if certificate.state.as_ref() != expected_state {
        return Err(CertificateScopedError::StateAnchorMismatch);
    }
    if certificate.wal.as_ref() != expected_wal {
        return Err(CertificateScopedError::WalAnchorMismatch);
    }
    Ok(())
}

/// Verify the legacy **policy-provenance** signature carried by a certificate
/// (feature `provenance`). This does not authenticate the certificate's input,
/// decision, state, or WAL fields. Reconstructs the
/// [`crate::provenance::SignedPolicy`] and checks it against the disclosed
/// policy; `trusted_key`, when supplied, pins the signer to a trust anchor.
#[cfg(feature = "provenance")]
pub fn verify_certificate_signature(
    certificate: &DecisionCertificate,
    snapshot: &PolicySnapshot,
    trusted_key: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<(), crate::provenance::ProvenanceError> {
    use crate::provenance::{
        verify_signed_policy, verify_signed_policy_with_key, ProvenanceError, SignedPolicy,
    };
    let Some(signature) = &certificate.signature else {
        return Err(ProvenanceError::BadSignature);
    };
    let signed = SignedPolicy {
        policy_digest_hex: certificate.policy_digest_hex.clone(),
        signer_id: signature.signer_id.clone(),
        signed_at_epoch_ms: signature.signed_at_epoch_ms,
        public_key_hex: signature.public_key_hex.clone(),
        signature_hex: signature.signature_hex.clone(),
    };
    match trusted_key {
        Some(key) => verify_signed_policy_with_key(snapshot, &signed, key),
        None => verify_signed_policy(snapshot, &signed),
    }
}

#[cfg(feature = "provenance")]
impl CertificateSignature {
    /// Build certificate signature fields from a signed policy.
    pub fn from_signed_policy(signed: &crate::provenance::SignedPolicy) -> Self {
        Self {
            signer_id: signed.signer_id.clone(),
            signed_at_epoch_ms: signed.signed_at_epoch_ms,
            public_key_hex: signed.public_key_hex.clone(),
            signature_hex: signed.signature_hex.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelModel, ALL_PROVIDERS, ALL_REGIONS};

    fn policy() -> PolicySnapshot {
        PolicySnapshot::try_new(
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
        .unwrap()
    }

    fn input() -> KernelInput {
        KernelInput {
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
        }
    }

    #[test]
    fn issued_certificate_verifies() {
        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let cert =
            issue_certificate(&policy, request, &decision, CertificateAnchors::default()).unwrap();
        verify_certificate(&cert, &policy, request, &decision).unwrap();
    }

    #[test]
    fn tampered_decision_digest_is_rejected() {
        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let mut cert =
            issue_certificate(&policy, request, &decision, CertificateAnchors::default()).unwrap();
        cert.decision_digest_hex = "0".repeat(64);
        assert_eq!(
            verify_certificate(&cert, &policy, request, &decision),
            Err(CertificateError::DecisionDigestMismatch)
        );
    }

    #[test]
    fn certificate_bound_to_wrong_policy_is_rejected() {
        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let cert =
            issue_certificate(&policy, request, &decision, CertificateAnchors::default()).unwrap();

        let other = PolicySnapshot::try_new(
            8, // different epoch → different policy digest
            42,
            9_600,
            5_500,
            3_500,
            2,
            policy.models().to_vec(),
        )
        .unwrap();
        assert_eq!(
            verify_certificate(&cert, &other, request, &decision),
            Err(CertificateError::PolicyDigestMismatch)
        );
    }

    #[test]
    fn certificate_verifier_binds_policy_and_catalog_epochs() {
        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let certificate =
            issue_certificate(&policy, request, &decision, CertificateAnchors::default()).unwrap();

        let mut tampered = certificate.clone();
        tampered.policy_epoch += 1;
        assert!(verify_certificate(&tampered, &policy, request, &decision).is_err());

        let mut tampered = certificate;
        tampered.catalog_epoch += 1;
        assert!(verify_certificate(&tampered, &policy, request, &decision).is_err());
    }

    #[test]
    fn scoped_certificate_verifier_binds_state_and_wal_anchors() {
        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let state = CertificateState {
            step: 7,
            state_digest_before_hex: "11".repeat(32),
            state_digest_after_hex: "22".repeat(32),
        };
        let wal = CertificateWal {
            sequence: 9,
            entry_hash: "33".repeat(32),
        };
        let certificate = issue_certificate(
            &policy,
            request,
            &decision,
            CertificateAnchors {
                state: Some(state.clone()),
                wal: Some(wal.clone()),
                signature: None,
            },
        )
        .unwrap();

        verify_certificate_scoped(
            &certificate,
            &policy,
            request,
            &decision,
            Some(&state),
            Some(&wal),
        )
        .unwrap();

        let mut wrong_state = state.clone();
        wrong_state.step += 1;
        assert_eq!(
            verify_certificate_scoped(
                &certificate,
                &policy,
                request,
                &decision,
                Some(&wrong_state),
                Some(&wal),
            ),
            Err(CertificateScopedError::StateAnchorMismatch)
        );

        let mut wrong_wal = wal;
        wrong_wal.sequence += 1;
        assert_eq!(
            verify_certificate_scoped(
                &certificate,
                &policy,
                request,
                &decision,
                Some(&state),
                Some(&wrong_wal),
            ),
            Err(CertificateScopedError::WalAnchorMismatch)
        );
    }

    #[cfg(feature = "provenance")]
    #[test]
    fn signed_certificate_verifies_and_rejects_wrong_key() {
        use crate::provenance::sign_policy;
        use ed25519_dalek::SigningKey;

        let policy = policy();
        let request = input();
        let decision = policy.prescribe(request);
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = sign_policy(&policy, &key, "risk-officer:ayse", 1_783_000_000_000);

        let anchors = CertificateAnchors {
            signature: Some(CertificateSignature::from_signed_policy(&signed)),
            ..CertificateAnchors::default()
        };
        let cert = issue_certificate(&policy, request, &decision, anchors).unwrap();

        verify_certificate(&cert, &policy, request, &decision).unwrap();
        verify_certificate_signature(&cert, &policy, Some(&key.verifying_key())).unwrap();

        let wrong = SigningKey::from_bytes(&[1u8; 32]);
        assert!(
            verify_certificate_signature(&cert, &policy, Some(&wrong.verifying_key())).is_err()
        );
    }
}
