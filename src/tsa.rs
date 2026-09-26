//! RFC 3161 timestamp tokens: a third party's signed statement that a digest
//! existed at a given time.
//!
//! A witness cosignature says when a *witness* saw a checkpoint. A token from a
//! timestamping authority (TSA) says the same for an organisation whose job is
//! keeping time, whose signing certificate is typically audited, and whose
//! tokens courts and regulators already accept. Stamping a checkpoint's digest
//! ([`crate::checkpoint::Checkpoint::digest`]) dates every record the
//! checkpoint commits to, so one token per checkpoint dates millions of
//! decisions.
//!
//! [`request`] builds the DER `TimeStampReq` to send to a TSA (over HTTP with
//! content type `application/timestamp-query`; the transport is the caller's).
//! [`verify_response`] checks what comes back:
//!
//! 1. the response status is granted, and it carries a CMS `SignedData` whose
//!    content is a `TSTInfo`;
//! 2. the `TSTInfo` message imprint is SHA-256, -384 or -512 of exactly the
//!    digest that was asked about, and the nonce, if one was sent, matches;
//! 3. the signed attributes bind the content type and the digest of the
//!    `TSTInfo`, and the signature over them verifies — RSA PKCS#1 v1.5, or
//!    ECDSA on P-256 or P-384;
//! 4. the signer is one of the certificates the caller **pinned**, that
//!    certificate carries the critical `timeStamping` extended key usage, and
//!    the token's time lies inside its validity period.
//!
//! What it does not do, deliberately: build a chain to a root, or check
//! revocation. The caller names the TSA certificates it trusts, the way a
//! witness policy names the witnesses; a TSA that rotates its certificate has
//! to be pinned again. RSA-PSS signatures are not accepted.
//!
//! Only public-key operations happen here. The `rsa` crate's unfixed timing
//! advisory (RUSTSEC-2023-0071, "Marvin") concerns private-key operations and
//! does not apply to verification.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{Int, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectKeyIdentifier};
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// Largest response [`verify_response`] reads.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Why a timestamp response was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TsaError {
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("the TSA did not grant the request (status {0})")]
    NotGranted(u8),
    #[error("the token timestamps a different digest")]
    ImprintMismatch,
    #[error("the token's nonce is not the one sent")]
    NonceMismatch,
    #[error("unsupported algorithm {0}")]
    Unsupported(String),
    #[error("the token was not signed by any pinned TSA certificate")]
    UnknownSigner,
    #[error("the signed attributes do not bind this token's content")]
    AttributesMismatch,
    #[error("the TSA's signature does not verify")]
    BadSignature,
    #[error("the signing certificate lacks the critical timeStamping key usage")]
    NotATimestampingCertificate,
    #[error("the token's time is outside the signing certificate's validity")]
    OutsideValidity,
    #[error("a pinned certificate is malformed")]
    BadCertificate,
}

impl From<der::Error> for TsaError {
    fn from(_: der::Error) -> Self {
        Self::Malformed("DER does not decode")
    }
}

/// A TSA certificate the caller trusts to sign timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedTsa {
    cert: Certificate,
}

impl PinnedTsa {
    /// From a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, TsaError> {
        Ok(Self {
            cert: Certificate::from_der(der).map_err(|_| TsaError::BadCertificate)?,
        })
    }

    /// From a PEM certificate (the first one, if there are several).
    pub fn from_pem(pem: &str) -> Result<Self, TsaError> {
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        let start = pem.find(begin).ok_or(TsaError::BadCertificate)? + begin.len();
        let stop = pem[start..].find(end).ok_or(TsaError::BadCertificate)? + start;
        let b64: String = pem[start..stop].split_whitespace().collect();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| TsaError::BadCertificate)?;
        Self::from_der(&der)
    }

    /// The certificate's subject, for reports.
    #[must_use]
    pub fn subject(&self) -> String {
        self.cert.tbs_certificate.subject.to_string()
    }

    fn matches(&self, sid: &SignerIdentifier) -> bool {
        let tbs = &self.cert.tbs_certificate;
        match sid {
            SignerIdentifier::IssuerAndSerialNumber(ias) => {
                ias.issuer == tbs.issuer && ias.serial_number == tbs.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
                .extensions
                .iter()
                .flatten()
                .filter(|e| e.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
                .any(|e| {
                    SubjectKeyIdentifier::from_der(e.extn_value.as_bytes())
                        .is_ok_and(|own| own == *ski)
                }),
        }
    }

    fn check_timestamping_usage(&self) -> Result<(), TsaError> {
        let ok = self
            .cert
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .filter(|e| e.extn_id == ID_CE_EXT_KEY_USAGE)
            .any(|e| {
                e.critical
                    && ExtendedKeyUsage::from_der(e.extn_value.as_bytes())
                        .is_ok_and(|eku| eku.0.contains(&ID_KP_TIME_STAMPING))
            });
        if ok {
            Ok(())
        } else {
            Err(TsaError::NotATimestampingCertificate)
        }
    }

    fn check_validity(&self, unix: u64) -> Result<(), TsaError> {
        let v = &self.cert.tbs_certificate.validity;
        let from = v.not_before.to_unix_duration().as_secs();
        let until = v.not_after.to_unix_duration().as_secs();
        if (from..=until).contains(&unix) {
            Ok(())
        } else {
            Err(TsaError::OutsideValidity)
        }
    }
}

/// A token that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTimestamp {
    /// `genTime`, in Unix seconds, truncated.
    pub gen_time: u64,
    /// The TSA's stated accuracy, in whole seconds rounded up; 0 if unstated.
    pub accuracy_seconds: u64,
    /// The TSA's serial number for the token, big-endian.
    pub serial: Vec<u8>,
    /// The TSA policy the token was issued under.
    pub policy: String,
    /// Subject of the pinned certificate that signed it.
    pub signer: String,
}

impl VerifiedTimestamp {
    /// The latest moment the stamped digest can have come into existence:
    /// `genTime` plus the accuracy. This is the bound to use as evidence.
    #[must_use]
    pub fn existed_by(&self) -> u64 {
        self.gen_time.saturating_add(self.accuracy_seconds)
    }
}

fn positive_int(bytes: &[u8]) -> Result<Int, TsaError> {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|&b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(&trimmed);
    Ok(Int::new(&body)?)
}

fn int_value(i: &Int) -> &[u8] {
    let b = i.as_bytes();
    let zeros = b.iter().take_while(|&&x| x == 0).count();
    &b[zeros.min(b.len().saturating_sub(1))..]
}

/// The DER `TimeStampReq` for `digest` (a SHA-256 digest), asking the TSA to
/// include its certificate. Send a fresh `nonce` to tie the response to this
/// request.
pub fn request(digest: &[u8; 32], nonce: Option<u64>) -> Result<Vec<u8>, TsaError> {
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: spki::AlgorithmIdentifier {
                oid: ID_SHA256,
                parameters: None,
            },
            hashed_message: OctetString::new(digest.to_vec())?,
        },
        req_policy: None,
        nonce: nonce.map(|n| positive_int(&n.to_be_bytes())).transpose()?,
        cert_req: true,
        extensions: None,
    };
    Ok(req.to_der()?)
}

fn hash(alg: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, TsaError> {
    Ok(match *alg {
        ID_SHA256 => Sha256::digest(data).to_vec(),
        ID_SHA384 => Sha384::digest(data).to_vec(),
        ID_SHA512 => Sha512::digest(data).to_vec(),
        other => return Err(TsaError::Unsupported(other.to_string())),
    })
}

/// Checks a DER `TimeStampResp` for `digest` against the pinned TSAs.
///
/// `digest` is the 32 bytes that were stamped: SHA-256 of the checkpoint
/// body. `nonce` is the one sent in the request, if any.
pub fn verify_response(
    response: &[u8],
    digest: &[u8; 32],
    nonce: Option<u64>,
    pinned: &[PinnedTsa],
) -> Result<VerifiedTimestamp, TsaError> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(TsaError::Malformed("response is too large"));
    }
    let resp = TimeStampResp::from_der(response)?;
    let status = resp.status.status as u8;
    if status > 1 {
        return Err(TsaError::NotGranted(status));
    }
    let token = resp
        .time_stamp_token
        .ok_or(TsaError::Malformed("a granted response carries a token"))?;
    verify_token(&token, digest, nonce, pinned)
}

/// Checks a token (a CMS `ContentInfo`) given as DER, for when the token was
/// stored without its response envelope.
pub fn verify_token_der(
    token: &[u8],
    digest: &[u8; 32],
    nonce: Option<u64>,
    pinned: &[PinnedTsa],
) -> Result<VerifiedTimestamp, TsaError> {
    if token.len() > MAX_RESPONSE_BYTES {
        return Err(TsaError::Malformed("token is too large"));
    }
    verify_token(&ContentInfo::from_der(token)?, digest, nonce, pinned)
}

fn verify_token(
    token: &ContentInfo,
    digest: &[u8; 32],
    nonce: Option<u64>,
    pinned: &[PinnedTsa],
) -> Result<VerifiedTimestamp, TsaError> {
    if token.content_type != ID_SIGNED_DATA {
        return Err(TsaError::Malformed("token is not CMS SignedData"));
    }
    let signed: SignedData = token.content.decode_as()?;
    if signed.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(TsaError::Malformed("token content is not a TSTInfo"));
    }
    let econtent = signed
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(TsaError::Malformed("token has no content"))?;
    let tst_der = econtent.decode_as::<OctetString>()?;
    let tst = TstInfo::from_der(tst_der.as_bytes())?;

    // The request carried the checkpoint digest itself as a SHA-256 imprint;
    // a token over anything else is not about this checkpoint.
    let imprint = &tst.message_imprint;
    if imprint.hash_algorithm.oid != ID_SHA256 || imprint.hashed_message.as_bytes() != digest {
        return Err(TsaError::ImprintMismatch);
    }
    if let Some(n) = nonce {
        let sent = positive_int(&n.to_be_bytes())?;
        match &tst.nonce {
            Some(got) if int_value(got) == int_value(&sent) => {}
            _ => return Err(TsaError::NonceMismatch),
        }
    }

    let infos = signed.signer_infos.0.as_slice();
    let [info] = infos else {
        return Err(TsaError::Malformed("a token has exactly one signer"));
    };
    let pin = pinned
        .iter()
        .find(|p| p.matches(&info.sid))
        .ok_or(TsaError::UnknownSigner)?;
    check_signed_attributes(info, tst_der.as_bytes())?;
    verify_signature(pin, info)?;

    let gen_time = tst.gen_time.to_unix_duration().as_secs();
    pin.check_timestamping_usage()?;
    pin.check_validity(gen_time)?;

    let accuracy_seconds = tst.accuracy.as_ref().map_or(0, |a| {
        let sub = a.millis.unwrap_or(0) > 0 || a.micros.unwrap_or(0) > 0;
        a.seconds.unwrap_or(0).saturating_add(u64::from(sub))
    });
    Ok(VerifiedTimestamp {
        gen_time,
        accuracy_seconds,
        serial: int_value(&tst.serial_number).to_vec(),
        policy: tst.policy.to_string(),
        signer: pin.subject(),
    })
}

fn check_signed_attributes(info: &SignerInfo, tst_der: &[u8]) -> Result<(), TsaError> {
    let attrs = info
        .signed_attrs
        .as_ref()
        .ok_or(TsaError::AttributesMismatch)?;
    let single = |oid: ObjectIdentifier| -> Result<der::Any, TsaError> {
        let mut found = attrs.iter().filter(|a| a.oid == oid);
        let attr = found.next().ok_or(TsaError::AttributesMismatch)?;
        if found.next().is_some() || attr.values.len() != 1 {
            return Err(TsaError::AttributesMismatch);
        }
        Ok(attr
            .values
            .get(0)
            .ok_or(TsaError::AttributesMismatch)?
            .clone())
    };
    let content_type: ObjectIdentifier = single(ID_CONTENT_TYPE)?.decode_as()?;
    if content_type != ID_CT_TST_INFO {
        return Err(TsaError::AttributesMismatch);
    }
    let message_digest: OctetString = single(ID_MESSAGE_DIGEST)?.decode_as()?;
    if message_digest.as_bytes() != hash(&info.digest_alg.oid, tst_der)? {
        return Err(TsaError::AttributesMismatch);
    }
    Ok(())
}

fn verify_signature(pin: &PinnedTsa, info: &SignerInfo) -> Result<(), TsaError> {
    let attrs = info
        .signed_attrs
        .as_ref()
        .ok_or(TsaError::AttributesMismatch)?;
    // RFC 5652 §5.4: the signature is over the DER of the attributes as a
    // SET OF, not over their [0] IMPLICIT encoding inside SignerInfo.
    let signed_bytes = attrs.to_der()?;
    let digest_alg = info.digest_alg.oid;
    let digest = hash(&digest_alg, &signed_bytes)?;
    let sig = info.signature.as_bytes();
    let spki = &pin.cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(TsaError::BadCertificate)?;

    match info.signature_algorithm.oid {
        RSA_ENCRYPTION | SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA => {
            let implied = match info.signature_algorithm.oid {
                SHA256_WITH_RSA => Some(ID_SHA256),
                SHA384_WITH_RSA => Some(ID_SHA384),
                SHA512_WITH_RSA => Some(ID_SHA512),
                _ => None,
            };
            if implied.is_some_and(|h| h != digest_alg) {
                return Err(TsaError::Unsupported("mismatched RSA digest".into()));
            }
            if spki.algorithm.oid != RSA_ENCRYPTION {
                return Err(TsaError::BadSignature);
            }
            use rsa::pkcs1::DecodeRsaPublicKey as _;
            let key = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
                .map_err(|_| TsaError::BadCertificate)?;
            let scheme = match digest_alg {
                ID_SHA256 => rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                ID_SHA384 => rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha384>(),
                ID_SHA512 => rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha512>(),
                other => return Err(TsaError::Unsupported(other.to_string())),
            };
            key.verify(scheme, &digest, sig)
                .map_err(|_| TsaError::BadSignature)
        }
        ECDSA_WITH_SHA256 | ECDSA_WITH_SHA384 | ECDSA_WITH_SHA512 => {
            let implied = match info.signature_algorithm.oid {
                ECDSA_WITH_SHA256 => ID_SHA256,
                ECDSA_WITH_SHA384 => ID_SHA384,
                _ => ID_SHA512,
            };
            if implied != digest_alg {
                return Err(TsaError::Unsupported("mismatched ECDSA digest".into()));
            }
            if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
                return Err(TsaError::BadSignature);
            }
            let curve: ObjectIdentifier = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or(TsaError::BadCertificate)?
                .decode_as()
                .map_err(|_| TsaError::BadCertificate)?;
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            match curve {
                SECP256R1 => {
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| TsaError::BadCertificate)?;
                    let sig = p256::ecdsa::Signature::from_der(sig)
                        .map_err(|_| TsaError::BadSignature)?;
                    key.verify_prehash(&digest, &sig)
                        .map_err(|_| TsaError::BadSignature)
                }
                SECP384R1 => {
                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| TsaError::BadCertificate)?;
                    let sig = p384::ecdsa::Signature::from_der(sig)
                        .map_err(|_| TsaError::BadSignature)?;
                    key.verify_prehash(&digest, &sig)
                        .map_err(|_| TsaError::BadSignature)
                }
                other => Err(TsaError::Unsupported(other.to_string())),
            }
        }
        other => Err(TsaError::Unsupported(other.to_string())),
    }
}
