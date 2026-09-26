//! RFC 3161 tokens from a local OpenSSL TSA and from two public TSAs.
//!
//! Everything in `tests/fixtures/rfc3161/` was produced once and pinned:
//!
//! - `body.txt` is a checkpoint body; its SHA-256 is the digest stamped.
//! - `req.tsq` is the request (`openssl ts -query -digest … -sha256 -cert`),
//!   with a nonce.
//! - `rsa.tsr`, `p256.tsr`, `p384.tsr` are replies from `openssl ts -reply`
//!   with `tsa.cnf` and a self-signed TSA certificate of each key type.
//! - `freetsa.tsr` and `digicert.tsr` are the same request answered by
//!   <https://freetsa.org/tsr> and <http://timestamp.digicert.com>, and
//!   `freetsa.crt`, `digicert.crt` their signing certificates.
//! - `noeku.crt` and `expired.crt` carry the RSA signer's name, serial and key
//!   but no timeStamping key usage, or a validity that ended in 2021;
//!   `wrongkey.crt` carries its name, serial and usage with another key.
//!
//! `openssl ts -verify` accepted every token before it was pinned here.
//!
//! What OpenSSL will not produce (a certificate that serves another purpose
//! too, a token without or with a wrong ESS signing-certificate attribute) is
//! built at the end of this file.

#![cfg(feature = "preview-tsa")]

use calybris_core::tsa::{request, verify_response, PinnedTsa, TsaError};
use der::Decode as _;
use sha2::{Digest, Sha256};
use x509_tsp::TimeStampReq;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/rfc3161/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn pin(name: &str) -> PinnedTsa {
    PinnedTsa::from_pem(&String::from_utf8(fixture(name)).unwrap()).unwrap()
}

fn digest() -> [u8; 32] {
    Sha256::digest(fixture("body.txt")).into()
}

/// The nonce `req.tsq` carried.
fn nonce() -> u64 {
    let req = TimeStampReq::from_der(&fixture("req.tsq")).unwrap();
    let bytes = req.nonce.unwrap();
    let raw = bytes.as_bytes();
    let raw = &raw[raw.len() - 8..];
    u64::from_be_bytes(raw.try_into().unwrap())
}

#[test]
fn the_local_tsa_tokens_of_every_key_type_verify() {
    for key in ["rsa", "p256", "p384"] {
        let got = verify_response(
            &fixture(&format!("{key}.tsr")),
            &digest(),
            Some(nonce()),
            &[pin(&format!("{key}.crt"))],
        )
        .unwrap_or_else(|e| panic!("{key}: {e}"));
        assert_eq!(got.signer, "CN=Calybris Test TSA", "{key}");
        assert_eq!(got.policy, "1.3.6.1.4.1.99999.1");
        assert_eq!(got.accuracy_seconds, 1);
        assert_eq!(got.existed_by(), got.gen_time + 1);
        // 2026-09-26, when the fixtures were made.
        assert!(
            (1_790_380_000..1_790_470_000).contains(&got.gen_time),
            "{}",
            got.gen_time
        );
    }
}

#[test]
fn tokens_from_public_tsas_verify_against_their_pinned_certificates() {
    for tsa in ["freetsa", "digicert"] {
        let got = verify_response(
            &fixture(&format!("{tsa}.tsr")),
            &digest(),
            Some(nonce()),
            &[pin(&format!("{tsa}.crt"))],
        )
        .unwrap_or_else(|e| panic!("{tsa}: {e}"));
        assert!(
            (1_790_380_000..1_790_470_000).contains(&got.gen_time),
            "{tsa}"
        );
    }
}

#[test]
fn a_token_for_another_digest_or_nonce_is_refused() {
    let resp = fixture("rsa.tsr");
    let mut other = digest();
    other[0] ^= 1;
    assert_eq!(
        verify_response(&resp, &other, None, &[pin("rsa.crt")]),
        Err(TsaError::ImprintMismatch)
    );
    assert_eq!(
        verify_response(&resp, &digest(), Some(nonce() ^ 1), &[pin("rsa.crt")]),
        Err(TsaError::NonceMismatch)
    );
    // Without an expected nonce the nonce is not checked.
    verify_response(&resp, &digest(), None, &[pin("rsa.crt")]).unwrap();
}

#[test]
fn only_a_pinned_timestamping_certificate_in_its_validity_counts() {
    let resp = fixture("rsa.tsr");
    let d = digest();
    assert_eq!(
        verify_response(&resp, &d, None, &[pin("p256.crt"), pin("freetsa.crt")]),
        Err(TsaError::UnknownSigner)
    );
    assert_eq!(
        verify_response(&resp, &d, None, &[]),
        Err(TsaError::UnknownSigner)
    );
    assert_eq!(
        verify_response(&resp, &d, None, &[pin("noeku.crt")]),
        Err(TsaError::NotATimestampingCertificate)
    );
    assert_eq!(
        verify_response(&resp, &d, None, &[pin("expired.crt")]),
        Err(TsaError::OutsideValidity)
    );
    // A certificate with the signer's name and serial but another key.
    let impostor = verify_response(&fixture("p256.tsr"), &d, None, &[pin("rsa.crt")]);
    assert!(impostor.is_err());
}

#[test]
fn the_signature_itself_is_checked() {
    let d = digest();
    // The signer's name, serial and usage, but not its key.
    assert_eq!(
        verify_response(&fixture("rsa.tsr"), &d, None, &[pin("wrongkey.crt")]),
        Err(TsaError::BadSignature)
    );
    // The last byte of an OpenSSL reply is the last byte of the signature.
    for key in ["rsa", "p256", "p384"] {
        let mut bad = fixture(&format!("{key}.tsr"));
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_response(&bad, &d, None, &[pin(&format!("{key}.crt"))]),
            Err(TsaError::BadSignature),
            "{key}"
        );
    }
}

#[test]
fn no_single_byte_change_to_a_token_verifies_as_different_content() {
    let resp = fixture("p256.tsr");
    let d = digest();
    let honest = verify_response(&resp, &d, Some(nonce()), &[pin("p256.crt")]).unwrap();
    for i in 0..resp.len() {
        for flip in [0x01_u8, 0x80] {
            let mut bad = resp.clone();
            bad[i] ^= flip;
            // Must not panic; and whatever still verifies (a byte in the
            // embedded certificate, which is ignored in favour of the pin)
            // must say exactly what the honest token says.
            if let Ok(v) = verify_response(&bad, &d, Some(nonce()), &[pin("p256.crt")]) {
                assert_eq!(v, honest, "byte {i} flipped with {flip:#04x}");
            }
        }
    }
}

#[test]
fn garbage_is_refused_not_panicked_on() {
    for bad in [&b""[..], b"\x30", b"\x30\x03\x02\x01\x02", &[0xff; 100]] {
        assert!(verify_response(bad, &digest(), None, &[pin("rsa.crt")]).is_err());
    }
    assert!(verify_response(&vec![0x30; 70_000], &digest(), None, &[]).is_err());
}

#[test]
fn a_request_carries_the_digest_a_nonce_and_asks_for_the_certificate() {
    let der = request(&digest(), Some(0x87C4_0377_02A3_23F5)).unwrap();
    let req = TimeStampReq::from_der(&der).unwrap();
    assert_eq!(req.message_imprint.hashed_message.as_bytes(), digest());
    assert_eq!(
        req.message_imprint.hash_algorithm.oid.to_string(),
        "2.16.840.1.101.3.4.2.1"
    );
    assert!(req.cert_req);
    // A nonce with its top bit set is encoded as a positive INTEGER.
    assert_eq!(req.nonce.unwrap().as_bytes()[0], 0x00);
    let small = TimeStampReq::from_der(&request(&digest(), Some(5)).unwrap()).unwrap();
    assert_eq!(small.nonce.unwrap().as_bytes(), [5]);
    assert!(TimeStampReq::from_der(&request(&digest(), None).unwrap())
        .unwrap()
        .nonce
        .is_none());
}

/// Tokens built here for what `openssl ts -reply` will not produce: a
/// certificate that also serves another purpose (OpenSSL refuses to sign with
/// one), and tokens whose ESS signing-certificate attribute is missing or
/// names another certificate. The key is a fixed scalar, not a stored secret,
/// and every token is otherwise valid, so each check is the only thing that
/// can refuse it.
mod built {
    use cms::cert::IssuerAndSerialNumber;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
    };
    use der::asn1::{Any, BitString, GeneralizedTime, Int, ObjectIdentifier as Oid};
    use der::asn1::{OctetString, SetOfVec};
    use der::{Encode as _, Sequence};
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest as _, Sha256};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use std::str::FromStr as _;
    use std::time::Duration;
    use x509_cert::attr::Attribute;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};
    use x509_tsp::{MessageImprint, TspVersion, TstInfo};

    const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
    const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
    const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
    const P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
    const EXT_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.37");
    pub const TIME_STAMPING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.8");
    pub const SERVER_AUTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.1");
    const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
    const TST_INFO: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.4");
    const CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
    const MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
    const SIGNING_CERTIFICATE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.12");
    const SIGNING_CERTIFICATE_V2: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.47");
    /// The serial number every built certificate carries.
    pub const SERIAL: u8 = 0x42;

    #[derive(Sequence)]
    struct IssuerSerial {
        issuer: Vec<GeneralName>,
        serial_number: SerialNumber,
    }

    #[derive(Sequence)]
    struct CertId {
        cert_hash: OctetString,
        issuer_serial: IssuerSerial,
    }

    #[derive(Sequence)]
    struct CertIdV2 {
        hash_algorithm: AlgorithmIdentifierOwned,
        cert_hash: OctetString,
        issuer_serial: IssuerSerial,
    }

    #[derive(Sequence)]
    struct SigningCertificate {
        certs: Vec<CertId>,
    }

    #[derive(Sequence)]
    struct SigningCertificateV2 {
        certs: Vec<CertIdV2>,
    }

    /// Which certificate an ESS attribute names: the DER it hashes, and the
    /// serial number it gives.
    pub type Names<'a> = Option<(&'a [u8], u8)>;

    fn key() -> SigningKey {
        SigningKey::from_slice(&[7; 32]).unwrap()
    }

    fn alg(oid: Oid) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    fn name() -> Name {
        Name::from_str("CN=Calybris Built TSA").unwrap()
    }

    fn serial(n: u8) -> SerialNumber {
        SerialNumber::new(&[n]).unwrap()
    }

    fn at(secs: u64) -> GeneralizedTime {
        GeneralizedTime::from_unix_duration(Duration::from_secs(secs)).unwrap()
    }

    /// A certificate for the fixed key, valid 2020 to 2040, with one
    /// extended key usage extension per entry of `usages`.
    pub fn cert(usages: &[(&[Oid], bool)]) -> Vec<u8> {
        let public = key().verifying_key().to_encoded_point(false);
        let extensions = usages
            .iter()
            .map(|(purposes, critical)| Extension {
                extn_id: EXT_KEY_USAGE,
                critical: *critical,
                extn_value: OctetString::new(ExtendedKeyUsage(purposes.to_vec()).to_der().unwrap())
                    .unwrap(),
            })
            .collect();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial(SERIAL),
            signature: alg(ECDSA_SHA256),
            issuer: name(),
            validity: Validity {
                not_before: Time::GeneralTime(at(1_577_836_800)),
                not_after: Time::GeneralTime(at(2_208_988_800)),
            },
            subject: name(),
            subject_public_key_info: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: EC_PUBLIC_KEY,
                    parameters: Some(Any::encode_from(&P256).unwrap()),
                },
                subject_public_key: BitString::from_bytes(public.as_bytes()).unwrap(),
            },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        // A pinned certificate is trusted as given; its own signature is
        // never checked, so any bytes serve.
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg(ECDSA_SHA256),
            signature: BitString::from_bytes(&[0]).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    /// A token for `digest`, signed by the fixed key, whose signed
    /// attributes carry an ESS `signingCertificate` naming `v1` and a
    /// `signingCertificateV2` naming `v2`, each only if given.
    pub fn token(digest: &[u8; 32], v1: Names<'_>, v2: Names<'_>) -> Vec<u8> {
        let tst = TstInfo {
            version: TspVersion::V1,
            policy: Oid::new_unwrap("1.3.6.1.4.1.99999.1"),
            message_imprint: MessageImprint {
                hash_algorithm: alg(SHA256),
                hashed_message: OctetString::new(digest.to_vec()).unwrap(),
            },
            serial_number: Int::new(&[1]).unwrap(),
            gen_time: at(1_750_000_000),
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };
        let tst_der = tst.to_der().unwrap();
        let attr = |oid, value: Any| Attribute {
            oid,
            values: SetOfVec::try_from(vec![value]).unwrap(),
        };
        let names = |serial_number: u8| IssuerSerial {
            issuer: vec![GeneralName::DirectoryName(name())],
            serial_number: serial(serial_number),
        };
        let digest_of_tst = OctetString::new(Sha256::digest(&tst_der).to_vec()).unwrap();
        let mut attrs = vec![
            attr(CONTENT_TYPE, Any::encode_from(&TST_INFO).unwrap()),
            attr(MESSAGE_DIGEST, Any::encode_from(&digest_of_tst).unwrap()),
        ];
        if let Some((der, n)) = v1 {
            let id = CertId {
                cert_hash: OctetString::new(sha1::Sha1::digest(der).to_vec()).unwrap(),
                issuer_serial: names(n),
            };
            let value = SigningCertificate { certs: vec![id] };
            attrs.push(attr(SIGNING_CERTIFICATE, Any::encode_from(&value).unwrap()));
        }
        if let Some((der, n)) = v2 {
            let id = CertIdV2 {
                hash_algorithm: alg(SHA256),
                cert_hash: OctetString::new(Sha256::digest(der).to_vec()).unwrap(),
                issuer_serial: names(n),
            };
            let value = SigningCertificateV2 { certs: vec![id] };
            attrs.push(attr(
                SIGNING_CERTIFICATE_V2,
                Any::encode_from(&value).unwrap(),
            ));
        }
        let attrs = SetOfVec::try_from(attrs).unwrap();
        let signature: Signature = key()
            .sign_prehash(&Sha256::digest(attrs.to_der().unwrap()))
            .unwrap();
        let info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: name(),
                serial_number: serial(SERIAL),
            }),
            digest_alg: alg(SHA256),
            signed_attrs: Some(attrs),
            signature_algorithm: alg(ECDSA_SHA256),
            signature: OctetString::new(signature.to_der().as_bytes().to_vec()).unwrap(),
            unsigned_attrs: None,
        };
        let signed = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![alg(SHA256)]).unwrap(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: TST_INFO,
                econtent: Some(Any::new(der::Tag::OctetString, tst_der).unwrap()),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![info]).unwrap()),
        };
        ContentInfo {
            content_type: SIGNED_DATA,
            content: Any::encode_from(&signed).unwrap(),
        }
        .to_der()
        .unwrap()
    }
}

/// RFC 3161 §2.3: the TSA's key is reserved for timestamping. A certificate
/// whose extended key usage also allows anything else is refused, however
/// the token is otherwise right; so are a non-critical usage and two usage
/// extensions.
#[test]
fn a_certificate_that_serves_another_purpose_is_not_a_timestamping_key() {
    use built::{cert, token, SERIAL, SERVER_AUTH, TIME_STAMPING};
    use calybris_core::tsa::verify_token_der;
    let d = digest();
    let check = |der: &[u8]| {
        let t = token(&d, None, Some((der, SERIAL)));
        verify_token_der(&t, &d, None, &[PinnedTsa::from_der(der).unwrap()])
    };
    let only = cert(&[(&[TIME_STAMPING], true)]);
    let v = check(&only).unwrap();
    assert_eq!(v.gen_time, 1_750_000_000);
    for usages in [
        &[(&[TIME_STAMPING, SERVER_AUTH][..], true)][..],
        &[(&[SERVER_AUTH, TIME_STAMPING][..], true)],
        &[(&[TIME_STAMPING][..], false)],
        &[(&[TIME_STAMPING][..], true), (&[TIME_STAMPING][..], true)],
        &[],
    ] {
        assert_eq!(
            check(&cert(usages)),
            Err(TsaError::NotATimestampingCertificate),
            "{usages:?}"
        );
    }
}

/// RFC 3161 §2.4.1 and RFC 5816: the token must name its signing
/// certificate, and name the pinned one. A token for the same key without
/// that attribute, or naming another certificate or serial, is refused.
#[test]
fn the_token_must_name_the_pinned_certificate() {
    use built::{cert, token, SERIAL, SERVER_AUTH, TIME_STAMPING};
    use calybris_core::tsa::verify_token_der;
    let d = digest();
    let pinned = cert(&[(&[TIME_STAMPING], true)]);
    // Same key, name and serial; another certificate.
    let other = cert(&[(&[TIME_STAMPING, SERVER_AUTH], true)]);
    let pin = [PinnedTsa::from_der(&pinned).unwrap()];
    let check = |v1, v2| verify_token_der(&token(&d, v1, v2), &d, None, &pin);

    let right = Some((&pinned[..], SERIAL));
    check(None, right).unwrap();
    check(right, None).unwrap();
    check(right, right).unwrap();

    assert_eq!(check(None, None), Err(TsaError::NoSigningCertificate));
    for (v1, v2) in [
        (None, Some((&other[..], SERIAL))),
        (Some((&other[..], SERIAL)), None),
        (None, Some((&pinned[..], SERIAL + 1))),
        (Some((&pinned[..], SERIAL + 1)), None),
        (Some((&other[..], SERIAL)), right),
        (right, Some((&other[..], SERIAL))),
    ] {
        assert_eq!(
            check(v1, v2),
            Err(TsaError::SigningCertificateMismatch),
            "{:?} {:?}",
            v1.map(|x| x.1),
            v2.map(|x| x.1)
        );
    }
}
