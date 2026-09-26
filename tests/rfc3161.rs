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
