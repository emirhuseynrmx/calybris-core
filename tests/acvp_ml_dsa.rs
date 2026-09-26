//! NIST ACVP known-answer tests for the ML-DSA-65 operations `hybrid` uses.
//!
//! This is conformance, not an audit. It shows that the RustCrypto `ml-dsa`
//! crate, called the way `hybrid` calls it, produces exactly the keys and
//! signatures NIST's validation vectors expect, and rejects the signatures
//! they expect rejected. It says nothing about side channels or about code
//! paths these vectors do not reach, which is what an independent audit is for.
//!
//! `tests/fixtures/acvp_ml_dsa_65.json` holds the ML-DSA-65 cases of the
//! ACVP-Server `internalProjection.json` files (a US Government work); its
//! `source` field names the commit. The groups are the ones matching
//! `hybrid`: key generation from a seed, deterministic signing through the
//! external "pure" interface with a context string, and verification through
//! the same interface.

#![cfg(all(feature = "preview-pq", feature = "serde"))]

use ml_dsa::signature::Keypair as _;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, SigningKey,
    VerifyingKey,
};
use sha2::{Digest, Sha256};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/acvp_ml_dsa_65.json")).unwrap()
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn key_generation_from_a_seed_matches_every_nist_vector() {
    let f = fixture();
    let cases = f["keyGen"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for case in cases {
        let seed: [u8; 32] = unhex(&case["seed"]).try_into().unwrap();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        assert_eq!(
            sk.verifying_key().encode().as_slice(),
            unhex(&case["pk"]),
            "tcId {}",
            case["tcId"]
        );
        #[allow(deprecated)]
        let expanded = sk.expanded_key().to_expanded();
        let digest: [u8; 32] = Sha256::digest(expanded.as_slice()).into();
        assert_eq!(
            digest.to_vec(),
            unhex(&case["sk_sha256"]),
            "tcId {}",
            case["tcId"]
        );
    }
}

#[test]
fn deterministic_signing_with_a_context_matches_every_nist_vector() {
    let f = fixture();
    let cases = f["sigGen"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let sk_bytes = unhex(&case["sk"]);
        #[allow(deprecated)]
        let sk = ExpandedSigningKey::<MlDsa65>::from_expanded(
            sk_bytes
                .as_slice()
                .try_into()
                .expect("an ML-DSA-65 expanded key"),
        );
        let sig = sk
            .sign_deterministic(&unhex(&case["message"]), &unhex(&case["context"]))
            .unwrap();
        assert_eq!(
            sig.encode().as_slice(),
            unhex(&case["signature"]),
            "tcId {}",
            case["tcId"]
        );
    }
}

#[test]
fn verification_accepts_and_rejects_exactly_as_nist_expects() {
    let f = fixture();
    let cases = f["sigVer"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    let mut rejected = 0;
    for case in cases {
        let pk_bytes = unhex(&case["pk"]);
        let vk = VerifyingKey::<MlDsa65>::decode(
            &EncodedVerifyingKey::<MlDsa65>::try_from(pk_bytes.as_slice()).unwrap(),
        );
        let sig_bytes = unhex(&case["signature"]);
        let accepted = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
            .ok()
            .and_then(|enc| Signature::<MlDsa65>::decode(&enc))
            .is_some_and(|sig| {
                vk.verify_with_context(&unhex(&case["message"]), &unhex(&case["context"]), &sig)
            });
        assert_eq!(
            accepted,
            case["testPassed"].as_bool().unwrap(),
            "tcId {} ({})",
            case["tcId"],
            case["reason"]
        );
        rejected += usize::from(!accepted);
    }
    assert_eq!(rejected, 12, "the vectors include twelve forgeries");
}
