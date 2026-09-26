//! The trust layer's refusals at its edges: malformed origins, keys and
//! notes, the limits on signatures, checkpoints of another log, and tokens
//! handled without their response envelope. Each is an input an attacker or
//! a broken peer can send; each must be refused with a reason, not accepted
//! and not a panic.

#![cfg(feature = "preview")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use calybris_core::audit::{AuditError, Auditor, Comparison, WitnessPolicy};
use calybris_core::checkpoint::{
    Checkpoint, CheckpointError, LogSigner, NoteVerifier, SignedNote, WitnessSigner, MAX_SIGNATURES,
};
use calybris_core::merkle::{leaf_hash, root_of, Hash, TreeHead};

const ORIGIN: &str = "decisions.example/log";

fn head(n: usize) -> TreeHead {
    let d: Vec<Hash> = (0..n as u64).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    TreeHead {
        size: n as u64,
        root: root_of(&d),
    }
}

fn log() -> LogSigner {
    LogSigner::from_seed(ORIGIN, &[1; 32]).unwrap()
}

#[test]
fn origins_and_extensions_are_single_clean_lines() {
    for bad in ["", "two\nlines", "tab\there", "nul\0"] {
        assert!(Checkpoint::new(bad, head(1)).is_err(), "{bad:?}");
    }
    let cp = Checkpoint::new(ORIGIN, head(1)).unwrap();
    for bad in ["", "two\nlines", "bell\u{7}"] {
        assert!(cp.clone().with_extension(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        cp.with_extension("prev abc").unwrap().extensions(),
        ["prev abc"]
    );
}

#[test]
fn verifier_and_signer_keys_are_refused_when_malformed() {
    let good = log().verifier().to_vkey();
    let key = good.rsplit('+').next().unwrap();
    let wrong_algorithm = BASE64.encode([[9_u8].as_slice(), &[0; 32]].concat());
    for bad in [
        "no-plus-signs".to_owned(),
        format!("{ORIGIN}+zzzzzzzz+{key}"),
        format!("{ORIGIN}+0123+{key}"),
        format!("{ORIGIN}+01234567+not base64!"),
        format!("{ORIGIN}+01234567+"),
        format!("{ORIGIN}+01234567+{wrong_algorithm}"),
        format!("{ORIGIN}+01234567+{}", BASE64.encode([1_u8; 5])),
    ] {
        assert!(NoteVerifier::parse(&bad).is_err(), "{bad}");
    }
    let v = NoteVerifier::parse(&good).unwrap();
    assert_eq!(v.algorithm(), 0x01);
    assert_eq!(v.key_hash(), log().verifier().key_hash());
    assert_eq!(v.to_vkey(), good);

    let skey = log().to_skey();
    let tail = skey.strip_prefix("PRIVATE+KEY+").unwrap();
    let (_, rest) = tail.split_once('+').unwrap();
    let (_, encoded) = rest.split_once('+').unwrap();
    for bad in [
        tail.to_owned(),
        "PRIVATE+KEY+only-a-name".to_owned(),
        format!("PRIVATE+KEY+bad name+{rest}"),
        format!("PRIVATE+KEY+{ORIGIN}+xyz+{encoded}"),
        format!("PRIVATE+KEY+{ORIGIN}+01234567+%%%"),
    ] {
        assert!(LogSigner::from_skey(&bad).is_err(), "{bad}");
    }
    // A witness key (algorithm 0x04) never signs as a log. The other way
    // round is allowed on purpose: a witness may take an Ed25519 seed, as
    // Go's tooling writes them, since cosignatures are domain-separated.
    let witness_skey = WitnessSigner::from_seed("w.example", &[2; 32])
        .unwrap()
        .to_skey();
    assert_eq!(
        LogSigner::from_skey(&witness_skey).unwrap_err(),
        CheckpointError::WrongAlgorithm(0x04)
    );
    assert!(LogSigner::from_skey(&skey).is_ok());
}

#[test]
fn a_signer_never_prints_its_secret() {
    let log = log();
    let shown = format!("{log:?}");
    let secret = log.to_skey();
    let secret_part = secret.rsplit('+').next().unwrap();
    assert!(
        shown.contains("LogSigner") && shown.contains(ORIGIN),
        "{shown}"
    );
    assert!(!shown.contains(secret_part), "{shown}");
    let w = WitnessSigner::from_seed("w.example", &[2; 32]).unwrap();
    let shown = format!("{w:?}");
    assert!(!shown.contains(w.to_skey().rsplit('+').next().unwrap()));
}

/// A note carries at most [`MAX_SIGNATURES`] lines, whether it arrives with
/// them or they are added one by one.
#[test]
fn notes_are_limited_in_signatures_and_refuse_malformed_blocks() {
    let text = Checkpoint::new(ORIGIN, head(2)).unwrap().body();
    let line = |i: usize| {
        let sig = BASE64.encode([&(i as u32).to_be_bytes()[..], &[0; 64]].concat());
        format!("— w{i}.example {sig}\n")
    };
    let full: String = (0..MAX_SIGNATURES).map(line).collect();
    let mut note = SignedNote::parse(&format!("{text}\n{full}")).unwrap();
    assert_eq!(note.signatures().len(), MAX_SIGNATURES);
    let extra = SignedNote::parse(&format!("{text}\n{}", line(MAX_SIGNATURES)))
        .unwrap()
        .signatures()[0]
        .clone();
    assert_eq!(
        note.add_signature(extra),
        Err(CheckpointError::TooManySignatures)
    );
    let over: String = (0..=MAX_SIGNATURES).map(line).collect();
    assert_eq!(
        SignedNote::parse(&format!("{text}\n{over}")),
        Err(CheckpointError::TooManySignatures)
    );

    for bad in [
        format!("{text}\n"),
        format!("{text}\n\n"),
        format!("{text}\n— bad+name AAAAAAAA\n"),
        format!("{text}\n— name-only\n"),
        format!("{text}\nno dash here\n"),
        format!("{text}\n— w.example AAAA\n"),
    ] {
        assert!(SignedNote::parse(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_cosignature_of_the_wrong_length_or_over_too_short_a_text_is_refused() {
    let w = WitnessSigner::from_seed("w.example", &[2; 32]).unwrap();
    assert!(w.cosign("only\ntwo\n", 1).is_err());
    let log = log();
    let mut note = log.sign(&Checkpoint::new(ORIGIN, head(2)).unwrap());
    let good = w.cosign(note.text(), 7).unwrap();
    // The witness's name and key hash, but a signature 4 bytes short.
    let raw = BASE64
        .decode(good.line().trim_end().rsplit(' ').next().unwrap())
        .unwrap();
    let short = BASE64.encode(&raw[..raw.len() - 4]);
    let forged = SignedNote::parse(&format!("{}\n— w.example {short}\n", note.text()))
        .unwrap()
        .signatures()[0]
        .clone();
    note.add_signature(forged).unwrap();
    assert!(note.cosignature_time(w.verifier()).is_err());
}

/// Checkpoints of another log, even signed by the right key, are not this
/// log's; and two checkpoints of one size with two roots are proof.
#[test]
fn an_auditor_refuses_another_origin_and_catches_a_second_root_at_one_size() {
    let log = log();
    let w = WitnessSigner::from_seed("w.example", &[2; 32]).unwrap();
    let policy = WitnessPolicy::new(vec![w.verifier().clone()], 1).unwrap();
    assert_eq!(policy.threshold(), 1);
    assert_eq!(policy.witnesses().len(), 1);
    let cosigned = |origin: &str, h: TreeHead| {
        let mut n = log.sign(&Checkpoint::new(origin, h).unwrap());
        let line = w.cosign(n.text(), 5).unwrap();
        n.add_signature(line).unwrap();
        n.render()
    };
    let mut auditor = Auditor::new(ORIGIN, log.verifier().clone(), policy);
    assert_eq!(
        auditor
            .compare(&cosigned(ORIGIN, head(2)), &[])
            .unwrap_err(),
        AuditError::NoCheckpoint
    );
    auditor
        .advance(&cosigned(ORIGIN, head(4)), &[], 10)
        .unwrap();

    let elsewhere = cosigned("another.example/log", head(4));
    assert!(matches!(
        auditor.advance(&elsewhere, &[], 10),
        Err(AuditError::WrongOrigin { .. })
    ));
    assert!(matches!(
        auditor.compare(&elsewhere, &[]),
        Err(AuditError::WrongOrigin { .. })
    ));

    let second_root = cosigned(
        ORIGIN,
        TreeHead {
            size: 4,
            root: [9; 32],
        },
    );
    assert!(matches!(
        auditor.compare(&second_root, &[]).unwrap(),
        Comparison::SplitView(_)
    ));
    assert_eq!(
        auditor.advance(&second_root, &[], 10).unwrap_err(),
        AuditError::Inconsistent
    );
}

#[cfg(feature = "preview-tsa")]
mod tsa {
    use calybris_core::tsa::{verify_response, verify_token_der, PinnedTsa, TsaError};
    use der::{Decode as _, Encode as _};
    use sha2::{Digest as _, Sha256};

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

    /// A token kept without its response envelope verifies the same way.
    #[test]
    fn a_bare_token_verifies_like_the_response_it_came_in() {
        let digest: [u8; 32] = Sha256::digest(fixture("body.txt")).into();
        for (tsr, crt) in [
            ("rsa.tsr", "rsa.crt"),
            ("p256.tsr", "p256.crt"),
            ("p384.tsr", "p384.crt"),
        ] {
            let raw = fixture(tsr);
            let resp = x509_tsp::TimeStampResp::from_der(&raw).unwrap();
            let token = resp.time_stamp_token.unwrap().to_der().unwrap();
            let pins = [pin(crt)];
            let bare = verify_token_der(&token, &digest, None, &pins).unwrap();
            let wrapped = verify_response(&fixture(tsr), &digest, None, &pins).unwrap();
            assert_eq!(bare, wrapped, "{tsr}");
            assert!(pins[0].subject().contains("CN="), "{}", pins[0].subject());
            assert!(verify_token_der(&token[..token.len() - 1], &digest, None, &pins).is_err());
        }
        let huge = vec![0_u8; 1 << 20];
        assert!(matches!(
            verify_token_der(&huge, &[0; 32], None, &[pin("rsa.crt")]),
            Err(TsaError::Malformed(_))
        ));
        assert!(matches!(
            verify_response(&huge, &[0; 32], None, &[pin("rsa.crt")]),
            Err(TsaError::Malformed(_))
        ));
        for bad in [
            "",
            "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----",
        ] {
            assert!(PinnedTsa::from_pem(bad).is_err());
        }
        assert!(PinnedTsa::from_der(b"junk").is_err());
    }
}
