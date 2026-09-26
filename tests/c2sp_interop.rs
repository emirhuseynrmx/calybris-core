//! Byte-for-byte agreement with the Go reference implementation of the C2SP
//! signed-note and tlog-cosignature formats.
//!
//! `tests/fixtures/c2sp_go_vectors.json` was written by
//! `tests/interop/c2sp_go/main.go`, which signs a checkpoint with
//! `golang.org/x/mod/sumdb/note` and co-signs it with
//! `github.com/transparency-dev/formats/note`. Ed25519 signing is
//! deterministic, so agreement runs both ways without Go in the loop: this
//! crate verifies what Go signed, and signing the same checkpoint with the
//! same keys and timestamp reproduces Go's note exactly — which Go therefore
//! verifies.

#![cfg(all(feature = "preview", feature = "serde"))]

use calybris_core::checkpoint::{LogSigner, NoteVerifier, SignedNote, WitnessSigner};

struct Vectors {
    log_skey: String,
    log_vkey: String,
    witness_skey: String,
    witness_vkey: String,
    note: String,
}

fn vectors() -> Vectors {
    let raw = include_str!("fixtures/c2sp_go_vectors.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_owned();
    Vectors {
        log_skey: s("log_skey"),
        log_vkey: s("log_vkey"),
        witness_skey: s("witness_skey"),
        witness_vkey: s("witness_vkey"),
        note: s("note"),
    }
}

#[test]
fn a_note_signed_and_cosigned_by_go_verifies_here() {
    let v = vectors();
    let log = NoteVerifier::parse(&v.log_vkey).unwrap();
    let witness = NoteVerifier::parse(&v.witness_vkey).unwrap();
    let note = SignedNote::parse(&v.note).unwrap();
    note.verify(&log).unwrap();
    let time = note.cosignature_time(&witness).unwrap();
    assert!(time > 1_700_000_000, "a real Unix time, got {time}");
    let cp = note.checkpoint().unwrap();
    assert_eq!(cp.origin(), "calybris.example/interop");
    assert_eq!(cp.size(), 5);
    assert_eq!(cp.extensions(), ["prev deadbeef"]);
    assert_eq!(note.render(), v.note, "parse and render are exact inverses");
}

#[test]
fn keys_written_by_go_read_and_write_back_identically() {
    let v = vectors();
    let log = LogSigner::from_skey(&v.log_skey).unwrap();
    assert_eq!(log.to_skey(), v.log_skey);
    assert_eq!(log.verifier().to_vkey(), v.log_vkey);
    let witness = WitnessSigner::from_skey(&v.witness_skey).unwrap();
    assert_eq!(witness.to_skey(), v.witness_skey);
    assert_eq!(witness.verifier().to_vkey(), v.witness_vkey);
}

#[test]
fn signing_here_reproduces_go_byte_for_byte() {
    let v = vectors();
    let go_note = SignedNote::parse(&v.note).unwrap();
    let cp = go_note.checkpoint().unwrap();
    let witness_key = NoteVerifier::parse(&v.witness_vkey).unwrap();
    let time = go_note.cosignature_time(&witness_key).unwrap();

    let log = LogSigner::from_skey(&v.log_skey).unwrap();
    let witness = WitnessSigner::from_skey(&v.witness_skey).unwrap();
    let mut ours = log.sign(&cp);
    ours.add_signature(witness.cosign(ours.text(), time).unwrap())
        .unwrap();
    assert_eq!(ours.render(), v.note);
}
