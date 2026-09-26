//! OpenTimestamps proofs written by the reference client, and one Bitcoin
//! block.
//!
//! `tests/fixtures/ots/`:
//!
//! - `hello-world.txt.ots` and `incomplete.txt.ots` are the examples shipped
//!   with the reference client (github.com/opentimestamps/opentimestamps-client,
//!   `examples/`): one anchored in Bitcoin block 358391 in 2015, one pending.
//! - `checkpoint.body.ots` stamps a Calybris checkpoint body: built with the
//!   reference Python library, submitted to a.pool and b.pool.opentimestamps.org
//!   on 2026-09-26, pending when pinned.
//! - `block358391.hex` is that block's 80-byte header, as served identically
//!   by mempool.space and blockstream.info.

#![cfg(feature = "preview")]

use calybris_core::ots::{DetachedTimestamp, OtsError, Status};
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/ots/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn header() -> [u8; 80] {
    let hex = String::from_utf8(fixture("block358391.hex")).unwrap();
    let hex = hex.trim();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn ci_fuzz_unsorted_forks_roundtrip_without_changing_the_proof() {
    let raw = fixture("crash-065f6fa91bd55aef2965abcfebdcec4eb0715d5f.ots");
    let proof = DetachedTimestamp::parse(&raw).unwrap();
    let canonical = proof.serialize();
    let again = DetachedTimestamp::parse(&canonical).unwrap();
    assert_eq!(again, proof);
    assert_eq!(again.serialize(), canonical);
    assert_eq!(again.digest(), proof.digest());
    assert_eq!(
        again.timestamp().attestations(),
        proof.timestamp().attestations()
    );
    assert!(matches!(
        proof.status(),
        Status::Pending { .. } | Status::Anchored { .. }
    ));
}

#[test]
fn reference_client_files_parse_and_serialize_back_byte_for_byte() {
    for name in ["hello-world.txt", "incomplete.txt", "checkpoint.body"] {
        let raw = fixture(&format!("{name}.ots"));
        let proof = DetachedTimestamp::parse(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        let digest: [u8; 32] = Sha256::digest(fixture(name)).into();
        assert_eq!(proof.digest(), digest, "{name} is a proof of that file");
        assert_eq!(proof.serialize(), raw, "{name}: canonical order differs");
    }
}

#[test]
fn a_2015_proof_verifies_against_the_bitcoin_block_it_names() {
    let proof = DetachedTimestamp::parse(&fixture("hello-world.txt.ots")).unwrap();
    assert_eq!(
        proof.status(),
        Status::Anchored {
            heights: vec![358_391]
        }
    );
    let v = proof.verify_bitcoin(358_391, &header()).unwrap();
    assert_eq!(v.height, 358_391);
    assert_eq!(
        v.block_hash,
        "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
    );
    // 2015-05-28 15:41:18 UTC.
    assert_eq!(v.block_time, 1_432_827_678);

    // Evidence only once a trusted source names the same block.
    let confirmed = v
        .confirm("000000000000000003E892881A8CDCDC117C06D444057C98B6F04A9EE75A2319")
        .unwrap();
    assert_eq!(confirmed.block_time, 1_432_827_678);
    assert_eq!(
        v.confirm("00000000000000000d27a82e56e6c2e0c0e1d7a4c2c9f4d6a9d4b3d8e8f6d5c4"),
        Err(OtsError::NotOnChain)
    );
}

/// The review finding: a header anyone can write, carrying the proof's real
/// Merkle root and an easy target, ground in a few hundred hashes. Before the
/// work floor it passed every check a header can have on its own.
#[test]
fn a_forged_low_difficulty_header_with_the_right_merkle_root_is_refused() {
    let proof = DetachedTimestamp::parse(&fixture("hello-world.txt.ots")).unwrap();
    let mut forged = header();
    forged[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes()); // regtest target
    let found = (0_u32..1_000_000).any(|nonce| {
        forged[76..80].copy_from_slice(&nonce.to_le_bytes());
        let hash: [u8; 32] = Sha256::digest(Sha256::digest(forged)).into();
        hash[31] < 0x7f
    });
    assert!(found, "a regtest-difficulty header takes a few hashes");
    assert_eq!(
        proof.verify_bitcoin(358_391, &forged),
        Err(OtsError::InsufficientWork)
    );
}

#[test]
fn a_header_that_does_not_commit_to_the_proof_or_lacks_the_work_is_refused() {
    let proof = DetachedTimestamp::parse(&fixture("hello-world.txt.ots")).unwrap();
    let mut other_root = header();
    other_root[40] ^= 1;
    assert_eq!(
        proof.verify_bitcoin(358_391, &other_root),
        Err(OtsError::NotInBlock)
    );

    // The right Merkle root in a header whose nonce was changed: its hash no
    // longer meets the target.
    let mut no_work = header();
    no_work[76] ^= 1;
    assert_eq!(
        proof.verify_bitcoin(358_391, &no_work),
        Err(OtsError::BadProofOfWork)
    );

    // The height is part of the check: the right header, claimed for
    // another height, is refused.
    assert_eq!(
        proof.verify_bitcoin(358_390, &header()),
        Err(OtsError::NotInBlock)
    );

    // A pending proof commits to no block at all.
    let pending = DetachedTimestamp::parse(&fixture("incomplete.txt.ots")).unwrap();
    assert_eq!(
        pending.verify_bitcoin(358_391, &header()),
        Err(OtsError::NotInBlock)
    );
}

#[test]
fn a_fresh_checkpoint_stamp_is_pending_and_never_reported_as_anchored() {
    let proof = DetachedTimestamp::parse(&fixture("checkpoint.body.ots")).unwrap();
    assert_eq!(
        proof.status(),
        Status::Pending {
            calendars: vec![
                "https://alice.btc.calendar.opentimestamps.org".into(),
                "https://bob.btc.calendar.opentimestamps.org".into(),
            ]
        }
    );
    assert_eq!(proof.pending().len(), 2);
    assert_eq!(
        proof.verify_bitcoin(358_391, &header()),
        Err(OtsError::NotInBlock)
    );
}

#[test]
fn every_truncation_and_single_byte_change_is_handled_without_panic() {
    let raw = fixture("hello-world.txt.ots");
    for cut in 0..raw.len() {
        assert!(DetachedTimestamp::parse(&raw[..cut]).is_err());
    }
    let honest = DetachedTimestamp::parse(&raw).unwrap();
    for i in 0..raw.len() {
        let mut bad = raw.clone();
        bad[i] ^= 0x01;
        // Whatever still parses must no longer verify against the block at
        // its height, unless the change did not alter the proof's meaning.
        // (Editing the attestation's height is such a change: it then names
        // a block whose header does not commit to it.)
        if let Ok(p) = DetachedTimestamp::parse(&bad) {
            if p.verify_bitcoin(358_391, &header()).is_ok() {
                assert_eq!(
                    p.timestamp().attestations(),
                    honest.timestamp().attestations(),
                    "byte {i}"
                );
            }
        }
    }
}
