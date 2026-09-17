//! The fuzz seeds have to be the shape their target decodes.
//!
//! libFuzzer cannot be run on every developer machine, so nothing would
//! otherwise notice a seed that never decodes. A seed like that is not merely
//! useless: it makes the fuzz target look seeded while leaving it to rediscover
//! the format from random bytes, which is the whole thing seeding exists to
//! avoid.
//!
//! This is also the test that keeps `fuzz/seeds` in step with the targets. If a
//! target is added without seeds, or a seed directory is named after a target
//! that no longer exists, it fails here rather than silently in a job nobody
//! reads.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use calybris_core::budget::BudgetSnapshot;
use calybris_core::outcome::Outcome;
use calybris_core::provenance::SignedPolicy;
use calybris_core::receipt::DecisionReceipt;
use calybris_core::wal::WalEntry;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every target declared in `fuzz/Cargo.toml`, read from the manifest rather
/// than listed here, so the two cannot drift apart.
fn declared_targets() -> BTreeSet<String> {
    let manifest =
        fs::read_to_string(repo().join("fuzz/Cargo.toml")).expect("the fuzz manifest must exist");
    let mut targets = BTreeSet::new();
    for line in manifest.lines() {
        if let Some(rest) = line.trim().strip_prefix("name = \"") {
            if let Some(name) = rest.strip_suffix('"') {
                // The package itself is also `name = "..."`; its value has a
                // dash, and no target does.
                if !name.contains('-') {
                    targets.insert(name.to_string());
                }
            }
        }
    }
    assert!(
        !targets.is_empty(),
        "no fuzz targets parsed from the manifest"
    );
    targets
}

fn seeds_for(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = repo().join("fuzz/seeds").join(target);
    let mut seeds: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("{target} has no seed directory at fuzz/seeds/{target}"))
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            (name, fs::read(entry.path()).expect("read seed"))
        })
        .collect();
    seeds.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!seeds.is_empty(), "{target} has an empty seed directory");
    seeds
}

#[test]
fn every_fuzz_target_has_seeds_and_every_seed_directory_has_a_target() {
    let declared = declared_targets();

    let seed_root = repo().join("fuzz/seeds");
    let on_disk: BTreeSet<String> = fs::read_dir(&seed_root)
        .expect("fuzz/seeds must exist")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(
        declared, on_disk,
        "the fuzz targets and the seed directories disagree",
    );
}

#[test]
fn every_snapshot_seed_decodes_as_a_snapshot() {
    for (name, bytes) in seeds_for("snapshot_decode") {
        serde_json::from_slice::<BudgetSnapshot>(&bytes)
            .unwrap_or_else(|e| panic!("snapshot_decode/{name} is not a BudgetSnapshot: {e}"));
    }
}

#[test]
fn every_outcome_seed_decodes_as_an_outcome() {
    for (name, bytes) in seeds_for("outcome_decode") {
        let outcome = serde_json::from_slice::<Outcome>(&bytes)
            .unwrap_or_else(|e| panic!("outcome_decode/{name} is not an Outcome: {e}"));
        // A seed that validation refuses is fine and useful; one that panics is
        // the bug the target is looking for, so it must not be in the corpus.
        let _ = outcome.validate();
    }
}

#[test]
fn every_policy_seed_decodes_as_a_signed_policy() {
    for (name, bytes) in seeds_for("policy_decode") {
        serde_json::from_slice::<SignedPolicy>(&bytes)
            .unwrap_or_else(|e| panic!("policy_decode/{name} is not a SignedPolicy: {e}"));
    }
}

#[test]
fn every_receipt_seed_decodes_as_a_receipt() {
    for (name, bytes) in seeds_for("receipt_decode") {
        serde_json::from_slice::<DecisionReceipt>(&bytes)
            .unwrap_or_else(|e| panic!("receipt_decode/{name} is not a DecisionReceipt: {e}"));
    }
}

#[test]
fn every_wal_seed_has_at_least_one_decodable_line() {
    for (name, bytes) in seeds_for("wal_decode") {
        let decodable = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .filter(|line| serde_json::from_slice::<WalEntry<serde_json::Value>>(line).is_ok())
            .count();
        assert!(
            decodable > 0,
            "wal_decode/{name} has no line that decodes as a WAL entry",
        );
    }
}

/// The kernel target reads raw integers, so its seeds are bytes rather than
/// JSON. The only thing to check is that they are long enough to be used at
/// all — the target returns immediately below 32 bytes.
#[test]
fn every_kernel_seed_is_long_enough_to_reach_the_kernel() {
    for (name, bytes) in seeds_for("kernel_decide") {
        assert!(
            bytes.len() >= 32,
            "kernel_decide/{name} is {} bytes; the target ignores anything under 32",
            bytes.len(),
        );
    }
}
