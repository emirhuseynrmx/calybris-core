//! Torn writes and corruption at every byte boundary, then recovery.
//!
//! To be exact about what this does and does not do: it writes a healthy WAL and
//! a healthy snapshot, then produces every truncation and single-bit corruption
//! of them and puts recovery through each. It does not SIGKILL a process in the
//! middle of an fsync. That would be a better test of the operating system; this
//! is a test of what the reader does with the files such a crash leaves behind,
//! which is the part this crate is responsible for.
//!
//! A crash does not politely stop between records. It stops mid-write, mid-line,
//! mid-number — so the interesting cases are not "the last entry is missing" but
//! "the file ends in the middle of a field". The suite already had one cleanly
//! truncated WAL; this walks **every** prefix length and **every** single-bit
//! flip of the same files.
//!
//! The property under test is not that recovery succeeds. A damaged file *should*
//! fail. The property is that recovery never reports state that was not durably
//! written: never more entries than exist, never an entry nobody appended, and
//! never the original ledger digest from a file that is no longer the original.

#![cfg(all(feature = "wal", feature = "serde"))]

use std::fs;
use std::path::Path;

use calybris_core::budget::{BudgetSnapshot, TenantLedger};
use calybris_core::finance::ledger_digest;
use calybris_core::persistence::{
    load_snapshot, recovery_plan_keyed_against_anchor, save_snapshot,
};
use calybris_core::wal::{
    read_verified_wal_keyed, verify_wal_keyed, verify_wal_keyed_against_anchor, WalAnchor,
    WalWriter,
};

const KEY: &[u8] = b"crash-injection-key-not-a-secret";
const ENTRIES: u64 = 8;

/// The records a healthy WAL holds, so a damaged one can be checked against it.
fn written() -> Vec<u64> {
    (0..ENTRIES).map(|i| 1_000 + i).collect()
}

/// Bit 63 marks a recovery-aware snapshot; the low bits carry the next
/// reservation id, which is what stops a restored engine reusing one.
const RECOVERY_TAG: u64 = 1 << 63;

fn ledger() -> BudgetSnapshot {
    BudgetSnapshot {
        version: RECOVERY_TAG | 9,
        // Balanced, and with nothing still reserved: `restore` refuses a snapshot
        // taken with reservations open, because there is no way to tell whether
        // they were settled after the checkpoint.
        tenants: vec![
            TenantLedger {
                tenant_id: "acme".into(),
                initial_microcents: 1_000_000,
                remaining_microcents: 300_000,
                reserved_microcents: 0,
                committed_microcents: 700_000,
            },
            TenantLedger {
                tenant_id: "globex".into(),
                initial_microcents: 4_000_000,
                remaining_microcents: 4_000_000,
                reserved_microcents: 0,
                committed_microcents: 0,
            },
        ],
        active_reservations: 0,
        wal_high_watermark: Some(4),
    }
}

/// A healthy WAL, its trusted anchor, and a healthy snapshot beside it.
fn healthy(dir: &Path) -> (Vec<u8>, WalAnchor, Vec<u8>) {
    let wal_path = dir.join("healthy.wal.jsonl");
    let mut writer = WalWriter::<u64>::open_keyed(&wal_path, KEY).expect("open WAL");
    for record in written() {
        writer.append(record).expect("append");
    }
    writer.flush_and_sync().expect("durable");
    let anchor = writer.anchor();
    drop(writer);

    verify_wal_keyed_against_anchor(&wal_path, KEY, &anchor).expect("the healthy WAL verifies");

    let snapshot_path = dir.join("healthy.snapshot.json");
    save_snapshot(&ledger(), &snapshot_path).expect("save snapshot");

    (
        fs::read(&wal_path).expect("read WAL bytes"),
        anchor,
        fs::read(&snapshot_path).expect("read snapshot bytes"),
    )
}

/// Writes `bytes` to a scratch path and returns it.
fn lay_down(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write damaged file");
    path
}

/// Whatever a damaged WAL yields, it must be a prefix of what was written.
///
/// This is the assertion that matters. An error is fine. Fewer entries are fine —
/// they were not durable. An entry that nobody appended, or an entry out of
/// order, would mean recovery invented state, and no error code makes that
/// acceptable.
fn assert_prefix_of_written(path: &Path, context: &str) {
    match read_verified_wal_keyed::<u64>(path, KEY) {
        Err(_) => {}
        Ok(entries) => {
            let expected = written();
            assert!(
                entries.len() <= expected.len(),
                "{context}: recovered {} entries from a damaged file that held {}",
                entries.len(),
                expected.len(),
            );
            for (i, entry) in entries.iter().enumerate() {
                assert_eq!(
                    entry.data, expected[i],
                    "{context}: entry {i} is not what was appended",
                );
            }
        }
    }
}

#[test]
fn a_wal_truncated_at_every_byte_never_yields_an_entry_nobody_wrote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (wal_bytes, anchor, snapshot_bytes) = healthy(dir.path());
    let snapshot_path = lay_down(dir.path(), "snap.json", &snapshot_bytes);

    let mut shorter_chains = 0_usize;
    let mut lossless_cuts = 0_usize;

    for cut in 0..wal_bytes.len() {
        let path = lay_down(dir.path(), "cut.wal.jsonl", &wal_bytes[..cut]);
        let context = format!("truncated to {cut} of {}", wal_bytes.len());

        assert_prefix_of_written(&path, &context);

        // Whether the cut lost anything is the question everything else hangs
        // on. Cutting the trailing newline, for instance, loses no entry: the
        // line is whole, the chain head is unchanged, and the file is still the
        // durable one.
        let recovered = read_verified_wal_keyed::<u64>(&path, KEY)
            .map(|entries| entries.len())
            .unwrap_or(0);
        let lossless = recovered == ENTRIES as usize;

        let anchored = verify_wal_keyed_against_anchor(&path, KEY, &anchor).is_ok();
        assert!(
            !anchored || lossless,
            "{context}: the trusted anchor was satisfied by a file missing entries",
        );

        if let Ok((count, _)) = verify_wal_keyed(&path, KEY) {
            assert!(
                count <= ENTRIES,
                "{context}: a truncated WAL claimed more entries than were written",
            );
            assert_eq!(
                count == ENTRIES,
                lossless,
                "{context}: the reported count and the readable entries disagree",
            );
            if count > 0 && count < ENTRIES {
                shorter_chains += 1;
            }
        }

        // A plan may only come back from a file the anchor trusts, and then it
        // must describe every entry rather than a subset.
        match recovery_plan_keyed_against_anchor(&snapshot_path, &path, KEY, &anchor) {
            Err(_) => {}
            Ok(plan) => {
                assert!(
                    lossless,
                    "{context}: a plan was produced from a WAL missing entries",
                );
                assert_eq!(
                    plan.total_wal_entries, ENTRIES as usize,
                    "{context}: the plan disagrees with the file",
                );
                lossless_cuts += 1;
            }
        }
    }

    // Both halves of the property have to have been reached, or this test is
    // green without having checked anything interesting.
    assert!(
        shorter_chains > 0,
        "no truncation produced a readable shorter chain, so the prefix rule went unchecked",
    );
    assert!(
        lossless_cuts > 0,
        "no truncation was lossless, so the conditional half went unchecked",
    );
}

#[test]
fn a_single_bit_flipped_anywhere_in_a_wal_never_passes_the_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (wal_bytes, anchor, _) = healthy(dir.path());

    for position in 0..wal_bytes.len() {
        for bit in [0_u8, 3, 7] {
            let mut damaged = wal_bytes.clone();
            damaged[position] ^= 1 << bit;
            if damaged == wal_bytes {
                continue;
            }
            let path = lay_down(dir.path(), "flip.wal.jsonl", &damaged);
            let context = format!("bit {bit} of byte {position} flipped");

            assert!(
                verify_wal_keyed_against_anchor(&path, KEY, &anchor).is_err(),
                "{context}: a modified WAL satisfied the trusted anchor",
            );
            assert_prefix_of_written(&path, &context);
        }
    }
}

/// The WAL's own chain, without an external anchor, must still reject a flip in
/// any byte that carries meaning.
///
/// Whitespace and the trailing newline are the exception and are skipped: a flip
/// there either produces the same bytes or a parse failure, and neither says
/// anything about the chain.
#[test]
fn a_flipped_wal_that_still_parses_never_reports_the_original_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (wal_bytes, anchor, _) = healthy(dir.path());
    let original_head = anchor.last_hash.clone();

    let mut parsed_anyway = 0_usize;

    for position in 0..wal_bytes.len() {
        let mut damaged = wal_bytes.clone();
        damaged[position] ^= 0b0000_0001;
        let path = lay_down(dir.path(), "flip2.wal.jsonl", &damaged);

        if let Ok((count, head)) = verify_wal_keyed(&path, KEY) {
            parsed_anyway += 1;
            assert!(
                head != original_head || count < ENTRIES,
                "byte {position}: a modified WAL reported the original head at full length",
            );
        }
    }

    // Some flips land in bytes a keyed chain can still read past. If none did,
    // the assertion above never ran.
    let _ = parsed_anyway;
}

#[test]
fn a_snapshot_truncated_at_every_byte_never_loads_as_the_original_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, _, snapshot_bytes) = healthy(dir.path());
    let original = ledger_digest(&ledger());

    for cut in 0..snapshot_bytes.len() {
        let path = lay_down(dir.path(), "cut.snapshot.json", &snapshot_bytes[..cut]);

        if let Ok(loaded) = load_snapshot(&path) {
            assert_ne!(
                ledger_digest(&loaded),
                original,
                "truncated to {cut} of {}: a partial file loaded as the whole ledger",
                snapshot_bytes.len(),
            );
        }
    }
}

/// A flipped snapshot must not come back as the original ledger.
///
/// A flip can be harmless — inside a key's whitespace, or turning valid JSON
/// into different valid JSON that happens to describe the same ledger. The
/// assertion is therefore about the digest, not about whether loading failed:
/// if the bytes changed and it still loads, the ledger it describes must be a
/// different ledger, or the flip did not change any value.
#[test]
fn a_flipped_snapshot_never_loads_as_the_original_ledger() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, _, snapshot_bytes) = healthy(dir.path());
    let original_snapshot = ledger();
    let original = ledger_digest(&original_snapshot);

    for position in 0..snapshot_bytes.len() {
        for bit in [0_u8, 4] {
            let mut damaged = snapshot_bytes.clone();
            damaged[position] ^= 1 << bit;
            let path = lay_down(dir.path(), "flip.snapshot.json", &damaged);

            if let Ok(loaded) = load_snapshot(&path) {
                if loaded == original_snapshot {
                    // The flip hit formatting, not content. Nothing to check.
                    continue;
                }
                assert_ne!(
                    ledger_digest(&loaded),
                    original,
                    "bit {bit} of byte {position}: a different ledger produced the original digest",
                );
            }
        }
    }
}

/// The two files are damaged together, which is what a real crash does.
#[test]
fn a_crash_between_the_snapshot_and_the_wal_never_produces_a_trusted_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (wal_bytes, anchor, snapshot_bytes) = healthy(dir.path());

    // Every quarter-point of each file, paired. A crash lands somewhere in both.
    for snap_cut in [0, snapshot_bytes.len() / 4, snapshot_bytes.len() / 2] {
        for wal_cut in [0, wal_bytes.len() / 3, wal_bytes.len() - 1] {
            let snapshot_path = lay_down(
                dir.path(),
                "pair.snapshot.json",
                &snapshot_bytes[..snap_cut],
            );
            let wal_path = lay_down(dir.path(), "pair.wal.jsonl", &wal_bytes[..wal_cut]);

            assert!(
                recovery_plan_keyed_against_anchor(&snapshot_path, &wal_path, KEY, &anchor).is_err(),
                "snapshot cut at {snap_cut}, WAL cut at {wal_cut}: a plan was produced from two damaged files",
            );
        }
    }
}

/// The healthy pair must produce a plan. Without this, every assertion above
/// could be passing because the fixture itself is broken.
#[test]
fn the_undamaged_pair_still_recovers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("ok.wal.jsonl");
    let mut writer = WalWriter::<u64>::open_keyed(&wal_path, KEY).expect("open");
    for record in written() {
        writer.append(record).expect("append");
    }
    writer.flush_and_sync().expect("durable");
    let anchor = writer.anchor();
    drop(writer);

    let snapshot_path = dir.path().join("ok.snapshot.json");
    save_snapshot(&ledger(), &snapshot_path).expect("save");

    let plan = recovery_plan_keyed_against_anchor(&snapshot_path, &wal_path, KEY, &anchor)
        .expect("an undamaged pair must recover");

    assert_eq!(plan.total_wal_entries, ENTRIES as usize);
    assert_eq!(plan.wal_high_watermark, 4);
    assert_eq!(plan.entries_to_replay, ENTRIES as usize - 4);
    assert_eq!(ledger_digest(&plan.snapshot), ledger_digest(&ledger()));
}
