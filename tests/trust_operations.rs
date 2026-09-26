//! The trust layer under operational failure: a witness's state file
//! corrupted, lost or restored from an old backup, witnesses running at the
//! same time, and a log rotating its signing key.
//!
//! Each test states what the design promises in that situation and checks
//! exactly that, including where the promise ends: one witness restored from
//! a backup can be made to cosign a fork, and what catches it then is the
//! quorum and any auditor holding the real checkpoint.

#![cfg(feature = "full")]
#![cfg(feature = "preview")]

use std::path::Path;
use std::sync::{Arc, Barrier};

use calybris_core::audit::{
    verify_checkpoint, AuditError, Auditor, Comparison, KeyStatus, TimeEvidence, WitnessPolicy,
};
use calybris_core::checkpoint::{Checkpoint, LogSigner, SignedNote, WitnessSigner};
use calybris_core::merkle::{consistency_proof, leaf_hash, root_of, Hash, TreeHead};
use calybris_core::witness::{AddCheckpoint, FileStore, Witness, WitnessError, WitnessStore};

const ORIGIN: &str = "decisions.example/log";

fn leaves(tag: &[u8], n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| {
            let mut data = tag.to_vec();
            data.extend_from_slice(&(i as u64).to_be_bytes());
            leaf_hash(&data)
        })
        .collect()
}

fn log() -> LogSigner {
    LogSigner::from_seed(ORIGIN, &[1; 32]).unwrap()
}

fn head(d: &[Hash]) -> TreeHead {
    TreeHead {
        size: d.len() as u64,
        root: root_of(d),
    }
}

fn note(log: &LogSigner, d: &[Hash]) -> SignedNote {
    log.sign(&Checkpoint::new(ORIGIN, head(d)).unwrap())
}

/// The request proving `d` from its first `old` leaves.
fn request(n: &SignedNote, d: &[Hash], old: usize) -> AddCheckpoint {
    AddCheckpoint {
        old_size: old as u64,
        proof: if old == 0 {
            Vec::new()
        } else {
            consistency_proof(d, old as u64).unwrap()
        },
        note: n.render(),
    }
}

fn signer(i: u8) -> WitnessSigner {
    WitnessSigner::from_seed(&format!("w{i}.example"), &[60 + i; 32]).unwrap()
}

fn witness_at(dir: &Path, i: u8, log: &LogSigner) -> Witness<FileStore> {
    let path = dir.join(format!("w{i}.json"));
    let store = if path.exists() {
        FileStore::open(&path).unwrap()
    } else {
        FileStore::create(&path).unwrap()
    };
    let mut w = Witness::new(signer(i), store);
    w.add_log(ORIGIN, log.verifier().clone());
    w
}

/// Asks `w` to cosign and appends the line to `n` on success.
fn cosign(
    w: &mut Witness<FileStore>,
    n: &mut SignedNote,
    d: &[Hash],
    old: usize,
    now: u64,
) -> Result<(), WitnessError> {
    let line = w.add_checkpoint(&request(n, d, old), now)?;
    n.add_signature(line).unwrap();
    Ok(())
}

fn policy(ids: &[u8], k: usize) -> WitnessPolicy {
    WitnessPolicy::new(
        ids.iter().map(|&i| signer(i).verifier().clone()).collect(),
        k,
    )
    .unwrap()
}

#[test]
fn a_corrupted_state_file_is_refused_and_left_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let log = log();
    let d = leaves(b"a", 6);
    let mut w = witness_at(dir.path(), 0, &log);
    cosign(&mut w, &mut note(&log, &d), &d, 0, 1).unwrap();
    let path = dir.path().join("w0.json");
    let good = std::fs::read(&path).unwrap();
    let truncated = &good[..good.len() / 2];
    let bad_root = String::from_utf8(good.clone())
        .unwrap()
        .replace("\"root\": \"", "\"root\": \"AA");

    let more = leaves(b"a", 9);
    for corrupt in [
        b"".as_slice(),
        b"{not json",
        truncated,
        bad_root.as_bytes(),
        b"[]",
    ] {
        std::fs::write(&path, corrupt).unwrap();
        assert!(FileStore::open(&path).is_err(), "{corrupt:?} opened");
        let err = w
            .add_checkpoint(&request(&note(&log, &more), &more, 6), 2)
            .unwrap_err();
        assert!(matches!(err, WitnessError::Store(_)), "{err:?}");
        assert_eq!(err.http_status(), 500);
        assert_eq!(std::fs::read(&path).unwrap(), corrupt, "left as it was");
    }
}

#[test]
fn a_lost_state_file_is_refused_not_taken_for_a_new_witness() {
    let dir = tempfile::tempdir().unwrap();
    let log = log();
    let d = leaves(b"a", 6);
    let mut w = witness_at(dir.path(), 0, &log);
    cosign(&mut w, &mut note(&log, &d), &d, 0, 1).unwrap();
    let path = dir.path().join("w0.json");
    std::fs::remove_file(&path).unwrap();

    // Without the refusal, this rewritten history would be cosigned: the
    // witness would believe it had never seen the log.
    let fork = leaves(b"b", 6);
    let err = w
        .add_checkpoint(&request(&note(&log, &fork), &fork, 0), 2)
        .unwrap_err();
    assert!(
        matches!(&err, WitnessError::Store(m) if m.contains("is missing")),
        "{err:?}"
    );
    assert!(FileStore::open(&path).is_err());
    assert!(!path.exists(), "a refusal creates nothing");
}

/// The boundary of what a witness can know about itself. Restored from an
/// old backup, one witness cosigns a fork that extends the head it
/// remembers. The quorum does not form, and an auditor holding the real
/// checkpoint turns the fork into proof anyone can check with the log's key.
/// If a majority were restored, the fork would pass the quorum check, and
/// only that proof would remain; so backups of witnesses run by different
/// parties must never be rolled back together.
#[test]
fn a_witness_restored_from_a_stale_backup_cannot_carry_a_fork_past_the_quorum() {
    let dir = tempfile::tempdir().unwrap();
    let log = log();
    let a = leaves(b"a", 10);
    let mut ws: Vec<_> = (0..3).map(|i| witness_at(dir.path(), i, &log)).collect();

    let mut a6 = note(&log, &a[..6]);
    for w in &mut ws {
        cosign(w, &mut a6, &a[..6], 0, 100).unwrap();
    }
    let backups: Vec<Vec<u8>> = (0..3)
        .map(|i| std::fs::read(dir.path().join(format!("w{i}.json"))).unwrap())
        .collect();
    let mut a10 = note(&log, &a);
    for w in &mut ws {
        cosign(w, &mut a10, &a, 6, 200).unwrap();
    }
    let policy = policy(&[0, 1, 2], 2);
    let mut auditor = Auditor::new(ORIGIN, log.verifier().clone(), policy.clone());
    auditor.advance(&a6.render(), &[], 150).unwrap();
    auditor
        .advance(&a10.render(), &consistency_proof(&a, 6).unwrap(), 250)
        .unwrap();

    // The log forks after the sixth record; witness 0 is restored to size 6.
    let mut b = a[..6].to_vec();
    b.extend(leaves(b"b", 4));
    std::fs::write(dir.path().join("w0.json"), &backups[0]).unwrap();
    let mut b10 = note(&log, &b);
    cosign(&mut ws[0], &mut b10, &b, 6, 300).unwrap();
    for w in &mut ws[1..] {
        assert_eq!(
            cosign(w, &mut b10, &b, 6, 300),
            Err(WitnessError::Conflict { latest: 10 })
        );
    }
    assert_eq!(
        verify_checkpoint(&b10.render(), log.verifier(), &policy).unwrap_err(),
        AuditError::QuorumNotMet { got: 1, need: 2 }
    );
    let Comparison::SplitView(proof) = auditor.compare(&b10.render(), &[]).unwrap() else {
        panic!("the fork was not caught");
    };
    proof.verify(log.verifier()).unwrap();

    // A majority rolled back: the fork passes the quorum, and the auditor's
    // proof is what is left.
    std::fs::write(dir.path().join("w1.json"), &backups[1]).unwrap();
    cosign(&mut ws[1], &mut b10, &b, 6, 300).unwrap();
    verify_checkpoint(&b10.render(), log.verifier(), &policy).unwrap();
    assert!(matches!(
        auditor.compare(&b10.render(), &[]).unwrap(),
        Comparison::SplitView(_)
    ));
}

/// Witnesses in their own threads with their own state files, all at once,
/// and several instances of one witness racing on one state file: the
/// independent ones all cosign, and of the racing ones exactly one fork wins.
/// Threads on one machine, sharing only the file lock; different machines
/// share nothing at all, which only makes the first half easier.
#[test]
fn witnesses_at_the_same_time_cosign_once_each_and_one_state_admits_one_fork() {
    let dir = tempfile::tempdir().unwrap();
    let log = log();
    let d = leaves(b"a", 6);
    let n = note(&log, &d);

    let barrier = Arc::new(Barrier::new(5));
    let lines: Vec<_> = (0..5_u8)
        .map(|i| {
            let (barrier, dir, n, d) =
                (barrier.clone(), dir.path().to_owned(), n.clone(), d.clone());
            std::thread::spawn(move || {
                let mut w = witness_at(&dir, i, &self::log());
                barrier.wait();
                w.add_checkpoint(&request(&n, &d, 0), 10).unwrap()
            })
        })
        // Every thread must be running before any is joined: the barrier
        // waits for all five.
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    let mut all = n;
    for line in lines {
        all.add_signature(line).unwrap();
    }
    let w = verify_checkpoint(&all.render(), log.verifier(), &policy(&[0, 1, 2, 3, 4], 5)).unwrap();
    assert_eq!(w.cosigned.len(), 5);

    // Eight instances of witness 9 over one file, each shown its own fork.
    let path = dir.path().join("w9.json");
    FileStore::create(&path).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let results: Vec<_> = (0..8_u8)
        .map(|i| {
            let (barrier, path) = (barrier.clone(), path.clone());
            std::thread::spawn(move || {
                let log = self::log();
                let fork = leaves(&[b'f', i], 6);
                let mut w = Witness::new(signer(9), FileStore::open(&path).unwrap());
                w.add_log(ORIGIN, log.verifier().clone());
                barrier.wait();
                let r = w.add_checkpoint(&request(&note(&log, &fork), &fork, 0), 10);
                (root_of(&fork), r)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    let winners: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    for (_, r) in &results {
        if let Err(e) = r {
            assert_eq!(*e, WitnessError::Conflict { latest: 6 });
        }
    }
    let stored = FileStore::open(&path)
        .unwrap()
        .latest(ORIGIN)
        .unwrap()
        .unwrap();
    assert_eq!(stored.root, winners[0].0);
}

/// A log key is rotated through a transition checkpoint signed by both keys.
/// Verifiers holding either key accept it, witnesses keep their history
/// across the change, an auditor hands over from the old key to the new at
/// that checkpoint, and after the old key is revoked a thief holding it
/// can neither get a checkpoint cosigned nor have one accepted.
#[test]
fn a_log_key_rotates_through_a_checkpoint_both_keys_sign() {
    let dir = tempfile::tempdir().unwrap();
    let old = log();
    let new = LogSigner::from_seed(ORIGIN, &[2; 32]).unwrap();
    let d = leaves(b"a", 10);
    let mut ws: Vec<_> = (0..2).map(|i| witness_at(dir.path(), i, &old)).collect();
    let policy = policy(&[0, 1], 2);

    let mut n6 = note(&old, &d[..6]);
    for w in &mut ws {
        cosign(w, &mut n6, &d[..6], 0, 100).unwrap();
    }

    // The transition: the old key signs, and the new key adds its line.
    let cp8 = Checkpoint::new(ORIGIN, head(&d[..8])).unwrap();
    let mut n8 = old.sign(&cp8);
    n8.add_signature(new.sign(&cp8).signatures()[0].clone())
        .unwrap();
    for w in &mut ws {
        cosign(w, &mut n8, &d[..8], 6, 200).unwrap();
    }
    n8.verify(old.verifier()).unwrap();
    n8.verify(new.verifier()).unwrap();

    // Witnesses switch keys and keep their memory of the log.
    for w in &mut ws {
        w.add_log(ORIGIN, new.verifier().clone());
    }
    let mut n10 = note(&new, &d);
    for w in &mut ws {
        cosign(w, &mut n10, &d, 8, 300).unwrap();
    }
    assert!(n10.verify(old.verifier()).is_err());

    let mut before = Auditor::new(ORIGIN, old.verifier().clone(), policy.clone());
    before.advance(&n6.render(), &[], 150).unwrap();
    before
        .advance(&n8.render(), &consistency_proof(&d[..8], 6).unwrap(), 250)
        .unwrap();
    let mut after = Auditor::new(ORIGIN, new.verifier().clone(), policy.clone());
    after.advance(&n8.render(), &[], 250).unwrap();
    after
        .advance(&n10.render(), &consistency_proof(&d, 8).unwrap(), 350)
        .unwrap();

    // The old key is revoked at 250. What the quorum dated before then
    // still counts; a checkpoint the thief signs afterwards gets no
    // cosignature, and nothing dates it before the revocation.
    let revoked = KeyStatus::revoked_at(250);
    let seen = verify_checkpoint(&n6.render(), old.verifier(), &policy).unwrap();
    revoked
        .accepts(&[TimeEvidence::witnesses(seen.seen_by())])
        .unwrap();
    let e = leaves(b"a", 12);
    let stolen = note(&old, &e);
    for w in &mut ws {
        assert_eq!(
            w.add_checkpoint(&request(&stolen, &e, 10), 400),
            Err(WitnessError::BadLogSignature)
        );
    }
    assert!(revoked.accepts(&[]).is_err());
    assert!(revoked.accepts(&[TimeEvidence::witnesses(400)]).is_err());
}
