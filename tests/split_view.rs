//! Split-view detection with real witnesses.
//!
//! A log that holds its signing key can sign as many histories as it likes.
//! These tests play that log against witnesses running the actual
//! `witness::Witness` state machine: the log shows one history to some
//! witnesses and a different one to others, in every order, and then tries to
//! get each fork cosigned by everyone. What must hold:
//!
//! - No witness ever cosigns both forks.
//! - With a majority threshold, at most one fork reaches quorum.
//! - An auditor holding either fork catches the other, with transferable
//!   proof when the sizes match.

#![cfg(feature = "preview")]

use calybris_core::audit::{verify_checkpoint, AuditError, Auditor, Comparison, WitnessPolicy};
use calybris_core::checkpoint::{Checkpoint, LogSigner, SignedNote, WitnessSigner};
use calybris_core::merkle::{consistency_proof, leaf_hash, root_of, Hash, TreeHead};
use calybris_core::witness::{AddCheckpoint, MemoryStore, Witness};
use proptest::prelude::*;

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

fn witnesses(n: usize) -> Vec<Witness<MemoryStore>> {
    (0..n)
        .map(|i| {
            let seed = [u8::try_from(40 + i).unwrap(); 32];
            let mut w = Witness::new(
                WitnessSigner::from_seed(&format!("w{i}.example"), &seed).unwrap(),
                MemoryStore::new(),
            );
            w.add_log(ORIGIN, log().verifier().clone());
            w
        })
        .collect()
}

fn policy(ws: &[Witness<MemoryStore>], k: usize) -> WitnessPolicy {
    WitnessPolicy::new(
        ws.iter().map(|w| w.signer().verifier().clone()).collect(),
        k,
    )
    .unwrap()
}

/// The log's side: ask `w` to cosign `note`, the log's checkpoint of the tree
/// over `d`, proving consistency from whatever `w` last cosigned. Returns
/// whether the witness cosigned.
fn submit(w: &mut Witness<MemoryStore>, d: &[Hash], note: &mut SignedNote) -> bool {
    let old = w.store().heads().get(ORIGIN).map_or(0, |h| h.size);
    if old > d.len() as u64 {
        return false;
    }
    let proof = if old == 0 || old == d.len() as u64 {
        Vec::new()
    } else {
        consistency_proof(d, old).unwrap()
    };
    let req = AddCheckpoint {
        old_size: old,
        proof,
        note: note.render(),
    };
    match w.add_checkpoint(&req, 1_000) {
        Ok(sig) => {
            note.add_signature(sig).unwrap();
            true
        }
        Err(_) => false,
    }
}

fn signed(log: &LogSigner, d: &[Hash]) -> SignedNote {
    let head = TreeHead {
        size: d.len() as u64,
        root: root_of(d),
    };
    log.sign(&Checkpoint::new(ORIGIN, head).unwrap())
}

#[test]
fn a_witness_that_saw_one_history_refuses_the_other() {
    let log = log();
    let mut ws = witnesses(1);
    let honest = leaves(b"a", 12);
    let mut fork = honest[..5].to_vec();
    fork.extend(leaves(b"b", 7));

    let mut a = signed(&log, &honest);
    assert!(submit(&mut ws[0], &honest, &mut a));
    let mut b = signed(&log, &fork);
    assert!(!submit(&mut ws[0], &fork, &mut b));
    // Not even a longer version of the fork, with a correct proof in its own
    // history, gets through.
    let mut longer = fork.clone();
    longer.extend(leaves(b"c", 9));
    let mut c = signed(&log, &longer);
    assert!(!submit(&mut ws[0], &longer, &mut c));
}

#[test]
fn an_auditor_on_the_quorum_history_proves_the_fork_it_is_shown() {
    let log = log();
    let mut ws = witnesses(3);
    let honest = leaves(b"a", 10);
    let mut fork = honest[..4].to_vec();
    fork.extend(leaves(b"b", 6));

    let mut a = signed(&log, &honest);
    for w in &mut ws {
        assert!(submit(w, &honest, &mut a));
    }
    let mut auditor = Auditor::new(ORIGIN, log.verifier().clone(), policy(&ws, 2));
    auditor.advance(&a.render(), &[], 1_000).unwrap();

    // Same size, different root: the log's two signatures are the proof.
    let b = signed(&log, &fork);
    match auditor.compare(&b.render(), &[]).unwrap() {
        Comparison::SplitView(evidence) => evidence.verify(log.verifier()).unwrap(),
        Comparison::Consistent => panic!("fork of equal size went unnoticed"),
    }
    // It never reaches the quorum either.
    assert!(matches!(
        verify_checkpoint(&b.render(), log.verifier(), &policy(&ws, 2)),
        Err(AuditError::QuorumNotMet { got: 0, need: 2 })
    ));
}

fn fork_case() -> impl Strategy<Value = (usize, usize, usize, usize, u32)> {
    (3_usize..=7).prop_flat_map(|n| {
        (2_usize..40).prop_flat_map(move |honest| {
            (0..honest).prop_flat_map(move |shared| {
                (shared + 1..shared + 40, 0_u32..(1 << n))
                    .prop_map(move |(fork_len, order)| (n, honest, shared, fork_len, order))
            })
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// The log shows each witness one fork first (bit i of `order`), then
    /// tries to get the other fork cosigned by every witness.
    #[test]
    fn with_a_majority_threshold_at_most_one_fork_reaches_quorum(
        (n, honest_len, shared, fork_len, order) in fork_case()
    ) {
        let log = log();
        let mut ws = witnesses(n);
        let k = n / 2 + 1;
        let honest = leaves(b"a", honest_len);
        let mut fork = honest[..shared].to_vec();
        fork.extend(leaves(b"b", fork_len - shared));

        let mut a = signed(&log, &honest);
        let mut b = signed(&log, &fork);
        let mut signed_a = vec![false; n];
        let mut signed_b = vec![false; n];
        for (i, w) in ws.iter_mut().enumerate() {
            if order & (1 << i) == 0 {
                signed_a[i] = submit(w, &honest, &mut a);
                signed_b[i] = submit(w, &fork, &mut b);
            } else {
                signed_b[i] = submit(w, &fork, &mut b);
                signed_a[i] = submit(w, &honest, &mut a);
            }
        }

        // A fork is a fork only if neither history extends the other.
        let fork_extends_honest = fork_len >= honest_len
            && root_of(&fork[..honest_len]) == root_of(&honest);
        let honest_extends_fork = honest_len >= fork_len
            && root_of(&honest[..fork_len]) == root_of(&fork);
        prop_assume!(!fork_extends_honest && !honest_extends_fork);

        for i in 0..n {
            prop_assert!(!(signed_a[i] && signed_b[i]), "witness {} signed both forks", i);
        }
        let p = policy(&ws, k);
        let a_ok = verify_checkpoint(&a.render(), log.verifier(), &p).is_ok();
        let b_ok = verify_checkpoint(&b.render(), log.verifier(), &p).is_ok();
        prop_assert!(!(a_ok && b_ok));

        // Whichever fork reached quorum, an auditor holding it catches the
        // other: proof for equal sizes, a failed consistency proof otherwise.
        let (winner, loser, winner_leaves, loser_leaves) = if a_ok {
            (&a, &b, &honest, &fork)
        } else if b_ok {
            (&b, &a, &fork, &honest)
        } else {
            return Ok(());
        };
        let mut auditor = Auditor::new(ORIGIN, log.verifier().clone(), p);
        auditor.advance(&winner.render(), &[], 1_000).unwrap();
        let (small, large) = if winner_leaves.len() <= loser_leaves.len() {
            (winner_leaves, loser_leaves)
        } else {
            (loser_leaves, winner_leaves)
        };
        // The best proof the log can offer: a real proof inside the larger tree.
        let proof = if small.len() == large.len() {
            Vec::new()
        } else {
            consistency_proof(large, small.len() as u64).unwrap()
        };
        match auditor.compare(&loser.render(), &proof) {
            Ok(Comparison::SplitView(evidence)) => {
                prop_assert_eq!(small.len(), large.len());
                prop_assert!(evidence.verify(log.verifier()).is_ok());
            }
            Err(AuditError::Inconsistent) => prop_assert_ne!(small.len(), large.len()),
            other => prop_assert!(false, "fork not caught: {:?}", other),
        }
    }
}
