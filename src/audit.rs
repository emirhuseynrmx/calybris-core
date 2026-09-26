//! What an outside auditor checks: witness quorums, split views, record
//! inclusion, and when a record provably existed.
//!
//! The pieces below answer four questions an auditor who trusts neither the
//! log operator nor any single witness has to be able to answer.
//!
//! **Did enough independent parties see this checkpoint?**
//! [`WitnessPolicy`] names the witnesses a verifier trusts and how many of them
//! must have cosigned. A checkpoint that clears the policy has been checked by
//! that many witnesses against everything each of them signed before. With a
//! threshold above half the witnesses, two checkpoints that do not extend each
//! other cannot both clear it unless the witnesses that signed both are
//! dishonest: an honest witness signs at most one history.
//!
//! **Was I shown the same log as everyone else?** A split view is a log
//! showing different histories to different parties. [`Auditor`] keeps one
//! party's view and accepts a new checkpoint only with a consistency proof from
//! the last one; [`Auditor::compare`] checks a checkpoint someone else was shown.
//! Two checkpoints of the same size with different roots, both signed by the
//! log, are proof anyone can check: [`SplitView`] carries them.
//!
//! **Is this record in the log, and since when?** [`Auditor::verify_record`]
//! checks an inclusion proof against the latest witnessed checkpoint and says
//! by when the witnesses had seen it. That time is not the operator's claim:
//! it is the `threshold`-th earliest cosignature time, so at least `threshold`
//! independent witnesses say they had seen the checkpoint by then.
//!
//! **What if the operator's keys are stolen, or the operator turns?** A stolen
//! log key signs checkpoints; it cannot make honest witnesses cosign a history
//! that contradicts what they already signed, so the witnessed past cannot be
//! rewritten and a fork cannot reach the quorum. What it *can* do is sign new
//! records, possibly dated in the past. [`KeyStatus`] closes that: once a key
//! is marked revoked at time *t*, something it signed counts only if its
//! *signature* is proven — by witnesses, an RFC 3161 token or a
//! Bitcoin-anchored OpenTimestamps proof, never by the signer's own clock — to
//! have existed before *t*. Evidence that dates only the signed content does
//! not count: a thief can sign an old body that was timestamped long ago.

use crate::checkpoint::{
    Checkpoint, CheckpointError, NoteVerifier, SignedNote, ALG_COSIGNATURE_V1,
};
use crate::merkle::{verify_consistency, verify_inclusion, Hash, MerkleError};

/// Why an audit check failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    #[error("{0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("{0}")]
    Merkle(#[from] MerkleError),
    #[error("witness policy is invalid: {0}")]
    BadPolicy(&'static str),
    #[error("{got} of the required {need} witnesses cosigned")]
    QuorumNotMet { got: usize, need: usize },
    #[error("checkpoint is for {got:?}, not the audited log {want:?}")]
    WrongOrigin { got: String, want: String },
    #[error("checkpoint is smaller than one already accepted")]
    Shrinking,
    /// The log could not show that one of its checkpoints extends another.
    /// Not proof of a fork on its own, since the proof may simply be wrong,
    /// but a log that cannot produce the proof has not shown one history.
    #[error("the log did not prove that one checkpoint extends the other")]
    Inconsistent,
    #[error("the newest witness cosignature is older than the allowed age")]
    Stale,
    #[error("no checkpoint has been accepted yet")]
    NoCheckpoint,
    #[error("nothing proves this existed before its key was revoked")]
    TimeUnproven,
    /// There is evidence of when the content existed, none of when it was
    /// signed.
    #[error("the evidence dates the content, not the signature, so it cannot show the signature predates the revocation")]
    SignatureUndated,
    #[error(
        "this was first proven to exist at {existed_by}, after its key was revoked at {revoked_at}"
    )]
    SignedAfterRevocation { existed_by: u64, revoked_at: u64 },
}

/// The witnesses a verifier trusts and how many must cosign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessPolicy {
    witnesses: Vec<NoteVerifier>,
    threshold: usize,
}

impl WitnessPolicy {
    /// `threshold` of `witnesses` must cosign. Each witness must be a
    /// `cosignature/v1` key and appear once.
    pub fn new(witnesses: Vec<NoteVerifier>, threshold: usize) -> Result<Self, AuditError> {
        if threshold == 0 {
            return Err(AuditError::BadPolicy("threshold must be at least one"));
        }
        if threshold > witnesses.len() {
            return Err(AuditError::BadPolicy(
                "threshold exceeds the number of witnesses",
            ));
        }
        if witnesses
            .iter()
            .any(|w| w.algorithm() != ALG_COSIGNATURE_V1)
        {
            return Err(AuditError::BadPolicy(
                "witness keys must be cosignature/v1 keys",
            ));
        }
        for (i, w) in witnesses.iter().enumerate() {
            if witnesses[..i].iter().any(|o| {
                o.public_key() == w.public_key()
                    || (o.name() == w.name() && o.key_hash() == w.key_hash())
            }) {
                return Err(AuditError::BadPolicy("a witness is listed twice"));
            }
        }
        Ok(Self {
            witnesses,
            threshold,
        })
    }

    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    #[must_use]
    pub fn witnesses(&self) -> &[NoteVerifier] {
        &self.witnesses
    }

    /// The valid cosignatures on `note` from this policy's witnesses. Lines
    /// from other keys are ignored; a line from a listed witness that does
    /// not verify is not counted.
    #[must_use]
    pub fn cosignatures(&self, note: &SignedNote) -> Vec<Cosigned> {
        self.witnesses
            .iter()
            .filter_map(|w| {
                note.cosignature_time(w).ok().map(|time| Cosigned {
                    witness: w.name().to_owned(),
                    time,
                })
            })
            .collect()
    }
}

/// One witness's valid cosignature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosigned {
    pub witness: String,
    /// Unix seconds, as the witness stated it.
    pub time: u64,
}

/// A checkpoint signed by the log and cosigned by a quorum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witnessed {
    pub note: SignedNote,
    pub checkpoint: Checkpoint,
    /// Every counted cosignature, earliest first.
    pub cosigned: Vec<Cosigned>,
    threshold: usize,
}

impl Witnessed {
    /// The time by which at least `threshold` witnesses say they had seen
    /// this checkpoint: the `threshold`-th earliest cosignature time.
    #[must_use]
    pub fn seen_by(&self) -> u64 {
        self.cosigned[self.threshold - 1].time
    }

    /// The time since which at least `threshold` witnesses have seen the
    /// log in this state: the `threshold`-th latest cosignature time. A log
    /// that stops publishing lets this age.
    #[must_use]
    pub fn fresh_as_of(&self) -> u64 {
        self.cosigned[self.cosigned.len() - self.threshold].time
    }
}

/// Checks the log's signature and the witness quorum on a checkpoint note.
pub fn verify_checkpoint(
    note: &str,
    log: &NoteVerifier,
    policy: &WitnessPolicy,
) -> Result<Witnessed, AuditError> {
    let note = SignedNote::parse(note)?;
    note.verify(log)?;
    let checkpoint = note.checkpoint()?;
    let mut cosigned = policy.cosignatures(&note);
    if cosigned.len() < policy.threshold {
        return Err(AuditError::QuorumNotMet {
            got: cosigned.len(),
            need: policy.threshold,
        });
    }
    cosigned.sort_by_key(|c| c.time);
    Ok(Witnessed {
        note,
        checkpoint,
        cosigned,
        threshold: policy.threshold,
    })
}

/// Two checkpoints of the same log and size with different roots, both
/// validly signed by the log: proof, checkable by anyone with the log's key,
/// that the log showed two histories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitView {
    pub first: SignedNote,
    pub second: SignedNote,
}

impl SplitView {
    /// Re-checks the evidence from scratch.
    pub fn verify(&self, log: &NoteVerifier) -> Result<(), AuditError> {
        self.first.verify(log)?;
        self.second.verify(log)?;
        let (a, b) = (self.first.checkpoint()?, self.second.checkpoint()?);
        if a.origin() == b.origin() && a.size() == b.size() && a.root() != b.root() {
            Ok(())
        } else {
            Err(AuditError::Inconsistent)
        }
    }
}

/// What [`Auditor::compare`] concluded about a checkpoint someone else saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Comparison {
    /// It is on the same history as the auditor's view.
    Consistent,
    /// It contradicts the auditor's view, with transferable proof.
    SplitView(Box<SplitView>),
}

/// Who dated a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSource {
    /// A witness quorum, by the `threshold`-th earliest cosignature time.
    Witnesses,
    /// An RFC 3161 timestamping authority, at `genTime` plus its accuracy.
    Rfc3161,
    /// A Bitcoin block committing to it through OpenTimestamps, confirmed to
    /// be on the chain; the block's timestamp.
    Bitcoin,
}

/// What a piece of time evidence covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Covers {
    /// The signed content only, such as a checkpoint body. Dates what was
    /// said, not when anyone signed it.
    Content,
    /// The content together with the signature on it: a stamp over
    /// `SignedNote::signed_by`, or a witness cosignature (a witness checks the
    /// log's signature before it cosigns).
    Signature,
}

/// When a signed record provably existed, by whose word, and over what.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeEvidence {
    pub source: TimeSource,
    /// Unix seconds.
    pub time: u64,
    pub covers: Covers,
}

impl TimeEvidence {
    /// A witness quorum's time. It covers the log's signature: C2SP witnesses
    /// verify it before they cosign.
    #[must_use]
    pub fn witnesses(time: u64) -> Self {
        Self {
            source: TimeSource::Witnesses,
            time,
            covers: Covers::Signature,
        }
    }

    #[must_use]
    pub fn rfc3161(time: u64, covers: Covers) -> Self {
        Self {
            source: TimeSource::Rfc3161,
            time,
            covers,
        }
    }

    #[must_use]
    pub fn bitcoin(time: u64, covers: Covers) -> Self {
        Self {
            source: TimeSource::Bitcoin,
            time,
            covers,
        }
    }
}

/// The earliest time any piece of independent evidence puts on a record's
/// content.
#[must_use]
pub fn existed_by(evidence: &[TimeEvidence]) -> Option<u64> {
    evidence.iter().map(|e| e.time).min()
}

/// The earliest time any piece of independent evidence puts on a record's
/// signature. Content-only evidence is ignored.
#[must_use]
pub fn signed_by(evidence: &[TimeEvidence]) -> Option<u64> {
    evidence
        .iter()
        .filter(|e| e.covers == Covers::Signature)
        .map(|e| e.time)
        .min()
}

/// Whether a signing key is still trusted, and if not, since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    /// Compromised or retired at this time (Unix seconds). Only what was
    /// provably signed before it still counts.
    Revoked {
        at: u64,
    },
}

impl KeyStatus {
    /// Decides whether something signed by a key with this status counts,
    /// given the independent evidence of when its signature existed. The
    /// signer's own timestamp is deliberately not an input: a thief with the
    /// key writes whatever date suits. Nor is evidence covering only the
    /// content: the thief can sign content that was timestamped long ago.
    pub fn accepts(self, evidence: &[TimeEvidence]) -> Result<(), AuditError> {
        let Self::Revoked { at } = self else {
            return Ok(());
        };
        match signed_by(evidence) {
            None if existed_by(evidence).is_some() => Err(AuditError::SignatureUndated),
            None => Err(AuditError::TimeUnproven),
            Some(t) if t < at => Ok(()),
            Some(t) => Err(AuditError::SignedAfterRevocation {
                existed_by: t,
                revoked_at: at,
            }),
        }
    }
}

/// A record found in the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordProof {
    pub index: u64,
    /// The size of the witnessed checkpoint it was proven against.
    pub tree_size: u64,
    /// When a witness quorum had seen that checkpoint.
    pub seen_by: u64,
}

/// One party's view of one log: the latest checkpoint it accepted, which
/// every later checkpoint must extend.
#[derive(Clone, Debug)]
pub struct Auditor {
    log: NoteVerifier,
    origin: String,
    policy: WitnessPolicy,
    max_age: Option<u64>,
    latest: Option<Witnessed>,
}

impl Auditor {
    /// Audits the log named `origin`, signed by `log`, requiring `policy`.
    #[must_use]
    pub fn new(origin: &str, log: NoteVerifier, policy: WitnessPolicy) -> Self {
        Self {
            log,
            origin: origin.to_owned(),
            policy,
            max_age: None,
            latest: None,
        }
    }

    /// Also refuses a checkpoint whose quorum's newest cosignatures are more
    /// than `seconds` old, so a log cannot freeze its history by going quiet.
    #[must_use]
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    #[must_use]
    pub fn latest(&self) -> Option<&Witnessed> {
        self.latest.as_ref()
    }

    fn check(&self, note: &str, now: u64) -> Result<Witnessed, AuditError> {
        let w = verify_checkpoint(note, &self.log, &self.policy)?;
        if w.checkpoint.origin() != self.origin {
            return Err(AuditError::WrongOrigin {
                got: w.checkpoint.origin().to_owned(),
                want: self.origin.clone(),
            });
        }
        if let Some(max) = self.max_age {
            if now.saturating_sub(w.fresh_as_of()) > max {
                return Err(AuditError::Stale);
            }
        }
        Ok(w)
    }

    /// Accepts the log's next checkpoint, given the consistency proof from
    /// the latest one accepted (empty for the first, or for the same size).
    pub fn advance(
        &mut self,
        note: &str,
        proof: &[Hash],
        now: u64,
    ) -> Result<&Witnessed, AuditError> {
        let next = self.check(note, now)?;
        if let Some(prev) = &self.latest {
            let (old, new) = (prev.checkpoint.head(), next.checkpoint.head());
            if new.size < old.size {
                return Err(AuditError::Shrinking);
            }
            if new.size == old.size && new.root != old.root {
                // Both passed the log-signature check above: this is proof.
                return Err(AuditError::Inconsistent);
            }
            if old.size > 0 && verify_consistency(&old, &new, proof).is_err() {
                return Err(AuditError::Inconsistent);
            }
        }
        Ok(self.latest.insert(next))
    }

    /// Checks a checkpoint another party was shown against this view.
    ///
    /// `proof` is the consistency proof between the two, from the smaller to
    /// the larger; it is not needed when the sizes are equal. The foreign
    /// checkpoint needs the log's signature but not the quorum: a split view
    /// is proven by the log's own signatures.
    pub fn compare(&self, note: &str, proof: &[Hash]) -> Result<Comparison, AuditError> {
        let ours = self.latest.as_ref().ok_or(AuditError::NoCheckpoint)?;
        let theirs = SignedNote::parse(note)?;
        theirs.verify(&self.log)?;
        let cp = theirs.checkpoint()?;
        if cp.origin() != self.origin {
            return Err(AuditError::WrongOrigin {
                got: cp.origin().to_owned(),
                want: self.origin.clone(),
            });
        }
        let (a, b) = (ours.checkpoint.head(), cp.head());
        if a.size == b.size {
            return Ok(if a.root == b.root {
                Comparison::Consistent
            } else {
                Comparison::SplitView(Box::new(SplitView {
                    first: ours.note.clone(),
                    second: theirs,
                }))
            });
        }
        let (small, large) = if a.size < b.size { (a, b) } else { (b, a) };
        if small.size == 0 || verify_consistency(&small, &large, proof).is_ok() {
            Ok(Comparison::Consistent)
        } else {
            Err(AuditError::Inconsistent)
        }
    }

    /// Checks that `leaf_hash` is record `index` of the latest accepted
    /// checkpoint.
    pub fn verify_record(
        &self,
        index: u64,
        leaf_hash: &Hash,
        proof: &[Hash],
    ) -> Result<RecordProof, AuditError> {
        let latest = self.latest.as_ref().ok_or(AuditError::NoCheckpoint)?;
        verify_inclusion(&latest.checkpoint.head(), index, leaf_hash, proof)?;
        Ok(RecordProof {
            index,
            tree_size: latest.checkpoint.size(),
            seen_by: latest.seen_by(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{LogSigner, WitnessSigner};
    use crate::merkle::{consistency_proof, inclusion_proof, leaf_hash, root_of, TreeHead};

    const ORIGIN: &str = "decisions.example/log";

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    fn witnesses(n: u8) -> Vec<WitnessSigner> {
        (0..n)
            .map(|i| WitnessSigner::from_seed(&format!("w{i}.example"), &[100 + i; 32]).unwrap())
            .collect()
    }

    fn policy(ws: &[WitnessSigner], k: usize) -> WitnessPolicy {
        WitnessPolicy::new(ws.iter().map(|w| w.verifier().clone()).collect(), k).unwrap()
    }

    fn cosigned(log: &LogSigner, d: &[Hash], by: &[&WitnessSigner], time: u64) -> String {
        let head = TreeHead {
            size: d.len() as u64,
            root: root_of(d),
        };
        let mut note = log.sign(&Checkpoint::new(ORIGIN, head).unwrap());
        for (i, w) in by.iter().enumerate() {
            note.add_signature(w.cosign(note.text(), time + i as u64).unwrap())
                .unwrap();
        }
        note.render()
    }

    fn log() -> LogSigner {
        LogSigner::from_seed(ORIGIN, &[1; 32]).unwrap()
    }

    #[test]
    fn a_quorum_is_counted_over_distinct_trusted_witnesses_only() {
        let log = log();
        let ws = witnesses(3);
        let p = policy(&ws, 2);
        let d = leaves(4);
        let ok = cosigned(&log, &d, &[&ws[0], &ws[2]], 1_000);
        let w = verify_checkpoint(&ok, log.verifier(), &p).unwrap();
        assert_eq!(w.cosigned.len(), 2);
        assert_eq!(w.seen_by(), 1_001);
        assert_eq!(w.fresh_as_of(), 1_000);

        let one = cosigned(&log, &d, &[&ws[1]], 1_000);
        assert_eq!(
            verify_checkpoint(&one, log.verifier(), &p),
            Err(AuditError::QuorumNotMet { got: 1, need: 2 })
        );

        // A stranger's cosignature does not count toward the quorum.
        let stranger = WitnessSigner::from_seed("stranger", &[7; 32]).unwrap();
        let padded = cosigned(&log, &d, &[&ws[1], &stranger], 1_000);
        assert!(verify_checkpoint(&padded, log.verifier(), &p).is_err());
    }

    #[test]
    fn a_policy_refuses_duplicates_zero_and_impossible_thresholds() {
        let ws = witnesses(2);
        let keys: Vec<_> = ws.iter().map(|w| w.verifier().clone()).collect();
        assert!(WitnessPolicy::new(keys.clone(), 0).is_err());
        assert!(WitnessPolicy::new(keys.clone(), 3).is_err());
        let twice = vec![keys[0].clone(), keys[0].clone()];
        assert!(WitnessPolicy::new(twice, 1).is_err());
        let log_key = log().verifier().clone();
        assert!(WitnessPolicy::new(vec![log_key], 1).is_err());
    }

    #[test]
    fn an_auditor_follows_one_history_and_refuses_a_fork() {
        let log = log();
        let ws = witnesses(3);
        let refs: Vec<&WitnessSigner> = ws.iter().collect();
        let mut a = Auditor::new(ORIGIN, log.verifier().clone(), policy(&ws, 2));
        let d = leaves(20);
        a.advance(&cosigned(&log, &d[..8], &refs, 10), &[], 10)
            .unwrap();
        let p = consistency_proof(&d[..15], 8).unwrap();
        a.advance(&cosigned(&log, &d[..15], &refs, 20), &p, 20)
            .unwrap();

        let mut fork = d.clone();
        fork[2] = leaf_hash(b"rewritten");
        let p = consistency_proof(&fork, 15).unwrap();
        assert_eq!(
            a.advance(&cosigned(&log, &fork, &refs, 30), &p, 30)
                .unwrap_err(),
            AuditError::Inconsistent
        );
        assert_eq!(
            a.advance(&cosigned(&log, &d[..9], &refs, 30), &[], 30)
                .unwrap_err(),
            AuditError::Shrinking
        );
        assert_eq!(a.latest().unwrap().checkpoint.size(), 15);
    }

    #[test]
    fn two_parties_comparing_notes_catch_a_split_view_with_proof() {
        let log = log();
        let ws = witnesses(1);
        let mut alice = Auditor::new(ORIGIN, log.verifier().clone(), policy(&ws, 1));
        let d = leaves(10);
        alice
            .advance(&cosigned(&log, &d, &[&ws[0]], 5), &[], 5)
            .unwrap();

        let mut other = d.clone();
        other[9] = leaf_hash(b"what bob was shown");
        let bobs = cosigned(&log, &other, &[], 5);
        let Comparison::SplitView(evidence) = alice.compare(&bobs, &[]).unwrap() else {
            panic!("the split view went unnoticed");
        };
        evidence.verify(log.verifier()).unwrap();

        // Honest views of different sizes compare as consistent.
        let later = leaves(14);
        let p = consistency_proof(&later, 10).unwrap();
        assert_eq!(
            alice.compare(&cosigned(&log, &later, &[], 6), &p).unwrap(),
            Comparison::Consistent
        );
        // A larger tree with a different past cannot prove consistency.
        let mut forked_later = later.clone();
        forked_later[0] = leaf_hash(b"x");
        let p = consistency_proof(&forked_later, 10).unwrap();
        assert_eq!(
            alice.compare(&cosigned(&log, &forked_later, &[], 6), &p),
            Err(AuditError::Inconsistent)
        );
    }

    #[test]
    fn split_view_evidence_is_rejected_when_it_proves_nothing() {
        let log = log();
        let d = leaves(3);
        let a = SignedNote::parse(&cosigned(&log, &d, &[], 0)).unwrap();
        let fake = SplitView {
            first: a.clone(),
            second: a,
        };
        assert_eq!(fake.verify(log.verifier()), Err(AuditError::Inconsistent));
    }

    #[test]
    fn a_log_that_goes_quiet_goes_stale() {
        let log = log();
        let ws = witnesses(1);
        let mut a =
            Auditor::new(ORIGIN, log.verifier().clone(), policy(&ws, 1)).with_max_age(3_600);
        let d = leaves(2);
        let note = cosigned(&log, &d, &[&ws[0]], 1_000);
        a.advance(&note, &[], 1_000 + 3_600).unwrap();
        assert_eq!(
            a.advance(&note, &[], 1_000 + 3_601).unwrap_err(),
            AuditError::Stale
        );
    }

    #[test]
    fn records_are_proven_against_the_witnessed_checkpoint() {
        let log = log();
        let ws = witnesses(3);
        let refs: Vec<&WitnessSigner> = ws.iter().collect();
        let mut a = Auditor::new(ORIGIN, log.verifier().clone(), policy(&ws, 2));
        let d = leaves(12);
        assert_eq!(
            a.verify_record(0, &d[0], &[]),
            Err(AuditError::NoCheckpoint)
        );
        a.advance(&cosigned(&log, &d, &refs, 500), &[], 500)
            .unwrap();
        let p = inclusion_proof(&d, 7).unwrap();
        let r = a.verify_record(7, &d[7], &p).unwrap();
        assert_eq!((r.index, r.tree_size, r.seen_by), (7, 12, 501));
        assert!(a.verify_record(7, &leaf_hash(b"forged"), &p).is_err());
    }

    /// The review finding: a body timestamped at 10:00, the key revoked at
    /// 11:00, and the thief signing the old body at 12:00. The body evidence
    /// is real and early, and must not vouch for the signature.
    #[test]
    fn content_only_evidence_never_vouches_for_a_signature_after_revocation() {
        let revoked = KeyStatus::Revoked { at: 11 };
        let body_at_ten = [
            TimeEvidence::rfc3161(10, Covers::Content),
            TimeEvidence::bitcoin(10, Covers::Content),
        ];
        assert_eq!(
            revoked.accepts(&body_at_ten),
            Err(AuditError::SignatureUndated)
        );
        assert_eq!(existed_by(&body_at_ten), Some(10));
        assert_eq!(signed_by(&body_at_ten), None);
        // The same time, covering the signature, does count.
        assert_eq!(
            revoked.accepts(&[TimeEvidence::rfc3161(10, Covers::Signature)]),
            Ok(())
        );
    }

    #[test]
    fn a_revoked_key_counts_only_for_what_was_proven_before_revocation() {
        let revoked = KeyStatus::Revoked { at: 1_000 };
        assert_eq!(KeyStatus::Active.accepts(&[]), Ok(()));
        assert_eq!(revoked.accepts(&[]), Err(AuditError::TimeUnproven));
        assert_eq!(revoked.accepts(&[TimeEvidence::witnesses(999)]), Ok(()));
        assert_eq!(
            revoked.accepts(&[TimeEvidence::rfc3161(1_000, Covers::Signature)]),
            Err(AuditError::SignedAfterRevocation {
                existed_by: 1_000,
                revoked_at: 1_000
            })
        );
        // The earliest independent evidence decides.
        assert_eq!(
            revoked.accepts(&[
                TimeEvidence::bitcoin(2_000, Covers::Signature),
                TimeEvidence::witnesses(900)
            ]),
            Ok(())
        );
    }
}
