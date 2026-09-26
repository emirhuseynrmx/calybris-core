//! An independent witness: it cosigns a checkpoint only when that checkpoint
//! extends every checkpoint of the same log it has cosigned before.
//!
//! A log operator can sign any checkpoint it likes, including two different
//! histories for two different audiences. A witness is the party that refuses
//! to go along. It remembers the latest checkpoint it cosigned for each log and
//! signs a new one only with a consistency proof that the new tree extends the
//! old; it never signs a smaller tree, and never a different root at the same
//! size. Run by someone the operator does not control, a witness turns "the
//! operator says there is one history" into something a verifier can check:
//! a checkpoint cosigned by enough independent witnesses is one every one of
//! them has checked against everything they signed before.
//!
//! The protocol is C2SP tlog-witness (<https://c2sp.org/tlog-witness>), so a
//! Calybris log can use witnesses that already run, and this witness can serve
//! any log that speaks it. The request body is
//!
//! ```text
//! old <size the client believes the witness last cosigned>
//! <consistency proof hash, base64>   (zero or more lines)
//!
//! <checkpoint note, signed by the log>
//! ```
//!
//! and the response is the cosignature line. [`WitnessError::http_status`]
//! maps each refusal to the status code the specification assigns. Transport,
//! authentication and the clock are the caller's: this module decides, signs
//! and records, and nothing else.
//!
//! State is written **before** the cosignature is returned, through a
//! compare-and-swap, so neither a crash nor two concurrent requests can make
//! the witness sign two checkpoints that do not extend one another.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::checkpoint::{CheckpointError, NoteSignature, NoteVerifier, SignedNote, WitnessSigner};
use crate::merkle::{verify_consistency, Hash, TreeHead};

/// Largest request body [`AddCheckpoint::parse`] reads.
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
/// Most consistency-proof lines a request may carry: a proof between trees
/// of any two `u64` sizes has at most 2 × 64 hashes.
pub const MAX_PROOF_HASHES: usize = 128;

/// A tlog-witness `add-checkpoint` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddCheckpoint {
    /// The size the client believes the witness last cosigned; 0 for a log
    /// the witness has never cosigned.
    pub old_size: u64,
    /// Consistency proof from `old_size` to the checkpoint's size.
    pub proof: Vec<Hash>,
    /// The checkpoint note, signed by the log.
    pub note: String,
}

impl AddCheckpoint {
    /// Reads a request body.
    pub fn parse(body: &str) -> Result<Self, WitnessError> {
        let bad = WitnessError::Malformed;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(bad("request body is too large"));
        }
        let (head, note) = body
            .split_once("\n\n")
            .ok_or(bad("request has no blank line before the checkpoint"))?;
        let mut lines = head.split('\n');
        let old = lines
            .next()
            .and_then(|l| l.strip_prefix("old "))
            .ok_or(bad("request must start with `old <size>`"))?;
        let old_ok = !old.is_empty()
            && old.bytes().all(|b| b.is_ascii_digit())
            && (old == "0" || !old.starts_with('0'));
        if !old_ok {
            return Err(bad("old size must be decimal without leading zeros"));
        }
        let old_size = old.parse().map_err(|_| bad("old size exceeds u64"))?;
        let mut proof = Vec::new();
        for line in lines {
            if proof.len() == MAX_PROOF_HASHES {
                return Err(bad("consistency proof is too long"));
            }
            let raw = BASE64
                .decode(line)
                .map_err(|_| bad("proof line is not standard base64"))?;
            let hash: Hash = raw
                .as_slice()
                .try_into()
                .map_err(|_| bad("proof line is not a 32-byte hash"))?;
            proof.push(hash);
        }
        Ok(Self {
            old_size,
            proof,
            note: note.to_owned(),
        })
    }

    /// The request body as text.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("old {}\n", self.old_size);
        for hash in &self.proof {
            out.push_str(&BASE64.encode(hash));
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&self.note);
        out
    }
}

/// Why a witness refused to cosign.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("malformed checkpoint: {0}")]
    BadCheckpoint(CheckpointError),
    #[error("this witness does not know the log {0:?}")]
    UnknownLog(String),
    #[error("checkpoint is not signed by the log's key")]
    BadLogSignature,
    /// The client's `old` is not the size this witness last cosigned. The
    /// response tells it the size it should prove from.
    #[error("witness last cosigned size {latest}, not the size given")]
    Conflict { latest: u64 },
    #[error("checkpoint is smaller than the size given")]
    Shrinking,
    #[error("checkpoint does not extend the last one this witness cosigned")]
    BadProof,
    #[error("witness state: {0}")]
    Store(String),
}

impl WitnessError {
    /// The HTTP status C2SP tlog-witness assigns to this refusal.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Malformed(_) | Self::BadCheckpoint(_) | Self::Shrinking => 400,
            Self::BadLogSignature => 403,
            Self::UnknownLog(_) => 404,
            Self::Conflict { .. } => 409,
            Self::BadProof => 422,
            Self::Store(_) => 500,
        }
    }

    /// The response body for this refusal: the witness's latest size for a
    /// conflict (content type `text/x.tlog.size`), the reason otherwise.
    #[must_use]
    pub fn response_body(&self) -> String {
        match self {
            Self::Conflict { latest } => format!("{latest}\n"),
            other => format!("{other}\n"),
        }
    }
}

/// Where a witness keeps the latest tree head it cosigned for each log.
///
/// The store is what stops a witness being rolled back, so an implementation
/// that persists must make [`WitnessStore::compare_and_swap`] atomic and
/// durable before it returns `true`.
pub trait WitnessStore {
    /// The latest head cosigned for `origin`, if any.
    fn latest(&self, origin: &str) -> Result<Option<TreeHead>, String>;

    /// Records `new` for `origin` only if the stored value is still
    /// `expected`. Returns whether it did.
    fn compare_and_swap(
        &mut self,
        origin: &str,
        expected: Option<TreeHead>,
        new: TreeHead,
    ) -> Result<bool, String>;
}

/// A store in memory, for tests and for witnesses that persist elsewhere.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryStore {
    heads: BTreeMap<String, TreeHead>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every log and the head last cosigned for it.
    #[must_use]
    pub fn heads(&self) -> &BTreeMap<String, TreeHead> {
        &self.heads
    }
}

impl WitnessStore for MemoryStore {
    fn latest(&self, origin: &str) -> Result<Option<TreeHead>, String> {
        Ok(self.heads.get(origin).copied())
    }

    fn compare_and_swap(
        &mut self,
        origin: &str,
        expected: Option<TreeHead>,
        new: TreeHead,
    ) -> Result<bool, String> {
        if self.heads.get(origin).copied() != expected {
            return Ok(false);
        }
        self.heads.insert(origin.to_owned(), new);
        Ok(true)
    }
}

/// A store in one JSON file, for a witness that runs as a process.
///
/// Every compare-and-swap takes an exclusive lock on a sibling lock file,
/// re-reads the file under it, and replaces the file by an atomic rename after
/// `fsync`, so two witness processes sharing the file cannot both win, and a
/// crash leaves either the old state or the new one. Losing this file is
/// what would let the witness be rolled back: keep it with the witness key.
#[cfg(feature = "serde")]
#[derive(Clone, Debug)]
pub struct FileStore {
    path: std::path::PathBuf,
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredHead {
    size: u64,
    root: String,
}

#[cfg(feature = "serde")]
impl FileStore {
    /// A store at `path`. The file need not exist yet.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read_all(&self) -> Result<BTreeMap<String, TreeHead>, String> {
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e.to_string()),
        };
        let stored: BTreeMap<String, StoredHead> =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        stored
            .into_iter()
            .map(|(origin, h)| {
                let root: Hash = BASE64
                    .decode(&h.root)
                    .ok()
                    .and_then(|r| r.try_into().ok())
                    .ok_or_else(|| {
                        format!("stored root for {origin:?} is not 32 bytes of base64")
                    })?;
                Ok((origin, TreeHead { size: h.size, root }))
            })
            .collect()
    }

    fn write_all(&self, heads: &BTreeMap<String, TreeHead>) -> Result<(), String> {
        let stored: BTreeMap<&String, StoredHead> = heads
            .iter()
            .map(|(o, h)| {
                (
                    o,
                    StoredHead {
                        size: h.size,
                        root: BASE64.encode(h.root),
                    },
                )
            })
            .collect();
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut tmp = tempfile::Builder::new()
            .prefix(".witness-state.tmp.")
            .tempfile_in(parent)
            .map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(&mut tmp, &stored).map_err(|e| e.to_string())?;
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        tmp.persist(&self.path).map_err(|e| e.error.to_string())?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl WitnessStore for FileStore {
    fn latest(&self, origin: &str) -> Result<Option<TreeHead>, String> {
        Ok(self.read_all()?.get(origin).copied())
    }

    fn compare_and_swap(
        &mut self,
        origin: &str,
        expected: Option<TreeHead>,
        new: TreeHead,
    ) -> Result<bool, String> {
        use fs2::FileExt as _;
        let mut lock_path = self.path.clone().into_os_string();
        lock_path.push(".lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| e.to_string())?;
        lock.lock_exclusive().map_err(|e| e.to_string())?;
        let mut heads = self.read_all()?;
        if heads.get(origin).copied() != expected {
            return Ok(false);
        }
        heads.insert(origin.to_owned(), new);
        self.write_all(&heads)?;
        Ok(true)
    }
}

/// The root of the empty tree, `SHA-256("")`.
fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// A witness: its key, the logs it serves, and its memory.
pub struct Witness<S: WitnessStore> {
    signer: WitnessSigner,
    logs: BTreeMap<String, NoteVerifier>,
    store: S,
}

impl<S: WitnessStore> std::fmt::Debug for Witness<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Witness")
            .field("signer", &self.signer)
            .field("logs", &self.logs.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<S: WitnessStore> Witness<S> {
    #[must_use]
    pub fn new(signer: WitnessSigner, store: S) -> Self {
        Self {
            signer,
            logs: BTreeMap::new(),
            store,
        }
    }

    /// Serves the log whose checkpoints carry `origin` and are signed by
    /// `key`. A witness is configured with its logs; it does not learn them
    /// from requests.
    pub fn add_log(&mut self, origin: &str, key: NoteVerifier) {
        self.logs.insert(origin.to_owned(), key);
    }

    #[must_use]
    pub fn signer(&self) -> &WitnessSigner {
        &self.signer
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Handles an `add-checkpoint` request at time `now` (Unix seconds) and
    /// returns the cosignature line, or the reason it refused.
    pub fn add_checkpoint(
        &mut self,
        request: &AddCheckpoint,
        now: u64,
    ) -> Result<NoteSignature, WitnessError> {
        let note = SignedNote::parse(&request.note).map_err(WitnessError::BadCheckpoint)?;
        let checkpoint = note.checkpoint().map_err(WitnessError::BadCheckpoint)?;
        let origin = checkpoint.origin().to_owned();
        let key = self
            .logs
            .get(&origin)
            .ok_or_else(|| WitnessError::UnknownLog(origin.clone()))?;
        note.verify(key)
            .map_err(|_| WitnessError::BadLogSignature)?;

        let latest = self.store.latest(&origin).map_err(WitnessError::Store)?;
        let latest_size = latest.map_or(0, |h| h.size);
        if request.old_size != latest_size {
            return Err(WitnessError::Conflict {
                latest: latest_size,
            });
        }
        let new = checkpoint.head();
        if new.size < request.old_size {
            return Err(WitnessError::Shrinking);
        }
        let extends = match latest {
            Some(old) if old.size > 0 => verify_consistency(&old, &new, &request.proof).is_ok(),
            // Nothing but the empty tree cosigned yet: any non-empty tree
            // extends it, and an empty tree has exactly one root.
            _ => request.proof.is_empty() && (new.size > 0 || new.root == empty_root()),
        };
        if !extends {
            return Err(WitnessError::BadProof);
        }

        if !self
            .store
            .compare_and_swap(&origin, latest, new)
            .map_err(WitnessError::Store)?
        {
            let now_latest = self.store.latest(&origin).map_err(WitnessError::Store)?;
            return Err(WitnessError::Conflict {
                latest: now_latest.map_or(0, |h| h.size),
            });
        }
        self.signer
            .cosign(note.text(), now)
            .map_err(WitnessError::BadCheckpoint)
    }
}

/// Reads a witness's response body: one or more signature lines.
pub fn parse_cosignatures(body: &str) -> Result<Vec<NoteSignature>, WitnessError> {
    let body = body
        .strip_suffix('\n')
        .ok_or(WitnessError::Malformed("response must end in a newline"))?;
    body.split('\n')
        .map(|line| NoteSignature::parse_line(line).map_err(WitnessError::BadCheckpoint))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{Checkpoint, LogSigner};
    use crate::merkle::{consistency_proof, leaf_hash, root_of};

    const ORIGIN: &str = "decisions.example/log";

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    fn log() -> LogSigner {
        LogSigner::from_seed(ORIGIN, &[1; 32]).unwrap()
    }

    fn note_for(log: &LogSigner, d: &[Hash]) -> String {
        let head = TreeHead {
            size: d.len() as u64,
            root: root_of(d),
        };
        log.sign(&Checkpoint::new(ORIGIN, head).unwrap()).render()
    }

    fn witness() -> Witness<MemoryStore> {
        let mut w = Witness::new(
            WitnessSigner::from_seed("witness.example", &[9; 32]).unwrap(),
            MemoryStore::new(),
        );
        w.add_log(ORIGIN, log().verifier().clone());
        w
    }

    fn request(d: &[Hash], old: usize, note: String) -> AddCheckpoint {
        let proof = if old == 0 || old == d.len() {
            Vec::new()
        } else {
            consistency_proof(d, old as u64).unwrap()
        };
        AddCheckpoint {
            old_size: old as u64,
            proof,
            note,
        }
    }

    #[test]
    fn a_growing_log_is_cosigned_step_by_step() {
        let log = log();
        let mut w = witness();
        let d = leaves(30);
        let mut old = 0;
        for n in [1, 5, 5, 17, 30] {
            let note = note_for(&log, &d[..n]);
            let sig = w
                .add_checkpoint(&request(&d[..n], old, note.clone()), 100 + n as u64)
                .unwrap_or_else(|e| panic!("n={n}: {e}"));
            let mut signed = SignedNote::parse(&note).unwrap();
            signed.add_signature(sig).unwrap();
            assert_eq!(
                signed.cosignature_time(w.signer().verifier()).unwrap(),
                100 + n as u64
            );
            old = n;
        }
        assert_eq!(w.store().heads()[ORIGIN].size, 30);
    }

    #[test]
    fn a_rewritten_history_is_refused_after_the_real_one_was_cosigned() {
        let log = log();
        let mut w = witness();
        let d = leaves(10);
        w.add_checkpoint(&request(&d[..6], 0, note_for(&log, &d[..6])), 1)
            .unwrap();

        // Same log key, a history that differs at leaf 3.
        let mut fork = d.clone();
        fork[3] = leaf_hash(b"rewritten");
        let err = w
            .add_checkpoint(&request(&fork, 6, note_for(&log, &fork)), 2)
            .unwrap_err();
        assert_eq!(err, WitnessError::BadProof);
        assert_eq!(err.http_status(), 422);

        // The same size with another root.
        let err = w
            .add_checkpoint(&request(&fork[..6], 6, note_for(&log, &fork[..6])), 3)
            .unwrap_err();
        assert_eq!(err, WitnessError::BadProof);
        // The refusal left the witness where it was.
        assert_eq!(w.store().heads()[ORIGIN].root, root_of(&d[..6]));
    }

    #[test]
    fn a_stale_old_size_is_a_conflict_that_names_the_latest() {
        let log = log();
        let mut w = witness();
        let d = leaves(8);
        w.add_checkpoint(&request(&d[..4], 0, note_for(&log, &d[..4])), 1)
            .unwrap();
        let err = w
            .add_checkpoint(&request(&d, 0, note_for(&log, &d)), 2)
            .unwrap_err();
        assert_eq!(err, WitnessError::Conflict { latest: 4 });
        assert_eq!(err.http_status(), 409);
        assert_eq!(err.response_body(), "4\n");
    }

    #[test]
    fn a_smaller_tree_is_never_cosigned() {
        let log = log();
        let mut w = witness();
        let d = leaves(8);
        w.add_checkpoint(&request(&d, 0, note_for(&log, &d)), 1)
            .unwrap();
        let req = AddCheckpoint {
            old_size: 8,
            proof: Vec::new(),
            note: note_for(&log, &d[..5]),
        };
        assert_eq!(w.add_checkpoint(&req, 2), Err(WitnessError::Shrinking));
    }

    #[test]
    fn unknown_logs_and_foreign_signatures_are_refused() {
        let mut w = witness();
        let d = leaves(3);
        let stranger = LogSigner::from_seed(ORIGIN, &[2; 32]).unwrap();
        let err = w
            .add_checkpoint(&request(&d, 0, note_for(&stranger, &d)), 1)
            .unwrap_err();
        assert_eq!(err.http_status(), 403);

        let other = LogSigner::from_seed("other.example/log", &[1; 32]).unwrap();
        let head = TreeHead {
            size: 3,
            root: root_of(&d),
        };
        let note = other
            .sign(&Checkpoint::new("other.example/log", head).unwrap())
            .render();
        let err = w
            .add_checkpoint(
                &AddCheckpoint {
                    old_size: 0,
                    proof: Vec::new(),
                    note,
                },
                1,
            )
            .unwrap_err();
        assert_eq!(err.http_status(), 404);
    }

    #[test]
    fn an_empty_tree_has_one_root_and_first_checkpoints_carry_no_proof() {
        let log = log();
        let mut w = witness();
        let bogus_empty = TreeHead {
            size: 0,
            root: [5; 32],
        };
        let note = log
            .sign(&Checkpoint::new(ORIGIN, bogus_empty).unwrap())
            .render();
        let req = AddCheckpoint {
            old_size: 0,
            proof: Vec::new(),
            note,
        };
        assert_eq!(w.add_checkpoint(&req, 1), Err(WitnessError::BadProof));

        let d = leaves(4);
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![[0; 32]],
            note: note_for(&log, &d),
        };
        assert_eq!(w.add_checkpoint(&req, 1), Err(WitnessError::BadProof));
    }

    /// A store that another request updates between the witness's read and
    /// its write.
    struct Racing {
        inner: MemoryStore,
        interloper: Option<TreeHead>,
    }

    impl WitnessStore for Racing {
        fn latest(&self, origin: &str) -> Result<Option<TreeHead>, String> {
            self.inner.latest(origin)
        }
        fn compare_and_swap(
            &mut self,
            origin: &str,
            expected: Option<TreeHead>,
            new: TreeHead,
        ) -> Result<bool, String> {
            if let Some(head) = self.interloper.take() {
                self.inner.heads.insert(origin.to_owned(), head);
            }
            self.inner.compare_and_swap(origin, expected, new)
        }
    }

    #[test]
    fn a_lost_race_is_a_conflict_not_a_second_signature() {
        let log = log();
        let d = leaves(9);
        let mut w = Witness::new(
            WitnessSigner::from_seed("w", &[9; 32]).unwrap(),
            Racing {
                inner: MemoryStore::new(),
                interloper: Some(TreeHead {
                    size: 7,
                    root: root_of(&d[..7]),
                }),
            },
        );
        w.add_log(ORIGIN, log.verifier().clone());
        let err = w
            .add_checkpoint(&request(&d, 0, note_for(&log, &d)), 1)
            .unwrap_err();
        assert_eq!(err, WitnessError::Conflict { latest: 7 });
    }

    #[test]
    fn requests_render_and_parse_as_c2sp_bodies() {
        let log = log();
        let d = leaves(11);
        let req = request(&d, 4, note_for(&log, &d));
        let body = req.render();
        assert!(body.starts_with("old 4\n"));
        assert_eq!(AddCheckpoint::parse(&body).unwrap(), req);
        for bad in [
            "old 04\n\nx".to_owned(),
            "old\n\nx".to_owned(),
            "new 4\n\nx".to_owned(),
            "old 4\nnot-base64\n\nx".to_owned(),
            "old 4\nAAAA\n\nx".to_owned(),
            "old 4\n".to_owned(),
            format!("old 4\n{}\nx", "A".repeat(MAX_REQUEST_BYTES)),
        ] {
            assert!(AddCheckpoint::parse(&bad).is_err(), "accepted {bad:?}");
        }
        let lines = format!(
            "old 1\n{}\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n".repeat(129)
        );
        assert!(AddCheckpoint::parse(&lines).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_file_store_survives_a_restart_and_refuses_a_rewind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let log = log();
        let d = leaves(9);
        let signer = || WitnessSigner::from_seed("w", &[9; 32]).unwrap();

        let mut w = Witness::new(signer(), FileStore::new(&path));
        w.add_log(ORIGIN, log.verifier().clone());
        w.add_checkpoint(&request(&d[..6], 0, note_for(&log, &d[..6])), 1)
            .unwrap();
        drop(w);

        // A new process with the same file remembers size 6.
        let mut w = Witness::new(signer(), FileStore::new(&path));
        w.add_log(ORIGIN, log.verifier().clone());
        let mut fork = d.clone();
        fork[0] = leaf_hash(b"rewritten");
        assert_eq!(
            w.add_checkpoint(&request(&fork[..6], 0, note_for(&log, &fork[..6])), 2),
            Err(WitnessError::Conflict { latest: 6 })
        );
        w.add_checkpoint(&request(&d, 6, note_for(&log, &d)), 3)
            .unwrap();
        assert_eq!(
            FileStore::new(&path).latest(ORIGIN).unwrap().unwrap().size,
            9
        );

        std::fs::write(&path, b"{not json").unwrap();
        assert!(FileStore::new(&path).latest(ORIGIN).is_err());
    }

    #[test]
    fn a_response_parses_back_into_signature_lines() {
        let log = log();
        let mut w = witness();
        let d = leaves(2);
        let sig = w
            .add_checkpoint(&request(&d, 0, note_for(&log, &d)), 5)
            .unwrap();
        assert_eq!(parse_cosignatures(&sig.line()).unwrap(), vec![sig]);
        assert!(parse_cosignatures("no newline").is_err());
    }
}
