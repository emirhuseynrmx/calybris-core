//! Hash-chained Write-Ahead Log — tamper-evident, crash-detecting.
//!
//! Each entry's hash chains to the previous, forming a tamper-evident log.
//! Optionally keyed with HMAC-SHA256: without a key the chain detects
//! accidental corruption; with a key an attacker cannot recompute
//! consistent hashes without possessing the secret.
//!
//! The chain is validated on startup before accepting new decisions.
//! Generic over the decision type: any `Serialize` type works.

use crate::digest::{bytes_to_hex, digest_to_hex, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{audit_bundle, verify_decision, VerifyResult};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A single entry in the hash-chained WAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalEntry<T> {
    /// Monotonically increasing sequence number (starts at 1).
    pub sequence: u64,
    /// Hash of the previous entry (or `"genesis"` for the first).
    pub previous_hash: String,
    /// Hash of this entry (SHA-256 or HMAC-SHA256 of `previous_hash` + `data`).
    pub entry_hash: String,
    /// The decision or record stored in this entry.
    pub data: T,
}

/// WAL error types.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("WAL JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("WAL chain broken at sequence {sequence}: expected {expected}, found {found}")]
    ChainBroken {
        sequence: u64,
        expected: String,
        found: String,
    },
    #[error("WAL duplicate sequence: {0}")]
    DuplicateSequence(u64),
    #[error("WAL audit failed at sequence {sequence}: {reason}")]
    AuditFailed { sequence: u64, reason: String },
}

/// Full audit record: policy/input/decision digests + replay flag + optional metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditedRecord<M> {
    pub audit: crate::verify::AuditBundle,
    pub input: KernelInput,
    pub decision: KernelDecision,
    pub metadata: M,
}

/// Result of replay-verifying one audited WAL entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalReplayVerdict {
    pub sequence: u64,
    pub replay_valid: bool,
    pub policy_digest_match: bool,
    pub input_digest_match: bool,
    pub decision_digest_match: bool,
}

impl<M> WalWriter<AuditedRecord<M>>
where
    M: Serialize,
{
    /// Append a fully audited decision record (bundle + input + decision + metadata).
    pub fn append_audited(
        &mut self,
        snapshot: &PolicySnapshot,
        input: KernelInput,
        decision: KernelDecision,
        metadata: M,
    ) -> Result<WalEntry<AuditedRecord<M>>, WalError> {
        let audit = audit_bundle(snapshot, input, &decision);
        let record = AuditedRecord {
            audit,
            input,
            decision,
            metadata,
        };
        self.append(record)
    }
}

/// Append an audited record to any WAL writer.
pub fn append_audited<M>(
    wal: &mut WalWriter<AuditedRecord<M>>,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: KernelDecision,
    metadata: M,
) -> Result<WalEntry<AuditedRecord<M>>, WalError>
where
    M: Serialize,
{
    wal.append_audited(snapshot, input, decision, metadata)
}

fn compute_hash(
    previous_hash: &str,
    data_json: &str,
    key: Option<&[u8]>,
) -> Result<String, WalError> {
    match key {
        Some(k) => {
            let mut mac = HmacSha256::new_from_slice(k).map_err(|_| {
                WalError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid HMAC key length",
                ))
            })?;
            mac.update(previous_hash.as_bytes());
            mac.update(data_json.as_bytes());
            Ok(bytes_to_hex(&mac.finalize().into_bytes()))
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(previous_hash.as_bytes());
            hasher.update(data_json.as_bytes());
            Ok(bytes_to_hex(&hasher.finalize()))
        }
    }
}

#[cfg(test)]
fn hash_entry<T: Serialize>(
    previous_hash: &str,
    data: &T,
    key: Option<&[u8]>,
) -> Result<String, WalError> {
    let payload = serde_json::to_string(data)?;
    compute_hash(previous_hash, &payload, key)
}

/// Hash-chained WAL writer.
/// Hash-chained, tamper-evident Write-Ahead Log writer.
///
/// Without a key, the chain detects accidental corruption (bit rot, truncation).
/// With an HMAC key ([`open_keyed`](WalWriter::open_keyed)), an attacker who
/// modifies the file cannot recompute valid hashes.
///
/// The chain is validated on every [`open`](WalWriter::open) call.
pub struct WalWriter<T> {
    file: File,
    sequence: u64,
    last_hash: String,
    hmac_key: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Serialize> WalWriter<T> {
    /// Open or create a WAL file. Validates existing chain on open.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        Self::open_inner(path, None)
    }

    /// Open or create a WAL file with HMAC-SHA256 keying.
    /// Every entry's hash is computed with the key — an attacker who
    /// modifies the file cannot recompute valid hashes without it.
    pub fn open_keyed(path: &Path, key: &[u8]) -> Result<Self, WalError> {
        Self::open_inner(path, Some(key.to_vec()))
    }

    fn open_inner(path: &Path, hmac_key: Option<Vec<u8>>) -> Result<Self, WalError> {
        let (sequence, last_hash) = if path.exists() {
            validate_chain_inner(path, hmac_key.as_deref())?
        } else {
            (0, "genesis".to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file,
            sequence,
            last_hash,
            hmac_key,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append a decision to the WAL. Returns the entry with proof.
    ///
    /// Writes to the OS buffer but does **not** fsync. Call [`sync`] or
    /// [`flush_and_sync`] explicitly when you need crash durability.
    /// This keeps the hot path fast (~1µs per append) while letting
    /// callers batch durability when appropriate.
    #[must_use = "check the returned entry for the hash chain link"]
    pub fn append(&mut self, data: T) -> Result<WalEntry<T>, WalError> {
        self.sequence += 1;
        // Serialize data once — reuse for both hash computation and file write.
        let data_json = serde_json::to_string(&data)?;
        let entry_hash = compute_hash(&self.last_hash, &data_json, self.hmac_key.as_deref())?;

        // Build the line manually to avoid serializing data a second time.
        // Format: {"sequence":N,"previous_hash":"...","entry_hash":"...","data":...}
        writeln!(
            self.file,
            "{{\"sequence\":{},\"previous_hash\":\"{}\",\"entry_hash\":\"{}\",\"data\":{}}}",
            self.sequence, self.last_hash, entry_hash, data_json
        )?;

        let prev = self.last_hash.clone();
        self.last_hash = entry_hash.clone();

        Ok(WalEntry {
            sequence: self.sequence,
            previous_hash: prev,
            entry_hash,
            data,
        })
    }

    /// Flush userspace buffer to OS and fsync to disk.
    /// Call after a batch of appends for crash durability.
    pub fn flush_and_sync(&mut self) -> Result<(), WalError> {
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Flush userspace buffer to OS (no fsync).
    pub fn flush(&mut self) -> Result<(), WalError> {
        self.file.flush()?;
        Ok(())
    }

    /// Sync data to disk (fsync). Assumes buffer is already flushed.
    pub fn sync(&self) -> Result<(), WalError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Current sequence number (equals the number of entries written).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Alias for [`sequence`](Self::sequence) — total entries written.
    pub fn entry_count(&self) -> u64 {
        self.sequence
    }

    /// Last hash in the chain.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Validate the hash chain in an existing WAL file (unkeyed).
    pub fn validate_chain(path: &Path) -> Result<(u64, String), WalError> {
        validate_chain_inner(path, None)
    }
}

/// Validate the hash chain, optionally with an HMAC key.
/// Uses serde_json's preserve_order feature so re-serializing the data
/// field produces the same JSON bytes as the original write.
fn validate_chain_inner(path: &Path, key: Option<&[u8]>) -> Result<(u64, String), WalError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: WalEntry<serde_json::Value> = serde_json::from_str(&line)?;

        if entry.sequence != expected_sequence {
            return Err(WalError::DuplicateSequence(entry.sequence));
        }

        if entry.previous_hash != expected_prev_hash {
            return Err(WalError::ChainBroken {
                sequence: entry.sequence,
                expected: expected_prev_hash,
                found: entry.previous_hash,
            });
        }

        let data_str = serde_json::to_string(&entry.data)?;
        let computed = compute_hash(&entry.previous_hash, &data_str, key)?;
        // Constant-time comparison to prevent timing side-channel on keyed WAL
        if computed
            .as_bytes()
            .ct_eq(entry.entry_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(WalError::ChainBroken {
                sequence: entry.sequence,
                expected: computed,
                found: entry.entry_hash,
            });
        }

        last_hash = entry.entry_hash;
        last_sequence = entry.sequence;
        expected_sequence += 1;
        expected_prev_hash = last_hash.clone();
    }

    Ok((last_sequence, last_hash))
}

/// Read a WAL file **without** chain verification.
///
/// Use [`read_verified_wal`] or [`read_verified_wal_keyed`] if you need
/// tamper detection. This function is faster but trusts the data.
pub fn read_wal<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<WalEntry<T>>, WalError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: WalEntry<T> = serde_json::from_str(&line)?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Verify the hash chain integrity of a WAL file (unkeyed).
pub fn verify_wal(path: &Path) -> Result<(u64, String), WalError> {
    validate_chain_inner(path, None)
}

/// Verify the hash chain integrity of a WAL file with HMAC key.
pub fn verify_wal_keyed(path: &Path, key: &[u8]) -> Result<(u64, String), WalError> {
    validate_chain_inner(path, Some(key))
}

/// Read a WAL file AND verify its chain integrity (unkeyed).
pub fn read_verified_wal<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<Vec<WalEntry<T>>, WalError> {
    validate_chain_inner(path, None)?;
    read_wal(path)
}

/// Read a WAL file AND verify its chain integrity with HMAC key.
pub fn read_verified_wal_keyed<T: for<'de> Deserialize<'de>>(
    path: &Path,
    key: &[u8],
) -> Result<Vec<WalEntry<T>>, WalError> {
    validate_chain_inner(path, Some(key))?;
    read_wal(path)
}

/// Replay-verify every audited entry against `snapshot` (chain + digests + prescribe).
///
/// Metadata is ignored during replay (`serde_json::Value`).
pub fn replay_audited_wal(
    path: &Path,
    snapshot: &PolicySnapshot,
) -> Result<Vec<WalReplayVerdict>, WalError> {
    replay_audited_wal_keyed::<serde_json::Value>(path, snapshot, None)
}

/// Replay-verify audited WAL with optional HMAC key.
pub fn replay_audited_wal_keyed<M>(
    path: &Path,
    snapshot: &PolicySnapshot,
    key: Option<&[u8]>,
) -> Result<Vec<WalReplayVerdict>, WalError>
where
    M: for<'de> Deserialize<'de>,
{
    validate_chain_inner(path, key)?;
    let entries = read_wal::<AuditedRecord<M>>(path)?;
    let expected_policy = digest_to_hex(&policy_digest(snapshot));

    let mut verdicts = Vec::with_capacity(entries.len());
    for entry in entries {
        let bundle = &entry.data.audit;
        let replay = verify_decision(snapshot, entry.data.input, &entry.data.decision);
        let replay_valid = replay == VerifyResult::Valid;
        let policy_digest_match = bundle.policy_digest_hex == expected_policy;
        let input_digest_match = bundle.input_digest_hex
            == digest_to_hex(&crate::digest::input_digest(&entry.data.input));
        let decision_digest_match = bundle.decision_digest_hex
            == digest_to_hex(&crate::digest::decision_digest(&entry.data.decision));

        if !replay_valid || !policy_digest_match || !input_digest_match || !decision_digest_match {
            return Err(WalError::AuditFailed {
                sequence: entry.sequence,
                reason: format!(
                    "replay_valid={replay_valid} policy_match={policy_digest_match} input_match={input_digest_match} decision_match={decision_digest_match}"
                ),
            });
        }

        verdicts.push(WalReplayVerdict {
            sequence: entry.sequence,
            replay_valid,
            policy_digest_match,
            input_digest_match,
            decision_digest_match,
        });
    }
    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "target/test-wal-{}-{}.jsonl",
            name,
            std::process::id()
        ))
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TestDecision {
        model: String,
        cost: i64,
    }

    #[test]
    fn append_and_read() {
        let path = temp_path("append");
        let _ = std::fs::remove_file(&path);

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        wal.append(TestDecision {
            model: "gpt-4o".into(),
            cost: 100,
        })
        .unwrap();
        wal.append(TestDecision {
            model: "mini".into(),
            cost: 10,
        })
        .unwrap();
        wal.sync().unwrap();

        assert_eq!(wal.sequence(), 2);

        let entries = read_wal::<TestDecision>(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data.model, "gpt-4o");
        assert_eq!(entries[1].data.model, "mini");
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn chain_validates_on_reopen() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_eq!(wal.sequence(), 2);
        wal.append(TestDecision {
            model: "c".into(),
            cost: 3,
        })
        .unwrap();
        assert_eq!(wal.sequence(), 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_entry_detected() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        let result = WalWriter::<TestDecision>::open(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_starts_fresh() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_eq!(wal.sequence(), 0);
        assert_eq!(wal.last_hash(), "genesis");

        wal.append(TestDecision {
            model: "first".into(),
            cost: 42,
        })
        .unwrap();
        assert_eq!(wal.sequence(), 1);
        assert_ne!(wal.last_hash(), "genesis");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn different_data_different_hash() {
        let h1 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "y".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        assert_ne!(h1, h2);
    }

    // ── HMAC tests ──

    #[test]
    fn hmac_keyed_chain_validates() {
        let path = temp_path("hmac-basic");
        let _ = std::fs::remove_file(&path);
        let key = b"calybris-secret-key-2026";

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 10,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 20,
            })
            .unwrap();
            wal.sync().unwrap();
        }

        // Reopen with same key succeeds
        let wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
        assert_eq!(wal.sequence(), 2);

        // verify_wal_keyed also works
        let (count, _) = verify_wal_keyed(&path, key).unwrap();
        assert_eq!(count, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_wrong_key_rejects() {
        let path = temp_path("hmac-wrongkey");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, b"correct-key").unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
        }

        // Wrong key → chain broken
        let result = WalWriter::<TestDecision>::open_keyed(&path, b"wrong-key");
        assert!(result.is_err());

        // No key → also fails (HMAC hash != plain SHA-256 hash)
        let result = WalWriter::<TestDecision>::open(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_tamper_detected() {
        let path = temp_path("hmac-tamper");
        let _ = std::fs::remove_file(&path);
        let key = b"audit-key";

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        // Tamper data
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        // Even with the correct key, tamper is detected
        let result = verify_wal_keyed(&path, key);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_different_key_different_hash() {
        let h1 = compute_hash("prev", "{\"x\":1}", Some(b"key-a")).unwrap();
        let h2 = compute_hash("prev", "{\"x\":1}", Some(b"key-b")).unwrap();
        let h3 = compute_hash("prev", "{\"x\":1}", None).unwrap();
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn read_verified_keyed_works() {
        let path = temp_path("hmac-read-verified");
        let _ = std::fs::remove_file(&path);
        let key = b"read-key";

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "x".into(),
                cost: 42,
            })
            .unwrap();
        }

        let entries = read_verified_wal_keyed::<TestDecision>(&path, key).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.model, "x");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audited_append_replay_roundtrip() {
        use crate::kernel::*;

        let path = temp_path("audited-replay");
        let _ = std::fs::remove_file(&path);

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, "meta".to_string())
                .unwrap();
            wal.sync().unwrap();
        }

        let verdicts = replay_audited_wal(&path, &snapshot).unwrap();
        assert_eq!(verdicts.len(), 1);
        assert!(verdicts[0].replay_valid);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audited_replay_fails_on_input_digest_mismatch() {
        use crate::kernel::*;

        let path = temp_path("audited-input-tamper");
        let _ = std::fs::remove_file(&path);

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, ()).unwrap();
            wal.sync().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen(
            &digest_to_hex(&crate::digest::input_digest(&input)),
            "0000000000000000000000000000000000000000000000000000000000000000",
            1,
        );
        std::fs::write(&path, tampered).unwrap();

        let result = replay_audited_wal(&path, &snapshot);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    // Fuzz-like proptest: random data, random sequence lengths
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_data_survives_roundtrip(
            model in "[a-z]{1,20}",
            cost in any::<i64>(),
            count in 1_usize..50,
        ) {
            let path = temp_path(&format!("fuzz-{}-{}", cost, count));
            let _ = std::fs::remove_file(&path);

            {
                let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
                for i in 0..count {
                    wal.append(TestDecision {
                        model: format!("{model}{i}"),
                        cost: cost.wrapping_add(i as i64),
                    }).unwrap();
                }
            }

            // Reopen validates chain
            let wal = WalWriter::<TestDecision>::open(&path).unwrap();
            prop_assert_eq!(wal.sequence() as usize, count);

            let entries = read_verified_wal::<TestDecision>(&path).unwrap();
            prop_assert_eq!(entries.len(), count);

            let _ = std::fs::remove_file(&path);
        }
    }
}
