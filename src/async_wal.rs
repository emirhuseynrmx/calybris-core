//! Async hash-chained Write-Ahead Log using Tokio.
//!
//! Feature-gated behind `async`. Same tamper-evident guarantees as the
//! synchronous [`wal`](crate::wal) module — HMAC-SHA256, constant-time
//! comparison, chain validation on open — but with non-blocking I/O.

use crate::digest::bytes_to_hex;
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{audit_bundle, verified_audit_bundle};
use crate::wal::{
    writer_lock_path, WalAnchor, MAX_WAL_ENTRY_BYTES, MAX_WAL_PAYLOAD_BYTES, MIN_HMAC_KEY_BYTES,
    WAL_ANCHOR_SCHEMA,
};
use fs2::FileExt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

use std::fs::{File as StdFile, OpenOptions as StdOpenOptions};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// Async WAL error types.
#[derive(Debug, thiserror::Error)]
pub enum AsyncWalError {
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

fn async_wal_io_error(kind: std::io::ErrorKind, message: impl Into<String>) -> AsyncWalError {
    AsyncWalError::Io(std::io::Error::new(kind, message.into()))
}

fn validate_hmac_key(key: &[u8]) -> Result<(), AsyncWalError> {
    if key.len() < MIN_HMAC_KEY_BYTES {
        return Err(async_wal_io_error(
            std::io::ErrorKind::InvalidInput,
            format!(
                "WAL HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes, found {}",
                key.len()
            ),
        ));
    }
    Ok(())
}

/// A single entry in the async hash-chained WAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalEntry<T> {
    pub sequence: u64,
    pub previous_hash: String,
    pub entry_hash: String,
    pub data: T,
}

/// Full audit record for async WAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditedRecord<M> {
    pub audit: crate::verify::AuditBundle,
    pub input: KernelInput,
    pub decision: KernelDecision,
    pub metadata: M,
}

fn compute_hash(
    previous_hash: &str,
    data_json: &str,
    key: Option<&[u8]>,
) -> Result<String, AsyncWalError> {
    match key {
        Some(k) => {
            validate_hmac_key(k)?;
            let mut mac = HmacSha256::new_from_slice(k).map_err(|_| {
                AsyncWalError::Io(std::io::Error::new(
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

async fn validate_chain_async(
    path: &Path,
    key: Option<&[u8]>,
) -> Result<(u64, String), AsyncWalError> {
    if let Some(key) = key {
        validate_hmac_key(key)?;
    }
    let file = File::open(path).await?;
    validate_chain_async_reader(file, key).await
}

async fn validate_chain_async_reader(
    file: File,
    key: Option<&[u8]>,
) -> Result<(u64, String), AsyncWalError> {
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();

    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;

    loop {
        line.clear();
        let read = (&mut reader)
            .take((MAX_WAL_ENTRY_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_WAL_ENTRY_BYTES {
            return Err(async_wal_io_error(
                std::io::ErrorKind::InvalidData,
                format!(
                    "WAL entry exceeds {MAX_WAL_ENTRY_BYTES} bytes: found {}",
                    line.len()
                ),
            ));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let entry: WalEntry<Box<serde_json::value::RawValue>> = serde_json::from_slice(&line)?;

        if entry.sequence != expected_sequence {
            return Err(AsyncWalError::DuplicateSequence(entry.sequence));
        }

        if entry.previous_hash != expected_prev_hash {
            return Err(AsyncWalError::ChainBroken {
                sequence: entry.sequence,
                expected: expected_prev_hash,
                found: entry.previous_hash,
            });
        }

        let computed = compute_hash(&entry.previous_hash, entry.data.get(), key)?;
        if computed
            .as_bytes()
            .ct_eq(entry.entry_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(AsyncWalError::ChainBroken {
                sequence: entry.sequence,
                expected: computed,
                found: entry.entry_hash,
            });
        }

        last_hash = entry.entry_hash;
        last_sequence = entry.sequence;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            AsyncWalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;
        expected_prev_hash = last_hash.clone();
    }

    Ok((last_sequence, last_hash))
}

/// Async hash-chained, tamper-evident WAL writer.
///
/// Same security guarantees as [`crate::wal::WalWriter`] but uses
/// `tokio::fs` for non-blocking I/O. Suitable for async runtimes
/// where blocking the executor is unacceptable.
pub struct AsyncWalWriter<T> {
    file: File,
    _writer_lock: StdFile,
    #[allow(dead_code)]
    path: PathBuf,
    sequence: u64,
    last_hash: String,
    hmac_key: Option<Vec<u8>>,
    sync_on_append: bool,
    poisoned: bool,
    _phantom: std::marker::PhantomData<T>,
}

fn acquire_writer_lock(path: &Path) -> Result<StdFile, AsyncWalError> {
    let lock_path = writer_lock_path(path)?;
    let lock_file = StdOpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.try_lock_exclusive().map_err(|_| {
        async_wal_io_error(
            std::io::ErrorKind::WouldBlock,
            format!("WAL already has an active writer: {}", path.display()),
        )
    })?;
    Ok(lock_file)
}

impl<T: Serialize> AsyncWalWriter<T> {
    /// Open or create an async WAL file. Validates existing chain on open.
    pub async fn open(path: &Path) -> Result<Self, AsyncWalError> {
        Self::open_inner(path, None, false).await
    }

    /// Open with HMAC-SHA256 keying.
    pub async fn open_keyed(path: &Path, key: &[u8]) -> Result<Self, AsyncWalError> {
        Self::open_inner(path, Some(key.to_vec()), false).await
    }

    /// Open with config-driven sync behavior.
    pub async fn open_with_sync(path: &Path, sync_on_append: bool) -> Result<Self, AsyncWalError> {
        Self::open_inner(path, None, sync_on_append).await
    }

    async fn open_inner(
        path: &Path,
        hmac_key: Option<Vec<u8>>,
        sync_on_append: bool,
    ) -> Result<Self, AsyncWalError> {
        if let Some(key) = hmac_key.as_deref() {
            validate_hmac_key(key)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .await?;
        let writer_lock = acquire_writer_lock(path)?;
        let mut read_file = file.try_clone().await?;
        read_file.seek(SeekFrom::Start(0)).await?;
        let (sequence, last_hash) =
            validate_chain_async_reader(read_file, hmac_key.as_deref()).await?;

        Ok(Self {
            file,
            _writer_lock: writer_lock,
            path: path.to_path_buf(),
            sequence,
            last_hash,
            hmac_key,
            sync_on_append,
            poisoned: false,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append a record to the WAL. Optionally syncs based on config.
    pub async fn append(&mut self, data: T) -> Result<WalEntry<T>, AsyncWalError> {
        if self.poisoned {
            return Err(async_wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        let next_sequence = self.sequence.checked_add(1).ok_or_else(|| {
            AsyncWalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;

        let data_json = serde_json::to_string(&data)?;
        if data_json.len() > MAX_WAL_PAYLOAD_BYTES {
            return Err(async_wal_io_error(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "WAL payload exceeds {MAX_WAL_PAYLOAD_BYTES} bytes: found {}",
                    data_json.len()
                ),
            ));
        }
        let entry_hash = compute_hash(&self.last_hash, &data_json, self.hmac_key.as_deref())?;
        let previous_hash = self.last_hash.clone();

        let line = format!(
            "{{\"sequence\":{},\"previous_hash\":\"{}\",\"entry_hash\":\"{}\",\"data\":{}}}\n",
            next_sequence, previous_hash, entry_hash, data_json
        );
        if line.len() > MAX_WAL_ENTRY_BYTES {
            return Err(async_wal_io_error(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "WAL entry exceeds {MAX_WAL_ENTRY_BYTES} bytes: found {}",
                    line.len()
                ),
            ));
        }

        if let Err(error) = self.file.write_all(line.as_bytes()).await {
            self.poisoned = true;
            return Err(AsyncWalError::Io(error));
        }

        if self.sync_on_append {
            if let Err(error) = self.file.sync_data().await {
                self.poisoned = true;
                return Err(AsyncWalError::Io(error));
            }
        }

        self.sequence = next_sequence;
        self.last_hash = entry_hash.clone();

        Ok(WalEntry {
            sequence: self.sequence,
            previous_hash,
            entry_hash,
            data,
        })
    }

    /// Flush and fsync to disk.
    pub async fn flush_and_sync(&mut self) -> Result<(), AsyncWalError> {
        if self.poisoned {
            return Err(async_wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        if let Err(error) = self.file.flush().await {
            self.poisoned = true;
            return Err(AsyncWalError::Io(error));
        }
        if let Err(error) = self.file.sync_data().await {
            self.poisoned = true;
            return Err(AsyncWalError::Io(error));
        }
        Ok(())
    }

    /// Current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Last hash in the chain.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Capture the current trusted WAL head.
    #[must_use]
    pub fn anchor(&self) -> WalAnchor {
        WalAnchor {
            schema_version: WAL_ANCHOR_SCHEMA.to_string(),
            sequence: self.sequence,
            last_hash: self.last_hash.clone(),
            keyed: self.hmac_key.is_some(),
        }
    }
}

impl<M> AsyncWalWriter<AuditedRecord<M>>
where
    M: Serialize,
{
    /// Append a fully audited decision record (async).
    pub async fn append_audited(
        &mut self,
        snapshot: &PolicySnapshot,
        input: KernelInput,
        decision: KernelDecision,
        metadata: M,
    ) -> Result<WalEntry<AuditedRecord<M>>, AsyncWalError> {
        let audit = audit_bundle(snapshot, input, &decision);
        let record = AuditedRecord {
            audit,
            input,
            decision,
            metadata,
        };
        self.append(record).await
    }

    /// Verify and append (fail-closed, async).
    pub async fn append_verified_audited(
        &mut self,
        snapshot: &PolicySnapshot,
        input: KernelInput,
        decision: KernelDecision,
        metadata: M,
    ) -> Result<WalEntry<AuditedRecord<M>>, AsyncWalError> {
        let audit = verified_audit_bundle(snapshot, input, &decision).map_err(|result| {
            AsyncWalError::AuditFailed {
                sequence: self.sequence.saturating_add(1),
                reason: format!("verify_decision failed: {result:?}"),
            }
        })?;
        let record = AuditedRecord {
            audit,
            input,
            decision,
            metadata,
        };
        self.append(record).await
    }
}

/// Verify async WAL chain integrity (unkeyed).
pub async fn verify_async_wal(path: &Path) -> Result<(u64, String), AsyncWalError> {
    validate_chain_async(path, None).await
}

/// Verify async WAL chain integrity with HMAC key.
pub async fn verify_async_wal_keyed(
    path: &Path,
    key: &[u8],
) -> Result<(u64, String), AsyncWalError> {
    validate_chain_async(path, Some(key)).await
}

async fn verify_async_anchor(
    path: &Path,
    key: Option<&[u8]>,
    anchor: &WalAnchor,
) -> Result<(u64, String), AsyncWalError> {
    if anchor.schema_version != WAL_ANCHOR_SCHEMA {
        return Err(AsyncWalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown WAL anchor schema: {}", anchor.schema_version),
        )));
    }
    if anchor.keyed != key.is_some() {
        return Err(async_wal_io_error(
            std::io::ErrorKind::InvalidInput,
            "WAL anchor keyed mode does not match verifier mode",
        ));
    }
    let (sequence, hash) = validate_chain_async(path, key).await?;
    if sequence != anchor.sequence || hash != anchor.last_hash {
        return Err(async_wal_io_error(
            std::io::ErrorKind::InvalidData,
            format!(
                "WAL anchor mismatch: expected sequence {} hash {}, found sequence {} hash {}",
                anchor.sequence, anchor.last_hash, sequence, hash
            ),
        ));
    }
    Ok((sequence, hash))
}

/// Verify an async WAL against a trusted external head anchor.
pub async fn verify_async_wal_against_anchor(
    path: &Path,
    anchor: &WalAnchor,
) -> Result<(u64, String), AsyncWalError> {
    verify_async_anchor(path, None, anchor).await
}

/// Verify a keyed async WAL against a trusted external head anchor.
pub async fn verify_async_wal_keyed_against_anchor(
    path: &Path,
    key: &[u8],
    anchor: &WalAnchor,
) -> Result<(u64, String), AsyncWalError> {
    verify_async_anchor(path, Some(key), anchor).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HMAC_KEY: &[u8; 32] = b"calybris-test-hmac-key-000000001";

    fn assert_io_error<T>(
        result: Result<T, AsyncWalError>,
        expected_kind: std::io::ErrorKind,
        expected_message: &str,
    ) {
        match result {
            Err(AsyncWalError::Io(error)) => {
                assert_eq!(error.kind(), expected_kind);
                assert!(
                    error.to_string().contains(expected_message),
                    "unexpected error: {error}"
                );
            }
            Err(error) => panic!("expected async WAL I/O error, got: {error}"),
            Ok(_) => panic!("expected async WAL I/O error, got success"),
        }
    }

    #[tokio::test]
    async fn async_append_and_verify() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("async-wal.jsonl");

        let mut wal = AsyncWalWriter::<serde_json::Value>::open(&path)
            .await
            .unwrap();
        wal.append(serde_json::json!({"model": "gpt-4o", "cost": 100}))
            .await
            .unwrap();
        wal.append(serde_json::json!({"model": "mini", "cost": 10}))
            .await
            .unwrap();
        wal.flush_and_sync().await.unwrap();

        assert_eq!(wal.sequence(), 2);

        let (count, _) = verify_async_wal(&path).await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn async_keyed_wal() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("keyed-async.jsonl");
        let key = TEST_HMAC_KEY;

        {
            let mut wal = AsyncWalWriter::<serde_json::Value>::open_keyed(&path, key)
                .await
                .unwrap();
            wal.append(serde_json::json!({"x": 1})).await.unwrap();
            wal.flush_and_sync().await.unwrap();
        }

        let (count, _) = verify_async_wal_keyed(&path, key).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn async_short_hmac_key_is_rejected_for_empty_wal() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("short-key.jsonl");
        assert_io_error(
            AsyncWalWriter::<serde_json::Value>::open_keyed(&path, b"short").await,
            std::io::ErrorKind::InvalidInput,
            "at least 32 bytes, found 5",
        );
    }

    #[tokio::test]
    async fn async_sync_on_append() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-append.jsonl");

        let mut wal = AsyncWalWriter::<serde_json::Value>::open_with_sync(&path, true)
            .await
            .unwrap();
        wal.append(serde_json::json!({"durable": true}))
            .await
            .unwrap();
        assert_eq!(wal.sequence(), 1);
    }

    #[tokio::test]
    async fn async_second_writer_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("single-writer.jsonl");
        let _first = AsyncWalWriter::<serde_json::Value>::open(&path)
            .await
            .unwrap();
        assert_io_error(
            AsyncWalWriter::<serde_json::Value>::open(&path).await,
            std::io::ErrorKind::WouldBlock,
            "active writer",
        );
    }

    #[tokio::test]
    #[cfg(any(unix, windows))]
    async fn async_hard_link_alias_shares_writer_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hard-link.jsonl");
        let alias = dir.path().join("hard-link-alias.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let _writer = AsyncWalWriter::<serde_json::Value>::open(&path)
            .await
            .unwrap();

        assert_io_error(
            AsyncWalWriter::<serde_json::Value>::open(&alias).await,
            std::io::ErrorKind::WouldBlock,
            "active writer",
        );
    }

    #[tokio::test]
    async fn async_anchor_detects_clean_suffix_truncation() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("anchored.jsonl");
        let anchor = {
            let mut wal = AsyncWalWriter::<serde_json::Value>::open(&path)
                .await
                .unwrap();
            wal.append(serde_json::json!({"n": 1})).await.unwrap();
            wal.append(serde_json::json!({"n": 2})).await.unwrap();
            wal.flush_and_sync().await.unwrap();
            wal.anchor()
        };
        let content = std::fs::read_to_string(&path).unwrap();
        let retained = content.lines().take(1).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&path, retained).unwrap();

        assert_eq!(verify_async_wal(&path).await.unwrap().0, 1);
        assert_io_error(
            verify_async_wal_against_anchor(&path, &anchor).await,
            std::io::ErrorKind::InvalidData,
            "WAL anchor mismatch",
        );
    }

    #[tokio::test]
    async fn async_oversized_wal_line_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("oversized.jsonl");
        std::fs::write(&path, vec![b'x'; MAX_WAL_ENTRY_BYTES + 1]).unwrap();
        assert_io_error(
            verify_async_wal(&path).await,
            std::io::ErrorKind::InvalidData,
            "WAL entry exceeds",
        );
    }

    #[tokio::test]
    async fn async_oversized_payload_is_rejected_before_writer_state_advances() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("oversized-payload.jsonl");
        let mut wal = AsyncWalWriter::<String>::open(&path).await.unwrap();
        let payload = "x".repeat(MAX_WAL_PAYLOAD_BYTES);
        assert_io_error(
            wal.append(payload).await,
            std::io::ErrorKind::InvalidInput,
            "WAL payload exceeds",
        );
        assert_eq!(wal.sequence(), 0);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn async_audited_roundtrip() {
        use crate::kernel::*;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audited-async.jsonl");

        let snapshot = PolicySnapshot::try_new(
            1,
            1,
            9600,
            5500,
            3500,
            0,
            vec![KernelModel {
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
            }],
        )
        .unwrap();

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

        let mut wal = AsyncWalWriter::open(&path).await.unwrap();
        wal.append_audited(&snapshot, input, decision, "async-meta".to_string())
            .await
            .unwrap();
        wal.flush_and_sync().await.unwrap();
        assert_eq!(wal.sequence(), 1);
    }
}
