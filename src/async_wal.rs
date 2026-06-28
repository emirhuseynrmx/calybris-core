//! Async hash-chained Write-Ahead Log using Tokio.
//!
//! Feature-gated behind `async`. Same tamper-evident guarantees as the
//! synchronous [`wal`](crate::wal) module — HMAC-SHA256, constant-time
//! comparison, chain validation on open — but with non-blocking I/O.

use crate::digest::bytes_to_hex;
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{audit_bundle, verified_audit_bundle};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let entry: WalEntry<serde_json::Value> = serde_json::from_str(&line)?;

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

        let data_str = serde_json::to_string(&entry.data)?;
        let computed = compute_hash(&entry.previous_hash, &data_str, key)?;
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
        expected_sequence += 1;
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
    #[allow(dead_code)]
    path: PathBuf,
    sequence: u64,
    last_hash: String,
    hmac_key: Option<Vec<u8>>,
    sync_on_append: bool,
    _phantom: std::marker::PhantomData<T>,
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
        let (sequence, last_hash) = if path.exists() {
            validate_chain_async(path, hmac_key.as_deref()).await?
        } else {
            (0, "genesis".to_string())
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            sequence,
            last_hash,
            hmac_key,
            sync_on_append,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append a record to the WAL. Optionally syncs based on config.
    pub async fn append(&mut self, data: T) -> Result<WalEntry<T>, AsyncWalError> {
        let next_sequence = self.sequence.checked_add(1).ok_or_else(|| {
            AsyncWalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;

        let data_json = serde_json::to_string(&data)?;
        let entry_hash = compute_hash(&self.last_hash, &data_json, self.hmac_key.as_deref())?;
        let previous_hash = self.last_hash.clone();

        let line = format!(
            "{{\"sequence\":{},\"previous_hash\":\"{}\",\"entry_hash\":\"{}\",\"data\":{}}}\n",
            next_sequence, previous_hash, entry_hash, data_json
        );

        self.file.write_all(line.as_bytes()).await?;

        if self.sync_on_append {
            self.file.sync_data().await?;
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
        self.file.flush().await?;
        self.file.sync_data().await?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let key = b"async-secret-key";

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
