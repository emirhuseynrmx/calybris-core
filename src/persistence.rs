//! Snapshot persistence and point-in-time recovery.
//!
//! Save [`crate::budget::BudgetSnapshot`] to disk, load it back, and restore engine state.
//! Combined with WAL replay, this gives crash recovery and backup/restore.
//!
//! Snapshot writes fsync file contents before atomic replacement. On Unix the
//! parent-directory fsync is also required and errors are propagated. Rust's
//! standard library does not expose portable Windows directory fsync, so the
//! directory-entry durability guarantee is platform dependent there.

use crate::budget::{BudgetEngine, BudgetSnapshot, RestoreError};
use fs2::FileExt;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// Maximum accepted size for one JSON persistence artifact.
pub const MAX_PERSISTENCE_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

/// Schema for the atomically committed snapshot/WAL generation manifest.
#[cfg(feature = "wal")]
pub const CHECKPOINT_MANIFEST_SCHEMA: &str = "calybris.checkpoint-manifest.v1";

/// The final commit record for one durable checkpoint generation.
#[cfg(feature = "wal")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifest {
    pub schema_version: String,
    pub snapshot_file: String,
    pub wal_anchor_file: String,
    pub snapshot_version: u64,
    pub ledger_digest_hex: String,
    pub wal_sequence: u64,
    pub wal_hash: String,
    pub wal_keyed: bool,
}

/// A manifest-consistent snapshot/WAL-anchor generation.
///
/// Use [`load_and_verify_coordinated_checkpoint`] to additionally verify the
/// actual WAL bytes against the committed anchor.
#[cfg(feature = "wal")]
#[derive(Debug, Clone)]
pub struct CoordinatedCheckpoint {
    pub manifest: CheckpointManifest,
    pub snapshot: BudgetSnapshot,
    pub anchor: crate::wal::WalAnchor,
}

/// Persistence error types.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("restore error: {0}")]
    Restore(#[from] RestoreError),
}

/// Save a budget snapshot with file-data fsync and atomic replacement.
///
/// On Unix, parent-directory fsync is mandatory and failures are returned. On
/// Windows, the standard library does not provide portable directory fsync;
/// callers requiring a power-loss guarantee for the directory entry must add
/// a platform-specific storage layer.
pub fn save_snapshot(snapshot: &BudgetSnapshot, path: &Path) -> Result<(), PersistenceError> {
    save_json_atomic(snapshot, path)
}

fn save_json_atomic<T: serde::Serialize>(value: &T, path: &Path) -> Result<(), PersistenceError> {
    let json = serde_json::to_string_pretty(value)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("snapshot");
    // Windows does not guarantee that concurrent replace-existing operations
    // against the same destination all succeed. A durable sibling lock file
    // serializes writers across both threads and processes while preserving
    // atomic visibility of the final rename/persist operation.
    let lock_path: PathBuf = parent.join(format!(".{filename}.calybris.lock"));
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock_file.lock_exclusive()?;
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".{filename}.tmp."))
        .tempfile_in(parent)?;
    temporary.write_all(json.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| PersistenceError::Io(error.error))?;

    sync_parent_directory(path)?;
    FileExt::unlock(&lock_file)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), PersistenceError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), PersistenceError> {
    Ok(())
}

fn load_json_bounded<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, PersistenceError> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_PERSISTENCE_ARTIFACT_BYTES as u64 {
        return Err(PersistenceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("persistence artifact exceeds {MAX_PERSISTENCE_ARTIFACT_BYTES} bytes"),
        )));
    }
    let mut bytes = Vec::new();
    file.take((MAX_PERSISTENCE_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PERSISTENCE_ARTIFACT_BYTES {
        return Err(PersistenceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("persistence artifact exceeds {MAX_PERSISTENCE_ARTIFACT_BYTES} bytes"),
        )));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Save a trusted WAL head anchor with fsync-backed atomic replacement.
#[cfg(feature = "wal")]
pub fn save_wal_anchor(
    anchor: &crate::wal::WalAnchor,
    path: &Path,
) -> Result<(), PersistenceError> {
    save_json_atomic(anchor, path)
}

/// Load a trusted WAL head anchor.
#[cfg(feature = "wal")]
pub fn load_wal_anchor(path: &Path) -> Result<crate::wal::WalAnchor, PersistenceError> {
    load_json_bounded(path)
}

/// Load a budget snapshot from a JSON file.
pub fn load_snapshot(path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    load_json_bounded(path)
}

/// Checkpoint engine state without WAL binding.
///
/// Use [`checkpoint_with_wal`] when you have a WAL writer — it records the
/// WAL sequence so recovery knows where to start replaying.
pub fn checkpoint(engine: &BudgetEngine, path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    let snapshot = engine.snapshot();
    save_snapshot(&snapshot, path)?;
    Ok(snapshot)
}

/// Checkpoint engine state alongside a WAL sequence.
///
/// Records the current WAL sequence as [`BudgetSnapshot::wal_high_watermark`]
/// so that [`recovery_plan`] can determine exactly which WAL entries need
/// replay after a crash.
pub fn checkpoint_with_wal(
    engine: &BudgetEngine,
    path: &Path,
    wal_sequence: u64,
) -> Result<BudgetSnapshot, PersistenceError> {
    let mut snapshot = engine.snapshot();
    snapshot.wal_high_watermark = Some(wal_sequence);
    save_snapshot(&snapshot, path)?;
    Ok(snapshot)
}

/// Commit a generation in WAL -> snapshot -> manifest order.
///
/// The WAL is flushed and synced first. Snapshot and anchor files are immutable,
/// generation-specific files; the manifest is atomically replaced last and is
/// therefore the only recovery commit point. Parent-directory power-loss
/// durability follows the platform contract documented by [`save_snapshot`].
/// Callers must route each logical
/// ledger mutation and its WAL append through the same application-level
/// admission boundary used for this checkpoint.
#[cfg(feature = "wal")]
pub fn checkpoint_coordinated<T: serde::Serialize>(
    engine: &BudgetEngine,
    wal: &mut crate::wal::WalWriter<T>,
    directory: &Path,
) -> Result<CoordinatedCheckpoint, PersistenceError> {
    std::fs::create_dir_all(directory)?;
    wal.flush_and_sync()
        .map_err(|error| invalid_recovery_data(error.to_string()))?;
    let anchor = wal.anchor();
    let mut snapshot = engine.snapshot();
    snapshot.wal_high_watermark = Some(anchor.sequence);

    let snapshot_file = format!(
        "snapshot-v{}-wal-{}.json",
        snapshot.version, anchor.sequence
    );
    let wal_anchor_file = format!(
        "wal-anchor-v{}-wal-{}.json",
        snapshot.version, anchor.sequence
    );
    save_snapshot(&snapshot, &directory.join(&snapshot_file))?;
    save_wal_anchor(&anchor, &directory.join(&wal_anchor_file))?;

    let manifest = CheckpointManifest {
        schema_version: CHECKPOINT_MANIFEST_SCHEMA.to_string(),
        snapshot_file,
        wal_anchor_file,
        snapshot_version: snapshot.version,
        ledger_digest_hex: crate::digest::digest_to_hex(&crate::finance::ledger_digest(&snapshot)),
        wal_sequence: anchor.sequence,
        wal_hash: anchor.last_hash.clone(),
        wal_keyed: anchor.keyed,
    };
    save_json_atomic(&manifest, &directory.join("checkpoint-manifest.json"))?;
    Ok(CoordinatedCheckpoint {
        manifest,
        snapshot,
        anchor,
    })
}

/// Load the last committed generation and fail closed on any cross-file mismatch.
#[cfg(feature = "wal")]
pub fn load_coordinated_checkpoint(
    directory: &Path,
) -> Result<CoordinatedCheckpoint, PersistenceError> {
    let manifest: CheckpointManifest =
        load_json_bounded(&directory.join("checkpoint-manifest.json"))?;
    if manifest.schema_version != CHECKPOINT_MANIFEST_SCHEMA {
        return Err(invalid_recovery_data(format!(
            "unknown checkpoint manifest schema: {}",
            manifest.schema_version
        )));
    }
    validate_generation_filename(&manifest.snapshot_file)?;
    validate_generation_filename(&manifest.wal_anchor_file)?;

    let snapshot = load_snapshot(&directory.join(&manifest.snapshot_file))?;
    let anchor = load_wal_anchor(&directory.join(&manifest.wal_anchor_file))?;
    let digest = crate::digest::digest_to_hex(&crate::finance::ledger_digest(&snapshot));
    if snapshot.version != manifest.snapshot_version
        || snapshot.wal_high_watermark != Some(manifest.wal_sequence)
        || digest != manifest.ledger_digest_hex
    {
        return Err(invalid_recovery_data(
            "checkpoint snapshot does not match committed manifest",
        ));
    }
    anchor
        .verify_head(
            manifest.wal_sequence,
            manifest.wal_hash.clone(),
            manifest.wal_keyed,
        )
        .map_err(|error| invalid_recovery_data(error.to_string()))?;
    Ok(CoordinatedCheckpoint {
        manifest,
        snapshot,
        anchor,
    })
}

/// Load a manifest-consistent checkpoint and verify the actual WAL against its anchor.
#[cfg(feature = "wal")]
pub fn load_and_verify_coordinated_checkpoint(
    directory: &Path,
    wal_path: &Path,
    hmac_key: Option<&[u8]>,
) -> Result<CoordinatedCheckpoint, PersistenceError> {
    let checkpoint = load_coordinated_checkpoint(directory)?;
    match (checkpoint.anchor.keyed, hmac_key) {
        (true, Some(key)) => {
            crate::wal::verify_wal_keyed_against_anchor(wal_path, key, &checkpoint.anchor)
        }
        (false, None) => crate::wal::verify_wal_against_anchor(wal_path, &checkpoint.anchor),
        (true, None) => {
            return Err(invalid_recovery_data(
                "checkpoint WAL is keyed but no HMAC key was supplied",
            ));
        }
        (false, Some(_)) => {
            return Err(invalid_recovery_data(
                "checkpoint WAL is unkeyed but an HMAC key was supplied",
            ));
        }
    }
    .map_err(|error| invalid_recovery_data(error.to_string()))?;
    Ok(checkpoint)
}

#[cfg(feature = "wal")]
fn validate_generation_filename(filename: &str) -> Result<(), PersistenceError> {
    let mut components = Path::new(filename).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(invalid_recovery_data(
            "checkpoint manifest contains an unsafe generation filename",
        )),
    }
}

#[cfg(feature = "wal")]
fn invalid_recovery_data(message: impl Into<String>) -> PersistenceError {
    PersistenceError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

/// Restore engine state from a snapshot file.
///
/// Loads the snapshot, validates it (no active reservations, conservation
/// balanced), and restores the engine. This is an **exclusive recovery**
/// operation — no concurrent hot-path ops should be running.
pub fn restore(engine: &BudgetEngine, path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    let snapshot = load_snapshot(path)?;
    engine.restore_from_snapshot(snapshot.clone())?;
    Ok(snapshot)
}

/// Recovery strategy: load snapshot + count WAL entries that need replay.
///
/// Uses [`BudgetSnapshot::wal_high_watermark`] (set by [`checkpoint_with_wal`])
/// to determine which WAL entries are newer than the checkpoint. If no watermark
/// is set, all WAL entries are counted as needing replay.
#[cfg(feature = "wal")]
fn recovery_plan_inner(
    snapshot_path: &Path,
    wal_path: &Path,
    key: Option<&[u8]>,
    anchor: Option<&crate::wal::WalAnchor>,
) -> Result<RecoveryPlan, PersistenceError> {
    let snapshot = load_snapshot(snapshot_path)?;
    let high = snapshot.wal_high_watermark.unwrap_or(0);
    let mut total_wal_entries = 0_usize;
    let mut entries_to_replay = 0_usize;

    let head = if let Some(k) = key {
        crate::wal::visit_verified_wal_keyed::<serde_json::Value, _>(wal_path, k, |entry| {
            total_wal_entries += 1;
            if entry.sequence > high {
                entries_to_replay += 1;
            }
        })
    } else {
        crate::wal::visit_verified_wal::<serde_json::Value, _>(wal_path, |entry| {
            total_wal_entries += 1;
            if entry.sequence > high {
                entries_to_replay += 1;
            }
        })
    }
    .map_err(|e| PersistenceError::Io(std::io::Error::other(e.to_string())))?;

    if let Some(anchor) = anchor {
        anchor
            .verify_head(head.0, head.1, key.is_some())
            .map_err(|e| PersistenceError::Io(std::io::Error::other(e.to_string())))?;
    }

    Ok(RecoveryPlan {
        snapshot,
        total_wal_entries,
        entries_to_replay,
        wal_high_watermark: high,
    })
}

/// Recovery plan with chain-verified WAL read (unkeyed).
///
/// Verifies the WAL hash chain before counting entries. Use
/// [`recovery_plan_keyed`] for HMAC-keyed WAL files.
#[cfg(feature = "wal")]
pub fn recovery_plan(
    snapshot_path: &Path,
    wal_path: &Path,
) -> Result<RecoveryPlan, PersistenceError> {
    recovery_plan_inner(snapshot_path, wal_path, None, None)
}

/// Recovery plan with chain-verified WAL read (HMAC-keyed).
#[cfg(feature = "wal")]
pub fn recovery_plan_keyed(
    snapshot_path: &Path,
    wal_path: &Path,
    key: &[u8],
) -> Result<RecoveryPlan, PersistenceError> {
    recovery_plan_inner(snapshot_path, wal_path, Some(key), None)
}

/// Recovery plan with an unkeyed WAL pinned to a trusted external head.
#[cfg(feature = "wal")]
pub fn recovery_plan_against_anchor(
    snapshot_path: &Path,
    wal_path: &Path,
    anchor: &crate::wal::WalAnchor,
) -> Result<RecoveryPlan, PersistenceError> {
    recovery_plan_inner(snapshot_path, wal_path, None, Some(anchor))
}

/// Recovery plan with a keyed WAL pinned to a trusted external head.
#[cfg(feature = "wal")]
pub fn recovery_plan_keyed_against_anchor(
    snapshot_path: &Path,
    wal_path: &Path,
    key: &[u8],
    anchor: &crate::wal::WalAnchor,
) -> Result<RecoveryPlan, PersistenceError> {
    recovery_plan_inner(snapshot_path, wal_path, Some(key), Some(anchor))
}

/// A recovery plan describing what needs to happen to restore state.
#[cfg(feature = "wal")]
#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    /// The snapshot to restore from.
    pub snapshot: BudgetSnapshot,
    /// Total entries in the WAL file.
    pub total_wal_entries: usize,
    /// Entries newer than the checkpoint that need domain-specific replay.
    pub entries_to_replay: usize,
    /// The WAL sequence at checkpoint time (0 if not set).
    pub wal_high_watermark: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetEngine;

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    fn save_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("snapshot.json");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 100_000);
        engine.commit(id.unwrap(), 90_000);

        let saved = checkpoint(&engine, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap();

        assert_eq!(saved.tenants.len(), loaded.tenants.len());
        assert_eq!(saved.tenants[0].tenant_id, loaded.tenants[0].tenant_id);
        assert_eq!(
            saved.tenants[0].remaining_microcents,
            loaded.tenants[0].remaining_microcents
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    fn restore_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("snapshot.json");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 100_000);
        engine.commit(id.unwrap(), 90_000);
        checkpoint(&engine, &path).unwrap();

        let fresh = BudgetEngine::new();
        let snap = restore(&fresh, &path).unwrap();
        assert_eq!(fresh.remaining_microcents("desk"), Some(910_000));
        assert_eq!(fresh.committed_microcents("desk"), Some(90_000));
        assert_eq!(snap.tenants.len(), 1);
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    fn atomic_write_no_partial() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("atomic.json");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 500_000);
        checkpoint(&engine, &path).unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    fn checkpoint_with_wal_records_watermark() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("snap-wal.json");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let snap = checkpoint_with_wal(&engine, &path, 42).unwrap();
        assert_eq!(snap.wal_high_watermark, Some(42));

        let loaded = load_snapshot(&path).unwrap();
        assert_eq!(loaded.wal_high_watermark, Some(42));
    }

    #[test]
    #[cfg(feature = "wal")]
    fn coordinated_checkpoint_commits_a_verified_generation() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("events.wal");
        let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
        wal.append(serde_json::json!({"event": "reserve"})).unwrap();

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let committed = checkpoint_coordinated(&engine, &mut wal, dir.path()).unwrap();
        let recovered = load_coordinated_checkpoint(dir.path()).unwrap();
        let fully_verified =
            load_and_verify_coordinated_checkpoint(dir.path(), &wal_path, None).unwrap();

        assert_eq!(recovered.manifest, committed.manifest);
        assert_eq!(fully_verified.manifest, committed.manifest);
        assert_eq!(recovered.snapshot, committed.snapshot);
        assert_eq!(recovered.snapshot.wal_high_watermark, Some(1));
        assert_eq!(recovered.anchor.sequence, 1);
    }

    #[test]
    #[cfg(feature = "wal")]
    fn coordinated_checkpoint_full_verification_rejects_a_truncated_wal() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("events.wal");
        let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
        wal.append(serde_json::json!({"event": 1})).unwrap();
        wal.append(serde_json::json!({"event": 2})).unwrap();
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        checkpoint_coordinated(&engine, &mut wal, dir.path()).unwrap();
        drop(wal);

        let contents = std::fs::read_to_string(&wal_path).unwrap();
        let prefix = contents.lines().take(1).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&wal_path, prefix).unwrap();

        assert!(load_coordinated_checkpoint(dir.path()).is_ok());
        assert!(load_and_verify_coordinated_checkpoint(dir.path(), &wal_path, None).is_err());
    }

    #[test]
    fn oversized_persistence_artifact_is_rejected_before_json_parsing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("oversized.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len((MAX_PERSISTENCE_ARTIFACT_BYTES + 1) as u64)
            .unwrap();
        let error = load_snapshot(&path).unwrap_err();
        assert!(matches!(
            error,
            PersistenceError::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    #[cfg(feature = "wal")]
    fn coordinated_checkpoint_rejects_a_torn_committed_generation() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("events.wal");
        let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
        wal.append(serde_json::json!({"event": "reserve"})).unwrap();
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let committed = checkpoint_coordinated(&engine, &mut wal, dir.path()).unwrap();

        std::fs::write(
            dir.path().join(&committed.manifest.snapshot_file),
            b"{\"torn\":",
        )
        .unwrap();
        assert!(load_coordinated_checkpoint(dir.path()).is_err());
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    fn checkpoint_without_wal_has_no_watermark() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("snap-no-wal.json");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let snap = checkpoint(&engine, &path).unwrap();
        assert_eq!(snap.wal_high_watermark, None);
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    #[cfg(feature = "wal")]
    fn recovery_plan_uses_watermark() {
        let dir = tempfile::TempDir::new().unwrap();
        let snap_path = dir.path().join("snap.json");
        let wal_path = dir.path().join("wal.jsonl");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);

        {
            let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
            wal.append(serde_json::json!({"action": "reserve"}))
                .unwrap();
            wal.append(serde_json::json!({"action": "commit"})).unwrap();

            checkpoint_with_wal(&engine, &snap_path, wal.sequence()).unwrap();

            wal.append(serde_json::json!({"action": "release"}))
                .unwrap();
        }

        let plan = recovery_plan(&snap_path, &wal_path).unwrap();
        assert_eq!(plan.total_wal_entries, 3);
        assert_eq!(plan.wal_high_watermark, 2);
        assert_eq!(plan.entries_to_replay, 1);
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    #[cfg(feature = "wal")]
    fn anchored_recovery_rejects_clean_suffix_truncation() {
        let dir = tempfile::TempDir::new().unwrap();
        let snap_path = dir.path().join("snap.json");
        let wal_path = dir.path().join("wal.jsonl");
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        checkpoint(&engine, &snap_path).unwrap();

        let anchor = {
            let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
            wal.append(serde_json::json!({"a": 1})).unwrap();
            wal.append(serde_json::json!({"b": 2})).unwrap();
            wal.flush_and_sync().unwrap();
            wal.anchor()
        };
        let contents = std::fs::read_to_string(&wal_path).unwrap();
        let prefix = contents.lines().take(1).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&wal_path, prefix).unwrap();

        assert!(recovery_plan(&snap_path, &wal_path).is_ok());
        assert!(recovery_plan_against_anchor(&snap_path, &wal_path, &anchor).is_err());
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    #[cfg(feature = "wal")]
    fn wal_anchor_atomic_save_roundtrip_and_replace() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("anchor.json");
        let mut anchor = crate::wal::WalAnchor {
            schema_version: crate::wal::WAL_ANCHOR_SCHEMA.to_string(),
            sequence: 1,
            last_hash: "11".repeat(32),
            keyed: true,
        };
        save_wal_anchor(&anchor, &path).unwrap();
        assert_eq!(load_wal_anchor(&path).unwrap(), anchor);

        anchor.sequence = 2;
        anchor.last_hash = "22".repeat(32);
        save_wal_anchor(&anchor, &path).unwrap();
        assert_eq!(load_wal_anchor(&path).unwrap(), anchor);
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    #[cfg_attr(
        all(miri, windows),
        ignore = "miri/windows: tempfile directory creation is unsupported"
    )]
    #[cfg(feature = "wal")]
    fn recovery_plan_no_watermark_replays_all() {
        let dir = tempfile::TempDir::new().unwrap();
        let snap_path = dir.path().join("snap.json");
        let wal_path = dir.path().join("wal.jsonl");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        checkpoint(&engine, &snap_path).unwrap();

        {
            let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
            wal.append(serde_json::json!({"a": 1})).unwrap();
            wal.append(serde_json::json!({"b": 2})).unwrap();
        }

        let plan = recovery_plan(&snap_path, &wal_path).unwrap();
        assert_eq!(plan.entries_to_replay, 2);
        assert_eq!(plan.wal_high_watermark, 0);
    }

    #[test]
    fn snapshot_can_replace_an_existing_checkpoint() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("replace.json");
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);

        checkpoint(&engine, &path).unwrap();
        assert!(matches!(
            engine.top_up_tenant("desk", 500_000),
            crate::budget::TopUpResult::ToppedUp { .. }
        ));
        let replaced = checkpoint(&engine, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap();

        assert_eq!(loaded.version, replaced.version);
        assert_eq!(loaded.tenants[0].initial_microcents, 1_500_000);
    }

    #[test]
    fn concurrent_atomic_saves_do_not_share_a_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("snapshot.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let engine = BudgetEngine::new();
                    engine.ensure_tenant(&format!("desk-{index}"), 1_000_000);
                    let snapshot = engine.snapshot();
                    barrier.wait();
                    save_snapshot(&snapshot, &path)
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert_eq!(load_snapshot(&path).unwrap().tenants.len(), 1);
    }
}
