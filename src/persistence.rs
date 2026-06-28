//! Snapshot persistence and point-in-time recovery.
//!
//! Save [`crate::budget::BudgetSnapshot`] to disk, load it back, and restore engine state.
//! Combined with WAL replay, this gives crash recovery and backup/restore.
//!
//! Snapshot writes use temp-file + fsync + rename for crash durability.

use crate::budget::{BudgetEngine, BudgetSnapshot, RestoreError};
use std::io::Write;
use std::path::Path;

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

/// Save a budget snapshot to a JSON file with fsync-backed durability.
///
/// Writes to a `.tmp` file, fsyncs data, renames to target, then fsyncs the
/// parent directory. This prevents partial writes and ensures the rename is
/// durable even on power loss.
pub fn save_snapshot(snapshot: &BudgetSnapshot, path: &Path) -> Result<(), PersistenceError> {
    let json = serde_json::to_string_pretty(snapshot)?;
    let tmp = path.with_extension("tmp");

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(json.as_bytes())?;
    file.sync_data()?;
    drop(file);

    std::fs::rename(&tmp, path)?;

    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_data();
        }
    }
    Ok(())
}

/// Load a budget snapshot from a JSON file.
pub fn load_snapshot(path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    let data = std::fs::read_to_string(path)?;
    let snapshot: BudgetSnapshot = serde_json::from_str(&data)?;
    Ok(snapshot)
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
) -> Result<RecoveryPlan, PersistenceError> {
    let snapshot = load_snapshot(snapshot_path)?;

    let entries = if let Some(k) = key {
        crate::wal::read_verified_wal_keyed::<serde_json::Value>(wal_path, k)
    } else {
        crate::wal::read_verified_wal::<serde_json::Value>(wal_path)
    }
    .map_err(|e| PersistenceError::Io(std::io::Error::other(e.to_string())))?;

    let high = snapshot.wal_high_watermark.unwrap_or(0);
    let entries_to_replay = entries.iter().filter(|e| e.sequence > high).count();

    Ok(RecoveryPlan {
        snapshot,
        total_wal_entries: entries.len(),
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
    recovery_plan_inner(snapshot_path, wal_path, None)
}

/// Recovery plan with chain-verified WAL read (HMAC-keyed).
#[cfg(feature = "wal")]
pub fn recovery_plan_keyed(
    snapshot_path: &Path,
    wal_path: &Path,
    key: &[u8],
) -> Result<RecoveryPlan, PersistenceError> {
    recovery_plan_inner(snapshot_path, wal_path, Some(key))
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
}
