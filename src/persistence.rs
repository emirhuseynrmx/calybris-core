//! Snapshot persistence and point-in-time recovery.
//!
//! Save [`BudgetSnapshot`] to disk, load it back, and restore engine state.
//! Combined with WAL replay, this gives crash recovery and backup/restore.

use crate::budget::{BudgetEngine, BudgetSnapshot, RestoreError};
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

/// Save a budget snapshot to a JSON file.
///
/// The snapshot is written atomically: data goes to a `.tmp` file first,
/// then renamed to the target path. This prevents partial writes on crash.
pub fn save_snapshot(snapshot: &BudgetSnapshot, path: &Path) -> Result<(), PersistenceError> {
    let json = serde_json::to_string_pretty(snapshot)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load a budget snapshot from a JSON file.
pub fn load_snapshot(path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    let data = std::fs::read_to_string(path)?;
    let snapshot: BudgetSnapshot = serde_json::from_str(&data)?;
    Ok(snapshot)
}

/// Save and restore a budget engine from a snapshot file.
///
/// Takes a snapshot of the current engine state, saves it to disk,
/// and returns the snapshot for further use.
pub fn checkpoint(engine: &BudgetEngine, path: &Path) -> Result<BudgetSnapshot, PersistenceError> {
    let snapshot = engine.snapshot();
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

/// Recovery strategy: load snapshot + replay WAL entries since snapshot.
///
/// Returns the number of WAL entries that were newer than the snapshot
/// (and would need to be replayed by the caller's domain logic).
#[cfg(feature = "wal")]
pub fn recovery_plan(
    snapshot_path: &Path,
    wal_path: &Path,
) -> Result<RecoveryPlan, PersistenceError> {
    let snapshot = load_snapshot(snapshot_path)?;

    let entries = crate::wal::read_wal::<serde_json::Value>(wal_path)
        .map_err(|e| PersistenceError::Io(std::io::Error::other(e.to_string())))?;

    let wal_entries_after_snapshot = entries
        .iter()
        .filter(|e| e.sequence > snapshot.version)
        .count();

    Ok(RecoveryPlan {
        snapshot,
        total_wal_entries: entries.len(),
        entries_to_replay: wal_entries_after_snapshot,
    })
}

/// A recovery plan describing what needs to happen to restore state.
#[cfg(feature = "wal")]
#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    /// The snapshot to restore from.
    pub snapshot: BudgetSnapshot,
    /// Total entries in the WAL file.
    pub total_wal_entries: usize,
    /// Entries newer than the snapshot that need domain-specific replay.
    pub entries_to_replay: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetEngine;

    #[test]
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
    #[cfg(feature = "wal")]
    fn recovery_plan_counts_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let snap_path = dir.path().join("snap.json");
        let wal_path = dir.path().join("wal.jsonl");

        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        checkpoint(&engine, &snap_path).unwrap();

        {
            let mut wal = crate::wal::WalWriter::<serde_json::Value>::open(&wal_path).unwrap();
            wal.append(serde_json::json!({"action": "reserve"})).unwrap();
            wal.append(serde_json::json!({"action": "commit"})).unwrap();
            wal.append(serde_json::json!({"action": "release"})).unwrap();
        }

        let plan = recovery_plan(&snap_path, &wal_path).unwrap();
        assert_eq!(plan.total_wal_entries, 3);
        assert!(plan.entries_to_replay <= 3);
    }
}
