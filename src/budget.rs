//! Atomic budget engine with CAS (compare-and-swap) reservation management.
//!
//! All values are i64 **microcents** (1 US cent = 1,000,000 microcents).
//! The kernel itself uses currency-agnostic "microunits"; microcents are the
//! specific denomination chosen for the finance / pre-trade exposure layer.
//! No floating-point in the core API.
//!
//! CAS-based balance updates; metadata maps are mutex-protected.
//! Metadata locks use scoped ordering within each operation; restore requires exclusive recovery (no concurrent hot-path use).
//!
//! Conservation invariant (per tenant, after completed operations):
//!
//! ```text
//! remaining + reserved + committed_lifetime == initial
//! ```
//!
//! Holds after each **completed** reserve / commit / release / top-up and at reconciliation
//! boundaries (`verify_conservation`, `prove_conservation`). Mutations take a shared
//! `checkpoint_gate` guard and snapshots take its exclusive guard, so a snapshot waits for
//! in-flight mutations and is a linearizable, conservation-balanced transaction view.
//!
//! - `remaining` — spendable balance right now
//! - `reserved` — sum of active (uncommitted) holds
//! - `committed_lifetime` — cumulative spend since tenant creation (monotonic, never decreases)
//! - `initial` — total budget ever granted (`ensure_tenant` + [`top_up_tenant`](crate::budget::BudgetEngine::top_up_tenant))

use crate::sync::{Arc, AtomicI64, AtomicU64, Mutex, Ordering, RwLock};
use std::collections::HashMap;

/// Budget reservation result.
#[derive(Clone, Debug, PartialEq)]
pub enum BudgetReservation {
    Reserved {
        remaining_microcents: i64,
    },
    Insufficient {
        remaining_microcents: i64,
        required_microcents: i64,
    },
    MissingTenant,
    MissingReservation,
    ExposureLimitExceeded {
        current_reserved_microcents: i64,
        max_reserved_microcents: i64,
    },
    Overflow {
        current_reserved_microcents: i64,
    },
}

/// Result of topping up a tenant budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopUpResult {
    ToppedUp {
        added_microcents: i64,
        new_initial_microcents: i64,
        remaining_microcents: i64,
    },
    MissingTenant,
    InvalidAmount,
    Overflow,
}

/// Invalid configuration supplied at a budget-engine trust boundary.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetConfigurationError {
    #[error("{field} must be >= 0, got {value}")]
    NegativeAmount { field: &'static str, value: i64 },
}

/// Budget settlement result.
#[derive(Clone, Debug, PartialEq)]
pub enum BudgetSettlement {
    Committed {
        remaining_microcents: i64,
        actual_microcents: i64,
    },
    Released {
        remaining_microcents: i64,
        returned_microcents: i64,
    },
    Overrun {
        remaining_microcents: i64,
    },
    InvalidAmount,
    MissingReservation,
    MissingTenant,
    Overflow {
        remaining_microcents: i64,
    },
}

#[derive(Debug)]
struct ReservationRecord {
    tenant_id: Arc<str>,
    reserved_microcents: i64,
}

/// Atomically debit `amount` from `budget` if sufficient balance exists.
/// Returns `Ok(remaining)` or `Err(current_balance)`.
///
/// Uses a CAS loop — no lock required, safe under any contention.
#[inline]
fn debit_if_available(budget: &AtomicI64, amount: i64) -> Result<i64, i64> {
    let mut current = budget.load(Ordering::Acquire);
    loop {
        if current < amount {
            return Err(current);
        }
        match budget.compare_exchange_weak(
            current,
            current - amount,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(current - amount),
            Err(actual) => current = actual,
        }
    }
}

/// Atomically credit `amount` to `budget` if `current + amount` does not overflow.
#[inline]
fn credit_if_no_overflow(budget: &AtomicI64, amount: i64) -> Result<i64, ()> {
    let mut current = budget.load(Ordering::Acquire);
    loop {
        let new = current.checked_add(amount).ok_or(())?;
        match budget.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(new),
            Err(actual) => current = actual,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservedTotalError {
    Overflow,
    ExposureExceeded { current: i64 },
}

/// CAS-increment reserved total with `checked_add` (no silent wrap).
fn try_increment_reserved_total(
    total: &AtomicI64,
    amount: i64,
    max: i64,
) -> Result<i64, ReservedTotalError> {
    let mut current = total.load(Ordering::Acquire);
    loop {
        let new_total = match current.checked_add(amount) {
            Some(n) => n,
            None => return Err(ReservedTotalError::Overflow),
        };
        if max > 0 && new_total > max {
            return Err(ReservedTotalError::ExposureExceeded { current });
        }
        match total.compare_exchange_weak(current, new_total, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(new_total),
            Err(actual) => current = actual,
        }
    }
}

/// Atomic budget engine.
///
/// CAS-based balance updates on `Arc<AtomicI64>` — the atomic is cloned out of
/// the map before the CAS loop, so no lock is held during the contended operation.
/// Metadata maps are mutex-protected; each operation acquires only the locks it needs.
/// [`restore_from_snapshot`](Self::restore_from_snapshot) is exclusive recovery — not concurrent with hot-path ops.
pub struct BudgetEngine {
    /// Mutations take a shared guard; snapshots and restores take an exclusive guard.
    checkpoint_gate: RwLock<()>,
    tenant_budgets: Mutex<HashMap<Arc<str>, Arc<AtomicI64>>>,
    initial_microcents: Mutex<HashMap<Arc<str>, i64>>,
    committed_microcents: Mutex<HashMap<Arc<str>, i64>>,
    reservations: Mutex<HashMap<u64, ReservationRecord>>,
    /// Per-tenant cap on sum of open reservation holds (`0` = unlimited).
    max_reserved_microcents: Mutex<HashMap<Arc<str>, i64>>,
    /// Per-tenant sum of open holds — CAS-updated for concurrent exposure enforcement.
    tenant_reserved_totals: Mutex<HashMap<Arc<str>, Arc<AtomicI64>>>,
    // u64::MAX is ~18 quintillion reservations — practically unreachable.
    next_id: AtomicU64,
    /// Last recovery-aware snapshot version emitted by [`snapshot`](BudgetEngine::snapshot).
    snapshot_version: AtomicU64,
    /// Cumulative committed total at last [`crate::finance::certify_ledger`] call.
    last_certified_committed_total: Mutex<i64>,
}

/// Point-in-time ledger row for one tenant (integer microcents only).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TenantLedger {
    pub tenant_id: String,
    pub initial_microcents: i64,
    pub remaining_microcents: i64,
    pub reserved_microcents: i64,
    /// Cumulative lifetime spend for this tenant (monotonic; not "currently committed").
    pub committed_microcents: i64,
}

/// Immutable financial snapshot across all tenants.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BudgetSnapshot {
    /// Tagged recovery allocator fence assigned when this snapshot was captured.
    ///
    /// Recovery-aware snapshots encode the next reservation allocator position
    /// in this field. This preserves the public 0.5.x snapshot shape while
    /// preventing a restored engine from reusing a pre-checkpoint reservation ID.
    /// The high tag bit means serialized values exceed JavaScript's exact integer
    /// range; JavaScript consumers must use a BigInt-aware JSON parser and must not
    /// round-trip this field through `Number`.
    pub version: u64,
    pub tenants: Vec<TenantLedger>,
    pub active_reservations: usize,
    /// WAL sequence at checkpoint time. Used by recovery to determine which
    /// WAL entries need replay. `None` if snapshot was not taken alongside a WAL.
    #[cfg_attr(feature = "serde", serde(default))]
    pub wal_high_watermark: Option<u64>,
}

/// Check conservation invariant on a frozen snapshot (no additional engine reads).
#[must_use]
pub fn conservation_status_for_snapshot(snapshot: &BudgetSnapshot) -> ConservationStatus {
    for ledger in &snapshot.tenants {
        let Some(sum) = ledger
            .remaining_microcents
            .checked_add(ledger.reserved_microcents)
            .and_then(|v| v.checked_add(ledger.committed_microcents))
        else {
            return ConservationStatus::AggregateOverflow;
        };
        if sum != ledger.initial_microcents {
            let Some(delta) = sum.checked_sub(ledger.initial_microcents) else {
                return ConservationStatus::AggregateOverflow;
            };
            return ConservationStatus::Violation {
                tenant_id: ledger.tenant_id.clone(),
                delta_microcents: delta,
            };
        }
        if ledger.remaining_microcents < 0 {
            return ConservationStatus::Violation {
                tenant_id: ledger.tenant_id.clone(),
                delta_microcents: ledger.remaining_microcents,
            };
        }
    }
    ConservationStatus::Balanced
}

/// Result of the conservation invariant check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConservationStatus {
    /// `remaining + reserved + committed == initial` for every tenant in this snapshot.
    Balanced,
    /// Invariant violated — includes per-tenant deltas in microcents.
    Violation {
        tenant_id: String,
        delta_microcents: i64,
    },
    /// Sum of per-tenant ledger totals exceeds `i64::MAX` — aggregate certificate fields cannot be represented.
    AggregateOverflow,
}

impl std::fmt::Display for ConservationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Balanced => write!(f, "conservation balanced"),
            Self::Violation {
                tenant_id,
                delta_microcents,
            } => write!(
                f,
                "conservation violated for tenant {tenant_id}: delta={delta_microcents} microcents"
            ),
            Self::AggregateOverflow => write!(
                f,
                "aggregate ledger totals exceed i64::MAX — certificate totals cannot be represented"
            ),
        }
    }
}

impl std::error::Error for ConservationStatus {}

/// Error restoring engine state from a [`BudgetSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    #[error("cannot restore snapshot with {count} active reservations")]
    ActiveReservations { count: usize },
    #[error(
        "tenant {tenant_id} has reserved_microcents={reserved_microcents} with no active reservations"
    )]
    GhostReservation {
        tenant_id: String,
        reserved_microcents: i64,
    },
    #[error("tenant {tenant_id} has negative {field}: {value}")]
    NegativeLedgerField {
        tenant_id: String,
        field: &'static str,
        value: i64,
    },
    #[error("snapshot failed conservation: {status}")]
    ConservationViolation { status: ConservationStatus },
    #[error("duplicate tenant_id in snapshot: {tenant_id}")]
    DuplicateTenant { tenant_id: String },
}

/// Error migrating a pre-0.5.7 snapshot into the recovery-aware format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegacySnapshotMigrationError {
    #[error("snapshot is already recovery-aware")]
    AlreadyRecoveryAware,
    #[error("trusted next reservation ID must be in 1..={max}, found {value}")]
    InvalidAllocatorFence { value: u64, max: u64 },
    #[error("legacy snapshot is not recovery-eligible: {0}")]
    InvalidSnapshot(#[from] RestoreError),
}

/// Precise format and ledger errors for recovery-aware restores.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoverySnapshotError {
    #[error("legacy snapshot requires explicit migration with a trusted allocator fence")]
    LegacySnapshotRequiresMigration,
    #[error("invalid recovery allocator fence: {value}")]
    InvalidAllocatorFence { value: u64 },
    #[error("snapshot is not recovery-eligible: {0}")]
    InvalidSnapshot(#[from] RestoreError),
}

/// Snapshot allocator errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SnapshotAllocatorError {
    #[error("reservation allocator exhausted")]
    AllocatorExhausted,
}

const RECOVERY_SNAPSHOT_TAG: u64 = 1 << 63;
const RECOVERY_ALLOCATOR_MASK: u64 = RECOVERY_SNAPSHOT_TAG - 1;

fn allocator_from_snapshot_version(version: u64) -> Result<u64, RestoreError> {
    let next_id = version & RECOVERY_ALLOCATOR_MASK;
    if version & RECOVERY_SNAPSHOT_TAG == 0 || next_id == 0 {
        return Err(RestoreError::NegativeLedgerField {
            tenant_id: "<snapshot-metadata>".to_owned(),
            field: "recovery-aware version tag",
            value: i64::try_from(version).unwrap_or(i64::MAX),
        });
    }
    Ok(next_id)
}

pub(crate) fn validate_snapshot_for_restore(snap: &BudgetSnapshot) -> Result<(), RestoreError> {
    allocator_from_snapshot_version(snap.version)?;
    validate_snapshot_ledger(snap)
}

fn validate_snapshot_ledger(snap: &BudgetSnapshot) -> Result<(), RestoreError> {
    if snap.active_reservations > 0 {
        return Err(RestoreError::ActiveReservations {
            count: snap.active_reservations,
        });
    }
    let mut seen = std::collections::HashSet::new();
    for ledger in &snap.tenants {
        if !seen.insert(ledger.tenant_id.as_str()) {
            return Err(RestoreError::DuplicateTenant {
                tenant_id: ledger.tenant_id.clone(),
            });
        }
        if ledger.reserved_microcents != 0 {
            return Err(RestoreError::GhostReservation {
                tenant_id: ledger.tenant_id.clone(),
                reserved_microcents: ledger.reserved_microcents,
            });
        }
        if ledger.remaining_microcents < 0 {
            return Err(RestoreError::NegativeLedgerField {
                tenant_id: ledger.tenant_id.clone(),
                field: "remaining_microcents",
                value: ledger.remaining_microcents,
            });
        }
        if ledger.initial_microcents < 0 {
            return Err(RestoreError::NegativeLedgerField {
                tenant_id: ledger.tenant_id.clone(),
                field: "initial_microcents",
                value: ledger.initial_microcents,
            });
        }
        if ledger.committed_microcents < 0 {
            return Err(RestoreError::NegativeLedgerField {
                tenant_id: ledger.tenant_id.clone(),
                field: "committed_microcents",
                value: ledger.committed_microcents,
            });
        }
    }
    match conservation_status_for_snapshot(snap) {
        ConservationStatus::Balanced => Ok(()),
        status => Err(RestoreError::ConservationViolation { status }),
    }
}

/// Convert an untagged 0.5.x snapshot into the recovery-aware 0.5.7 format.
///
/// `trusted_next_reservation_id` must be greater than every reservation ID that
/// may have been issued before the snapshot was taken. That fence cannot be
/// reconstructed from the legacy snapshot itself, so guessing is unsafe and
/// this function fails closed when no positive fence is supplied.
pub fn migrate_legacy_snapshot(
    mut snapshot: BudgetSnapshot,
    trusted_next_reservation_id: u64,
) -> Result<BudgetSnapshot, LegacySnapshotMigrationError> {
    if snapshot.version & RECOVERY_SNAPSHOT_TAG != 0 {
        return Err(LegacySnapshotMigrationError::AlreadyRecoveryAware);
    }
    if trusted_next_reservation_id == 0 || trusted_next_reservation_id > RECOVERY_ALLOCATOR_MASK {
        return Err(LegacySnapshotMigrationError::InvalidAllocatorFence {
            value: trusted_next_reservation_id,
            max: RECOVERY_ALLOCATOR_MASK,
        });
    }
    validate_snapshot_ledger(&snapshot)?;
    snapshot.version = RECOVERY_SNAPSHOT_TAG | trusted_next_reservation_id;
    Ok(snapshot)
}

impl BudgetEngine {
    pub fn new() -> Self {
        Self {
            checkpoint_gate: RwLock::new(()),
            tenant_budgets: Mutex::new(HashMap::new()),
            initial_microcents: Mutex::new(HashMap::new()),
            committed_microcents: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
            max_reserved_microcents: Mutex::new(HashMap::new()),
            tenant_reserved_totals: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            snapshot_version: AtomicU64::new(0),
            last_certified_committed_total: Mutex::new(0),
        }
    }

    /// Set a per-tenant exposure cap on future reservation holds (`0` removes the cap).
    ///
    /// Updates are serialized against reservation admission. Lowering a cap is
    /// prospective: existing holds are not revoked, while every admission that
    /// linearizes after this method returns observes the new cap.
    pub fn set_max_reserved_microcents(&self, tenant_id: &str, max_microcents: i64) {
        let _ = self.try_set_max_reserved_microcents(tenant_id, max_microcents);
    }

    /// Checked exposure-cap update. Zero removes the cap; negative values are rejected.
    pub fn try_set_max_reserved_microcents(
        &self,
        tenant_id: &str,
        max_microcents: i64,
    ) -> Result<(), BudgetConfigurationError> {
        if max_microcents < 0 {
            return Err(BudgetConfigurationError::NegativeAmount {
                field: "max_reserved_microcents",
                value: max_microcents,
            });
        }
        let _mutation = self
            .checkpoint_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let key: Arc<str> = Arc::from(tenant_id);
        let mut limits = self
            .max_reserved_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if max_microcents == 0 {
            limits.remove(&key);
        } else {
            limits.insert(key, max_microcents);
        }
        Ok(())
    }

    /// Last emitted tagged recovery allocator fence, or zero before any snapshot.
    #[must_use]
    pub fn snapshot_version(&self) -> u64 {
        self.snapshot_version.load(Ordering::Acquire)
    }

    /// Sum of lifetime `committed_microcents` across all tenants.
    #[must_use]
    pub fn total_committed_microcents(&self) -> i64 {
        self.try_total_committed_microcents().unwrap_or(i64::MAX)
    }

    /// Checked sum of lifetime `committed_microcents` across all tenants.
    pub fn try_total_committed_microcents(&self) -> Result<i64, ConservationStatus> {
        let committed = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut total: i128 = 0;
        for amount in committed.values() {
            total = total
                .checked_add(i128::from(*amount))
                .ok_or(ConservationStatus::AggregateOverflow)?;
        }
        i64::try_from(total).map_err(|_| ConservationStatus::AggregateOverflow)
    }

    /// Committed total since the last financial certificate was issued.
    #[must_use]
    pub fn committed_since_last_certificate(&self) -> i64 {
        let current = self.total_committed_microcents();
        let baseline = *self
            .last_certified_committed_total
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        current.saturating_sub(baseline)
    }

    /// Advance certificate baseline from a frozen snapshot total; returns delta since last cert.
    pub(crate) fn rotate_certificate_baseline(&self, snapshot_total_committed: i64) -> i64 {
        let mut baseline = self
            .last_certified_committed_total
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if snapshot_total_committed <= *baseline {
            return 0;
        }
        let delta = snapshot_total_committed - *baseline;
        *baseline = snapshot_total_committed;
        delta
    }

    /// Rebuild tenant balances from a validated snapshot (no active or ghost reservations).
    ///
    /// Must be called during **exclusive recovery** — no concurrent `try_reserve`,
    /// `commit`, `release`, or `top_up_tenant` on this engine. Concurrent hot-path
    /// operations may hold cloned state across a clear/replace and corrupt restored ledgers.
    pub fn restore_from_snapshot(&self, snap: BudgetSnapshot) -> Result<(), RestoreError> {
        validate_snapshot_for_restore(&snap)?;
        let next_reservation_id = allocator_from_snapshot_version(snap.version)?;
        let restored_committed_total = snap
            .tenants
            .iter()
            .try_fold(0_i64, |total, tenant| {
                total.checked_add(tenant.committed_microcents)
            })
            .unwrap_or(i64::MAX);
        let _checkpoint = self
            .checkpoint_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        {
            let mut reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
            reservations.clear();
        }
        let mut budgets = self
            .tenant_budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut initials = self
            .initial_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut committed = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut reserved_totals = self
            .tenant_reserved_totals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut exposure_limits = self
            .max_reserved_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        budgets.clear();
        initials.clear();
        committed.clear();
        reserved_totals.clear();
        exposure_limits.clear();
        for ledger in snap.tenants {
            let key: Arc<str> = Arc::from(ledger.tenant_id.as_str());
            budgets.insert(
                Arc::clone(&key),
                Arc::new(AtomicI64::new(ledger.remaining_microcents)),
            );
            initials.insert(Arc::clone(&key), ledger.initial_microcents);
            committed.insert(Arc::clone(&key), ledger.committed_microcents);
            reserved_totals.insert(key, Arc::new(AtomicI64::new(ledger.reserved_microcents)));
        }
        self.next_id.store(next_reservation_id, Ordering::Release);
        self.snapshot_version.store(snap.version, Ordering::Release);
        *self
            .last_certified_committed_total
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = restored_committed_total;
        Ok(())
    }

    /// Restore with precise recovery-format diagnostics.
    ///
    /// Use this at new trust boundaries. The compatibility
    /// [`restore_from_snapshot`](Self::restore_from_snapshot) method retains
    /// its 0.5.x error type and therefore cannot name the legacy-format case.
    pub fn restore_from_recovery_snapshot(
        &self,
        snap: BudgetSnapshot,
    ) -> Result<(), RecoverySnapshotError> {
        if snap.version & RECOVERY_SNAPSHOT_TAG == 0 {
            return Err(RecoverySnapshotError::LegacySnapshotRequiresMigration);
        }
        let fence = snap.version & RECOVERY_ALLOCATOR_MASK;
        if fence == 0 {
            return Err(RecoverySnapshotError::InvalidAllocatorFence { value: fence });
        }
        validate_snapshot_ledger(&snap)?;
        self.restore_from_snapshot(snap)
            .map_err(RecoverySnapshotError::InvalidSnapshot)
    }

    /// Initialize a tenant with a budget in microcents.
    ///
    /// Idempotent — calling with an existing tenant does nothing (no top-up).
    /// Use [`top_up_tenant`](Self::top_up_tenant) to add funds later.
    /// `initial_microcents` is fixed at creation for audit binding; top-ups extend it.
    ///
    /// Negative `budget_microcents` is rejected (no-op).
    pub fn ensure_tenant(&self, tenant_id: &str, budget_microcents: i64) {
        let _ = self.try_ensure_tenant(tenant_id, budget_microcents);
    }

    /// Checked tenant initialization for external trust boundaries.
    pub fn try_ensure_tenant(
        &self,
        tenant_id: &str,
        budget_microcents: i64,
    ) -> Result<(), BudgetConfigurationError> {
        if budget_microcents < 0 {
            return Err(BudgetConfigurationError::NegativeAmount {
                field: "budget_microcents",
                value: budget_microcents,
            });
        }
        let _mutation = self
            .checkpoint_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut budgets = self
            .tenant_budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut initials = self
            .initial_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut committed = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut reserved_totals = self
            .tenant_reserved_totals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key: Arc<str> = Arc::from(tenant_id);
        if !budgets.contains_key(&key) {
            budgets.insert(
                Arc::clone(&key),
                Arc::new(AtomicI64::new(budget_microcents)),
            );
            initials.insert(Arc::clone(&key), budget_microcents);
            committed.insert(Arc::clone(&key), 0);
            reserved_totals.insert(key, Arc::new(AtomicI64::new(0)));
        }
        Ok(())
    }

    /// Add funds to an existing tenant (extends `initial` and `remaining` equally).
    ///
    /// Does not reset `committed_microcents` (lifetime spend is preserved).
    /// Returns [`TopUpResult::MissingTenant`] if the tenant was never created.
    pub fn top_up_tenant(&self, tenant_id: &str, amount_microcents: i64) -> TopUpResult {
        if amount_microcents <= 0 {
            return TopUpResult::InvalidAmount;
        }
        let _mutation = self
            .checkpoint_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());

        let key: Arc<str> = Arc::from(tenant_id);

        let budget = {
            let budgets = self
                .tenant_budgets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match budgets.get(&key) {
                Some(b) => Arc::clone(b),
                None => return TopUpResult::MissingTenant,
            }
        };

        let mut initials = self
            .initial_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let Some(current_initial) = initials.get(&key).copied() else {
            return TopUpResult::MissingTenant;
        };

        let Some(new_initial) = current_initial.checked_add(amount_microcents) else {
            return TopUpResult::Overflow;
        };

        let remaining = match credit_if_no_overflow(&budget, amount_microcents) {
            Ok(r) => r,
            Err(()) => return TopUpResult::Overflow,
        };

        *initials.get_mut(&key).expect("tenant exists") = new_initial;

        TopUpResult::ToppedUp {
            added_microcents: amount_microcents,
            new_initial_microcents: new_initial,
            remaining_microcents: remaining,
        }
    }

    /// Total budget ever granted to a tenant (`ensure_tenant` + top-ups).
    #[must_use]
    pub fn initial_microcents(&self, tenant_id: &str) -> Option<i64> {
        let initials = self
            .initial_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key: Arc<str> = Arc::from(tenant_id);
        initials.get(&key).copied()
    }

    /// Cumulative lifetime spend for a tenant (monotonic; increases on each successful [`commit`](Self::commit)).
    ///
    /// This is **not** "currently in-flight committed amount" — active holds live in [`reserved_microcents`](Self::reserved_microcents).
    #[must_use]
    pub fn committed_microcents(&self, tenant_id: &str) -> Option<i64> {
        let committed = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key: Arc<str> = Arc::from(tenant_id);
        committed.get(&key).copied()
    }

    /// Sum of active reservation holds for a tenant.
    #[must_use]
    pub fn reserved_microcents(&self, tenant_id: &str) -> i64 {
        let key: Arc<str> = Arc::from(tenant_id);
        let totals = self
            .tenant_reserved_totals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        totals
            .get(&key)
            .map(|t| t.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Capture a point-in-time ledger snapshot (mutex read — not on hot path).
    ///
    /// Lock order: reservations → budgets → initials → committed (matches hot path).
    /// This takes the exclusive checkpoint guard, so it waits for in-flight
    /// mutations. `std::sync::RwLock` gives writers no priority on every
    /// platform, so a sustained mutation stream can delay a snapshot.
    ///
    /// # Panics
    ///
    /// Panics when the reservation allocator is exhausted. Prefer
    /// [`Self::try_snapshot`] at API boundaries that must surface that error.
    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        self.try_snapshot()
            .expect("reservation allocator exhausted — use try_snapshot() for fallible capture")
    }

    /// Capture a snapshot, failing closed instead of repeating an allocator fence.
    pub fn try_snapshot(&self) -> Result<BudgetSnapshot, SnapshotAllocatorError> {
        let _checkpoint = self
            .checkpoint_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
        let budgets = self
            .tenant_budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let initials = self
            .initial_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let committed = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let reserved_totals = self
            .tenant_reserved_totals
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut tenants = Vec::with_capacity(budgets.len());
        for (tenant_id, balance) in budgets.iter() {
            tenants.push(TenantLedger {
                tenant_id: tenant_id.to_string(),
                initial_microcents: initials.get(tenant_id).copied().unwrap_or(0),
                remaining_microcents: balance.load(Ordering::Acquire),
                reserved_microcents: reserved_totals
                    .get(tenant_id)
                    .map(|t| t.load(Ordering::Acquire))
                    .unwrap_or(0),
                committed_microcents: committed.get(tenant_id).copied().unwrap_or(0),
            });
        }
        tenants.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        // Reserve one allocator position for the snapshot itself. Encoding the
        // resulting next ID in `version` gives recovery an exact, monotonic
        // allocator fence without changing the public 0.5.x struct layout.
        // Saturating here would re-emit one fence for every later snapshot, so
        // exhaustion fails closed instead.
        let previous_id = self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < RECOVERY_ALLOCATOR_MASK).then_some(current + 1)
            })
            .map_err(|_| SnapshotAllocatorError::AllocatorExhausted)?;
        let version = RECOVERY_SNAPSHOT_TAG | (previous_id + 1);
        self.snapshot_version.store(version, Ordering::Release);
        Ok(BudgetSnapshot {
            version,
            tenants,
            active_reservations: reservations.len(),
            wal_high_watermark: None,
        })
    }

    /// Verify conservation on a point-in-time snapshot.
    ///
    /// The snapshot gate waits for in-flight mutations before the frozen view is read.
    #[must_use]
    pub fn verify_conservation(&self) -> ConservationStatus {
        conservation_status_for_snapshot(&self.snapshot())
    }

    /// Remaining budget for a tenant in microcents.
    #[must_use]
    pub fn remaining_microcents(&self, tenant_id: &str) -> Option<i64> {
        let budgets = self
            .tenant_budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key: Arc<str> = Arc::from(tenant_id);
        budgets.get(&key).map(|b| b.load(Ordering::Acquire))
    }

    /// Reserve budget atomically using CAS.
    ///
    /// Returns `(BudgetReservation::Reserved { .. }, Some(id))` on success,
    /// or `(BudgetReservation::Insufficient { .. }, None)` if the tenant
    /// doesn't have enough balance. Zero or negative amounts are rejected.
    pub fn try_reserve(
        &self,
        tenant_id: &str,
        cost_microcents: i64,
    ) -> (BudgetReservation, Option<u64>) {
        if cost_microcents <= 0 {
            return (
                BudgetReservation::Insufficient {
                    remaining_microcents: 0,
                    required_microcents: cost_microcents,
                },
                None,
            );
        }
        let _mutation = self
            .checkpoint_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());

        let key: Arc<str> = Arc::from(tenant_id);
        let (budget, reserved_total) = {
            let budgets = self
                .tenant_budgets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let totals = self
                .tenant_reserved_totals
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match (budgets.get(&key), totals.get(&key)) {
                (Some(b), Some(t)) => (Arc::clone(b), Arc::clone(t)),
                _ => return (BudgetReservation::MissingTenant, None),
            }
        };

        let max_reserved = {
            let limits = self
                .max_reserved_microcents
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            limits.get(&key).copied().unwrap_or(0)
        };
        match try_increment_reserved_total(&reserved_total, cost_microcents, max_reserved) {
            Ok(_) => {}
            Err(ReservedTotalError::Overflow) => {
                return (
                    BudgetReservation::Overflow {
                        current_reserved_microcents: reserved_total.load(Ordering::Acquire),
                    },
                    None,
                );
            }
            Err(ReservedTotalError::ExposureExceeded { current }) => {
                return (
                    BudgetReservation::ExposureLimitExceeded {
                        current_reserved_microcents: current,
                        max_reserved_microcents: max_reserved,
                    },
                    None,
                );
            }
        }

        // Allocate before debiting so allocator exhaustion cannot require a
        // racy balance refund. Gaps after an insufficient debit are harmless;
        // reservation identifiers are monotonic capabilities, not counters.
        let id = match self
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < RECOVERY_ALLOCATOR_MASK).then_some(current + 1)
            }) {
            Ok(id) => id,
            Err(_) => {
                reserved_total.fetch_sub(cost_microcents, Ordering::AcqRel);
                return (
                    BudgetReservation::Overflow {
                        current_reserved_microcents: reserved_total.load(Ordering::Acquire),
                    },
                    None,
                );
            }
        };

        match debit_if_available(&budget, cost_microcents) {
            Err(current) => {
                reserved_total.fetch_sub(cost_microcents, Ordering::AcqRel);
                (
                    BudgetReservation::Insufficient {
                        remaining_microcents: current,
                        required_microcents: cost_microcents,
                    },
                    None,
                )
            }
            Ok(remaining) => {
                let mut reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
                reservations.insert(
                    id,
                    ReservationRecord {
                        tenant_id: Arc::clone(&key),
                        reserved_microcents: cost_microcents,
                    },
                );
                (
                    BudgetReservation::Reserved {
                        remaining_microcents: remaining,
                    },
                    Some(id),
                )
            }
        }
    }

    /// Commit a reservation with actual cost. Surplus is refunded.
    ///
    /// On successful commit, `committed_microcents` increases by `actual_microcents` (lifetime cumulative).
    ///
    /// **Overrun path:** if `actual_microcents > reserved`, the engine debits the difference.
    /// If the tenant cannot afford the overrun, `Overrun` is returned, the reservation is
    /// re-inserted, and the original reserved amount **stays deducted** (no refund).
    /// This is intentional — refunding on failed overrun would violate conservation (create money).
    /// Call [`release`](Self::release) to return the hold to spendable balance.
    pub fn commit(&self, reservation_id: u64, actual_microcents: i64) -> BudgetSettlement {
        if actual_microcents < 0 {
            return BudgetSettlement::InvalidAmount;
        }
        let _mutation = self
            .checkpoint_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());

        let mut reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
        let Some(reservation) = reservations.remove(&reservation_id) else {
            return BudgetSettlement::MissingReservation;
        };

        let budget = {
            let budgets = self
                .tenant_budgets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match budgets.get(&reservation.tenant_id) {
                Some(b) => Arc::clone(b),
                None => {
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::MissingTenant;
                }
            }
        };
        let tenant_key = Arc::clone(&reservation.tenant_id);
        let mut committed_guard = self
            .committed_microcents
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let current_committed = committed_guard.get(&tenant_key).copied().unwrap_or(0);
        let new_committed = match current_committed.checked_add(actual_microcents) {
            Some(v) => v,
            None => {
                drop(committed_guard);
                reservations.insert(reservation_id, reservation);
                return BudgetSettlement::Overflow {
                    remaining_microcents: budget.load(Ordering::Acquire),
                };
            }
        };

        let delta: i64 = actual_microcents - reservation.reserved_microcents;
        match delta.cmp(&0) {
            std::cmp::Ordering::Greater => {
                if let Err(remaining) = debit_if_available(&budget, delta) {
                    drop(committed_guard);
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::Overrun {
                        remaining_microcents: remaining,
                    };
                }
            }
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {}
        }

        committed_guard.insert(tenant_key.clone(), new_committed);
        drop(committed_guard);

        if delta < 0 {
            budget.fetch_add(-delta, Ordering::AcqRel);
        }

        {
            let totals = self
                .tenant_reserved_totals
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(total) = totals.get(&tenant_key) {
                total.fetch_sub(reservation.reserved_microcents, Ordering::AcqRel);
            }
        }

        let remaining = budget.load(Ordering::Acquire);
        BudgetSettlement::Committed {
            remaining_microcents: remaining,
            actual_microcents,
        }
    }

    /// Release a reservation, returning the full reserved amount to the tenant's budget.
    pub fn release(&self, reservation_id: u64) -> BudgetSettlement {
        let _mutation = self
            .checkpoint_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut reservations = self.reservations.lock().unwrap_or_else(|e| e.into_inner());
        let Some((_, reservation)) = reservations.remove_entry(&reservation_id) else {
            return BudgetSettlement::MissingReservation;
        };

        let budget = {
            let budgets = self
                .tenant_budgets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match budgets.get(&reservation.tenant_id) {
                Some(b) => Arc::clone(b),
                None => {
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::MissingTenant;
                }
            }
        };
        {
            let totals = self
                .tenant_reserved_totals
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(total) = totals.get(&reservation.tenant_id) {
                total.fetch_sub(reservation.reserved_microcents, Ordering::AcqRel);
            }
        }

        let returned = reservation.reserved_microcents;
        let remaining = budget.fetch_add(returned, Ordering::AcqRel) + returned;

        BudgetSettlement::Released {
            remaining_microcents: remaining,
            returned_microcents: returned,
        }
    }

    /// Number of registered tenants.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.tenant_budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Number of active (uncommitted, unreleased) reservations.
    #[must_use]
    pub fn active_reservations(&self) -> usize {
        self.reservations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl Default for BudgetEngine {
    // skipcq: RS-A1008
    // Delegating to `new()` is the form `clippy::new_without_default` requires.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_and_commit() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id) = engine.try_reserve("t1", 25_000_000);
        let settlement = engine.commit(id.unwrap(), 20_000_000);
        assert!(matches!(settlement, BudgetSettlement::Committed { .. }));
        assert_eq!(engine.remaining_microcents("t1"), Some(80_000_000));
    }

    #[test]
    fn reserve_insufficient() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 10_000_000);
        let (res, id) = engine.try_reserve("t1", 50_000_000);
        assert!(matches!(res, BudgetReservation::Insufficient { .. }));
        assert!(id.is_none());
    }

    #[test]
    fn release_returns_full_amount() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id) = engine.try_reserve("t1", 30_000_000);
        engine.release(id.unwrap());
        assert_eq!(engine.remaining_microcents("t1"), Some(100_000_000));
    }

    #[test]
    fn missing_tenant_rejected() {
        let engine = BudgetEngine::new();
        let (res, _) = engine.try_reserve("nonexistent", 1000);
        assert!(matches!(res, BudgetReservation::MissingTenant));
    }

    #[test]
    fn missing_reservation_rejected() {
        let engine = BudgetEngine::new();
        assert!(matches!(
            engine.commit(999, 1000),
            BudgetSettlement::MissingReservation
        ));
        assert!(matches!(
            engine.release(999),
            BudgetSettlement::MissingReservation
        ));
    }

    #[test]
    fn conservation_invariant() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id1) = engine.try_reserve("t1", 30_000_000);
        let (_, id2) = engine.try_reserve("t1", 20_000_000);
        engine.commit(id1.unwrap(), 25_000_000);
        engine.release(id2.unwrap());
        assert_eq!(engine.remaining_microcents("t1"), Some(75_000_000));
        assert_eq!(engine.committed_microcents("t1"), Some(25_000_000));
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }

    #[test]
    fn top_up_extends_initial_and_remaining() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 100_000_000);
        let result = engine.top_up_tenant("desk", 50_000_000);
        assert!(matches!(result, TopUpResult::ToppedUp { .. }));
        assert_eq!(engine.initial_microcents("desk"), Some(150_000_000));
        assert_eq!(engine.remaining_microcents("desk"), Some(150_000_000));
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }

    #[test]
    fn snapshot_balances() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk-a", 50_000_000);
        engine.ensure_tenant("desk-b", 80_000_000);
        let (_, id) = engine.try_reserve("desk-a", 10_000_000);
        engine.commit(id.unwrap(), 9_000_000);
        let snap = engine.snapshot();
        assert_eq!(snap.tenants.len(), 2);
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri: concurrency stress test")]
    fn snapshots_are_linearizable_with_reservation_mutations() {
        let engine = Arc::new(BudgetEngine::new());
        engine.ensure_tenant("desk", 1_000_000);
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let writer_engine = Arc::clone(&engine);
        let writer_running = Arc::clone(&running);
        let writer = std::thread::spawn(move || {
            for _ in 0..20_000 {
                let (_, id) = writer_engine.try_reserve("desk", 1);
                if let Some(id) = id {
                    let _ = writer_engine.release(id);
                }
            }
            writer_running.store(false, std::sync::atomic::Ordering::Release);
        });

        while running.load(std::sync::atomic::Ordering::Acquire) {
            let snapshot = engine.snapshot();
            assert_eq!(
                conservation_status_for_snapshot(&snapshot),
                ConservationStatus::Balanced
            );
            let reserved: i64 = snapshot
                .tenants
                .iter()
                .map(|tenant| tenant.reserved_microcents)
                .sum();
            assert_eq!(snapshot.active_reservations as i64, reserved);
        }
        writer.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri: use Loom for concurrent interleavings")]
    fn concurrent_reserve_never_overspends() {
        let engine = Arc::new(BudgetEngine::new());
        engine.ensure_tenant("t1", 100_000_000);
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let e = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let (res, _) = e.try_reserve("t1", 1_000_000);
                    matches!(res, BudgetReservation::Reserved { .. })
                })
            })
            .collect();
        let success: usize = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();
        assert_eq!(success, 100);
        assert_eq!(engine.remaining_microcents("t1"), Some(0));
    }

    #[test]
    fn zero_cost_rejected() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (res, _) = engine.try_reserve("t1", 0);
        assert!(matches!(res, BudgetReservation::Insufficient { .. }));
    }

    #[test]
    fn negative_cost_rejected() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (res, _) = engine.try_reserve("t1", -500);
        assert!(matches!(res, BudgetReservation::Insufficient { .. }));
    }

    #[test]
    fn negative_commit_rejected() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id) = engine.try_reserve("t1", 10_000_000);
        let result = engine.commit(id.unwrap(), -5_000_000);
        assert!(matches!(result, BudgetSettlement::InvalidAmount));
    }

    #[test]
    fn failed_overrun_does_not_create_budget() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 10_000_000);

        let (_, id) = engine.try_reserve("t1", 7_000_000);
        let id = id.unwrap();

        // remaining=3, reserved=7. commit with actual=11 → overrun delta=4 > remaining=3
        let result = engine.commit(id, 11_000_000);
        assert!(matches!(result, BudgetSettlement::Overrun { .. }));

        // remaining must still be 3 (not 10 — no refund on failed overrun)
        assert_eq!(engine.remaining_microcents("t1"), Some(3_000_000));

        // release should return the original 7, restoring to 10
        engine.release(id);
        assert_eq!(engine.remaining_microcents("t1"), Some(10_000_000));
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri: use Loom for concurrent interleavings")]
    fn no_deadlock_under_contention() {
        let engine = Arc::new(BudgetEngine::new());
        engine.ensure_tenant("t1", 1_000_000_000);
        let handles: Vec<_> = (0..50)
            .map(|i| {
                let e = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let (_, id) = e.try_reserve("t1", 1_000_000);
                    if let Some(id) = id {
                        if i % 3 == 0 {
                            e.release(id);
                        } else {
                            e.commit(id, 800_000);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(engine.remaining_microcents("t1").unwrap() > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri: use Loom for concurrent interleavings")]
    fn concurrent_overrun_never_goes_negative() {
        let engine = Arc::new(BudgetEngine::new());
        engine.ensure_tenant("t1", 50_000_000);

        // Reserve small amounts, commit with overrun
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let e = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let (_, id) = e.try_reserve("t1", 1_000_000);
                    if let Some(id) = id {
                        // Try to commit 3x the reserved amount (overrun)
                        let _ = e.commit(id, 3_000_000);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let remaining = engine.remaining_microcents("t1").unwrap();
        assert!(
            remaining >= 0,
            "budget must never go negative, got {remaining}"
        );
    }

    #[test]
    fn double_commit_rejected() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id) = engine.try_reserve("t1", 10_000_000);
        let id = id.unwrap();
        assert!(matches!(
            engine.commit(id, 8_000_000),
            BudgetSettlement::Committed { .. }
        ));
        assert!(matches!(
            engine.commit(id, 8_000_000),
            BudgetSettlement::MissingReservation
        ));
    }

    #[test]
    fn double_release_rejected() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 100_000_000);
        let (_, id) = engine.try_reserve("t1", 10_000_000);
        let id = id.unwrap();
        assert!(matches!(
            engine.release(id),
            BudgetSettlement::Released { .. }
        ));
        assert!(matches!(
            engine.release(id),
            BudgetSettlement::MissingReservation
        ));
    }

    #[test]
    fn restore_from_snapshot_roundtrip() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 100_000);
        engine.commit(id.unwrap(), 90_000);
        let snap = engine.snapshot();
        assert!(snap.active_reservations == 0);
        let fresh = BudgetEngine::new();
        fresh.restore_from_snapshot(snap).unwrap();
        assert_eq!(fresh.remaining_microcents("desk"), Some(910_000));
        assert_eq!(fresh.committed_microcents("desk"), Some(90_000));
        assert_eq!(fresh.verify_conservation(), ConservationStatus::Balanced);
    }

    #[test]
    fn restore_preserves_reservation_id_monotonicity() {
        let source = BudgetEngine::new();
        source.ensure_tenant("desk", 1_000_000);
        let (_, stale_id) = source.try_reserve("desk", 100_000);
        let stale_id = stale_id.expect("source reservation");
        assert!(matches!(
            source.release(stale_id),
            BudgetSettlement::Released { .. }
        ));

        let snapshot = source.snapshot();
        let recovered = BudgetEngine::new();
        recovered.restore_from_snapshot(snapshot).unwrap();
        let (_, recovered_id) = recovered.try_reserve("desk", 100_000);
        let recovered_id = recovered_id.expect("recovered reservation");

        assert!(recovered_id > stale_id);
        assert_eq!(
            recovered.release(stale_id),
            BudgetSettlement::MissingReservation
        );
        assert_eq!(recovered.reserved_microcents("desk"), 100_000);
    }

    #[test]
    fn legacy_snapshot_migration_requires_and_binds_a_trusted_allocator_fence() {
        let source = BudgetEngine::new();
        source.ensure_tenant("desk", 1_000_000);
        let mut legacy = source.snapshot();
        legacy.version = 7;

        assert!(migrate_legacy_snapshot(legacy.clone(), 0).is_err());
        let migrated = migrate_legacy_snapshot(legacy, 100).unwrap();
        let recovered = BudgetEngine::new();
        recovered.restore_from_snapshot(migrated).unwrap();
        let (_, reservation_id) = recovered.try_reserve("desk", 100_000);

        assert_eq!(reservation_id, Some(100));
    }

    #[test]
    fn snapshot_fails_closed_when_the_reservation_allocator_is_exhausted() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        // Last usable fence, so the next capture has no distinct position left.
        engine
            .next_id
            .store(RECOVERY_ALLOCATOR_MASK, Ordering::Release);

        assert_eq!(
            engine.try_snapshot(),
            Err(SnapshotAllocatorError::AllocatorExhausted)
        );
    }

    #[test]
    fn recovery_restore_reports_legacy_format_without_ledger_error_aliasing() {
        let legacy = BudgetSnapshot {
            version: 7,
            tenants: vec![],
            active_reservations: 0,
            wal_high_watermark: None,
        };
        let engine = BudgetEngine::new();
        assert_eq!(
            engine.restore_from_recovery_snapshot(legacy),
            Err(RecoverySnapshotError::LegacySnapshotRequiresMigration)
        );
    }

    #[test]
    fn restore_replaces_all_recovery_sensitive_runtime_state() {
        let source = BudgetEngine::new();
        source.ensure_tenant("desk", 1_000_000);
        let (_, id) = source.try_reserve("desk", 100_000);
        source.commit(id.unwrap(), 80_000);
        let snapshot = source.snapshot();

        let recovered = BudgetEngine::new();
        recovered.ensure_tenant("old", 1_000_000);
        recovered.set_max_reserved_microcents("desk", 1);
        assert_eq!(recovered.rotate_certificate_baseline(10), 10);
        recovered.restore_from_snapshot(snapshot).unwrap();

        assert_eq!(recovered.committed_since_last_certificate(), 0);
        let (reservation, id) = recovered.try_reserve("desk", 100_000);
        assert!(matches!(reservation, BudgetReservation::Reserved { .. }));
        recovered.release(id.unwrap());
    }

    #[test]
    fn ensure_tenant_rejects_negative_budget() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", -1);
        assert_eq!(engine.tenant_count(), 0);
        assert!(engine.try_ensure_tenant("desk", -1).is_err());
    }

    #[test]
    fn negative_exposure_cap_does_not_remove_existing_cap() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000);
        engine.set_max_reserved_microcents("desk", 100);
        assert!(engine.try_set_max_reserved_microcents("desk", -1).is_err());
        engine.set_max_reserved_microcents("desk", -1);
        let (result, id) = engine.try_reserve("desk", 101);
        assert!(matches!(
            result,
            BudgetReservation::ExposureLimitExceeded {
                max_reserved_microcents: 100,
                ..
            }
        ));
        assert!(id.is_none());

        engine.set_max_reserved_microcents("desk", 0);
        let (result, id) = engine.try_reserve("desk", 101);
        assert!(matches!(result, BudgetReservation::Reserved { .. }));
        engine.release(id.unwrap());
    }

    #[test]
    fn certificate_baseline_is_monotonic() {
        let engine = BudgetEngine::new();
        assert_eq!(engine.rotate_certificate_baseline(150), 150);
        assert_eq!(engine.rotate_certificate_baseline(100), 0);
        assert_eq!(engine.rotate_certificate_baseline(200), 50);
    }

    #[test]
    fn total_committed_microcents_reports_aggregate_overflow() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk-a", 1);
        engine.ensure_tenant("desk-b", 1);
        {
            let mut committed = engine
                .committed_microcents
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            committed.insert(Arc::from("desk-a"), i64::MAX);
            committed.insert(Arc::from("desk-b"), 1);
        }
        assert_eq!(
            engine.try_total_committed_microcents(),
            Err(ConservationStatus::AggregateOverflow)
        );
        assert_eq!(engine.total_committed_microcents(), i64::MAX);
    }

    #[test]
    fn adversarial_snapshot_per_tenant_sum_overflow() {
        let snap = BudgetSnapshot {
            version: 1,
            tenants: vec![TenantLedger {
                tenant_id: "evil".into(),
                initial_microcents: 0,
                remaining_microcents: i64::MAX,
                reserved_microcents: 1,
                committed_microcents: 0,
            }],
            active_reservations: 0,
            wal_high_watermark: None,
        };
        assert_eq!(
            conservation_status_for_snapshot(&snap),
            ConservationStatus::AggregateOverflow
        );
    }

    #[test]
    fn restore_rejects_duplicate_tenant() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let mut snap = engine.snapshot();
        snap.tenants.push(snap.tenants[0].clone());
        assert!(matches!(
            BudgetEngine::new().restore_from_snapshot(snap),
            Err(RestoreError::DuplicateTenant { .. })
        ));
    }

    #[test]
    fn top_up_rejects_overflow() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", i64::MAX - 10);
        assert!(matches!(
            engine.top_up_tenant("desk", 20),
            TopUpResult::Overflow
        ));
    }

    #[test]
    fn reserve_rejects_reserved_total_overflow() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", i64::MAX);
        engine.set_max_reserved_microcents("desk", 0);
        let (res, _) = engine.try_reserve("desk", i64::MAX);
        assert!(matches!(res, BudgetReservation::Reserved { .. }));
        let (res2, _) = engine.try_reserve("desk", 1);
        assert!(matches!(res2, BudgetReservation::Overflow { .. }));
    }

    #[test]
    fn commit_rejects_lifetime_overflow() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", i64::MAX);
        let (_, id) = engine.try_reserve("desk", 1);
        assert!(matches!(
            engine.commit(id.unwrap(), i64::MAX - 1),
            BudgetSettlement::Committed { .. }
        ));
        let (_, id2) = engine.try_reserve("desk", 1);
        assert!(matches!(
            engine.commit(id2.unwrap(), 2),
            BudgetSettlement::Overflow { .. }
        ));
    }

    #[test]
    fn restore_rejects_ghost_reserved() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let mut snap = engine.snapshot();
        snap.tenants[0].reserved_microcents = 100_000;
        assert!(matches!(
            BudgetEngine::new().restore_from_snapshot(snap),
            Err(RestoreError::GhostReservation { .. })
        ));
    }

    #[test]
    fn restore_rejects_unbalanced_snapshot() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let mut snap = engine.snapshot();
        snap.tenants[0].remaining_microcents = 0;
        assert!(matches!(
            BudgetEngine::new().restore_from_snapshot(snap),
            Err(RestoreError::ConservationViolation { .. })
        ));
    }

    #[test]
    fn restore_rejects_active_reservations() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 50_000);
        id.unwrap();
        let mut snap = engine.snapshot();
        snap.active_reservations = 1;
        let fresh = BudgetEngine::new();
        assert!(matches!(
            fresh.restore_from_snapshot(snap),
            Err(RestoreError::ActiveReservations { count: 1 })
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri: use Loom for concurrent interleavings")]
    fn exposure_limit_holds_under_concurrent_reserve() {
        let engine = Arc::new(BudgetEngine::new());
        engine.ensure_tenant("desk", 10_000_000);
        engine.set_max_reserved_microcents("desk", 100_000);
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let e = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let (res, _) = e.try_reserve("desk", 80_000);
                    matches!(res, BudgetReservation::Reserved { .. })
                })
            })
            .collect();
        let successes: usize = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();
        assert_eq!(successes, 1);
        assert!(engine.reserved_microcents("desk") <= 100_000);
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }

    #[test]
    fn exposure_limit_blocks_reserve() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        engine.set_max_reserved_microcents("desk", 100_000);
        let (_, id1) = engine.try_reserve("desk", 60_000);
        assert!(id1.is_some());
        let (res, id2) = engine.try_reserve("desk", 50_000);
        assert!(matches!(
            res,
            BudgetReservation::ExposureLimitExceeded { .. }
        ));
        assert!(id2.is_none());
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }

    use proptest::prelude::*;

    fn edge_amounts() -> impl Strategy<Value = i64> {
        prop_oneof![
            Just(1_i64),
            Just(-1),
            Just(0),
            Just(1_000_000_i64),
            1i64..1_000_000,
        ]
    }

    proptest! {
        #[test]
        fn aggressive_mixed_ops_maintain_conservation(
            tenant_count in 1_usize..8,
            seed_ops in prop::collection::vec((0u8..6, any::<u8>(), edge_amounts()), 5..80),
        ) {
            let engine = BudgetEngine::new();
            for t in 0..tenant_count {
                engine.ensure_tenant(&format!("tenant-{t}"), 2_000_000);
                if t % 2 == 0 {
                    engine.set_max_reserved_microcents(&format!("tenant-{t}"), 500_000);
                }
            }
            let mut open_ids = Vec::new();

            for (op, sel, amount) in seed_ops {
                let tenant = format!("tenant-{}", sel as usize % tenant_count);
                let snap_before = engine.snapshot();
                let digest_before = crate::finance::ledger_digest(&snap_before);

                match op % 6 {
                    0 => {
                        let (_, id) = engine.try_reserve(&tenant, amount);
                        if let Some(id) = id {
                            open_ids.push(id);
                        }
                    }
                    1 if !open_ids.is_empty() => {
                        let idx = sel as usize % open_ids.len();
                        let id = open_ids[idx];
                        let commit_amount = if amount <= 0 {
                            1
                        } else {
                            amount.saturating_mul(2)
                        };
                        match engine.commit(id, commit_amount) {
                            BudgetSettlement::Committed { .. } => {
                                open_ids.remove(idx);
                            }
                            BudgetSettlement::Overrun { .. } => {}
                            _ => {}
                        }
                    }
                    2 if !open_ids.is_empty() => {
                        let idx = sel as usize % open_ids.len();
                        let id = open_ids.remove(idx);
                        let _ = engine.release(id);
                    }
                    3 => {
                        if amount > 0 {
                            let _ = engine.top_up_tenant(&tenant, amount);
                        }
                    }
                    4 => {
                        let extra = format!("extra-{}", sel % 4);
                        if amount > 0 {
                            engine.ensure_tenant(&extra, amount);
                        }
                    }
                    _ => {
                        let _ = engine.snapshot();
                    }
                }

                prop_assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
                let snap_after = engine.snapshot();
                if open_ids.is_empty() && snap_after.active_reservations == 0 {
                    let digest_after = crate::finance::ledger_digest(&snap_after);
                    if snap_after.tenants == snap_before.tenants
                        && snap_after.version == snap_before.version
                    {
                        prop_assert_eq!(digest_before, digest_after);
                    }
                }
            }
        }

        #[test]
        fn random_ops_maintain_conservation(
            seed_ops in prop::collection::vec((0u8..4, any::<u8>(), 1i64..50_000), 1..40),
        ) {
            let engine = BudgetEngine::new();
            engine.ensure_tenant("t0", 5_000_000);
            engine.ensure_tenant("t1", 5_000_000);
            let mut open_ids = Vec::new();

            for (op, tenant_sel, amount) in seed_ops {
                let tenant = if tenant_sel % 2 == 0 { "t0" } else { "t1" };
                match op % 4 {
                    0 => {
                        let (_, id) = engine.try_reserve(tenant, amount);
                        if let Some(id) = id {
                            open_ids.push(id);
                        }
                    }
                    1 if !open_ids.is_empty() => {
                        let idx = (tenant_sel as usize) % open_ids.len();
                        let id = open_ids[idx];
                        match engine.commit(id, amount) {
                            BudgetSettlement::Committed { .. } => {
                                open_ids.remove(idx);
                            }
                            BudgetSettlement::Overrun { .. } => {}
                            _ => {}
                        }
                    }
                    2 if !open_ids.is_empty() => {
                        let idx = (tenant_sel as usize) % open_ids.len();
                        let id = open_ids.remove(idx);
                        let _ = engine.release(id);
                    }
                    3 => {
                        let _ = engine.top_up_tenant(tenant, amount);
                    }
                    _ => {}
                }
                prop_assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
            }
        }
    }
}
