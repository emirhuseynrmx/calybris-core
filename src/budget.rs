//! Atomic budget engine with CAS (compare-and-swap) reservation management.
//!
//! All values are i64 microcents (1 cent = 1,000,000 microcents).
//! No floating-point in the core API.
//!
//! CAS-based balance updates; metadata maps are mutex-protected.
//! Lock ordering is always: reservations first, then tenant_budgets — no deadlock.
//!
//! Conservation invariant (per tenant, at any instant):
//!
//! ```text
//! remaining + reserved + committed_lifetime == initial
//! ```
//!
//! - `remaining` — spendable balance right now
//! - `reserved` — sum of active (uncommitted) holds
//! - `committed_lifetime` — cumulative spend since tenant creation (monotonic, never decreases)
//! - `initial` — total budget ever granted (`ensure_tenant` + [`top_up_tenant`](BudgetEngine::top_up_tenant))

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/// Atomic budget engine.
///
/// CAS-based balance updates on `Arc<AtomicI64>` — the atomic is cloned out of
/// the map before the CAS loop, so no lock is held during the contended operation.
/// Metadata maps are mutex-protected with consistent lock ordering
/// (reservations → budgets) to prevent deadlock.
pub struct BudgetEngine {
    tenant_budgets: Mutex<HashMap<Arc<str>, Arc<AtomicI64>>>,
    initial_microcents: Mutex<HashMap<Arc<str>, i64>>,
    committed_microcents: Mutex<HashMap<Arc<str>, i64>>,
    reservations: Mutex<HashMap<u64, ReservationRecord>>,
    /// Per-tenant cap on sum of open reservation holds (`0` = unlimited).
    max_reserved_microcents: Mutex<HashMap<Arc<str>, i64>>,
    // u64::MAX is ~18 quintillion reservations — practically unreachable.
    next_id: AtomicU64,
    /// Monotonic epoch incremented on each [`snapshot`](BudgetEngine::snapshot) call.
    snapshot_version: AtomicU64,
    /// Cumulative committed total at last [`crate::finance::certify_ledger`] call.
    last_certified_committed_total: Mutex<i64>,
}

/// Point-in-time ledger row for one tenant (integer microcents only).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
pub struct BudgetSnapshot {
    pub tenants: Vec<TenantLedger>,
    pub active_reservations: usize,
}

/// Result of the conservation invariant check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConservationStatus {
    /// `remaining + reserved + committed == initial` for every tenant.
    Balanced,
    /// Invariant violated — includes per-tenant deltas in microcents.
    Violation {
        tenant_id: String,
        delta_microcents: i64,
    },
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
        }
    }
}

impl std::error::Error for ConservationStatus {}

/// Error restoring engine state from a [`BudgetSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    #[error("cannot restore snapshot with {count} active reservations")]
    ActiveReservations { count: usize },
}

impl BudgetEngine {
    pub fn new() -> Self {
        Self {
            tenant_budgets: Mutex::new(HashMap::new()),
            initial_microcents: Mutex::new(HashMap::new()),
            committed_microcents: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
            max_reserved_microcents: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            snapshot_version: AtomicU64::new(0),
            last_certified_committed_total: Mutex::new(0),
        }
    }

    /// Set a per-tenant exposure cap on open reservation holds (`0` removes the cap).
    pub fn set_max_reserved_microcents(&self, tenant_id: &str, max_microcents: i64) {
        let key: Arc<str> = Arc::from(tenant_id);
        let mut limits = self.max_reserved_microcents.lock().unwrap();
        if max_microcents <= 0 {
            limits.remove(&key);
        } else {
            limits.insert(key, max_microcents);
        }
    }

    /// Current snapshot epoch (incremented on each [`snapshot`](Self::snapshot)).
    #[must_use]
    pub fn snapshot_version(&self) -> u64 {
        self.snapshot_version.load(Ordering::Acquire)
    }

    /// Sum of lifetime `committed_microcents` across all tenants.
    #[must_use]
    pub fn total_committed_microcents(&self) -> i64 {
        self.committed_microcents.lock().unwrap().values().sum()
    }

    /// Committed total since the last financial certificate was issued.
    #[must_use]
    pub fn committed_since_last_certificate(&self) -> i64 {
        let current = self.total_committed_microcents();
        let baseline = *self.last_certified_committed_total.lock().unwrap();
        current.saturating_sub(baseline)
    }

    pub(crate) fn mark_certificate_issued(&self) {
        *self.last_certified_committed_total.lock().unwrap() = self.total_committed_microcents();
    }

    /// Rebuild tenant balances from a snapshot. Active reservations must be zero.
    pub fn restore_from_snapshot(&self, snap: BudgetSnapshot) -> Result<(), RestoreError> {
        if snap.active_reservations > 0 {
            return Err(RestoreError::ActiveReservations {
                count: snap.active_reservations,
            });
        }
        {
            let mut reservations = self.reservations.lock().unwrap();
            reservations.clear();
        }
        let mut budgets = self.tenant_budgets.lock().unwrap();
        let mut initials = self.initial_microcents.lock().unwrap();
        let mut committed = self.committed_microcents.lock().unwrap();
        budgets.clear();
        initials.clear();
        committed.clear();
        for ledger in snap.tenants {
            let key: Arc<str> = Arc::from(ledger.tenant_id.as_str());
            budgets.insert(
                Arc::clone(&key),
                Arc::new(AtomicI64::new(ledger.remaining_microcents)),
            );
            initials.insert(Arc::clone(&key), ledger.initial_microcents);
            committed.insert(key, ledger.committed_microcents);
        }
        Ok(())
    }

    /// Initialize a tenant with a budget in microcents.
    ///
    /// Idempotent — calling with an existing tenant does nothing (no top-up).
    /// Use [`top_up_tenant`](Self::top_up_tenant) to add funds later.
    /// `initial_microcents` is fixed at creation for audit binding; top-ups extend it.
    ///
    /// Panics in debug mode if `budget_microcents` is negative.
    pub fn ensure_tenant(&self, tenant_id: &str, budget_microcents: i64) {
        debug_assert!(
            budget_microcents >= 0,
            "initial budget must be non-negative"
        );
        let mut budgets = self.tenant_budgets.lock().unwrap();
        let mut initials = self.initial_microcents.lock().unwrap();
        let mut committed = self.committed_microcents.lock().unwrap();
        let key: Arc<str> = Arc::from(tenant_id);
        if !budgets.contains_key(&key) {
            budgets.insert(
                Arc::clone(&key),
                Arc::new(AtomicI64::new(budget_microcents)),
            );
            initials.insert(Arc::clone(&key), budget_microcents);
            committed.insert(key, 0);
        }
    }

    /// Add funds to an existing tenant (extends `initial` and `remaining` equally).
    ///
    /// Does not reset `committed_microcents` (lifetime spend is preserved).
    /// Returns [`TopUpResult::MissingTenant`] if the tenant was never created.
    pub fn top_up_tenant(&self, tenant_id: &str, amount_microcents: i64) -> TopUpResult {
        if amount_microcents <= 0 {
            return TopUpResult::InvalidAmount;
        }
        let key: Arc<str> = Arc::from(tenant_id);
        let budget = {
            let budgets = self.tenant_budgets.lock().unwrap();
            match budgets.get(&key) {
                Some(b) => Arc::clone(b),
                None => return TopUpResult::MissingTenant,
            }
        };
        let remaining = budget.fetch_add(amount_microcents, Ordering::AcqRel) + amount_microcents;
        let new_initial = {
            let mut initials = self.initial_microcents.lock().unwrap();
            match initials.get_mut(&key) {
                Some(entry) => {
                    *entry += amount_microcents;
                    *entry
                }
                None => return TopUpResult::MissingTenant,
            }
        };
        TopUpResult::ToppedUp {
            added_microcents: amount_microcents,
            new_initial_microcents: new_initial,
            remaining_microcents: remaining,
        }
    }

    /// Total budget ever granted to a tenant (`ensure_tenant` + top-ups).
    #[must_use]
    pub fn initial_microcents(&self, tenant_id: &str) -> Option<i64> {
        let initials = self.initial_microcents.lock().unwrap();
        let key: Arc<str> = Arc::from(tenant_id);
        initials.get(&key).copied()
    }

    /// Cumulative lifetime spend for a tenant (monotonic; increases on each successful [`commit`](Self::commit)).
    ///
    /// This is **not** "currently in-flight committed amount" — active holds live in [`reserved_microcents`](Self::reserved_microcents).
    #[must_use]
    pub fn committed_microcents(&self, tenant_id: &str) -> Option<i64> {
        let committed = self.committed_microcents.lock().unwrap();
        let key: Arc<str> = Arc::from(tenant_id);
        committed.get(&key).copied()
    }

    /// Sum of active reservation holds for a tenant.
    #[must_use]
    pub fn reserved_microcents(&self, tenant_id: &str) -> i64 {
        let reservations = self.reservations.lock().unwrap();
        let key: Arc<str> = Arc::from(tenant_id);
        reservations
            .values()
            .filter(|r| r.tenant_id == key)
            .map(|r| r.reserved_microcents)
            .sum()
    }

    /// Capture a point-in-time ledger snapshot (mutex read — not on hot path).
    ///
    /// Lock order: reservations → budgets → initials → committed (matches hot path).
    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        let reservations = self.reservations.lock().unwrap();
        let budgets = self.tenant_budgets.lock().unwrap();
        let initials = self.initial_microcents.lock().unwrap();
        let committed = self.committed_microcents.lock().unwrap();

        let mut reserved_by_tenant: HashMap<Arc<str>, i64> = HashMap::new();
        for record in reservations.values() {
            *reserved_by_tenant
                .entry(Arc::clone(&record.tenant_id))
                .or_insert(0) += record.reserved_microcents;
        }

        let mut tenants = Vec::with_capacity(budgets.len());
        for (tenant_id, balance) in budgets.iter() {
            tenants.push(TenantLedger {
                tenant_id: tenant_id.to_string(),
                initial_microcents: initials.get(tenant_id).copied().unwrap_or(0),
                remaining_microcents: balance.load(Ordering::Acquire),
                reserved_microcents: reserved_by_tenant.get(tenant_id).copied().unwrap_or(0),
                committed_microcents: committed.get(tenant_id).copied().unwrap_or(0),
            });
        }
        tenants.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        self.snapshot_version.fetch_add(1, Ordering::AcqRel);
        BudgetSnapshot {
            tenants,
            active_reservations: reservations.len(),
        }
    }

    /// Verify `remaining + reserved + committed_lifetime == initial` for every tenant.
    ///
    /// Takes a full ledger snapshot — intended for audit/reconciliation, not per-tick hot paths.
    #[must_use]
    pub fn verify_conservation(&self) -> ConservationStatus {
        for ledger in &self.snapshot().tenants {
            let sum = ledger.remaining_microcents
                + ledger.reserved_microcents
                + ledger.committed_microcents;
            if sum != ledger.initial_microcents {
                return ConservationStatus::Violation {
                    tenant_id: ledger.tenant_id.clone(),
                    delta_microcents: sum - ledger.initial_microcents,
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

    /// Remaining budget for a tenant in microcents.
    #[must_use]
    pub fn remaining_microcents(&self, tenant_id: &str) -> Option<i64> {
        let budgets = self.tenant_budgets.lock().unwrap();
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

        let key: Arc<str> = Arc::from(tenant_id);
        let budget = {
            let budgets = self.tenant_budgets.lock().unwrap();
            match budgets.get(&key) {
                Some(b) => Arc::clone(b),
                None => return (BudgetReservation::MissingTenant, None),
            }
        };

        let max_reserved = {
            let limits = self.max_reserved_microcents.lock().unwrap();
            limits.get(&key).copied().unwrap_or(0)
        };
        if max_reserved > 0 {
            let reservations = self.reservations.lock().unwrap();
            let current_reserved: i64 = reservations
                .values()
                .filter(|r| r.tenant_id == key)
                .map(|r| r.reserved_microcents)
                .sum();
            if current_reserved.saturating_add(cost_microcents) > max_reserved {
                return (
                    BudgetReservation::ExposureLimitExceeded {
                        current_reserved_microcents: current_reserved,
                        max_reserved_microcents: max_reserved,
                    },
                    None,
                );
            }
        }

        match debit_if_available(&budget, cost_microcents) {
            Err(current) => (
                BudgetReservation::Insufficient {
                    remaining_microcents: current,
                    required_microcents: cost_microcents,
                },
                None,
            ),
            Ok(remaining) => {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                let mut reservations = self.reservations.lock().unwrap();
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

        let mut reservations = self.reservations.lock().unwrap();
        let Some(reservation) = reservations.remove(&reservation_id) else {
            return BudgetSettlement::MissingReservation;
        };

        let budget = {
            let budgets = self.tenant_budgets.lock().unwrap();
            match budgets.get(&reservation.tenant_id) {
                Some(b) => Arc::clone(b),
                None => {
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::MissingTenant;
                }
            }
        };
        drop(reservations);

        let delta: i64 = actual_microcents - reservation.reserved_microcents;
        match delta.cmp(&0) {
            std::cmp::Ordering::Greater => {
                // Overrun: atomically debit additional amount via CAS
                if let Err(remaining) = debit_if_available(&budget, delta) {
                    // Can't afford overrun — re-insert reservation but do NOT refund.
                    // The original reserved amount is still deducted from the budget;
                    // refunding it here would violate conservation (create money).
                    let mut reservations = self.reservations.lock().unwrap();
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::Overrun {
                        remaining_microcents: remaining,
                    };
                }
            }
            std::cmp::Ordering::Less => {
                budget.fetch_add(-delta, Ordering::AcqRel);
            }
            std::cmp::Ordering::Equal => {}
        }

        {
            let mut committed = self.committed_microcents.lock().unwrap();
            *committed
                .entry(Arc::clone(&reservation.tenant_id))
                .or_insert(0) += actual_microcents;
        }

        let remaining = budget.load(Ordering::Acquire);
        BudgetSettlement::Committed {
            remaining_microcents: remaining,
            actual_microcents,
        }
    }

    /// Release a reservation, returning the full reserved amount to the tenant's budget.
    pub fn release(&self, reservation_id: u64) -> BudgetSettlement {
        let mut reservations = self.reservations.lock().unwrap();
        let Some((_, reservation)) = reservations.remove_entry(&reservation_id) else {
            return BudgetSettlement::MissingReservation;
        };

        let budget = {
            let budgets = self.tenant_budgets.lock().unwrap();
            match budgets.get(&reservation.tenant_id) {
                Some(b) => Arc::clone(b),
                None => {
                    reservations.insert(reservation_id, reservation);
                    return BudgetSettlement::MissingTenant;
                }
            }
        };
        drop(reservations);

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
        self.tenant_budgets.lock().unwrap().len()
    }

    /// Number of active (uncommitted, unreleased) reservations.
    #[must_use]
    pub fn active_reservations(&self) -> usize {
        self.reservations.lock().unwrap().len()
    }
}

impl Default for BudgetEngine {
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
                    if snap_after.tenants == snap_before.tenants {
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
