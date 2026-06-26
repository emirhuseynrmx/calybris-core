//! Atomic budget engine with CAS (compare-and-swap) reservation management.
//!
//! All values are i64 microcents (1 cent = 1,000,000 microcents).
//! No floating-point in the core API.
//!
//! CAS-based balance updates; metadata maps are mutex-protected.
//! Lock ordering is always: reservations first, then tenant_budgets — no deadlock.
//!
//! Conservation invariant: `remaining + reserved + committed = initial`

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
    reservations: Mutex<HashMap<u64, ReservationRecord>>,
    // u64::MAX is ~18 quintillion reservations — practically unreachable.
    next_id: AtomicU64,
}

impl BudgetEngine {
    pub fn new() -> Self {
        Self {
            tenant_budgets: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Initialize a tenant with a budget in microcents.
    ///
    /// Idempotent — calling with a tenant that already exists does nothing.
    /// Panics in debug mode if `budget_microcents` is negative.
    pub fn ensure_tenant(&self, tenant_id: &str, budget_microcents: i64) {
        debug_assert!(
            budget_microcents >= 0,
            "initial budget must be non-negative"
        );
        let mut budgets = self.tenant_budgets.lock().unwrap();
        let key: Arc<str> = Arc::from(tenant_id);
        budgets
            .entry(key)
            .or_insert_with(|| Arc::new(AtomicI64::new(budget_microcents)));
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
    /// If `actual_microcents > reserved`, the engine attempts to debit the
    /// difference (overrun). If the tenant can't afford the overrun, the
    /// reservation is re-inserted and `Overrun` is returned — the original
    /// reserved amount stays deducted (no refund on failed overrun).
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
        if delta > 0 {
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
        } else if delta < 0 {
            budget.fetch_add(-delta, Ordering::AcqRel);
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
}
