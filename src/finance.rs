//! Fixed-point financial layer for HFT-grade budget accounting.
//!
//! All amounts are `i64` microcents (1 USD cent = 1_000_000 microcents).
//! No `f64`. Conservation is provable via [`BudgetEngine::verify_conservation`].
//!
//! Typical HFT path: [`BudgetEngine::try_reserve`] → execute → [`BudgetEngine::commit`].
//! Hot-path reserve/commit uses CAS on `AtomicI64` — no mutex during debit.

use crate::budget::{BudgetEngine, BudgetSnapshot, ConservationStatus, TenantLedger};
use crate::digest::{digest_to_hex, LEDGER_DIGEST_TAG};
use sha2::{Digest, Sha256};

/// One microcent = 10⁻⁶ of a cent. 1 cent = 1_000_000 microcents.
pub const MICROCENTS_PER_CENT: i64 = 1_000_000;

/// Tamper-evident digest of a budget snapshot (tenants sorted by id).
pub fn ledger_digest(snapshot: &BudgetSnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEDGER_DIGEST_TAG);
    hasher.update((snapshot.tenants.len() as u64).to_le_bytes());
    hasher.update((snapshot.active_reservations as u64).to_le_bytes());
    for ledger in &snapshot.tenants {
        update_ledger(&mut hasher, ledger);
    }
    hasher.finalize().into()
}

#[inline]
fn update_ledger(hasher: &mut Sha256, ledger: &TenantLedger) {
    let id = ledger.tenant_id.as_bytes();
    hasher.update((id.len() as u32).to_le_bytes());
    hasher.update(id);
    hasher.update(ledger.initial_microcents.to_le_bytes());
    hasher.update(ledger.remaining_microcents.to_le_bytes());
    hasher.update(ledger.reserved_microcents.to_le_bytes());
    hasher.update(ledger.committed_microcents.to_le_bytes());
}

/// Financial proof certificate binding engine state to a ledger digest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FinancialCertificate {
    pub ledger_digest_hex: String,
    pub tenant_count: usize,
    pub active_reservations: usize,
    pub conservation_balanced: bool,
}

/// Issue a financial certificate from the current engine state.
pub fn certify_ledger(engine: &BudgetEngine) -> FinancialCertificate {
    let snapshot = engine.snapshot();
    let digest = ledger_digest(&snapshot);
    FinancialCertificate {
        ledger_digest_hex: digest_to_hex(&digest),
        tenant_count: snapshot.tenants.len(),
        active_reservations: snapshot.active_reservations,
        conservation_balanced: engine.verify_conservation() == ConservationStatus::Balanced,
    }
}

/// Prove conservation and return the ledger digest hex.
///
/// Returns `Err` with the violating tenant if the invariant is broken.
pub fn prove_conservation(engine: &BudgetEngine) -> Result<String, ConservationStatus> {
    match engine.verify_conservation() {
        ConservationStatus::Balanced => Ok(digest_to_hex(&ledger_digest(&engine.snapshot()))),
        violation @ ConservationStatus::Violation { .. } => Err(violation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetEngine;

    #[test]
    fn ledger_digest_stable() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("hft-desk", 1_000_000_000);
        let snap = engine.snapshot();
        assert_eq!(ledger_digest(&snap), ledger_digest(&snap));
        assert_eq!(ledger_digest(&snap).len(), 32);
    }

    #[test]
    fn financial_certificate_proves_conservation() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("hft-desk", 500_000_000);
        let (_, id) = engine.try_reserve("hft-desk", 100_000);
        engine.commit(id.unwrap(), 95_000);
        let cert = certify_ledger(&engine);
        assert!(cert.conservation_balanced);
        assert_eq!(cert.ledger_digest_hex.len(), 64);
        assert_eq!(prove_conservation(&engine).unwrap().len(), 64);
    }

    #[test]
    fn hft_reserve_commit_conserves() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("t1", 10_000_000_000);
        for _ in 0..1000 {
            let (_, id) = engine.try_reserve("t1", 10_000);
            if let Some(id) = id {
                engine.commit(id, 9_500);
            }
        }
        assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    }
}
