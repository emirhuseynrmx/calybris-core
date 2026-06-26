//! Fixed-point financial proofs for pre-trade budget and exposure guards.
//!
//! Domain-neutral: no exchange adapter, no alpha, no order book. Provides
//! ledger digest, conservation proof, and [`FinancialCertificate`] binding.
//!
//! All amounts are `i64` microcents (1 USD cent = 1_000_000 microcents). No `f64`.
//!
//! Typical pre-trade path: [`BudgetEngine::try_reserve`] → fill → [`BudgetEngine::commit`].
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

fn snapshot_totals(snapshot: &BudgetSnapshot) -> (i64, i64) {
    let mut initial = 0_i64;
    let mut committed = 0_i64;
    for ledger in &snapshot.tenants {
        initial = initial.saturating_add(ledger.initial_microcents);
        committed = committed.saturating_add(ledger.committed_microcents);
    }
    (initial, committed)
}

/// Conservation proof binding a frozen ledger snapshot to its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConservationProof {
    pub ledger_digest_hex: String,
    pub snapshot_version: u64,
    pub tenant_count: usize,
    pub active_reservations: usize,
    pub total_initial_microcents: i64,
    pub total_committed_microcents: i64,
}

/// Financial proof certificate binding a frozen snapshot to a ledger digest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FinancialCertificate {
    /// Monotonic snapshot epoch from [`BudgetEngine::snapshot_version`].
    pub snapshot_version: u64,
    pub ledger_digest_hex: String,
    pub tenant_count: usize,
    pub active_reservations: usize,
    pub conservation_balanced: bool,
    pub total_initial_microcents: i64,
    pub total_committed_microcents: i64,
    /// Lifetime committed spend since the previous certificate on this engine.
    pub committed_since_last_certificate: i64,
}

/// Issue a certificate from a frozen snapshot (no additional engine reads).
#[must_use]
pub fn certify_snapshot(
    snapshot: &BudgetSnapshot,
    snapshot_version: u64,
    conservation_balanced: bool,
    committed_since_last_certificate: i64,
) -> FinancialCertificate {
    let digest = ledger_digest(snapshot);
    let (total_initial, total_committed) = snapshot_totals(snapshot);
    FinancialCertificate {
        snapshot_version,
        ledger_digest_hex: digest_to_hex(&digest),
        tenant_count: snapshot.tenants.len(),
        active_reservations: snapshot.active_reservations,
        conservation_balanced,
        total_initial_microcents: total_initial,
        total_committed_microcents: total_committed,
        committed_since_last_certificate,
    }
}

/// Issue a financial certificate from the current engine state (single snapshot pass).
pub fn certify_ledger(engine: &BudgetEngine) -> FinancialCertificate {
    let snapshot = engine.snapshot();
    let balanced = engine.verify_conservation() == ConservationStatus::Balanced;
    let committed_since = engine.committed_since_last_certificate();
    let cert = certify_snapshot(
        &snapshot,
        engine.snapshot_version(),
        balanced,
        committed_since,
    );
    engine.mark_certificate_issued();
    cert
}

/// Prove conservation and return a structured proof binding the ledger digest.
///
/// Returns `Err` with the violating tenant if the invariant is broken.
pub fn prove_conservation(engine: &BudgetEngine) -> Result<ConservationProof, ConservationStatus> {
    let status = engine.verify_conservation();
    let snapshot = engine.snapshot();
    let digest = ledger_digest(&snapshot);
    let (total_initial, total_committed) = snapshot_totals(&snapshot);
    match status {
        ConservationStatus::Balanced => Ok(ConservationProof {
            ledger_digest_hex: digest_to_hex(&digest),
            snapshot_version: engine.snapshot_version(),
            tenant_count: snapshot.tenants.len(),
            active_reservations: snapshot.active_reservations,
            total_initial_microcents: total_initial,
            total_committed_microcents: total_committed,
        }),
        violation => Err(violation),
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
        assert!(cert.snapshot_version > 0);
        assert_eq!(cert.total_committed_microcents, 95_000);
        let proof = prove_conservation(&engine).unwrap();
        assert_eq!(proof.ledger_digest_hex, cert.ledger_digest_hex);
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

    #[test]
    fn ledger_digest_tenant_order_independent() {
        let engine_a = BudgetEngine::new();
        engine_a.ensure_tenant("alpha", 100_000);
        engine_a.ensure_tenant("zulu", 200_000);

        let engine_b = BudgetEngine::new();
        engine_b.ensure_tenant("zulu", 200_000);
        engine_b.ensure_tenant("alpha", 100_000);

        assert_eq!(
            ledger_digest(&engine_a.snapshot()),
            ledger_digest(&engine_b.snapshot())
        );
    }

    #[test]
    fn prove_conservation_ok_after_mixed_ops() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 100_000);
        engine.commit(id.unwrap(), 90_000);
        engine.top_up_tenant("desk", 50_000);
        let proof = prove_conservation(&engine).expect("balanced ledger");
        assert_eq!(proof.ledger_digest_hex.len(), 64);
        let cert = certify_ledger(&engine);
        assert!(cert.conservation_balanced);
        assert_eq!(cert.committed_since_last_certificate, 90_000);
    }

    #[test]
    fn certify_snapshot_is_immutable_binding() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let snap = engine.snapshot();
        let cert = certify_snapshot(&snap, 1, true, 0);
        engine.top_up_tenant("desk", 999_999);
        assert_ne!(ledger_digest(&engine.snapshot()), ledger_digest(&snap));
        assert_eq!(cert.ledger_digest_hex, digest_to_hex(&ledger_digest(&snap)));
    }
}
