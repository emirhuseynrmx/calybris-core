//! Fixed-point financial proofs for pre-trade budget and exposure guards.
//!
//! Domain-neutral: no exchange adapter, no alpha, no order book. Provides
//! ledger digest, conservation proof, and [`FinancialCertificate`] binding.
//!
//! All amounts are `i64` microcents (1 USD cent = 1_000_000 microcents). No `f64`.
//!
//! Typical pre-trade path: [`BudgetEngine::try_reserve`] → fill → [`BudgetEngine::commit`].
//! Hot-path reserve/commit uses CAS on `AtomicI64` — no mutex during debit.

use crate::budget::{
    conservation_status_for_snapshot, BudgetEngine, BudgetSnapshot, ConservationStatus,
    TenantLedger,
};
use crate::digest::{digest_to_hex, LEDGER_DIGEST_TAG};
use sha2::{Digest, Sha256};

/// One microcent = 10⁻⁶ of a cent. 1 cent = 1_000_000 microcents.
pub const MICROCENTS_PER_CENT: i64 = 1_000_000;

/// Tamper-evident digest of a budget snapshot (tenants sorted by id).
pub fn ledger_digest(snapshot: &BudgetSnapshot) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEDGER_DIGEST_TAG);
    hasher.update(snapshot.version.to_le_bytes());
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

fn snapshot_totals(snapshot: &BudgetSnapshot) -> Result<(i64, i64), ConservationStatus> {
    let mut initial: i128 = 0;
    let mut committed: i128 = 0;
    for ledger in &snapshot.tenants {
        initial = initial
            .checked_add(i128::from(ledger.initial_microcents))
            .ok_or(ConservationStatus::AggregateOverflow)?;
        committed = committed
            .checked_add(i128::from(ledger.committed_microcents))
            .ok_or(ConservationStatus::AggregateOverflow)?;
    }
    Ok((
        i64::try_from(initial).map_err(|_| ConservationStatus::AggregateOverflow)?,
        i64::try_from(committed).map_err(|_| ConservationStatus::AggregateOverflow)?,
    ))
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
    /// `false` when [`snapshot_totals`] cannot represent the sum in `i64` (fields are zero).
    pub aggregate_totals_representable: bool,
}

/// Financial proof certificate binding a frozen snapshot to a ledger digest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FinancialCertificate {
    /// Snapshot epoch embedded in the frozen [`BudgetSnapshot`].
    pub snapshot_version: u64,
    pub ledger_digest_hex: String,
    pub tenant_count: usize,
    pub active_reservations: usize,
    pub conservation_balanced: bool,
    pub total_initial_microcents: i64,
    pub total_committed_microcents: i64,
    /// `false` when aggregate totals overflow `i64` (`total_*` fields are zero).
    pub aggregate_totals_representable: bool,
    /// Lifetime committed spend since the previous certificate on this engine.
    pub committed_since_last_certificate: i64,
}

/// Issue a certificate from a frozen snapshot (no additional engine reads).
#[must_use]
pub fn certify_snapshot(
    snapshot: &BudgetSnapshot,
    conservation_balanced: bool,
    committed_since_last_certificate: i64,
) -> FinancialCertificate {
    let digest = ledger_digest(snapshot);
    let totals = snapshot_totals(snapshot);
    let (total_initial, total_committed, totals_representable) = match totals {
        Ok((initial, committed)) => (initial, committed, true),
        Err(ConservationStatus::AggregateOverflow) => (0, 0, false),
        Err(other) => unreachable!("snapshot_totals only returns AggregateOverflow: {other}"),
    };
    FinancialCertificate {
        snapshot_version: snapshot.version,
        ledger_digest_hex: digest_to_hex(&digest),
        tenant_count: snapshot.tenants.len(),
        active_reservations: snapshot.active_reservations,
        conservation_balanced: conservation_balanced && totals_representable,
        total_initial_microcents: total_initial,
        total_committed_microcents: total_committed,
        aggregate_totals_representable: totals_representable,
        committed_since_last_certificate,
    }
}

/// Issue a financial certificate from the current engine state (single snapshot pass).
///
/// Digest, conservation status, totals, and `committed_since_last_certificate` all bind to
/// the same frozen snapshot — baseline rotation uses the snapshot committed total, not a
/// subsequent engine read.
pub fn certify_ledger(engine: &BudgetEngine) -> FinancialCertificate {
    let snapshot = engine.snapshot();
    let per_tenant_balanced =
        conservation_status_for_snapshot(&snapshot) == ConservationStatus::Balanced;
    let totals = snapshot_totals(&snapshot);
    let total_committed = totals.as_ref().map(|(_, c)| *c).unwrap_or(0);
    let committed_since = if totals.is_ok() {
        engine.rotate_certificate_baseline(total_committed)
    } else {
        0
    };
    certify_snapshot(&snapshot, per_tenant_balanced, committed_since)
}

/// Prove conservation and return a structured proof binding the ledger digest.
///
/// Returns `Err` with the violating tenant if the invariant is broken.
/// Digest, conservation status, and version all refer to the same frozen snapshot.
pub fn prove_conservation(engine: &BudgetEngine) -> Result<ConservationProof, ConservationStatus> {
    let snapshot = engine.snapshot();
    let status = conservation_status_for_snapshot(&snapshot);
    let digest = ledger_digest(&snapshot);
    let totals = snapshot_totals(&snapshot);
    match status {
        ConservationStatus::Balanced => {
            let (total_initial, total_committed) = totals?;
            Ok(ConservationProof {
                ledger_digest_hex: digest_to_hex(&digest),
                snapshot_version: snapshot.version,
                tenant_count: snapshot.tenants.len(),
                active_reservations: snapshot.active_reservations,
                total_initial_microcents: total_initial,
                total_committed_microcents: total_committed,
                aggregate_totals_representable: true,
            })
        }
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
        assert!(cert.aggregate_totals_representable);
        assert_eq!(cert.ledger_digest_hex.len(), 64);
        assert!(cert.snapshot_version > 0);
        assert_eq!(cert.total_committed_microcents, 95_000);
        let proof = prove_conservation(&engine).unwrap();
        assert!(proof.aggregate_totals_representable);
        assert_eq!(proof.ledger_digest_hex.len(), 64);
        assert!(proof.snapshot_version > 0);
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
        let cert = certify_snapshot(&snap, true, 0);
        engine.top_up_tenant("desk", 999_999);
        assert_ne!(ledger_digest(&engine.snapshot()), ledger_digest(&snap));
        assert_eq!(cert.ledger_digest_hex, digest_to_hex(&ledger_digest(&snap)));
        assert_eq!(cert.snapshot_version, snap.version);
    }

    #[test]
    fn certify_ledger_binds_committed_delta_to_snapshot() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 100_000);
        engine.commit(id.unwrap(), 90_000);
        let cert = certify_ledger(&engine);
        assert_eq!(cert.total_committed_microcents, 90_000);
        assert_eq!(cert.committed_since_last_certificate, 90_000);
        assert_eq!(
            cert.total_committed_microcents,
            cert.committed_since_last_certificate
        );
    }

    #[test]
    fn prove_and_certify_are_internally_consistent() {
        let engine = BudgetEngine::new();
        engine.ensure_tenant("desk", 1_000_000);
        let (_, id) = engine.try_reserve("desk", 50_000);
        engine.commit(id.unwrap(), 40_000);
        let proof = prove_conservation(&engine).unwrap();
        assert_eq!(proof.snapshot_version, engine.snapshot_version());
        let cert = certify_ledger(&engine);
        assert!(cert.conservation_balanced);
        assert_eq!(cert.snapshot_version, engine.snapshot_version());
    }
}
