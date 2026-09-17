//! A budget snapshot arriving from disk is untrusted input.
//!
//! The property: decoding never panics, and a snapshot that decodes is either
//! refused by validation or is internally consistent. Recovery reads these
//! files after a crash, which is exactly when a panic is least affordable.

#![no_main]

use calybris_core::budget::{conservation_status_for_snapshot, BudgetSnapshot, ConservationStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(snapshot) = serde_json::from_slice::<BudgetSnapshot>(data) else {
        return;
    };

    // Whatever decoded, these must not panic on it.
    let _ = calybris_core::finance::ledger_digest(&snapshot);
    let status = conservation_status_for_snapshot(&snapshot);

    // A snapshot reported balanced must actually balance, per tenant. This is
    // the one place a decoder bug could turn into a silently wrong ledger.
    if status == ConservationStatus::Balanced {
        for tenant in &snapshot.tenants {
            let parts = tenant
                .remaining_microcents
                .checked_add(tenant.reserved_microcents)
                .and_then(|sum| sum.checked_add(tenant.committed_microcents));
            assert_eq!(
                parts,
                Some(tenant.initial_microcents),
                "balanced snapshot does not balance for {}",
                tenant.tenant_id,
            );
        }
    }
});
