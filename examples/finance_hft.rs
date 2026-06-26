/// HFT-style fixed-point budget path: CAS reserve → commit → conservation proof
///
/// ```bash
/// cargo run --example finance_hft
/// ```
use calybris_core::budget::{BudgetEngine, ConservationStatus};
use calybris_core::finance::{certify_ledger, prove_conservation, MICROCENTS_PER_CENT};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let engine = Arc::new(BudgetEngine::new());
    engine.ensure_tenant("hft-desk-1", 100_000_000 * MICROCENTS_PER_CENT);

    let started = Instant::now();
    let iterations = 50_000_u64;
    let mut committed = 0_u64;

    for i in 0..iterations {
        let (_, id) = engine.try_reserve("hft-desk-1", 10_000);
        if let Some(id) = id {
            engine.commit(id, 9_500 + (i % 100) as i64);
            committed += 1;
        }
    }
    let elapsed = started.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(iterations);

    assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
    let cert = certify_ledger(&engine);
    let digest = prove_conservation(&engine).unwrap();

    println!("HFT budget demo");
    println!("===============");
    println!("Iterations:     {iterations}");
    println!("Committed:      {committed}");
    println!("Avg ns/op:      {ns_per_op} (reserve+commit pairs)");
    println!("Conservation:   {}", cert.conservation_balanced);
    println!("Ledger digest:  {}...", &digest[..16]);
    println!("Tenants:        {}", cert.tenant_count);
    println!(
        "Remaining:      {:?} microcents",
        engine.remaining_microcents("hft-desk-1")
    );
}
