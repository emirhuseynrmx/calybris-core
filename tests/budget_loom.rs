//! Loom model checking for budget CAS + mutex interleavings.
//!
//! Run: `RUSTFLAGS='--cfg loom' cargo test --locked --test budget_loom`

#[cfg(loom)]
mod loom_tests {
    use calybris_core::budget::{
        conservation_status_for_snapshot, BudgetEngine, BudgetReservation, ConservationStatus,
    };
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn concurrent_reserve_release_two_threads() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 100_000);
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let t1 = thread::spawn(move || {
                let (_, id) = a.try_reserve("t1", 30_000);
                if let Some(id) = id {
                    let _ = a.release(id);
                }
            });
            let t2 = thread::spawn(move || {
                let (_, id) = b.try_reserve("t1", 30_000);
                if let Some(id) = id {
                    let _ = b.commit(id, 25_000);
                }
            });
            t1.join().unwrap();
            t2.join().unwrap();
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
            assert!(engine.remaining_microcents("t1").unwrap() >= 0);
        });
    }

    #[test]
    fn concurrent_reserve_never_overspends_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 50_000);
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let e = Arc::clone(&engine);
                    thread::spawn(move || {
                        let (res, _) = e.try_reserve("t1", 30_000);
                        matches!(res, BudgetReservation::Reserved { .. })
                    })
                })
                .collect();
            let successes: usize = handles
                .into_iter()
                .map(|h| h.join().unwrap() as usize)
                .sum();
            assert!(successes <= 1);
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn top_up_during_reserve_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 40_000);
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let t1 = thread::spawn(move || {
                let (_, id) = a.try_reserve("t1", 25_000);
                if let Some(id) = id {
                    let _ = a.commit(id, 20_000);
                }
            });
            let t2 = thread::spawn(move || {
                let _ = b.top_up_tenant("t1", 10_000);
            });
            t1.join().unwrap();
            t2.join().unwrap();
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn failed_overrun_preserves_conservation_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 20_000);
            let (_, id) = engine.try_reserve("t1", 15_000);
            let id = id.expect("reserved");
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let t1 = thread::spawn(move || {
                let _ = a.commit(id, 25_000);
            });
            let t2 = thread::spawn(move || {
                let _ = b.release(id);
            });
            t1.join().unwrap();
            t2.join().unwrap();
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn exposure_cap_concurrent_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 500_000);
            engine.set_max_reserved_microcents("t1", 100_000);
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let t1 = thread::spawn(move || {
                let (res, _) = a.try_reserve("t1", 80_000);
                matches!(res, BudgetReservation::Reserved { .. })
            });
            let t2 = thread::spawn(move || {
                let (res, _) = b.try_reserve("t1", 80_000);
                matches!(res, BudgetReservation::Reserved { .. })
            });
            let s1 = t1.join().unwrap();
            let s2 = t2.join().unwrap();
            assert!(!(s1 && s2));
            assert!(engine.reserved_microcents("t1") <= 100_000);
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn concurrent_two_topups_preserve_conservation_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 100_000);

            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);

            let t1 = thread::spawn(move || {
                let _ = a.top_up_tenant("t1", 50_000);
            });

            let t2 = thread::spawn(move || {
                let _ = b.top_up_tenant("t1", 50_000);
            });

            t1.join().unwrap();
            t2.join().unwrap();

            assert_eq!(engine.initial_microcents("t1"), Some(200_000));
            assert_eq!(engine.remaining_microcents("t1"), Some(200_000));
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn snapshot_restore_after_mutation_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 40_000);
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let t1 = thread::spawn(move || {
                let _ = a.top_up_tenant("t1", 10_000);
            });
            let t2 = thread::spawn(move || {
                let (_, id) = b.try_reserve("t1", 15_000);
                if let Some(id) = id {
                    let _ = b.release(id);
                }
            });
            t1.join().unwrap();
            t2.join().unwrap();
            let snap = engine.snapshot();
            assert_eq!(
                conservation_status_for_snapshot(&snap),
                ConservationStatus::Balanced
            );
            let restored = BudgetEngine::new();
            restored.restore_from_snapshot(snap).unwrap();
            assert_eq!(restored.verify_conservation(), ConservationStatus::Balanced);
        });
    }
}

#[cfg(not(loom))]
#[test]
fn loom_tests_require_cfg() {
    eprintln!("skip: run with RUSTFLAGS='--cfg loom' cargo test --test budget_loom");
}
