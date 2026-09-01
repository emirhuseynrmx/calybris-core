//! Loom model checking for budget CAS + mutex interleavings.
//!
//! Run: `CALYBRIS_LOOM=1 cargo test --locked --features loom-model --test budget_loom`

#[cfg(loom)]
mod loom_tests {
    use calybris_core::budget::{
        conservation_status_for_snapshot, BudgetEngine, BudgetReservation, BudgetSettlement,
        ConservationStatus,
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
            let t1 = thread::spawn(move || a.commit(id, 25_000));
            let t2 = thread::spawn(move || b.release(id));
            let commit = t1.join().unwrap();
            let release = t2.join().unwrap();
            assert!(matches!(
                (commit, release),
                (
                    BudgetSettlement::Overrun { .. },
                    BudgetSettlement::Released { .. }
                ) | (
                    BudgetSettlement::MissingReservation,
                    BudgetSettlement::Released { .. }
                )
            ));
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn successful_commit_and_release_are_linearizable_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 20_000);
            let (_, id) = engine.try_reserve("t1", 10_000);
            let id = id.expect("reserved");
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let commit = thread::spawn(move || a.commit(id, 8_000));
            let release = thread::spawn(move || b.release(id));
            let outcomes = (commit.join().unwrap(), release.join().unwrap());
            assert!(matches!(
                outcomes,
                (
                    BudgetSettlement::Committed { .. },
                    BudgetSettlement::MissingReservation
                ) | (
                    BudgetSettlement::MissingReservation,
                    BudgetSettlement::Released { .. }
                )
            ));
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn overflow_commit_and_release_are_linearizable_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", i64::MAX);
            let (_, first_id) = engine.try_reserve("t1", 1);
            assert!(matches!(
                engine.commit(first_id.unwrap(), i64::MAX - 1),
                BudgetSettlement::Committed { .. }
            ));
            let (_, id) = engine.try_reserve("t1", 1);
            let id = id.expect("reserved");
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let commit = thread::spawn(move || a.commit(id, 2));
            let release = thread::spawn(move || b.release(id));
            let outcomes = (commit.join().unwrap(), release.join().unwrap());
            assert!(matches!(
                outcomes,
                (
                    BudgetSettlement::Overflow { .. },
                    BudgetSettlement::Released { .. }
                ) | (
                    BudgetSettlement::MissingReservation,
                    BudgetSettlement::Released { .. }
                )
            ));
            assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);
        });
    }

    #[test]
    fn two_commits_on_one_reservation_have_one_winner_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 20_000);
            let (_, id) = engine.try_reserve("t1", 10_000);
            let id = id.expect("reserved");
            let a = Arc::clone(&engine);
            let b = Arc::clone(&engine);
            let first = thread::spawn(move || a.commit(id, 8_000));
            let second = thread::spawn(move || b.commit(id, 8_000));
            let outcomes = (first.join().unwrap(), second.join().unwrap());
            assert!(matches!(
                outcomes,
                (
                    BudgetSettlement::Committed { .. },
                    BudgetSettlement::MissingReservation
                ) | (
                    BudgetSettlement::MissingReservation,
                    BudgetSettlement::Committed { .. }
                )
            ));
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
    fn exposure_cap_update_is_a_reservation_barrier_loom() {
        loom::model(|| {
            let engine = Arc::new(BudgetEngine::new());
            engine.ensure_tenant("t1", 500_000);
            engine.set_max_reserved_microcents("t1", 100_000);

            let reserve_engine = Arc::clone(&engine);
            let update_engine = Arc::clone(&engine);
            let reserve = thread::spawn(move || {
                let (_, id) = reserve_engine.try_reserve("t1", 80_000);
                if let Some(id) = id {
                    let _ = reserve_engine.release(id);
                }
            });
            let update = thread::spawn(move || {
                update_engine.set_max_reserved_microcents("t1", 10_000);
            });
            reserve.join().unwrap();
            update.join().unwrap();

            let (result, id) = engine.try_reserve("t1", 20_000);
            assert!(matches!(
                result,
                BudgetReservation::ExposureLimitExceeded {
                    max_reserved_microcents: 10_000,
                    ..
                }
            ));
            assert!(id.is_none());
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
    eprintln!("skip: run with CALYBRIS_LOOM=1 cargo test --features loom-model --test budget_loom");
}
