use std::hint::black_box;
use std::sync::Arc;
use std::thread;

use calybris_core::budget::BudgetEngine;
use calybris_core::finance::{ledger_digest, MICROCENTS_PER_CENT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_reserve(c: &mut Criterion) {
    let engine = Arc::new(BudgetEngine::new());
    engine.ensure_tenant("bench", 1_000_000_000 * MICROCENTS_PER_CENT);

    c.bench_function("budget/try_reserve", |b| {
        b.iter(|| {
            let (res, id) = engine.try_reserve("bench", 10_000);
            if let Some(id) = id {
                black_box(engine.release(id));
            } else {
                black_box(res);
            }
        });
    });
}

fn bench_reserve_commit(c: &mut Criterion) {
    let engine = Arc::new(BudgetEngine::new());
    engine.ensure_tenant("bench", 1_000_000_000 * MICROCENTS_PER_CENT);

    c.bench_function("budget/reserve_commit", |b| {
        b.iter(|| {
            let (_, id) = engine.try_reserve("bench", 10_000);
            if let Some(id) = id {
                black_box(engine.commit(id, 9_500));
            }
        });
    });
}

fn bench_top_up(c: &mut Criterion) {
    let engine = Arc::new(BudgetEngine::new());
    engine.ensure_tenant("bench", 100_000_000 * MICROCENTS_PER_CENT);

    c.bench_function("budget/top_up_tenant", |b| {
        b.iter(|| {
            black_box(engine.top_up_tenant("bench", 1_000));
        });
    });
}

fn bench_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("budget/contention");
    for threads in [4_usize, 16, 32] {
        group.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &n| {
            b.iter(|| {
                let engine = Arc::new(BudgetEngine::new());
                engine.ensure_tenant("bench", 100_000_000);
                let handles: Vec<_> = (0..n)
                    .map(|i| {
                        let e = Arc::clone(&engine);
                        thread::spawn(move || {
                            let (_, id) = e.try_reserve("bench", 1_000);
                            if let Some(id) = id {
                                if i % 2 == 0 {
                                    e.release(id);
                                } else {
                                    e.commit(id, 900);
                                }
                            }
                        })
                    })
                    .collect();
                for h in handles {
                    h.join().unwrap();
                }
                black_box(engine.verify_conservation());
            });
        });
    }
    group.finish();
}

fn bench_snapshot_digest(c: &mut Criterion) {
    let engine = BudgetEngine::new();
    for i in 0..256 {
        engine.ensure_tenant(&format!("tenant-{i}"), 1_000_000 + i as i64);
    }
    let snap = engine.snapshot();

    c.bench_function("budget/snapshot", |b| {
        b.iter(|| black_box(engine.snapshot()));
    });

    c.bench_function("budget/ledger_digest", |b| {
        b.iter(|| black_box(ledger_digest(&snap)));
    });
}

criterion_group!(
    benches,
    bench_reserve,
    bench_reserve_commit,
    bench_top_up,
    bench_contention,
    bench_snapshot_digest
);
criterion_main!(benches);