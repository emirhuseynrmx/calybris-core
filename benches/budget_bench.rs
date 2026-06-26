use std::hint::black_box;

use calybris_core::budget::BudgetEngine;
use calybris_core::finance::MICROCENTS_PER_CENT;
use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;

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

criterion_group!(benches, bench_reserve, bench_reserve_commit);
criterion_main!(benches);
