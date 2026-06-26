use calybris_core::kernel::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn make_snapshot(model_count: u32) -> PolicySnapshot {
    let models: Vec<KernelModel> = (0..model_count)
        .map(|i| KernelModel {
            model_id: i,
            provider_id: (i % 6) as u16,
            quality_bps: 3000 + (i as u16) * 300,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 100 + i * 50,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 10 + (i as u64) * 50,
            output_cost_microunits_per_million_tokens: 40 + (i as u64) * 200,
        })
        .collect();
    PolicySnapshot::new(1, 1, 9600, 5500, 3500, 0, models)
}

fn make_input(seq: u64) -> KernelInput {
    KernelInput {
        request_sequence: seq,
        requested_model_id: (seq % 22) as u32,
        input_tokens: 500 + (seq % 10000) as u32,
        output_tokens: 200 + (seq % 5000) as u32,
        business_value_microunits: 50_000,
        budget_limit_microunits: 10_000_000,
        risk_bps: (seq % 8000) as u16,
        confidence_bps: 6000 + (seq % 4000) as u16,
        minimum_quality_bps: 3000 + (seq % 5000) as u16,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn bench_prescribe(c: &mut Criterion) {
    let snapshot = make_snapshot(22);
    let mut seq = 0_u64;

    c.bench_function("prescribe/22_models", |b| {
        b.iter(|| {
            seq += 1;
            black_box(snapshot.prescribe(make_input(seq)))
        })
    });
}

fn bench_model_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("prescribe_scaling");
    for count in [4, 8, 16, 22, 32, 64] {
        let snapshot = make_snapshot(count);
        let mut seq = 0_u64;
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                seq += 1;
                black_box(snapshot.prescribe(make_input(seq)))
            })
        });
    }
    group.finish();
}

fn bench_reject_path(c: &mut Criterion) {
    let snapshot = make_snapshot(22);

    c.bench_function("prescribe/reject_risk", |b| {
        b.iter(|| {
            black_box(snapshot.prescribe(KernelInput {
                request_sequence: 1,
                requested_model_id: 0,
                input_tokens: 1000,
                output_tokens: 500,
                business_value_microunits: 50_000,
                budget_limit_microunits: 10_000_000,
                risk_bps: 9900,
                confidence_bps: 9000,
                minimum_quality_bps: 3000,
                max_p95_latency_ms: 0,
                required_capabilities: 0,
                allowed_provider_mask: ALL_PROVIDERS,
                required_region_mask: 0,
            }))
        })
    });
}

criterion_group!(
    benches,
    bench_prescribe,
    bench_model_scaling,
    bench_reject_path
);
criterion_main!(benches);
