use calybris_core::kernel::*;
use std::time::Instant;

fn main() {
    let models: Vec<KernelModel> = (0..22)
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

    let snapshot = PolicySnapshot::new(1, 1, 9600, 5500, 3500, 0, models);

    let iterations = 1_000_000_u64;
    let started = Instant::now();

    for seq in 0..iterations {
        let input = KernelInput {
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
        };
        std::hint::black_box(snapshot.prescribe(input));
    }

    let elapsed = started.elapsed();
    let per_decision_ns = elapsed.as_nanos() / iterations as u128;
    let decisions_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!("Calybris Kernel Benchmark (22 models)");
    println!("  Iterations:      {iterations}");
    println!("  Elapsed:         {:.2}s", elapsed.as_secs_f64());
    println!("  Per decision:    {per_decision_ns} ns");
    println!("  Throughput:      {decisions_per_sec:.0} decisions/sec");
}
