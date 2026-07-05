//! Benchmarks for the 0.5.0 proof surfaces: canonical digests, decision
//! certificates, and Ed25519 policy signing/verification. These sit off the
//! `prescribe` hot path — the point is to know their absolute cost so callers
//! can decide what to compute per decision vs. per batch.

use std::hint::black_box;

use calybris_core::certificate::{issue_certificate, verify_certificate, CertificateAnchors};
use calybris_core::digest::{decision_digest, input_digest, policy_digest};
use calybris_core::kernel::*;
use calybris_core::provenance::{sign_policy, verify_signed_policy_with_key};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;

fn fixture() -> (PolicySnapshot, KernelInput, KernelDecision) {
    let policy = PolicySnapshot::try_new(
        7,
        42,
        9_600,
        5_500,
        3_500,
        2,
        vec![
            KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1_000,
            },
            KernelModel {
                model_id: 2,
                provider_id: 1,
                quality_bps: 7_500,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 90,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 25,
                output_cost_microunits_per_million_tokens: 125,
            },
        ],
    )
    .unwrap();
    let input = KernelInput {
        request_sequence: 1,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        business_value_microunits: 100_000,
        budget_limit_microunits: 50_000_000,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        minimum_quality_bps: 5_000,
        max_p95_latency_ms: 1_000,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };
    let decision = policy.prescribe(input);
    (policy, input, decision)
}

fn bench_proof(c: &mut Criterion) {
    let (policy, input, decision) = fixture();

    c.bench_function("digest/policy", |b| {
        b.iter(|| black_box(policy_digest(black_box(&policy))))
    });
    c.bench_function("digest/input", |b| {
        b.iter(|| black_box(input_digest(black_box(&input))))
    });
    c.bench_function("digest/decision", |b| {
        b.iter(|| black_box(decision_digest(black_box(&decision))))
    });

    c.bench_function("certificate/issue", |b| {
        b.iter(|| {
            black_box(
                issue_certificate(&policy, input, &decision, CertificateAnchors::default())
                    .unwrap(),
            )
        })
    });
    let cert = issue_certificate(&policy, input, &decision, CertificateAnchors::default()).unwrap();
    c.bench_function("certificate/verify", |b| {
        b.iter(|| {
            black_box(verify_certificate(
                black_box(&cert),
                &policy,
                input,
                &decision,
            ))
        })
    });

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let verifying = signing.verifying_key();
    c.bench_function("provenance/sign", |b| {
        b.iter(|| {
            black_box(sign_policy(
                &policy,
                &signing,
                "risk-officer:ayse",
                1_783_000_000_000,
            ))
        })
    });
    let signed = sign_policy(&policy, &signing, "risk-officer:ayse", 1_783_000_000_000);
    c.bench_function("provenance/verify", |b| {
        b.iter(|| {
            black_box(verify_signed_policy_with_key(
                &policy,
                black_box(&signed),
                &verifying,
            ))
        })
    });
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
