//! CALY-PROOF v1 conformance suite (Rust side).
//!
//! Iterates every labeled case in the shared conformance fixture and asserts
//! the byte-exact input/decision digests and decision fields. This is the
//! contract a third-party reimplementation (Go, TypeScript, browser) proves
//! itself against — a mismatch is a breaking proof-format change requiring a
//! new digest tag, never a silent re-pin.

#![cfg(feature = "wal")]

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};

const FIXTURE: &str = include_str!("fixtures/caly_proof_conformance_v1.json");

fn shared_policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
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
                capabilities: 0b101,
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
                capabilities: 0b001,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 25,
                output_cost_microunits_per_million_tokens: 125,
            },
        ],
    )
    .unwrap()
}

fn base() -> KernelInput {
    KernelInput {
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
        required_capabilities: 0b001,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

/// Rebuild each case's input by label — must mirror the generator exactly.
fn input_for(label: &str) -> KernelInput {
    match label {
        "execute_requested" => base(),
        "substitute" => KernelInput {
            request_sequence: 2,
            requested_model_id: 2,
            business_value_microunits: 5_000_000,
            ..base()
        },
        "reject_risk_hard_limit" => KernelInput {
            request_sequence: 3,
            risk_bps: 9_800,
            ..base()
        },
        "reject_confidence_hard_limit" => KernelInput {
            request_sequence: 4,
            confidence_bps: 5_000,
            ..base()
        },
        "reject_quality_constraint" => KernelInput {
            request_sequence: 5,
            minimum_quality_bps: 9_500,
            ..base()
        },
        "reject_budget_constraint" => KernelInput {
            request_sequence: 6,
            budget_limit_microunits: 1,
            ..base()
        },
        other => panic!("unknown conformance label: {other}"),
    }
}

#[test]
fn every_conformance_case_reproduces_its_pinned_digests() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let policy = shared_policy();

    assert_eq!(
        digest_to_hex(&policy_digest(&policy)),
        fixture["policy_digest_hex"].as_str().unwrap(),
        "shared policy digest drifted"
    );

    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 6, "expected the full outcome matrix");

    for case in cases {
        let label = case["label"].as_str().unwrap();
        let input = input_for(label);
        let decision = policy.prescribe(input);

        assert_eq!(
            digest_to_hex(&input_digest(&input)),
            case["input_digest_hex"].as_str().unwrap(),
            "input digest mismatch for case {label}"
        );
        assert_eq!(
            digest_to_hex(&decision_digest(&decision)),
            case["decision_digest_hex"].as_str().unwrap(),
            "decision digest mismatch for case {label}"
        );
        assert_eq!(
            decision.reason.to_string(),
            case["reason"].as_str().unwrap(),
            "reason mismatch for case {label}"
        );
        assert_eq!(
            u64::from(decision.selected_model_id),
            case["selected_model_id"].as_u64().unwrap(),
            "selected model mismatch for case {label}"
        );
        assert_eq!(
            decision.expected_utility_microunits,
            case["expected_utility_microunits"].as_i64().unwrap(),
            "utility mismatch for case {label}"
        );
    }
}
