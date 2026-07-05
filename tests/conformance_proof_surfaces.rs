//! Golden locks for the state (`calystt1`) and provenance (`calysig1`) proof
//! tags — the two digest surfaces the main conformance fixture does not cover.
//!
//! The signature vector doubles as a cross-platform determinism check:
//! Ed25519 must produce a byte-identical signature for the same key and
//! message on every platform, or the provenance contract is not portable.

#![cfg(all(feature = "wal", feature = "provenance"))]

use calybris_core::digest::digest_to_hex;
use calybris_core::kernel::{KernelModel, PolicySnapshot, ALL_REGIONS};
use calybris_core::provenance::{sign_policy, verify_signed_policy_with_key};
use calybris_core::state::{state_digest, stateful_audit_bundle, verify_trajectory, StateChain};
use ed25519_dalek::SigningKey;

// Pinned by examples/gen_proof_surface_vectors.rs. A mismatch is a breaking
// proof-format change requiring a new digest tag, never a silent re-pin.
const STATE_DIGEST_1_LE42: &str =
    "8c53c2b4d7877e6ffefeb307a46cdc48eac7664d15e0cec5d561637f847512e7";
const SIGNED_POLICY_DIGEST: &str =
    "bd6fa32994734821ba8fd8cba027df4cf219ecc9f290ba9ba182589ea269126c";
const SIGNED_PUBLIC_KEY: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const SIGNED_SIGNATURE: &str = "62afc28bc1f7848fd49247f9444ff80ce718da9f2e668503a9e45ed678789684\
d3b18b95b3acbc68d00b405060427dafac5801a088d887b13f01fd06798eb609";

fn fixture_policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
        7,
        42,
        9_600,
        5_500,
        3_500,
        2,
        vec![KernelModel {
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
        }],
    )
    .unwrap()
}

#[test]
fn state_digest_layout_is_pinned() {
    assert_eq!(
        digest_to_hex(&state_digest(1, &42_u64.to_le_bytes())),
        STATE_DIGEST_1_LE42,
        "calystt1 state digest layout changed — breaking proof-format change"
    );
    // Step is domain-separated: the same bytes at a different step differ.
    assert_ne!(
        state_digest(1, &42_u64.to_le_bytes()),
        state_digest(2, &42_u64.to_le_bytes()),
    );
}

#[test]
fn ed25519_signature_is_deterministic_and_portable() {
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let signed = sign_policy(
        &fixture_policy(),
        &signing,
        "risk-officer:ayse",
        1_783_000_000_000,
    );

    assert_eq!(signed.policy_digest_hex, SIGNED_POLICY_DIGEST);
    assert_eq!(signed.public_key_hex, SIGNED_PUBLIC_KEY);
    assert_eq!(
        signed.signature_hex, SIGNED_SIGNATURE,
        "Ed25519 signature diverged — the provenance contract is not byte-portable"
    );

    // And it verifies against the pinned trust anchor.
    verify_signed_policy_with_key(&fixture_policy(), &signed, &signing.verifying_key()).unwrap();
}

#[test]
fn state_trajectory_with_signed_certificate_verifies() {
    // A short trajectory: two decisions, chained state, both replay-valid.
    let policy = fixture_policy();
    let mut chain = StateChain::genesis(&1_000_000_u64.to_le_bytes());
    let mut bundles = Vec::new();
    for (i, next_state) in [999_000_u64, 998_000_u64].into_iter().enumerate() {
        let input = calybris_core::kernel::KernelInput {
            request_sequence: i as u64 + 1,
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
            allowed_provider_mask: calybris_core::kernel::ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = policy.prescribe(input);
        let transition = chain.advance(&next_state.to_le_bytes());
        bundles.push(stateful_audit_bundle(&policy, input, &decision, &transition).unwrap());
    }
    verify_trajectory(&bundles).unwrap();
}
