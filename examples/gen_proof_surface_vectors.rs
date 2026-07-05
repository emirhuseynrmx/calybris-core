//! Print byte-exact golden values for the state and provenance proof tags,
//! so `tests/conformance_proof_surfaces.rs` can pin them.
//!
//! Run: cargo run --example gen_proof_surface_vectors --features "wal,provenance"

use calybris_core::digest::digest_to_hex;
use calybris_core::kernel::{KernelModel, PolicySnapshot, ALL_REGIONS};
use calybris_core::provenance::sign_policy;
use calybris_core::state::state_digest;
use ed25519_dalek::SigningKey;

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

fn main() {
    // State digest of a fixed (step, canonical state bytes).
    let state_hex = digest_to_hex(&state_digest(1, &42_u64.to_le_bytes()));
    println!("state_digest(1, LE(42))    = {state_hex}");

    // Deterministic Ed25519 signature over the fixture policy.
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let signed = sign_policy(
        &fixture_policy(),
        &signing,
        "risk-officer:ayse",
        1_783_000_000_000,
    );
    println!("policy_digest_hex          = {}", signed.policy_digest_hex);
    println!("public_key_hex             = {}", signed.public_key_hex);
    println!("signature_hex              = {}", signed.signature_hex);
}
