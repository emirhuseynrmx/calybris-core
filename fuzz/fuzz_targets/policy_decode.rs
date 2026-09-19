//! A signed policy decides what every later decision means, and it arrives as
//! bytes from outside.
//!
//! The property here is a forgery check rather than a crash check. The fuzzer
//! has no signing key, so no artifact it can invent should ever verify against
//! a real snapshot. If one does, either the digest comparison or the signature
//! check is not doing its job, and the fuzzer has found a way to sign policies.

#![no_main]

use calybris_core::digest::{digest_to_hex, policy_digest};
use calybris_core::kernel::{KernelModel, PolicySnapshot, ALL_REGIONS};
use calybris_core::provenance::{verify_signed_policy, SignedPolicy};
use libfuzzer_sys::fuzz_target;

fn snapshot() -> PolicySnapshot {
    PolicySnapshot::try_new(
        1,
        1,
        9_000,
        1_000,
        2_000,
        5,
        vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0b1,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 3_000_000,
            output_cost_microunits_per_million_tokens: 15_000_000,
        }],
    )
    .expect("a fixed, valid snapshot")
}

fuzz_target!(|data: &[u8]| {
    let Ok(signed) = serde_json::from_slice::<SignedPolicy>(data) else {
        return;
    };

    let snapshot = snapshot();

    // Every byte of `signed` is attacker-controlled. Verification must answer
    // rather than crash, whatever the hex fields contain — including the wrong
    // length, non-hex characters, and an all-zero key.
    let result = verify_signed_policy(&snapshot, &signed);

    assert!(
        result.is_err(),
        "an unsigned artifact verified against a real policy: digest {}, signer {:?}",
        signed.policy_digest_hex,
        signed.signer_id,
    );

    // The same input must also fail against a policy it does name, so that a
    // matching digest alone is never enough.
    let mut naming_us = signed.clone();
    naming_us.policy_digest_hex = digest_to_hex(&policy_digest(&snapshot));
    assert!(
        verify_signed_policy(&snapshot, &naming_us).is_err(),
        "a correct digest with an invented signature was accepted",
    );
});
