//! A decision receipt is the artifact a third party is handed.
//!
//! The previous version of this target decoded and round-tripped, while its
//! comment claimed it fuzzed verification. It now actually calls the verifier:
//! a fixed trusted policy, input and decision stand in for the ones an auditor
//! would hold, and the fuzzer supplies the receipt.
//!
//! Three properties:
//!
//! - Verifying an attacker-supplied receipt never panics.
//! - If `verify_receipt` accepts one, the receipt's digests really are the
//!   digests of the policy, input and decision it was checked against. A
//!   coverage-guided fuzzer can eventually learn to put correct hex in a field,
//!   so "never accepts" would be the wrong assertion; "never accepts something
//!   that does not match" is the right one.
//! - `verify_receipt_signature` never accepts. That one is safe to state
//!   absolutely: the fuzzer holds no signing key, so any acceptance is a
//!   forgery.

#![no_main]

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{
    KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS,
};
use calybris_core::receipt::{verify_receipt, verify_receipt_signature, DecisionReceipt};
use libfuzzer_sys::fuzz_target;

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new_trusted(
        1,
        1,
        9_000,
        1_000,
        2_000,
        5,
        vec![
            KernelModel {
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
            },
            KernelModel {
                model_id: 2,
                provider_id: 1,
                quality_bps: 8_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 100,
                capabilities: 0b1,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 1_000_000,
                output_cost_microunits_per_million_tokens: 5_000_000,
            },
        ],
    )
    .expect("a fixed, valid policy")
}

fn request() -> KernelInput {
    KernelInput {
        request_sequence: 42,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        budget_limit_microunits: 50_000_000,
        business_value_microunits: 5_000_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        required_capabilities: 0b1,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(receipt) = serde_json::from_slice::<DecisionReceipt>(data) else {
        return;
    };

    // A receipt two readers could decode differently is a receipt they could
    // disagree about.
    if let Ok(encoded) = serde_json::to_vec(&receipt) {
        match serde_json::from_slice::<DecisionReceipt>(&encoded) {
            Ok(again) => assert_eq!(receipt, again, "a receipt did not survive a round trip"),
            Err(error) => panic!("a receipt we encoded would not decode: {error}"),
        }
    }

    let snapshot = policy();
    let input = request();
    let decision = snapshot.prescribe(input);

    // Every field is attacker-controlled. Verification must answer, not crash.
    if verify_receipt(&receipt, &snapshot, input, &decision).is_ok() {
        // Accepted. Then it must really describe what it was checked against.
        assert_eq!(
            receipt.policy_digest_hex,
            digest_to_hex(&policy_digest(&snapshot)),
            "an accepted receipt names a different policy",
        );
        assert_eq!(
            receipt.input_digest_hex,
            digest_to_hex(&input_digest(&input)),
            "an accepted receipt names a different input",
        );
        assert_eq!(
            receipt.decision_digest_hex,
            digest_to_hex(&decision_digest(&decision)),
            "an accepted receipt names a different decision",
        );
        assert!(
            receipt.replay_valid,
            "a receipt was accepted without claiming a valid replay",
        );
        assert_eq!(receipt.policy_epoch, decision.policy_epoch);
        assert_eq!(receipt.catalog_epoch, decision.catalog_epoch);
    }

    // No signing key exists here, so nothing the fuzzer builds may verify —
    // neither against the key embedded in the artifact nor against a trusted
    // one. An acceptance would mean the fuzzer can sign receipts.
    assert!(
        verify_receipt_signature(&receipt, None).is_err(),
        "an unsigned receipt passed signature verification",
    );
});
