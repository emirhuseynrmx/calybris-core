//! The kernel itself, on inputs no caller would construct on purpose.
//!
//! The property: deciding never panics and never wraps. The utility path
//! accumulates in i128 and clamps, and `overflow-checks` is on in this profile,
//! so an arithmetic mistake here is a crash the fuzzer reports rather than a
//! quietly wrong decision in production.
//!
//! It also checks the one invariant the kernel exists to hold: a decision is
//! reproducible. The same snapshot and the same input decide identically, twice.

#![no_main]

use calybris_core::digest::decision_digest;
use calybris_core::kernel::{KernelAction, KernelInput, KernelModel, PolicySnapshot};
use libfuzzer_sys::fuzz_target;

/// Consumes bytes as little-endian integers, and stops when they run out.
struct Bytes<'a> {
    data: &'a [u8],
}

impl<'a> Bytes<'a> {
    fn u8(&mut self) -> u8 {
        let (first, rest) = self.data.split_first().unwrap_or((&0, &[]));
        self.data = rest;
        *first
    }

    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) | (u16::from(self.u8()) << 8)
    }

    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) | (u32::from(self.u16()) << 16)
    }

    fn u64(&mut self) -> u64 {
        u64::from(self.u32()) | (u64::from(self.u32()) << 32)
    }

    fn i64(&mut self) -> i64 {
        self.u64() as i64
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut bytes = Bytes { data };

    let model_count = usize::from(bytes.u8() % 8) + 1;
    let mut models = Vec::with_capacity(model_count);
    for i in 0..model_count {
        models.push(KernelModel {
            model_id: bytes.u32(),
            // Kept inside the documented ceilings so the snapshot builds; the
            // interesting arithmetic is in the costs and the penalties.
            provider_id: bytes.u16() % 64,
            quality_bps: bytes.u16() % 10_001,
            risk_ceiling_bps: bytes.u16() % 10_001,
            enabled: bytes.u8() % 2,
            p95_latency_ms: bytes.u32(),
            capabilities: bytes.u64(),
            region_mask: bytes.u64(),
            input_cost_microunits_per_million_tokens: bytes.u64(),
            output_cost_microunits_per_million_tokens: bytes.u64(),
        });
        let _ = i;
    }

    let Ok(snapshot) = PolicySnapshot::try_new(
        bytes.u64(),
        bytes.u64(),
        bytes.u16() % 10_001,
        bytes.u16() % 10_001,
        bytes.u16() % 10_001,
        bytes.u64(),
        models,
    ) else {
        return;
    };

    let input = KernelInput {
        request_sequence: bytes.u64(),
        requested_model_id: bytes.u32(),
        input_tokens: bytes.u32(),
        output_tokens: bytes.u32(),
        business_value_microunits: bytes.i64(),
        budget_limit_microunits: bytes.u64(),
        risk_bps: bytes.u16() % 10_001,
        confidence_bps: bytes.u16() % 10_001,
        minimum_quality_bps: bytes.u16() % 10_001,
        max_p95_latency_ms: bytes.u32(),
        required_capabilities: bytes.u64(),
        allowed_provider_mask: bytes.u64(),
        required_region_mask: bytes.u64(),
    };

    if input.validate().is_err() {
        return;
    }

    let first = snapshot.prescribe(input);
    let second = snapshot.prescribe(input);
    assert_eq!(
        decision_digest(&first),
        decision_digest(&second),
        "the same input decided differently twice",
    );

    // Explaining must agree with deciding, on any input at all.
    let explanation = snapshot.explain(input);
    if first.action != KernelAction::Reject {
        assert!(
            explanation
                .candidates
                .iter()
                .any(|candidate| candidate.model_id == first.selected_model_id),
            "the selected model was not reported among the candidates",
        );
    }
});
