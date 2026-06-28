//! Observability instrumentation for the decision engine.
//!
//! Feature-gated behind `observability`. Emits structured [`tracing`] spans
//! and events for prescribe calls, budget operations, WAL appends, and
//! verification. Compatible with any tracing subscriber (stdout, Jaeger,
//! OpenTelemetry, Datadog).
//!
//! Does **not** add a subscriber — that's your application's job.

use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::VerifyResult;

/// Prescribe with tracing instrumentation.
///
/// Emits a `calybris.prescribe` span with input/decision fields.
#[tracing::instrument(
    name = "calybris.prescribe",
    skip(snapshot),
    fields(
        request_seq = input.request_sequence,
        model_id = input.requested_model_id,
        input_tokens = input.input_tokens,
        output_tokens = input.output_tokens,
    )
)]
pub fn prescribe_traced(snapshot: &PolicySnapshot, input: KernelInput) -> KernelDecision {
    let decision = snapshot.prescribe(input);
    tracing::info!(
        action = %decision.action,
        reason = %decision.reason,
        selected_model = decision.selected_model_id,
        utility = decision.expected_utility_microunits,
        cost = decision.estimated_cost_microunits,
        eligible = decision.eligible_models,
        "decision"
    );
    decision
}

/// Verify with tracing instrumentation.
#[tracing::instrument(
    name = "calybris.verify",
    skip(snapshot, decision),
    fields(request_seq = input.request_sequence)
)]
pub fn verify_traced(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> VerifyResult {
    let result = crate::verify::verify_decision(snapshot, input, decision);
    match &result {
        VerifyResult::Valid => tracing::info!("verified"),
        VerifyResult::Mismatch { .. } => tracing::warn!("mismatch"),
        VerifyResult::DigestMismatch { .. } => tracing::error!("digest_mismatch"),
    }
    result
}

/// Log a budget reservation event.
pub fn trace_reserve(tenant_id: &str, amount: i64, success: bool, remaining: i64) {
    if success {
        tracing::info!(
            target: "calybris.budget",
            tenant = tenant_id,
            amount,
            remaining,
            "reserved"
        );
    } else {
        tracing::warn!(
            target: "calybris.budget",
            tenant = tenant_id,
            amount,
            remaining,
            "insufficient"
        );
    }
}

/// Log a budget commit event.
pub fn trace_commit(tenant_id: &str, actual: i64, remaining: i64) {
    tracing::info!(
        target: "calybris.budget",
        tenant = tenant_id,
        actual,
        remaining,
        "committed"
    );
}

/// Log a budget release event.
pub fn trace_release(tenant_id: &str, returned: i64, remaining: i64) {
    tracing::info!(
        target: "calybris.budget",
        tenant = tenant_id,
        returned,
        remaining,
        "released"
    );
}

/// Log a WAL append event.
pub fn trace_wal_append(sequence: u64, entry_hash: &str) {
    tracing::debug!(
        target: "calybris.wal",
        sequence,
        hash = &entry_hash[..16],
        "appended"
    );
}

/// Log a conservation check result.
pub fn trace_conservation(balanced: bool, tenant_count: usize) {
    if balanced {
        tracing::info!(
            target: "calybris.finance",
            tenant_count,
            "conservation_balanced"
        );
    } else {
        tracing::error!(
            target: "calybris.finance",
            tenant_count,
            "conservation_violated"
        );
    }
}

/// Metrics snapshot for external export (Prometheus, OpenTelemetry, etc.).
///
/// Collect these values periodically and export to your metrics backend.
#[derive(Debug, Clone, Default)]
pub struct EngineMetrics {
    pub decisions_total: u64,
    pub decisions_executed: u64,
    pub decisions_substituted: u64,
    pub decisions_rejected: u64,
    pub reservations_active: u64,
    pub tenants_total: u64,
    pub conservation_balanced: bool,
    pub wal_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::*;

    fn test_snapshot() -> PolicySnapshot {
        PolicySnapshot::try_new(
            1, 1, 9600, 5500, 3500, 2,
            vec![KernelModel {
                model_id: 1, provider_id: 0, quality_bps: 9000, risk_ceiling_bps: 9500,
                enabled: 1, p95_latency_ms: 200, capabilities: 0, region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1000,
            }],
        ).unwrap()
    }

    fn test_input() -> KernelInput {
        KernelInput {
            request_sequence: 1, requested_model_id: 1,
            input_tokens: 1000, output_tokens: 500,
            business_value_microunits: 100_000, budget_limit_microunits: 50_000_000,
            risk_bps: 1000, confidence_bps: 9000, minimum_quality_bps: 5000,
            max_p95_latency_ms: 1000, required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS, required_region_mask: 0,
        }
    }

    #[test]
    fn prescribe_traced_works() {
        let snap = test_snapshot();
        let decision = prescribe_traced(&snap, test_input());
        assert!(decision.is_executable());
    }

    #[test]
    fn verify_traced_works() {
        let snap = test_snapshot();
        let input = test_input();
        let decision = snap.prescribe(input);
        let result = verify_traced(&snap, input, &decision);
        assert_eq!(result, VerifyResult::Valid);
    }
}
