//! Single proof envelope binding a decision to its full evidence chain.
//!
//! Collects policy + input + decision digests, replay result, WAL position,
//! and optional budget proof into one exportable struct.

use crate::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{verify_decision, VerifyResult};

/// A complete proof envelope for a single decision.
///
/// Combines all cryptographic evidence into one struct that can be serialized,
/// stored, or transmitted to an external auditor.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofEnvelope {
    pub proof_version: u16,

    pub policy_digest_hex: String,
    pub input_digest_hex: String,
    pub decision_digest_hex: String,

    pub replay_valid: bool,

    pub wal_sequence: Option<u64>,
    pub wal_entry_hash: Option<String>,

    pub budget_snapshot_version: Option<u64>,
    pub ledger_digest_hex: Option<String>,

    pub action: String,
    pub reason: String,
    pub selected_model_id: u32,
    pub counterfactual_model_id: u32,
    pub estimated_cost_microunits: u64,
    pub expected_utility_microunits: i64,
}

/// Build a proof envelope from a decision.
///
/// WAL and budget fields are `None` — use [`ProofEnvelopeBuilder`] to attach them.
pub fn seal(
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: &KernelDecision,
) -> ProofEnvelope {
    let replay = verify_decision(snapshot, input, decision);
    ProofEnvelope {
        proof_version: 1,
        policy_digest_hex: digest_to_hex(&policy_digest(snapshot)),
        input_digest_hex: digest_to_hex(&input_digest(&input)),
        decision_digest_hex: digest_to_hex(&decision_digest(decision)),
        replay_valid: replay == VerifyResult::Valid,
        wal_sequence: None,
        wal_entry_hash: None,
        budget_snapshot_version: None,
        ledger_digest_hex: None,
        action: format!("{}", decision.action),
        reason: format!("{}", decision.reason),
        selected_model_id: decision.selected_model_id,
        counterfactual_model_id: decision.counterfactual_model_id,
        estimated_cost_microunits: decision.estimated_cost_microunits,
        expected_utility_microunits: decision.expected_utility_microunits,
    }
}

/// Builder for attaching optional WAL and budget evidence to a [`ProofEnvelope`].
pub struct ProofEnvelopeBuilder {
    envelope: ProofEnvelope,
}

impl ProofEnvelopeBuilder {
    /// Start from a sealed envelope.
    #[must_use]
    pub fn new(snapshot: &PolicySnapshot, input: KernelInput, decision: &KernelDecision) -> Self {
        Self {
            envelope: seal(snapshot, input, decision),
        }
    }

    /// Attach WAL position.
    #[must_use]
    pub fn wal(mut self, sequence: u64, entry_hash: String) -> Self {
        self.envelope.wal_sequence = Some(sequence);
        self.envelope.wal_entry_hash = Some(entry_hash);
        self
    }

    /// Attach budget snapshot evidence.
    #[must_use]
    pub fn budget(mut self, snapshot_version: u64, ledger_digest_hex: String) -> Self {
        self.envelope.budget_snapshot_version = Some(snapshot_version);
        self.envelope.ledger_digest_hex = Some(ledger_digest_hex);
        self
    }

    /// Consume and return the envelope.
    #[must_use]
    pub fn build(self) -> ProofEnvelope {
        self.envelope
    }
}

impl ProofEnvelope {
    /// Whether all evidence fields are populated (replay + WAL position + WAL hash + budget version + ledger digest).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.replay_valid
            && self.wal_sequence.is_some()
            && self.wal_entry_hash.is_some()
            && self.budget_snapshot_version.is_some()
            && self.ledger_digest_hex.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::*;

    fn snap_and_input() -> (PolicySnapshot, KernelInput) {
        let snap = PolicySnapshot::try_new(
            1,
            1,
            9600,
            5500,
            3500,
            2,
            vec![KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9000,
                risk_ceiling_bps: 9500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1000,
            }],
        )
        .unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 1000,
            output_tokens: 500,
            business_value_microunits: 100_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 1000,
            confidence_bps: 9000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 1000,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        (snap, input)
    }

    #[test]
    fn seal_produces_valid_envelope() {
        let (snap, input) = snap_and_input();
        let decision = snap.prescribe(input);
        let envelope = seal(&snap, input, &decision);
        assert!(envelope.replay_valid);
        assert_eq!(envelope.proof_version, 1);
        assert_eq!(envelope.policy_digest_hex.len(), 64);
        assert!(!envelope.is_complete());
    }

    #[test]
    fn builder_attaches_wal_and_budget() {
        let (snap, input) = snap_and_input();
        let decision = snap.prescribe(input);
        let envelope = ProofEnvelopeBuilder::new(&snap, input, &decision)
            .wal(42, "abc123".to_string())
            .budget(7, "def456".to_string())
            .build();
        assert!(envelope.is_complete());
        assert_eq!(envelope.wal_sequence, Some(42));
        assert_eq!(envelope.budget_snapshot_version, Some(7));
    }

    #[test]
    fn tampered_decision_not_valid() {
        let (snap, input) = snap_and_input();
        let mut decision = snap.prescribe(input);
        decision.selected_model_id = 999;
        let envelope = seal(&snap, input, &decision);
        assert!(!envelope.replay_valid);
        assert!(!envelope.is_complete());
    }
}
