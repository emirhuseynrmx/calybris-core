//! `docs/SPECIFICATION.md`, executed.
//!
//! Every layout in that document is rebuilt here from the written description —
//! field order, widths, endianness, sort keys, presence bytes — and compared
//! against what the crate actually produces. A specification nobody runs drifts
//! from the code within one release, and this one is the thing a second
//! implementation would be written against, so it has to be the thing that
//! fails when they disagree.
//!
//! These are deliberately not the crate's own digest functions restated. Each
//! `spec_*` function below appends bytes the way a reader of the document would,
//! from a hasher of its own.

use calybris_core::budget::{BudgetSnapshot, TenantLedger};
use calybris_core::digest::{
    decision_digest, input_digest, policy_digest, DECISION_DIGEST_TAG, INPUT_DIGEST_TAG,
    LEDGER_DIGEST_TAG, POLICY_DIGEST_TAG,
};
use calybris_core::finance::ledger_digest;
use calybris_core::kernel::{
    KernelDecision, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS,
};
use calybris_core::outcome::{
    identity_digest, outcome_digest, selection_digest, DecisionIdentity, Disposition, Observation,
    Outcome, Selection, SelectionStrategy, IDENTITY_DIGEST_TAG, OUTCOME_DIGEST_TAG,
    SELECTION_DIGEST_TAG,
};
use sha2::{Digest, Sha256};

/// A writer that only knows what the document says.
#[derive(Default)]
struct Spec {
    bytes: Vec<u8>,
}

impl Spec {
    fn tagged(tag: &[u8]) -> Self {
        assert_eq!(tag.len(), 9, "every tag is eight characters and a NUL");
        assert_eq!(tag[8], 0);
        Self {
            bytes: tag.to_vec(),
        }
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn i64(&mut self, v: i64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(v);
        self
    }

    /// Presence byte, then the value only when there is one.
    fn opt_u64(&mut self, v: Option<u64>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).u64(x),
            None => self.u8(0),
        }
    }

    fn opt_u32(&mut self, v: Option<u32>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).u32(x),
            None => self.u8(0),
        }
    }

    fn opt_u16(&mut self, v: Option<u16>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).u16(x),
            None => self.u8(0),
        }
    }

    fn opt_bool(&mut self, v: Option<bool>) -> &mut Self {
        match v {
            Some(x) => self.u8(1).u8(u8::from(x)),
            None => self.u8(0),
        }
    }

    fn finish(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }
}

// --- the layouts, transcribed from the document ---------------------------

fn spec_policy(snapshot: &PolicySnapshot) -> [u8; 32] {
    let mut s = Spec::tagged(POLICY_DIGEST_TAG);
    s.u64(snapshot.policy_epoch)
        .u64(snapshot.catalog_epoch)
        .u16(snapshot.hard_risk_limit_bps)
        .u16(snapshot.minimum_confidence_bps)
        .u16(snapshot.risk_penalty_multiplier_bps)
        .u64(snapshot.latency_penalty_microunits_per_ms);

    let mut models: Vec<&KernelModel> = snapshot.models().iter().collect();
    models.sort_by_key(|m| m.model_id);
    for m in models {
        s.u32(m.model_id)
            .u16(m.provider_id)
            .u16(m.quality_bps)
            .u16(m.risk_ceiling_bps)
            .u8(m.enabled)
            .u32(m.p95_latency_ms)
            .u64(m.capabilities)
            .u64(m.region_mask)
            .u64(m.input_cost_microunits_per_million_tokens)
            .u64(m.output_cost_microunits_per_million_tokens);
    }
    s.finish()
}

fn spec_input(input: &KernelInput) -> [u8; 32] {
    let mut s = Spec::tagged(INPUT_DIGEST_TAG);
    s.u64(input.request_sequence)
        .u32(input.requested_model_id)
        .u32(input.input_tokens)
        .u32(input.output_tokens)
        .i64(input.business_value_microunits)
        .u64(input.budget_limit_microunits)
        .u16(input.risk_bps)
        .u16(input.confidence_bps)
        .u16(input.minimum_quality_bps)
        .u32(input.max_p95_latency_ms)
        .u64(input.required_capabilities)
        .u64(input.allowed_provider_mask)
        .u64(input.required_region_mask);
    s.finish()
}

fn spec_decision(decision: &KernelDecision) -> [u8; 32] {
    let mut s = Spec::tagged(DECISION_DIGEST_TAG);
    s.u64(decision.request_sequence)
        .u8(decision.action as u8)
        .u16(decision.reason as u16)
        .u32(decision.selected_model_id)
        .u16(decision.selected_model_index)
        .u64(decision.estimated_cost_microunits)
        .i64(decision.expected_utility_microunits)
        .u32(decision.counterfactual_model_id)
        .i64(decision.counterfactual_utility_microunits)
        .u16(decision.evaluated_models)
        .u16(decision.eligible_models)
        .u64(decision.policy_epoch)
        .u64(decision.catalog_epoch);
    s.finish()
}

fn spec_identity(identity: &DecisionIdentity) -> [u8; 32] {
    let mut s = Spec::tagged(IDENTITY_DIGEST_TAG);
    s.raw(&identity.policy_digest)
        .raw(&identity.input_digest)
        .raw(&identity.decision_digest)
        .u64(identity.request_sequence);
    s.finish()
}

fn spec_selection(selection: &Selection) -> [u8; 32] {
    let mut s = Spec::tagged(SELECTION_DIGEST_TAG);
    s.u8(selection.strategy as u8)
        .u32(selection.acted_model_id)
        .opt_u16(selection.propensity_bps);
    s.finish()
}

fn spec_outcome(outcome: &Outcome) -> [u8; 32] {
    let mut s = Spec::tagged(OUTCOME_DIGEST_TAG);
    s.raw(&spec_identity(&outcome.identity))
        .u64(outcome.observed_at_micros)
        .u32(outcome.revision)
        .raw(&spec_selection(&outcome.selection))
        .u8(outcome.disposition as u8)
        .opt_u64(outcome.observation.realized_cost_microunits)
        .opt_u32(outcome.observation.realized_latency_ms)
        .opt_bool(outcome.observation.succeeded);
    s.finish()
}

/// The watermark suffix, byte for byte as the document gives it.
const WATERMARK_TAG: &[u8] = b"calybris.ledger.wal-watermark.v1\0";

fn spec_ledger(snapshot: &BudgetSnapshot) -> [u8; 32] {
    let mut s = Spec::tagged(LEDGER_DIGEST_TAG);
    s.u64(snapshot.version)
        .u64(snapshot.tenants.len() as u64)
        .u64(snapshot.active_reservations as u64);

    let mut tenants: Vec<&TenantLedger> = snapshot.tenants.iter().collect();
    tenants.sort_by(|a, b| a.tenant_id.as_bytes().cmp(b.tenant_id.as_bytes()));
    for t in tenants {
        let id = t.tenant_id.as_bytes();
        s.u32(id.len() as u32)
            .raw(id)
            .i64(t.initial_microcents)
            .i64(t.remaining_microcents)
            .i64(t.reserved_microcents)
            .i64(t.committed_microcents);
    }

    // Not a presence byte: a snapshot without a watermark appends nothing at
    // all, so that ledger digests written before the field existed still verify.
    if let Some(watermark) = snapshot.wal_high_watermark {
        s.raw(WATERMARK_TAG).u64(watermark);
    }
    s.finish()
}

// --- fixtures --------------------------------------------------------------

fn models() -> Vec<KernelModel> {
    vec![
        // Deliberately not in model_id order: the document says the catalog is
        // sorted before hashing, and this is where that gets checked.
        KernelModel {
            model_id: 7,
            provider_id: 3,
            quality_bps: 8_100,
            risk_ceiling_bps: 9_400,
            enabled: 1,
            p95_latency_ms: 640,
            capabilities: 0b1011,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 2_750_000,
            output_cost_microunits_per_million_tokens: 11_000_000,
        },
        KernelModel {
            model_id: 2,
            provider_id: 0,
            quality_bps: 9_300,
            risk_ceiling_bps: 9_900,
            enabled: 1,
            p95_latency_ms: 180,
            capabilities: 0b1,
            region_mask: 0b101,
            input_cost_microunits_per_million_tokens: 3_000_000,
            output_cost_microunits_per_million_tokens: 15_000_000,
        },
        KernelModel {
            model_id: 41,
            provider_id: 12,
            quality_bps: 6_000,
            risk_ceiling_bps: 5_000,
            enabled: 0,
            p95_latency_ms: 1,
            capabilities: u64::MAX,
            region_mask: 0b1,
            input_cost_microunits_per_million_tokens: 1,
            output_cost_microunits_per_million_tokens: u64::MAX,
        },
    ]
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(9, 4, 9_500, 1_200, 2_200, 7, models()).expect("policy")
}

fn request() -> KernelInput {
    KernelInput {
        request_sequence: u64::MAX - 3,
        requested_model_id: 2,
        input_tokens: 12_000,
        output_tokens: 3_400,
        // Negative, so the spec's "two's complement" claim is actually exercised.
        business_value_microunits: -9_000_001,
        budget_limit_microunits: 80_000_000,
        risk_bps: 900,
        confidence_bps: 8_800,
        minimum_quality_bps: 1_000,
        max_p95_latency_ms: 5_000,
        required_capabilities: 0b1,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0b1,
    }
}

fn identity() -> DecisionIdentity {
    let policy = policy();
    let input = request();
    DecisionIdentity::of(&policy, &input, &policy.prescribe(input))
}

fn ledger() -> BudgetSnapshot {
    BudgetSnapshot {
        version: 1 << 62,
        // Out of byte order on purpose, and with a multi-byte tenant id: the
        // document says the sort key is bytes, not a locale collation.
        tenants: vec![
            TenantLedger {
                tenant_id: "zürich".to_string(),
                initial_microcents: 900_000,
                remaining_microcents: 12,
                reserved_microcents: 0,
                committed_microcents: 899_988,
            },
            TenantLedger {
                tenant_id: "Acme".to_string(),
                initial_microcents: i64::MAX,
                remaining_microcents: -1,
                reserved_microcents: 5,
                committed_microcents: 0,
            },
            TenantLedger {
                tenant_id: "acme".to_string(),
                initial_microcents: 0,
                remaining_microcents: 0,
                reserved_microcents: 0,
                committed_microcents: 0,
            },
        ],
        active_reservations: 3,
        wal_high_watermark: None,
    }
}

// --- the tests -------------------------------------------------------------

#[test]
fn the_policy_layout_is_what_the_document_says() {
    let policy = policy();
    assert_eq!(spec_policy(&policy), policy_digest(&policy));
}

/// The document says the catalog is sorted by `model_id`, which is only a real
/// claim if an unsorted catalog reaches the same digest.
#[test]
fn a_catalog_in_a_different_order_hashes_the_same() {
    let mut reordered = models();
    reordered.reverse();
    let shuffled =
        PolicySnapshot::try_new(9, 4, 9_500, 1_200, 2_200, 7, reordered).expect("policy");

    assert_eq!(policy_digest(&policy()), policy_digest(&shuffled));
    assert_eq!(spec_policy(&shuffled), policy_digest(&shuffled));
}

#[test]
fn the_input_layout_is_what_the_document_says() {
    let input = request();
    assert_eq!(spec_input(&input), input_digest(&input));
}

#[test]
fn the_decision_layout_is_what_the_document_says() {
    let decision = policy().prescribe(request());
    assert_eq!(spec_decision(&decision), decision_digest(&decision));
}

/// A rejection takes a different branch through the kernel and carries different
/// field values, so it gets its own pass through the layout.
#[test]
fn a_rejection_hashes_by_the_same_layout() {
    let mut input = request();
    input.budget_limit_microunits = 1;
    let decision = policy().prescribe(input);

    assert_eq!(spec_decision(&decision), decision_digest(&decision));
}

#[test]
fn the_identity_layout_is_what_the_document_says() {
    let identity = identity();
    assert_eq!(spec_identity(&identity), identity_digest(&identity));
}

#[test]
fn the_selection_layout_is_what_the_document_says() {
    for selection in [
        Selection {
            strategy: SelectionStrategy::MaximiseUtility,
            acted_model_id: 2,
            propensity_bps: Some(10_000),
        },
        Selection::explored(7, 1),
        Selection::explored(41, 9_999),
        Selection::human(7),
    ] {
        assert_eq!(
            spec_selection(&selection),
            selection_digest(&selection),
            "{selection:?}",
        );
    }
}

#[test]
fn the_outcome_layout_is_what_the_document_says() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);

    // Every presence byte in both states, and each disposition.
    let observations = [
        Observation::default(),
        Observation {
            realized_cost_microunits: Some(0),
            realized_latency_ms: None,
            succeeded: None,
        },
        Observation {
            realized_cost_microunits: None,
            realized_latency_ms: Some(0),
            succeeded: Some(false),
        },
        Observation {
            realized_cost_microunits: Some(u64::MAX),
            realized_latency_ms: Some(u32::MAX),
            succeeded: Some(true),
        },
    ];

    for observation in observations {
        for disposition in [
            Disposition::Applied,
            Disposition::Abandoned,
            Disposition::InFlight,
        ] {
            for selection in [Selection::followed(&decision), Selection::human(7)] {
                let mut outcome = Outcome::applied(&policy, &input, &decision, 42, observation);
                outcome.disposition = disposition;
                outcome.selection = selection;
                outcome.revision = 3;

                assert_eq!(
                    spec_outcome(&outcome),
                    outcome_digest(&outcome),
                    "{disposition:?} {observation:?}",
                );
            }
        }
    }
}

/// The document's stated reason for presence bytes. If this ever passes by
/// accident, the reason is wrong and so is the format.
#[test]
fn absent_and_zero_are_different_bytes() {
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);

    let absent = Outcome::applied(&policy, &input, &decision, 42, Observation::default());
    let mut zero = absent;
    zero.observation.realized_cost_microunits = Some(0);

    assert_ne!(outcome_digest(&absent), outcome_digest(&zero));
    assert_ne!(spec_outcome(&absent), spec_outcome(&zero));
}

/// Nine bytes, eight characters and a NUL, and no two the same.
#[test]
fn every_tag_is_distinct_and_well_formed() {
    let tags = [
        POLICY_DIGEST_TAG,
        INPUT_DIGEST_TAG,
        DECISION_DIGEST_TAG,
        IDENTITY_DIGEST_TAG,
        SELECTION_DIGEST_TAG,
        OUTCOME_DIGEST_TAG,
    ];

    for tag in tags {
        assert_eq!(tag.len(), 9, "{tag:?}");
        assert_eq!(tag[8], 0, "{tag:?}");
        assert!(tag[..8].iter().all(u8::is_ascii_alphanumeric), "{tag:?}");
        assert!(tag[..8].starts_with(b"caly"), "{tag:?}");
    }

    for (i, a) in tags.iter().enumerate() {
        for b in &tags[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn the_ledger_layout_is_what_the_document_says() {
    let snapshot = ledger();
    assert_eq!(spec_ledger(&snapshot), ledger_digest(&snapshot));
}

/// The document says tenants sort by raw bytes. `"Acme"` before `"acme"` is only
/// true under that rule, and a locale-aware collation would put them together.
#[test]
fn tenants_sort_by_bytes_and_not_by_locale() {
    let snapshot = ledger();
    let mut reordered = snapshot.clone();
    reordered.tenants.reverse();

    assert_eq!(ledger_digest(&snapshot), ledger_digest(&reordered));
    assert_eq!(spec_ledger(&reordered), ledger_digest(&reordered));
}

/// A snapshot with no watermark appends nothing at all, rather than appending a
/// zero. This is the one exception to the presence-byte rule, and it exists so
/// that ledger digests written before the field existed still verify.
#[test]
fn a_missing_watermark_appends_nothing_at_all() {
    assert_eq!(WATERMARK_TAG.len(), 33);

    let without = ledger();
    let mut with_zero = without.clone();
    with_zero.wal_high_watermark = Some(0);

    assert_eq!(spec_ledger(&with_zero), ledger_digest(&with_zero));
    assert_ne!(ledger_digest(&without), ledger_digest(&with_zero));
}
