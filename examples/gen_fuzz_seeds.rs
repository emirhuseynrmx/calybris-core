//! Writes the seed corpus the fuzz targets start from.
//!
//! A coverage-guided fuzzer handed only random bytes spends its whole budget
//! learning to produce `{`. Seeded with real documents, it spends it on the
//! fields. This is the difference between a fuzz target that runs and one that
//! finds things.
//!
//! ```text
//! cargo run --example gen_fuzz_seeds --features full
//! ```
//!
//! Output goes to `fuzz/seeds/<target>/`, which is committed. `fuzz/corpus/` is
//! the fuzzer's own working directory and is not.

use std::fs;
use std::path::Path;

use calybris_core::budget::{BudgetSnapshot, TenantLedger};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::outcome::{Disposition, Observation, Outcome, Selection};
use calybris_core::receipt::{issue_receipt, ReceiptAnchors, ReceiptState, ReceiptWal};

fn write(target: &str, name: &str, body: &str) {
    write_bytes(target, name, body.as_bytes());
}

/// The kernel target reads raw integers rather than JSON, so its seed is bytes
/// and must not be routed through a string conversion.
fn write_bytes(target: &str, name: &str, body: &[u8]) {
    let dir = Path::new("fuzz/seeds").join(target);
    fs::create_dir_all(&dir).expect("create seed directory");
    fs::write(dir.join(name), body).expect("write seed");
    println!("  fuzz/seeds/{target}/{name}  {} bayt", body.len());
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(
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
    .expect("policy")
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

fn main() {
    // --- snapshot_decode -------------------------------------------------
    let balanced = BudgetSnapshot {
        version: (1 << 63) | 9,
        tenants: vec![
            TenantLedger {
                tenant_id: "acme".into(),
                initial_microcents: 1_000_000,
                remaining_microcents: 300_000,
                reserved_microcents: 0,
                committed_microcents: 700_000,
            },
            TenantLedger {
                tenant_id: "globex".into(),
                initial_microcents: 4_000_000,
                remaining_microcents: 4_000_000,
                reserved_microcents: 0,
                committed_microcents: 0,
            },
        ],
        active_reservations: 0,
        wal_high_watermark: Some(4),
    };
    write(
        "snapshot_decode",
        "balanced.json",
        &serde_json::to_string_pretty(&balanced).expect("encode"),
    );

    let mut empty = balanced.clone();
    empty.tenants.clear();
    empty.wal_high_watermark = None;
    write(
        "snapshot_decode",
        "no-tenants-no-watermark.json",
        &serde_json::to_string(&empty).expect("encode"),
    );

    let mut extremes = balanced.clone();
    extremes.tenants[0].initial_microcents = i64::MAX;
    extremes.tenants[0].remaining_microcents = i64::MIN;
    write(
        "snapshot_decode",
        "extreme-amounts.json",
        &serde_json::to_string(&extremes).expect("encode"),
    );

    // --- outcome_decode ---------------------------------------------------
    let policy = policy();
    let input = request();
    let decision = policy.prescribe(input);

    let applied = Outcome::applied(
        &policy,
        &input,
        &decision,
        1_760_000_000_000_000,
        Observation {
            realized_cost_microunits: Some(4_100_000),
            realized_latency_ms: Some(238),
            succeeded: Some(true),
        },
    );
    write(
        "outcome_decode",
        "applied.json",
        &serde_json::to_string_pretty(&applied).expect("encode"),
    );

    write(
        "outcome_decode",
        "abandoned.json",
        &serde_json::to_string(&Outcome::abandoned(&policy, &input, &decision, 1)).expect("encode"),
    );

    // The one seed with an absent propensity, so the fuzzer sees that shape.
    let mut human = applied;
    human.selection = Selection::human(2);
    write(
        "outcome_decode",
        "human-no-propensity.json",
        &serde_json::to_string(&human).expect("encode"),
    );

    let mut in_flight = applied;
    in_flight.disposition = Disposition::InFlight;
    in_flight.observation = Observation {
        realized_cost_microunits: Some(0),
        realized_latency_ms: None,
        succeeded: None,
    };
    write(
        "outcome_decode",
        "in-flight-partial.json",
        &serde_json::to_string(&in_flight).expect("encode"),
    );

    // --- policy_decode ----------------------------------------------------
    // Shaped like a real signed policy, with a signature that is not one. The
    // target asserts nothing here ever verifies.
    write(
        "policy_decode",
        "shaped-but-unsigned.json",
        &format!(
            "{{\"policy_digest_hex\":\"{}\",\"signer_id\":\"policy-officer\",\
             \"signed_at_epoch_ms\":1760000000000,\"public_key_hex\":\"{}\",\
             \"signature_hex\":\"{}\"}}",
            "ab".repeat(32),
            "cd".repeat(32),
            "ef".repeat(64),
        ),
    );

    // --- wal_decode -------------------------------------------------------
    write(
        "wal_decode",
        "two-entries.jsonl",
        "{\"sequence\":1,\"previous_hash\":\"genesis\",\"entry_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"data\":1000}\n\
         {\"sequence\":2,\"previous_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"entry_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"data\":1001}\n",
    );

    // --- receipt_decode ---------------------------------------------------
    // Issued by the crate rather than hand-written, so the seed is exactly the
    // shape a reader meets. Anchored and unanchored are different shapes — the
    // state and wal fields are optional — so the fuzzer gets both.
    let anchored = issue_receipt(
        &policy,
        input,
        &decision,
        ReceiptAnchors {
            state: Some(ReceiptState {
                step: 3,
                state_digest_before_hex: "aa".repeat(32),
                state_digest_after_hex: "bb".repeat(32),
            }),
            wal: Some(ReceiptWal {
                sequence: 7,
                entry_hash: "cc".repeat(32),
            }),
        },
    )
    .expect("a replayable decision issues a receipt");
    write(
        "receipt_decode",
        "anchored.json",
        &serde_json::to_string_pretty(&anchored).expect("encode"),
    );

    let bare = issue_receipt(
        &policy,
        input,
        &decision,
        ReceiptAnchors {
            state: None,
            wal: None,
        },
    )
    .expect("a receipt without anchors is still a receipt");
    write(
        "receipt_decode",
        "unanchored.json",
        &serde_json::to_string(&bare).expect("encode"),
    );

    // --- kernel_decide ----------------------------------------------------
    // This target reads raw little-endian integers rather than JSON, so the
    // seed is bytes that decode into a usable catalog and request.
    let mut bytes = vec![2_u8]; // two models
    bytes.extend(std::iter::repeat_n(0x11_u8, 128));
    write_bytes("kernel_decide", "two-models.bin", &bytes);
}
