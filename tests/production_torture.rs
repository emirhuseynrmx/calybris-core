#![cfg(all(feature = "wal", feature = "provenance"))]

use std::fs;
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use calybris_core::budget::{BudgetEngine, ConservationStatus};
use calybris_core::digest::bytes_to_hex;
use calybris_core::finance::{ledger_digest, prove_conservation};
use calybris_core::kernel::{
    KernelDecision, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS,
};
use calybris_core::receipt::{
    issue_receipt, sign_receipt, verify_receipt, verify_receipt_signature, DecisionReceipt,
    ReceiptAnchors, ReceiptState, ReceiptWal,
};
use calybris_core::state::{
    stateful_audit_bundle, verify_trajectory, StateChain, StatefulAuditBundle,
};
use calybris_core::verify::verified_audit_bundle;
use calybris_core::wal::{
    verify_wal_keyed_against_anchor, visit_verified_wal_keyed, AuditedRecord, WalWriter,
};
use ed25519_dalek::SigningKey;

const HMAC_KEY: &[u8; 32] = b"calybris-torture-hmac-key-000001";

fn policy(model_count: u32) -> PolicySnapshot {
    let models = (0..model_count)
        .map(|model_id| KernelModel {
            model_id,
            provider_id: (model_id % 32) as u16,
            quality_bps: 5_000 + (model_id % 5_001) as u16,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 20 + (model_id % 1_000),
            capabilities: 1_u64 << (model_id % 16),
            region_mask: 1_u64 << (model_id % 16),
            input_cost_microunits_per_million_tokens: 100 + u64::from(model_id).saturating_mul(17),
            output_cost_microunits_per_million_tokens: 400 + u64::from(model_id).saturating_mul(71),
        })
        .collect();

    PolicySnapshot::try_new(9, 99, 9_800, 5_000, 4_000, 3, models)
        .expect("torture policy must be valid")
}

fn input(sequence: u64) -> KernelInput {
    KernelInput {
        request_sequence: sequence,
        requested_model_id: u32::MAX,
        input_tokens: u32::MAX - (sequence % 4_096) as u32,
        output_tokens: u32::MAX - (sequence % 2_048) as u32,
        business_value_microunits: i64::MAX - (sequence % 8_192) as i64,
        budget_limit_microunits: u64::MAX - sequence,
        risk_bps: (sequence % 5_000) as u16,
        confidence_bps: 9_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn rate(operations: usize, elapsed: Duration) -> f64 {
    operations as f64 / elapsed.as_secs_f64()
}

fn require_rate(name: &str, operations: usize, elapsed: Duration, minimum: f64) {
    let actual = rate(operations, elapsed);
    println!(
        "{name:<42} {:>12.0} ops/s  ({:>9.2} ms)",
        actual,
        elapsed.as_secs_f64() * 1_000.0
    );
    assert!(
        actual >= minimum,
        "{name} throughput regression: {actual:.0} ops/s < {minimum:.0} ops/s"
    );
}

fn require_duration(name: &str, elapsed: Duration, maximum: Duration) {
    println!("{name:<42} {:>12.2} ms", elapsed.as_secs_f64() * 1_000.0);
    assert!(
        elapsed <= maximum,
        "{name} latency regression: {elapsed:?} > {maximum:?}"
    );
}

fn build_state_trajectory(
    snapshot: &PolicySnapshot,
    decision: KernelDecision,
    request: KernelInput,
    count: usize,
) -> Vec<StatefulAuditBundle> {
    let mut chain = StateChain::genesis(&0_u64.to_le_bytes());
    let mut bundles = Vec::with_capacity(count);
    for step in 1..=count {
        let transition = chain.advance(&(step as u64).to_le_bytes());
        bundles.push(
            stateful_audit_bundle(snapshot, request, &decision, &transition)
                .expect("valid stateful bundle"),
        );
    }
    bundles
}

/// Release-only, deliberately hostile acceptance benchmark.
///
/// This is ignored by the normal test matrix because wall-clock gates are not
/// meaningful in debug builds. CI and the release workflow run it explicitly
/// with `--release --ignored --test-threads=1`.
#[test]
#[ignore = "release-only production torture benchmark"]
fn production_torture_benchmark() {
    println!(
        "\nCalybris {} production torture benchmark",
        env!("CARGO_PKG_VERSION")
    );
    println!("==============================================================");

    let snapshot = policy(64);
    let stable_input = input(1);
    let stable_decision = snapshot
        .prescribe_checked(stable_input)
        .expect("extreme but valid input");

    let kernel_operations = 5_000_000_usize;
    let started = Instant::now();
    for sequence in 1..=kernel_operations as u64 {
        black_box(
            snapshot
                .prescribe_checked(black_box(input(sequence)))
                .expect("generated input is valid"),
        );
    }
    require_rate(
        "checked kernel, 64 models, extreme u32/u64",
        kernel_operations,
        started.elapsed(),
        250_000.0,
    );

    let audit_operations = 100_000_usize;
    let started = Instant::now();
    for _ in 0..audit_operations {
        black_box(
            verified_audit_bundle(&snapshot, stable_input, &stable_decision)
                .expect("decision must replay"),
        );
    }
    require_rate(
        "fail-closed replay + audit bundle",
        audit_operations,
        started.elapsed(),
        20_000.0,
    );

    let state_count = 25_000_usize;
    let started = Instant::now();
    let trajectory = build_state_trajectory(&snapshot, stable_decision, stable_input, state_count);
    require_rate(
        "state proof generation, chained trajectory",
        state_count,
        started.elapsed(),
        10_000.0,
    );
    let started = Instant::now();
    verify_trajectory(&trajectory).expect("generated trajectory must verify");
    require_rate(
        "state trajectory verification",
        state_count,
        started.elapsed(),
        25_000.0,
    );

    let last_state = trajectory.last().expect("non-empty trajectory");
    let receipt_anchors = ReceiptAnchors {
        state: Some(ReceiptState {
            step: last_state.step,
            state_digest_before_hex: last_state.state_digest_before_hex.clone(),
            state_digest_after_hex: last_state.state_digest_after_hex.clone(),
        }),
        wal: Some(ReceiptWal {
            sequence: 25_000,
            entry_hash: bytes_to_hex(&[0xA5; 32]),
        }),
    };
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let verifying_key = signing_key.verifying_key();
    let receipt_operations = 25_000_usize;
    let started = Instant::now();
    let mut last_receipt = None;
    for timestamp in 0..receipt_operations as u64 {
        let mut receipt = issue_receipt(
            &snapshot,
            stable_input,
            &stable_decision,
            receipt_anchors.clone(),
        )
        .expect("receipt issuance");
        sign_receipt(
            &mut receipt,
            &signing_key,
            "torture-benchmark",
            1_783_000_000_000 + timestamp,
        )
        .expect("receipt signing");
        verify_receipt(&receipt, &snapshot, stable_input, &stable_decision)
            .expect("receipt verification");
        verify_receipt_signature(&receipt, Some(&verifying_key))
            .expect("receipt signature verification");
        last_receipt = Some(black_box(receipt));
    }
    require_rate(
        "issue + sign + replay + signature receipt",
        receipt_operations,
        started.elapsed(),
        2_500.0,
    );

    let receipt_json =
        serde_json::to_string(last_receipt.as_ref().expect("receipt generated")).unwrap();
    let malformed_receipt = format!(
        "{},\"unexpected_security_field\":true}}",
        &receipt_json[..receipt_json.len() - 1]
    );
    let malformed_operations = 100_000_usize;
    let started = Instant::now();
    for _ in 0..malformed_operations {
        assert!(serde_json::from_str::<DecisionReceipt>(&malformed_receipt).is_err());
    }
    require_rate(
        "strict receipt JSON rejection",
        malformed_operations,
        started.elapsed(),
        50_000.0,
    );

    let directory = tempfile::tempdir().expect("temporary WAL directory");
    std::env::set_var("CALYBRIS_WAL_LOCK_DIR", directory.path().join("locks"));
    let wal_path = directory.path().join("torture.wal.jsonl");
    let wal_operations = 25_000_usize;
    let mut writer =
        WalWriter::<AuditedRecord<u64>>::open_keyed(&wal_path, HMAC_KEY).expect("keyed WAL");
    let started = Instant::now();
    for metadata in 0..wal_operations as u64 {
        writer
            .append_verified_audited(&snapshot, stable_input, stable_decision, metadata)
            .expect("verified WAL append");
    }
    require_rate(
        "keyed audited WAL append, no fsync",
        wal_operations,
        started.elapsed(),
        2_000.0,
    );
    let started = Instant::now();
    writer.flush_and_sync().expect("durable WAL batch");
    require_duration(
        "25k-entry WAL flush + fsync",
        started.elapsed(),
        Duration::from_secs(5),
    );
    let anchor = writer.anchor();
    drop(writer);

    let mut visited = 0_usize;
    let started = Instant::now();
    let head =
        visit_verified_wal_keyed::<AuditedRecord<u64>, _>(&wal_path, HMAC_KEY, |_| visited += 1)
            .expect("streaming WAL verification");
    assert_eq!(visited, wal_operations);
    assert_eq!(head.0, wal_operations as u64);
    require_rate(
        "streaming keyed WAL verification",
        wal_operations,
        started.elapsed(),
        5_000.0,
    );
    verify_wal_keyed_against_anchor(&wal_path, HMAC_KEY, &anchor)
        .expect("complete WAL must match trusted anchor");

    let truncated_path = directory.path().join("truncated.wal.jsonl");
    let complete_wal = fs::read_to_string(&wal_path).expect("read completed WAL");
    let mut lines: Vec<&str> = complete_wal.lines().collect();
    lines.pop().expect("WAL contains entries");
    fs::write(&truncated_path, format!("{}\n", lines.join("\n")))
        .expect("write cleanly truncated WAL");
    assert!(
        verify_wal_keyed_against_anchor(&truncated_path, HMAC_KEY, &anchor).is_err(),
        "trusted anchor must reject a cleanly removed WAL suffix"
    );

    let threads = thread::available_parallelism()
        .map_or(4, usize::from)
        .clamp(4, 16);
    let operations_per_thread = 25_000_usize;
    let budget_operations = threads * operations_per_thread;
    let engine = Arc::new(BudgetEngine::new());
    engine.ensure_tenant("contended", i64::MAX / 4);
    let barrier = Arc::new(Barrier::new(threads + 1));
    let handles: Vec<_> = (0..threads)
        .map(|thread_id| {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for operation in 0..operations_per_thread {
                    let (_, reservation_id) = engine.try_reserve("contended", 100);
                    let reservation_id = reservation_id.expect("budget must remain sufficient");
                    if (thread_id + operation) % 2 == 0 {
                        black_box(engine.commit(reservation_id, 90));
                    } else {
                        black_box(engine.release(reservation_id));
                    }
                }
            })
        })
        .collect();
    let started = Instant::now();
    barrier.wait();
    for handle in handles {
        handle.join().expect("budget worker");
    }
    require_rate(
        "same-tenant reserve/commit/release contention",
        budget_operations,
        started.elapsed(),
        20_000.0,
    );
    assert_eq!(engine.verify_conservation(), ConservationStatus::Balanced);

    let ledger = BudgetEngine::new();
    for tenant in 0..25_000_u32 {
        ledger.ensure_tenant(&format!("tenant-{tenant:05}"), 1_000_000);
    }
    let started = Instant::now();
    let ledger_snapshot = ledger.snapshot();
    black_box(ledger_digest(&ledger_snapshot));
    black_box(prove_conservation(&ledger).expect("10k-tenant ledger must balance"));
    require_duration(
        "25k-tenant snapshot + digest + proof",
        started.elapsed(),
        Duration::from_secs(2),
    );

    println!("==============================================================");
    println!("PASS: every production torture gate held");
}
