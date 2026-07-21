//! End-to-end tests for the `calybris-verify` auditor binary: an auditor
//! with only the WAL file and the policy artifact must be able to verify —
//! and any tampering must fail with a non-zero exit code.

#![cfg(feature = "wal")]

use std::process::Command;

use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::wal::{WalAnchor, WalWriter};

fn policy_models() -> Vec<KernelModel> {
    vec![
        KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 250,
            output_cost_microunits_per_million_tokens: 1_000,
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 7_500,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 90,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 25,
            output_cost_microunits_per_million_tokens: 125,
        },
    ]
}

fn policy() -> PolicySnapshot {
    policy_at(3, 9)
}

fn policy_at(policy_epoch: u64, catalog_epoch: u64) -> PolicySnapshot {
    PolicySnapshot::try_new(
        policy_epoch,
        catalog_epoch,
        9_600,
        5_500,
        3_500,
        2,
        policy_models(),
    )
    .unwrap()
}

fn input(sequence: u64) -> KernelInput {
    KernelInput {
        request_sequence: sequence,
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
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

fn write_audited_wal(path: &std::path::Path, entries: u64) -> WalAnchor {
    let snapshot = policy();
    let mut wal = WalWriter::open(path).unwrap();
    for sequence in 1..=entries {
        let request = input(sequence);
        let decision = snapshot.prescribe(request);
        wal.append_verified_audited(&snapshot, request, decision, "e2e-test")
            .unwrap();
    }
    wal.flush_and_sync().unwrap();
    wal.anchor()
}

fn write_policy_artifact(path: &std::path::Path) {
    write_policy_artifact_at(path, 3, 9);
}

fn write_policy_artifact_at(path: &std::path::Path, policy_epoch: u64, catalog_epoch: u64) {
    let artifact = serde_json::json!({
        "policy_epoch": policy_epoch,
        "catalog_epoch": catalog_epoch,
        "hard_risk_limit_bps": 9_600,
        "minimum_confidence_bps": 5_500,
        "risk_penalty_multiplier_bps": 3_500,
        "latency_penalty_microunits_per_ms": 2,
        "models": policy_models(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&artifact).unwrap()).unwrap();
}

#[test]
fn json_verdict_escapes_control_characters() {
    let dir = tempfile::tempdir().unwrap();
    let missing_policy = dir.path().join("missing\npolicy.json");
    let output = Command::new(env!("CARGO_BIN_EXE_calybris-verify"))
        .args(["policy", missing_policy.to_str().unwrap(), "--json"])
        .output()
        .expect("run calybris-verify");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let verdict: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("invalid JSON verdict: {error}; output={stdout:?}"));
    assert_eq!(verdict["command"], "policy");
    assert_eq!(verdict["ok"], false);
    assert!(verdict["detail"].as_str().unwrap().contains('\n'));
}

#[test]
fn audit_accepts_repeated_policy_artifacts_for_rotated_wal() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("rotated.wal.jsonl");
    let first_policy_path = dir.path().join("policy-3.json");
    let second_policy_path = dir.path().join("policy-4.json");
    let first = policy_at(3, 9);
    let second = policy_at(4, 10);
    let mut wal = WalWriter::open(&wal_path).unwrap();
    for (sequence, snapshot) in [(1, &first), (2, &second)] {
        let request = input(sequence);
        wal.append_verified_audited(
            snapshot,
            request,
            snapshot.prescribe(request),
            "rotation-test",
        )
        .unwrap();
    }
    wal.flush_and_sync().unwrap();
    drop(wal);
    write_policy_artifact_at(&first_policy_path, 3, 9);
    write_policy_artifact_at(&second_policy_path, 4, 10);

    let (ok, out) = run(&[
        "audit",
        wal_path.to_str().unwrap(),
        "--policy",
        first_policy_path.to_str().unwrap(),
        "--policy",
        second_policy_path.to_str().unwrap(),
    ]);
    assert!(ok, "rotated audit failed: {out}");
    assert!(out.contains("AUDIT OK: 2 entries"));
    assert!(out.contains("kernel replay"));
}

fn run(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_calybris-verify"))
        .args(args)
        .output()
        .expect("run calybris-verify");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

#[test]
fn auditor_verifies_a_clean_trail_with_only_wal_and_policy_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("audited.wal.jsonl");
    let policy_path = dir.path().join("policy.json");
    write_audited_wal(&wal_path, 5);
    write_policy_artifact(&policy_path);

    let (ok, out) = run(&["chain", wal_path.to_str().unwrap()]);
    assert!(ok, "chain verification failed: {out}");
    assert!(out.contains("CHAIN OK: 5 entries"));

    let (ok, out) = run(&[
        "audit",
        wal_path.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
    ]);
    assert!(ok, "audit verification failed: {out}");
    assert!(out.contains("AUDIT OK: 5 entries"));
    assert!(out.contains("kernel replay"));
}

#[test]
fn tampered_payload_fails_the_audit() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("tampered.wal.jsonl");
    write_audited_wal(&wal_path, 3);

    // Flip one digit inside the second entry's business value.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let tampered = content.replacen(
        "\"business_value_microunits\":100000",
        "\"business_value_microunits\":100001",
        1,
    );
    assert_ne!(content, tampered, "tamper target not found");
    std::fs::write(&wal_path, tampered).unwrap();

    let (ok, out) = run(&["chain", wal_path.to_str().unwrap()]);
    assert!(!ok, "tampered chain must fail, got: {out}");
    assert!(out.contains("CHAIN FAILED"));
}

#[test]
fn anchor_rejects_a_cleanly_truncated_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("truncated.wal.jsonl");
    let anchor_path = dir.path().join("anchor.json");
    let anchor = write_audited_wal(&wal_path, 3);
    std::fs::write(&anchor_path, serde_json::to_string_pretty(&anchor).unwrap()).unwrap();

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let retained = content.lines().take(2).collect::<Vec<_>>().join("\n") + "\n";
    std::fs::write(&wal_path, retained).unwrap();

    let (ok, out) = run(&["chain", wal_path.to_str().unwrap()]);
    assert!(ok, "a valid prefix is internally consistent: {out}");

    let (ok, out) = run(&[
        "chain",
        wal_path.to_str().unwrap(),
        "--anchor",
        anchor_path.to_str().unwrap(),
    ]);
    assert!(!ok, "trusted anchor must reject suffix truncation: {out}");
    assert!(out.contains("CHAIN FAILED"));
}

#[test]
fn wrong_policy_artifact_fails_replay() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wrongpolicy.wal.jsonl");
    let policy_path = dir.path().join("policy.json");
    write_audited_wal(&wal_path, 2);

    // Same catalog, different risk limit: digests and replay must diverge.
    let artifact = serde_json::json!({
        "policy_epoch": 3,
        "catalog_epoch": 9,
        "hard_risk_limit_bps": 500,
        "minimum_confidence_bps": 5_500,
        "risk_penalty_multiplier_bps": 3_500,
        "latency_penalty_microunits_per_ms": 2,
        "models": policy_models(),
    });
    std::fs::write(&policy_path, serde_json::to_string(&artifact).unwrap()).unwrap();

    let (ok, out) = run(&[
        "audit",
        wal_path.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
    ]);
    assert!(!ok, "audit with wrong policy must fail, got: {out}");
    assert!(out.contains("AUDIT FAILED"));
}

#[test]
fn policy_command_prints_canonical_digest() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.json");
    write_policy_artifact(&policy_path);

    let (ok, out) = run(&["policy", policy_path.to_str().unwrap()]);
    assert!(ok, "policy digest failed: {out}");
    let digest = out.trim();
    assert_eq!(digest.len(), 64, "expected 64 hex chars, got: {digest}");
    assert_eq!(
        digest,
        calybris_core::digest::digest_to_hex(&calybris_core::digest::policy_digest(&policy())),
    );
}
