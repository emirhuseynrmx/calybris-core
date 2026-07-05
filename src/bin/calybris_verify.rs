//! calybris-verify — independent auditor CLI for CALY-PROOF v1 trails.
//!
//! An auditor does not run your decision engine; they run this:
//!
//! ```text
//! calybris-verify chain  decisions.wal.jsonl [--hmac-key-hex HEX]
//! calybris-verify audit  decisions.wal.jsonl [--policy policy.json] [--hmac-key-hex HEX]
//! calybris-verify policy policy.json
//! ```
//!
//! - `chain`  — hash-chain integrity (tamper/truncation/reorder detection).
//! - `audit`  — chain + per-entry digest checks on audited records; with
//!   `--policy`, additionally recomputes the policy digest and replays every
//!   decision through the kernel (full CALY-PROOF verification).
//! - `policy` — print the canonical policy digest of a policy artifact.
//!
//! Exit code 0 = everything verified; 1 = verification failure; 2 = usage.
//!
//! The policy artifact is JSON:
//!
//! ```json
//! {
//!   "policy_epoch": 7, "catalog_epoch": 42,
//!   "hard_risk_limit_bps": 9600, "minimum_confidence_bps": 5500,
//!   "risk_penalty_multiplier_bps": 3500, "latency_penalty_microunits_per_ms": 2,
//!   "models": [ { "model_id": 1, "provider_id": 0, ... } ]
//! }
//! ```

use std::path::Path;
use std::process::ExitCode;

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelModel, PolicySnapshot};
use calybris_core::wal::{read_verified_wal, read_verified_wal_keyed, AuditedRecord};
use calybris_core::wal::{verify_wal, verify_wal_keyed};

#[derive(serde::Deserialize)]
struct PolicyArtifact {
    policy_epoch: u64,
    catalog_epoch: u64,
    hard_risk_limit_bps: u16,
    minimum_confidence_bps: u16,
    risk_penalty_multiplier_bps: u16,
    latency_penalty_microunits_per_ms: u64,
    models: Vec<KernelModel>,
}

impl PolicyArtifact {
    fn into_snapshot(self) -> Result<PolicySnapshot, String> {
        PolicySnapshot::try_new(
            self.policy_epoch,
            self.catalog_epoch,
            self.hard_risk_limit_bps,
            self.minimum_confidence_bps,
            self.risk_penalty_multiplier_bps,
            self.latency_penalty_microunits_per_ms,
            self.models,
        )
        .map_err(|error| format!("invalid policy artifact: {error:?}"))
    }
}

fn load_policy(path: &str) -> Result<PolicySnapshot, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read policy artifact {path}: {error}"))?;
    let artifact: PolicyArtifact = serde_json::from_str(&raw)
        .map_err(|error| format!("cannot parse policy artifact {path}: {error}"))?;
    artifact.into_snapshot()
}

fn parse_hex_key(hex_key: &str) -> Result<Vec<u8>, String> {
    let hex_key = hex_key.trim();
    if hex_key.len() % 2 != 0 {
        return Err("HMAC key hex must have even length".to_string());
    }
    (0..hex_key.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_key[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at offset {i}"))
        })
        .collect()
}

struct Args {
    command: String,
    target: String,
    policy: Option<String>,
    hmac_key: Option<Vec<u8>>,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut positional = Vec::new();
    let mut policy = None;
    let mut hmac_key = None;
    let mut json = false;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policy" => {
                policy = Some(iter.next().ok_or("--policy requires a path")?);
            }
            "--hmac-key-hex" => {
                let raw = iter.next().ok_or("--hmac-key-hex requires a value")?;
                hmac_key = Some(parse_hex_key(&raw)?);
            }
            "--json" => json = true,
            "-h" | "--help" => return Err(String::new()),
            other => positional.push(other.to_string()),
        }
    }
    if positional.len() != 2 {
        return Err(String::new());
    }
    Ok(Args {
        command: positional[0].clone(),
        target: positional[1].clone(),
        policy,
        hmac_key,
        json,
    })
}

/// Emit a one-line JSON verdict for CI/compliance pipelines.
fn emit_json(command: &str, ok: bool, detail: &str) {
    let escaped = detail.replace('\\', "\\\\").replace('"', "\\\"");
    println!("{{\"command\":\"{command}\",\"ok\":{ok},\"detail\":\"{escaped}\"}}");
}

fn usage() {
    eprintln!(
        "calybris-verify — independent CALY-PROOF v1 auditor\n\n\
         USAGE:\n\
         \x20 calybris-verify chain  <wal.jsonl> [--hmac-key-hex HEX]\n\
         \x20 calybris-verify audit  <wal.jsonl> [--policy policy.json] [--hmac-key-hex HEX]\n\
         \x20 calybris-verify policy <policy.json>\n\n\
         Exit codes: 0 verified, 1 verification failure, 2 usage error.\n\
         Spec: docs/CALY_PROOF.md"
    );
}

fn cmd_chain(path: &Path, key: Option<&[u8]>, json: bool) -> ExitCode {
    let result = match key {
        Some(key) => verify_wal_keyed(path, key),
        None => verify_wal(path),
    };
    match result {
        Ok((entries, last_hash)) => {
            if json {
                emit_json(
                    "chain",
                    true,
                    &format!("{entries} entries, last hash {last_hash}"),
                );
            } else {
                println!("CHAIN OK: {entries} entries, last hash {last_hash}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if json {
                emit_json("chain", false, &error.to_string());
            } else {
                eprintln!("CHAIN FAILED: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn cmd_audit(
    path: &Path,
    policy: Option<PolicySnapshot>,
    key: Option<&[u8]>,
    json: bool,
) -> ExitCode {
    type Record = AuditedRecord<serde_json::Value>;
    let entries = match key {
        Some(key) => read_verified_wal_keyed::<Record>(path, key),
        None => read_verified_wal::<Record>(path),
    };
    let entries = match entries {
        Ok(entries) => entries,
        Err(error) => {
            if json {
                emit_json("audit", false, &format!("chain/parse: {error}"));
            } else {
                eprintln!("AUDIT FAILED (chain/parse): {error}");
            }
            return ExitCode::FAILURE;
        }
    };

    let expected_policy_hex = policy.as_ref().map(|p| digest_to_hex(&policy_digest(p)));
    let mut failures = 0_u64;
    for entry in &entries {
        let record = &entry.data;
        let mut problems = Vec::new();
        if digest_to_hex(&input_digest(&record.input)) != record.audit.input_digest_hex {
            problems.push("input digest mismatch");
        }
        if digest_to_hex(&decision_digest(&record.decision)) != record.audit.decision_digest_hex {
            problems.push("decision digest mismatch");
        }
        if let Some(expected) = &expected_policy_hex {
            if &record.audit.policy_digest_hex != expected {
                problems.push("policy digest mismatch");
            }
        }
        if let Some(policy) = &policy {
            use calybris_core::verify::{verify_decision, VerifyResult};
            if verify_decision(policy, record.input, &record.decision) != VerifyResult::Valid {
                problems.push("kernel replay mismatch");
            }
        }
        if !problems.is_empty() {
            failures += 1;
            eprintln!("seq {}: {}", entry.sequence, problems.join(", "));
        }
    }

    let mode = if policy.is_some() {
        "digests + policy + kernel replay"
    } else {
        "digests only (no policy artifact supplied)"
    };
    if failures == 0 {
        if json {
            emit_json(
                "audit",
                true,
                &format!("{} entries verified ({mode})", entries.len()),
            );
        } else {
            println!("AUDIT OK: {} entries verified ({mode})", entries.len());
        }
        ExitCode::SUCCESS
    } else {
        if json {
            emit_json(
                "audit",
                false,
                &format!("{failures}/{} entries failed ({mode})", entries.len()),
            );
        } else {
            eprintln!(
                "AUDIT FAILED: {failures}/{} entries failed ({mode})",
                entries.len()
            );
        }
        ExitCode::FAILURE
    }
}

fn cmd_policy(path: &str, json: bool) -> ExitCode {
    match load_policy(path) {
        Ok(snapshot) => {
            let hex = digest_to_hex(&policy_digest(&snapshot));
            if json {
                emit_json("policy", true, &hex);
            } else {
                println!("{hex}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if json {
                emit_json("policy", false, &error.to_string());
            } else {
                eprintln!("POLICY FAILED: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("error: {message}\n");
            }
            usage();
            return ExitCode::from(2);
        }
    };

    match args.command.as_str() {
        "chain" => cmd_chain(Path::new(&args.target), args.hmac_key.as_deref(), args.json),
        "audit" => {
            let policy = match args.policy.as_deref().map(load_policy) {
                Some(Ok(policy)) => Some(policy),
                Some(Err(error)) => {
                    eprintln!("error: {error}");
                    return ExitCode::FAILURE;
                }
                None => None,
            };
            cmd_audit(
                Path::new(&args.target),
                policy,
                args.hmac_key.as_deref(),
                args.json,
            )
        }
        "policy" => cmd_policy(&args.target, args.json),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}
