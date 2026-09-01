//! calybris-verify — independent auditor CLI for CALY-PROOF v1 trails.
//!
//! An auditor does not run your decision engine; they run this:
//!
//! ```text
//! calybris-verify chain  decisions.wal.jsonl [--anchor anchor.json] [--hmac-key-hex HEX]
//! calybris-verify audit  decisions.wal.jsonl [--policy policy.json ...] [--anchor anchor.json] [--hmac-key-hex HEX]
//! calybris-verify policy policy.json
//! ```
//!
//! - `chain`  — hash-chain integrity; with `--anchor`, clean suffix-truncation detection.
//! - `audit`  — chain + per-entry digest checks on audited records; with
//!   one or more `--policy` artifacts, additionally resolves each record's
//!   exact policy and replays every decision through the kernel.
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

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelModel, PolicySnapshot};
use calybris_core::wal::{
    verify_wal, verify_wal_against_anchor, verify_wal_keyed, verify_wal_keyed_against_anchor,
    visit_verified_wal, visit_verified_wal_keyed, AuditedRecord, WalAnchor, MIN_HMAC_KEY_BYTES,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
        PolicySnapshot::try_new_trusted(
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

const MAX_AUDITOR_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

fn read_artifact_bounded(path: &str, kind: &str) -> Result<String, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("cannot read {kind} {path}: {error}"))?;
    if file
        .metadata()
        .map_err(|error| format!("cannot read {kind} {path}: {error}"))?
        .len()
        > MAX_AUDITOR_ARTIFACT_BYTES as u64
    {
        return Err(format!("{kind} exceeds {MAX_AUDITOR_ARTIFACT_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_AUDITOR_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {kind} {path}: {error}"))?;
    if bytes.len() > MAX_AUDITOR_ARTIFACT_BYTES {
        return Err(format!("{kind} exceeds {MAX_AUDITOR_ARTIFACT_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|error| format!("cannot read {kind} {path}: {error}"))
}

fn load_policy(path: &str) -> Result<PolicySnapshot, String> {
    let raw = read_artifact_bounded(path, "policy artifact")?;
    let artifact: PolicyArtifact = serde_json::from_str(&raw)
        .map_err(|error| format!("cannot parse policy artifact {path}: {error}"))?;
    artifact.into_snapshot()
}

fn load_anchor(path: &str) -> Result<WalAnchor, String> {
    let raw = read_artifact_bounded(path, "WAL anchor")?;
    serde_json::from_str(&raw).map_err(|error| format!("cannot parse WAL anchor {path}: {error}"))
}

fn parse_hex_key(hex_key: &str) -> Result<Vec<u8>, String> {
    let hex_key = hex_key.trim();
    if hex_key.len() % 2 != 0 {
        return Err("HMAC key hex must have even length".to_string());
    }
    let mut key = Vec::with_capacity(hex_key.len() / 2);
    for (index, pair) in hex_key.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = nibble(pair[0]).ok_or_else(|| format!("invalid hex at offset {}", index * 2))?;
        let low =
            nibble(pair[1]).ok_or_else(|| format!("invalid hex at offset {}", index * 2 + 1))?;
        key.push((high << 4) | low);
    }
    if key.len() < MIN_HMAC_KEY_BYTES {
        return Err(format!(
            "HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes ({} hex chars)",
            MIN_HMAC_KEY_BYTES * 2
        ));
    }
    Ok(key)
}

struct Args {
    command: String,
    target: String,
    policies: Vec<String>,
    anchor: Option<String>,
    hmac_key: Option<Vec<u8>>,
    json: bool,
}

/// A bare usage request is distinct from a real parse failure, so the two are
/// not encoded as an empty message string.
enum ArgsError {
    Usage,
    Message(String),
}

impl From<&str> for ArgsError {
    fn from(message: &str) -> Self {
        Self::Message(message.to_string())
    }
}

impl From<String> for ArgsError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

fn parse_args() -> Result<Args, ArgsError> {
    let mut positional = Vec::new();
    let mut policies = Vec::new();
    let mut anchor = None;
    let mut hmac_key = None;
    let mut json = false;
    // argv[0] is intentionally discarded and never used for a security decision.
    let mut iter = std::env::args().skip(1); // nosemgrep: rust.lang.security.args.args
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--policy" => {
                policies.push(iter.next().ok_or("--policy requires a path")?);
            }
            "--anchor" => {
                anchor = Some(iter.next().ok_or("--anchor requires a path")?);
            }
            "--hmac-key-hex" => {
                let raw = iter.next().ok_or("--hmac-key-hex requires a value")?;
                hmac_key = Some(parse_hex_key(&raw)?);
            }
            "--json" => json = true,
            "-h" | "--help" => return Err(ArgsError::Usage),
            other => positional.push(other.to_string()),
        }
    }
    if positional.len() != 2 {
        return Err(ArgsError::Usage);
    }
    Ok(Args {
        command: positional[0].clone(),
        target: positional[1].clone(),
        policies,
        anchor,
        hmac_key,
        json,
    })
}

/// Emit a one-line JSON verdict for CI/compliance pipelines.
fn emit_json(command: &str, ok: bool, detail: &str) {
    let payload = serde_json::json!({
        "command": command,
        "ok": ok,
        "detail": detail,
    });
    println!("{payload}");
}

fn usage() {
    eprintln!(
        "calybris-verify — independent CALY-PROOF v1 auditor\n\n\
         USAGE:\n\
         \x20 calybris-verify chain  <wal.jsonl> [--anchor anchor.json] [--hmac-key-hex HEX]\n\
         \x20 calybris-verify audit  <wal.jsonl> [--policy policy.json ...] [--anchor anchor.json] [--hmac-key-hex HEX]\n\
         \x20 calybris-verify policy <policy.json>\n\n\
         Exit codes: 0 verified, 1 verification failure, 2 usage error.\n\
         Spec: docs/CALY_PROOF.md"
    );
}

fn cmd_chain(path: &Path, key: Option<&[u8]>, anchor: Option<&WalAnchor>, json: bool) -> ExitCode {
    let result = match (key, anchor) {
        (Some(key), Some(anchor)) => verify_wal_keyed_against_anchor(path, key, anchor),
        (None, Some(anchor)) => verify_wal_against_anchor(path, anchor),
        (Some(key), None) => verify_wal_keyed(path, key),
        (None, None) => verify_wal(path),
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
    policies: Vec<PolicySnapshot>,
    key: Option<&[u8]>,
    anchor: Option<&WalAnchor>,
    json: bool,
) -> ExitCode {
    type Record = AuditedRecord<serde_json::Value>;
    let policies: Vec<_> = policies
        .into_iter()
        .map(|policy| {
            (
                policy.policy_epoch,
                policy.catalog_epoch,
                digest_to_hex(&policy_digest(&policy)),
                policy,
            )
        })
        .collect();
    let has_policies = !policies.is_empty();
    let mut failures = 0_u64;
    let mut entries = 0_u64;
    let mut inspect = |entry: calybris_core::wal::WalEntry<Record>| {
        entries += 1;
        let record = &entry.data;
        let mut problems = Vec::new();
        if let Err(error) = record.audit.validate_canonical() {
            problems.push(format!("non-canonical audit bundle: {error}"));
        }
        if digest_to_hex(&input_digest(&record.input)) != record.audit.input_digest_hex {
            problems.push("input digest mismatch".to_string());
        }
        if digest_to_hex(&decision_digest(&record.decision)) != record.audit.decision_digest_hex {
            problems.push("decision digest mismatch".to_string());
        }
        let resolved_policy = policies
            .iter()
            .find(|(policy_epoch, catalog_epoch, digest, _)| {
                *policy_epoch == record.audit.policy_epoch
                    && *catalog_epoch == record.audit.catalog_epoch
                    && digest == &record.audit.policy_digest_hex
            });
        if has_policies && resolved_policy.is_none() {
            problems.push("policy not resolved".to_string());
        }
        if let Some((_, _, _, policy)) = resolved_policy {
            use calybris_core::verify::{verify_decision, VerifyResult};
            if verify_decision(policy, record.input, &record.decision) != VerifyResult::Valid {
                problems.push("kernel replay mismatch".to_string());
            }
        }
        if !problems.is_empty() {
            failures += 1;
            if !json {
                eprintln!("seq {}: {}", entry.sequence, problems.join(", "));
            }
        }
    };
    let head = match key {
        Some(key) => visit_verified_wal_keyed::<Record, _>(path, key, &mut inspect),
        None => visit_verified_wal::<Record, _>(path, &mut inspect),
    };
    let head = match head {
        Ok(head) => head,
        Err(error) => {
            if json {
                emit_json("audit", false, &format!("chain/parse: {error}"));
            } else {
                eprintln!("AUDIT FAILED (chain/parse): {error}");
            }
            return ExitCode::FAILURE;
        }
    };
    if let Some(anchor) = anchor {
        if let Err(error) = anchor.verify_head(head.0, head.1, key.is_some()) {
            if json {
                emit_json("audit", false, &format!("anchor: {error}"));
            } else {
                eprintln!("AUDIT FAILED (anchor): {error}");
            }
            return ExitCode::FAILURE;
        }
    }

    let mode = if has_policies {
        "digests + policy resolver + kernel replay"
    } else {
        "digests only (no policy artifact supplied)"
    };
    if failures == 0 {
        if json {
            emit_json(
                "audit",
                true,
                &format!("{entries} entries verified ({mode})"),
            );
        } else {
            println!("AUDIT OK: {entries} entries verified ({mode})");
        }
        ExitCode::SUCCESS
    } else {
        if json {
            emit_json(
                "audit",
                false,
                &format!("{failures}/{entries} entries failed ({mode})"),
            );
        } else {
            eprintln!("AUDIT FAILED: {failures}/{entries} entries failed ({mode})");
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
        Err(error) => {
            if let ArgsError::Message(message) = error {
                eprintln!("error: {message}\n");
            }
            usage();
            return ExitCode::from(2);
        }
    };

    match args.command.as_str() {
        "chain" => {
            let anchor = match args.anchor.as_deref().map(load_anchor) {
                Some(Ok(anchor)) => Some(anchor),
                Some(Err(error)) => {
                    if args.json {
                        emit_json("chain", false, &format!("anchor: {error}"));
                    } else {
                        eprintln!("error: {error}");
                    }
                    return ExitCode::FAILURE;
                }
                None => None,
            };
            cmd_chain(
                Path::new(&args.target),
                args.hmac_key.as_deref(),
                anchor.as_ref(),
                args.json,
            )
        }
        "audit" => {
            let mut policies = Vec::with_capacity(args.policies.len());
            for path in &args.policies {
                match load_policy(path) {
                    Ok(policy) => policies.push(policy),
                    Err(error) => {
                        if args.json {
                            emit_json("audit", false, &format!("policy: {error}"));
                        } else {
                            eprintln!("error: {error}");
                        }
                        return ExitCode::FAILURE;
                    }
                }
            }
            let anchor = match args.anchor.as_deref().map(load_anchor) {
                Some(Ok(anchor)) => Some(anchor),
                Some(Err(error)) => {
                    if args.json {
                        emit_json("audit", false, &format!("anchor: {error}"));
                    } else {
                        eprintln!("error: {error}");
                    }
                    return ExitCode::FAILURE;
                }
                None => None,
            };
            cmd_audit(
                Path::new(&args.target),
                policies,
                args.hmac_key.as_deref(),
                anchor.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_key_parser_rejects_unicode_without_panicking() {
        let unicode_64_bytes = format!("{}x", "€".repeat(21));
        assert!(parse_hex_key(&unicode_64_bytes).is_err());
    }

    #[test]
    fn hmac_key_parser_rejects_short_keys() {
        assert!(parse_hex_key("00").is_err());
    }
}
