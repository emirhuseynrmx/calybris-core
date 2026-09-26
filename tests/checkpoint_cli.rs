//! The checkpoint workflow through the `calybris-verify` binary, as an
//! operator, two witnesses and an auditor would run it — all offline.

#![cfg(all(feature = "wal", feature = "preview"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use calybris_core::checkpoint::SignedNote;
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::ots::DetachedTimestamp;
use calybris_core::wal::WalWriter;

const ORIGIN: &str = "decisions.example/log";

fn policy() -> PolicySnapshot {
    let model = KernelModel {
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
    };
    PolicySnapshot::try_new(3, 9, 9_600, 5_500, 3_500, 2, vec![model]).unwrap()
}

fn input(sequence: u64, value: i64) -> KernelInput {
    KernelInput {
        request_sequence: sequence,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        business_value_microunits: value,
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

/// Appends decisions `from..=to` to the WAL at `path`, each with business
/// value `value + sequence`.
fn append(path: &Path, from: u64, to: u64, value: i64) {
    let snapshot = policy();
    let mut wal = WalWriter::open(path).unwrap();
    for seq in from..=to {
        let request = input(seq, value + i64::try_from(seq).unwrap());
        wal.append_verified_audited(
            &snapshot,
            request,
            snapshot.prescribe(request),
            "checkpoint-cli",
        )
        .unwrap();
    }
    wal.flush_and_sync().unwrap();
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_calybris-verify"))
        .args(args)
        .output()
        .expect("run calybris-verify")
}

fn ok(args: &[&str]) -> String {
    let out = cli(args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    fn p(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    fn new() -> Self {
        let s = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        ok(&[
            "checkpoint",
            "keygen",
            "--name",
            ORIGIN,
            "--kind",
            "log",
            "--out",
            &s.p("log"),
        ]);
        for w in ["w1", "w2"] {
            ok(&[
                "checkpoint",
                "keygen",
                "--name",
                &format!("{w}.example"),
                "--kind",
                "witness",
                "--out",
                &s.p(w),
            ]);
        }
        s
    }

    /// Signs a checkpoint of `wal` into `note`, optionally linked to `prev`.
    fn checkpoint(&self, wal: &str, note: &str, prev: Option<&str>) {
        let key = self.p("log.skey");
        let mut args = vec![
            "checkpoint",
            "create",
            wal,
            "--origin",
            ORIGIN,
            "--key",
            &key,
        ];
        let prev_path;
        if let Some(prev) = prev {
            prev_path = self.p(prev);
            args.extend(["--prev", &prev_path]);
        }
        let out = self.p(note);
        args.extend(["--out", &out]);
        ok(&args);
    }

    /// Asks witness `w` to cosign `note`, proving from `old`; returns the
    /// raw CLI output.
    fn cosign(&self, w: &str, wal: &str, note: &str, old: u64, now: u64) -> Output {
        let req = ok(&[
            "checkpoint",
            "request",
            wal,
            "--note",
            &self.p(note),
            "--old",
            &old.to_string(),
        ]);
        let req_path = self.p(&format!("{note}.{w}.req"));
        std::fs::write(&req_path, req).unwrap();
        cli(&[
            "witness",
            "cosign",
            &req_path,
            "--key",
            &self.p(&format!("{w}.skey")),
            "--log",
            &format!("{ORIGIN}={}", self.p("log.vkey")),
            "--state",
            &self.p(&format!("{w}.state.json")),
            "--now",
            &now.to_string(),
            "--append-to",
            &self.p(note),
        ])
    }

    fn verify(&self, note: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "checkpoint".to_owned(),
            "verify".into(),
            self.p(note),
            "--log-key".into(),
            self.p("log.vkey"),
            "--witness".into(),
            self.p("w1.vkey"),
            "--witness".into(),
            self.p("w2.vkey"),
            "--threshold".into(),
            "2".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(&refs)
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn an_operator_two_witnesses_and_an_auditor_agree_on_one_history() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 10, 100_000);

    s.checkpoint(&wal, "000001.checkpoint", None);
    for w in ["w1", "w2"] {
        assert!(s
            .cosign(w, &wal, "000001.checkpoint", 0, 1_000)
            .status
            .success());
    }
    let out = s.verify("000001.checkpoint", &["--wal", &wal]);
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("2 of 2 required"), "{text}");
    assert!(!text.contains("FULL VERIFICATION"), "{text}");
    assert!(text.contains("RESULT: INDEPENDENTLY WITNESSED"), "{text}");

    // The log grows; the next checkpoint names the last and extends it.
    append(Path::new(&wal), 11, 15, 100_000);
    s.checkpoint(&wal, "000002.checkpoint", Some("000001.checkpoint"));
    for w in ["w1", "w2"] {
        assert!(s
            .cosign(w, &wal, "000002.checkpoint", 10, 2_000)
            .status
            .success());
    }
    let out = s.verify(
        "000002.checkpoint",
        &["--wal", &wal, "--prev", &s.p("000001.checkpoint")],
    );
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("names checkpoint of size 10"));

    // The first checkpoint still verifies against the grown WAL: its entries
    // are a prefix.
    assert!(s
        .verify("000001.checkpoint", &["--wal", &wal])
        .status
        .success());
}

#[test]
fn a_rewritten_history_signed_with_the_real_key_is_refused_by_the_witness() {
    let s = Setup::new();
    let wal = s.p("real.wal.jsonl");
    append(Path::new(&wal), 1, 10, 100_000);
    s.checkpoint(&wal, "real.checkpoint", None);
    assert!(s
        .cosign("w1", &wal, "real.checkpoint", 0, 1_000)
        .status
        .success());

    // Same log key, same size and more, different decisions.
    let forged = s.p("forged.wal.jsonl");
    append(Path::new(&forged), 1, 12, 999_000);
    s.checkpoint(&forged, "forged.checkpoint", None);
    let out = s.cosign("w1", &forged, "forged.checkpoint", 10, 2_000);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("REFUSED (422)"));

    // Nor can it start over from size 0 with this witness.
    let out = s.cosign("w1", &forged, "forged.checkpoint", 0, 2_000);
    assert!(String::from_utf8_lossy(&out.stderr).contains("REFUSED (409)"));
}

#[test]
fn an_auditor_catches_a_tampered_wal_and_a_missing_quorum() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 6, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    assert!(s
        .cosign("w1", &wal, "c.checkpoint", 0, 1_000)
        .status
        .success());

    // One of two witnesses: the 2-of-2 policy fails.
    let out = s.verify("c.checkpoint", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("1 of the required 2"),
        "{}",
        stdout(&out)
    );

    // A WAL other than the one checkpointed.
    assert!(s
        .cosign("w2", &wal, "c.checkpoint", 0, 1_000)
        .status
        .success());
    let other = s.p("other.wal.jsonl");
    append(Path::new(&other), 1, 6, 5);
    let out = s.verify("c.checkpoint", &["--wal", &other]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("do not reproduce the checkpoint root"));
}

#[test]
fn a_pending_timestamp_is_reported_as_pending_with_exit_code_3() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    for w in ["w1", "w2"] {
        assert!(s.cosign(w, &wal, "c.checkpoint", 0, 1_000).status.success());
    }

    // A proof in the state a calendar leaves it: submitted, not committed.
    let note = SignedNote::parse(&std::fs::read_to_string(s.p("c.checkpoint")).unwrap()).unwrap();
    let mut proof = DetachedTimestamp::new(note.checkpoint().unwrap().digest());
    let commitment = proof.prepare_submission([1; 16]);
    let uri = b"https://alice.btc.calendar.opentimestamps.org";
    let mut body = vec![0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
    body.push(u8::try_from(uri.len() + 1).unwrap());
    body.push(u8::try_from(uri.len()).unwrap());
    body.extend_from_slice(uri);
    proof.merge_calendar_response(&commitment, &body).unwrap();
    let ots_path = PathBuf::from(s.p("c.checkpoint.ots"));
    std::fs::write(&ots_path, proof.serialize()).unwrap();

    let out = s.verify("c.checkpoint", &["--ots", ots_path.to_str().unwrap()]);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("PENDING  OpenTimestamps"), "{text}");
    assert!(text.contains("RESULT: INCOMPLETE"), "{text}");
    assert!(!text.contains("in Bitcoin block"), "{text}");
    assert!(
        text.contains("covers the body only") || text.contains("have not committed"),
        "{text}"
    );
}

#[test]
fn a_revoked_key_counts_only_before_its_revocation() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    for (w, t) in [("w1", 1_000), ("w2", 1_500)] {
        assert!(s.cosign(w, &wal, "c.checkpoint", 0, t).status.success());
    }
    // The quorum had seen it by 1500, the later of the two cosignatures.
    assert!(s
        .verify("c.checkpoint", &["--revoked-at", "1501"])
        .status
        .success());
    let out = s.verify("c.checkpoint", &["--revoked-at", "1500"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("after its key was revoked"),
        "{}",
        stdout(&out)
    );
}

/// The review finding: the operator's own signature must not read as an
/// independent verification, and asking for independence must fail without it.
#[test]
fn a_signature_alone_is_reported_as_exactly_that_and_fails_a_requirement() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);

    let alone = cli(&[
        "checkpoint",
        "verify",
        &s.p("c.checkpoint"),
        "--log-key",
        &s.p("log.vkey"),
    ]);
    assert_eq!(alone.status.code(), Some(0));
    assert!(
        stdout(&alone).contains("RESULT: SIGNATURE VERIFIED ONLY"),
        "{}",
        stdout(&alone)
    );
    assert!(!stdout(&alone).contains("FULL VERIFICATION"));

    for req in ["witnessed", "timestamped", "bitcoin", "full"] {
        let out = cli(&[
            "checkpoint",
            "verify",
            &s.p("c.checkpoint"),
            "--log-key",
            &s.p("log.vkey"),
            "--require",
            req,
        ]);
        assert_eq!(out.status.code(), Some(1), "--require {req}");
        assert!(
            stdout(&out).contains("REQUIREMENT NOT MET"),
            "{}",
            stdout(&out)
        );
    }

    // Witnessed, but no timestamp: `full` still fails, `witnessed` passes.
    for w in ["w1", "w2"] {
        assert!(s.cosign(w, &wal, "c.checkpoint", 0, 1_000).status.success());
    }
    assert_eq!(
        s.verify("c.checkpoint", &["--require", "witnessed"])
            .status
            .code(),
        Some(0)
    );
    let out = s.verify("c.checkpoint", &["--require", "full"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("REQUIREMENT NOT MET: full"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn an_upgrade_skips_calendars_off_the_allowlist_and_says_how_to_admit_them() {
    let s = Setup::new();
    let mut proof = DetachedTimestamp::new([7; 32]);
    let commitment = proof.prepare_submission([1; 16]);
    let uri = b"https://my.calendar.example";
    let mut body = vec![0x00, 0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
    body.push(u8::try_from(uri.len() + 1).unwrap());
    body.push(u8::try_from(uri.len()).unwrap());
    body.extend_from_slice(uri);
    proof.merge_calendar_response(&commitment, &body).unwrap();
    let path = s.p("custom.ots");
    std::fs::write(&path, proof.serialize()).unwrap();

    let out = cli(&["checkpoint", "upgrade", &path]);
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("skipping") && err.contains("--allow-calendar"),
        "{err}"
    );
}
