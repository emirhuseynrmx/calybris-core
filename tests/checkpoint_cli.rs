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

#[cfg(feature = "preview-tsa")]
#[test]
fn real_timestamp_fixture_reports_timestamp_only_full_and_wrong_nonce_failure() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trust-demo");
    let file = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let note = file("000001.checkpoint");
    let key = file("log.vkey");
    let tsr = file("000001.checkpoint.signed.tsr");
    let cert = file("freetsa-tsa.crt");
    let witness = file("witness.vkey");
    let nonce = std::fs::read_to_string(file("000001.checkpoint.signed.nonce")).unwrap();
    let mut args = vec![
        "checkpoint",
        "verify",
        &note,
        "--log-key",
        &key,
        "--tsr",
        &tsr,
        "--tsa-cert",
        &cert,
        "--nonce",
        nonce.trim(),
        "--require",
        "timestamped",
    ];
    let out = cli(&args);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("RESULT: TIMESTAMP VERIFIED"));
    *args.last_mut().unwrap() = "full";
    assert!(!cli(&args).status.success());
    args.extend(["--witness", &witness]);
    let out = cli(&args);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("RESULT: FULL VERIFICATION COMPLETE"));
    // These pins check signatures, not whether the witness operator is independent.
    let pos = args.iter().position(|v| *v == "--nonce").unwrap();
    args[pos + 1] = "1";
    let out = cli(&args);
    assert!(!out.status.success());
    assert!(!stdout(&out).contains("FULL VERIFICATION COMPLETE"));
}

#[test]
fn two_real_processes_cannot_cosign_forks_from_the_same_state() {
    let s = Setup::new();
    let mut requests = Vec::new();
    for (name, value) in [("left", 100_000), ("right", 900_000)] {
        let wal = s.p(&format!("{name}.wal.jsonl"));
        let note = format!("{name}.checkpoint");
        append(Path::new(&wal), 1, 5, value);
        s.checkpoint(&wal, &note, None);
        let request = ok(&[
            "checkpoint",
            "request",
            &wal,
            "--note",
            &s.p(&note),
            "--old",
            "0",
        ]);
        let path = s.p(&format!("{name}.request"));
        std::fs::write(&path, request).unwrap();
        requests.push(path);
    }
    // A witness's state is created once, before any process shares it.
    ok(&["witness", "init", "--state", &s.p("shared.state.json")]);
    let children: Vec<_> = requests
        .iter()
        .map(|req| {
            Command::new(env!("CARGO_BIN_EXE_calybris-verify"))
                .args([
                    "witness",
                    "cosign",
                    req,
                    "--key",
                    &s.p("w1.skey"),
                    "--log",
                    &format!("{ORIGIN}={}", s.p("log.vkey")),
                    "--state",
                    &s.p("shared.state.json"),
                    "--now",
                    "1000",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let results: Vec<_> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.status.success()).count(), 1);
    let failure = results.iter().find(|r| !r.status.success()).unwrap();
    assert!(String::from_utf8_lossy(&failure.stderr).contains("REFUSED (409)"));
}

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
            ok(&[
                "witness",
                "init",
                "--state",
                &s.p(&format!("{w}.state.json")),
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

/// A witness whose state file is gone refuses to cosign instead of starting
/// again from nothing, and `witness init` never overwrites a state.
#[test]
fn a_witness_without_its_state_file_refuses_and_init_never_resets_one() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    assert!(s
        .cosign("w1", &wal, "c.checkpoint", 0, 1_000)
        .status
        .success());

    let state = s.p("w1.state.json");
    let again = cli(&["witness", "init", "--state", &state]);
    assert_eq!(again.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));

    std::fs::remove_file(&state).unwrap();
    append(Path::new(&wal), 4, 6, 100_000);
    s.checkpoint(&wal, "d.checkpoint", None);
    let out = s.cosign("w1", &wal, "d.checkpoint", 0, 2_000);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("is missing") && err.contains("witness init"),
        "{err}"
    );
    assert!(
        !Path::new(&state).exists(),
        "the refusal must not create a state"
    );
}

/// Every way the tool is told no: each command, what it must exit with, and
/// what it must say. A wrong input is exit 1 with a reason, a malformed
/// command line exit 2 with the usage; a failed check inside `verify` is a
/// FAILED line, never a crash or a pass.
#[test]
fn every_refusal_exits_with_its_code_and_says_why() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 4, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    let short = s.p("short.wal.jsonl");
    append(Path::new(&short), 1, 2, 100_000);
    let other = s.p("other.wal.jsonl");
    append(Path::new(&other), 1, 4, 555_000);
    s.checkpoint(&short, "small.checkpoint", None);
    let note = s.p("c.checkpoint");
    let vkey = s.p("log.vkey");
    let garbage = s.p("garbage.txt");
    std::fs::write(&garbage, "not a key or a note\n").unwrap();
    let missing = s.p("missing.checkpoint");
    let w1_vkey = s.p("w1.vkey");
    let small = s.p("small.checkpoint");
    let tsr = format!(
        "{}/tests/fixtures/rfc3161/rsa.tsr",
        env!("CARGO_MANIFEST_DIR")
    );
    let tsa_cert = format!(
        "{}/tests/fixtures/rfc3161/rsa.crt",
        env!("CARGO_MANIFEST_DIR")
    );
    fn verify<'a>(note: &'a str, vkey: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut a = vec!["checkpoint", "verify", note, "--log-key", vkey];
        a.extend_from_slice(extra);
        a
    }

    let cases: Vec<(Vec<&str>, i32, &str)> = vec![
        (vec!["checkpoint"], 2, "missing subcommand"),
        (vec!["checkpoint", "nope"], 2, "unknown command"),
        (vec!["witness", "verify"], 2, "unknown command"),
        (vec!["checkpoint", "verify", "--bogus"], 2, "unknown option"),
        (
            vec!["checkpoint", "verify", "--log-key"],
            2,
            "needs a value",
        ),
        (vec!["checkpoint", "verify"], 1, "exactly one file"),
        (
            vec!["checkpoint", "verify", &note],
            1,
            "--log-key is required",
        ),
        (
            vec!["checkpoint", "verify", &missing, "--log-key", &vkey],
            1,
            "cannot read",
        ),
        (
            vec!["checkpoint", "verify", &garbage, "--log-key", &vkey],
            1,
            "",
        ),
        (
            vec!["checkpoint", "verify", &note, "--log-key", &garbage],
            1,
            "",
        ),
        (
            vec![
                "checkpoint",
                "keygen",
                "--name",
                "x",
                "--kind",
                "nope",
                "--out",
                &garbage,
            ],
            1,
            "--kind",
        ),
        (
            vec![
                "checkpoint",
                "create",
                &missing,
                "--origin",
                ORIGIN,
                "--key",
                &vkey,
            ],
            1,
            "WAL",
        ),
        (
            vec![
                "checkpoint",
                "create",
                &wal,
                "--origin",
                ORIGIN,
                "--key",
                &garbage,
            ],
            1,
            "",
        ),
        (
            vec![
                "checkpoint",
                "create",
                &short,
                "--origin",
                ORIGIN,
                "--key",
                &vkey,
                "--prev",
                &note,
            ],
            1,
            "does not extend",
        ),
        (
            vec![
                "checkpoint",
                "create",
                &wal,
                "--origin",
                "other.example/log",
                "--key",
                &vkey,
                "--prev",
                &note,
            ],
            1,
            "another log",
        ),
        (
            vec!["checkpoint", "request", &wal, "--note", &note, "--old", "x"],
            1,
            "--old must be a number",
        ),
        (
            vec!["checkpoint", "request", &wal, "--note", &note, "--old", "9"],
            1,
            "larger than the checkpoint",
        ),
        (
            vec![
                "checkpoint",
                "request",
                &short,
                "--note",
                &note,
                "--old",
                "0",
            ],
            1,
            "not a checkpoint of this WAL",
        ),
        (
            vec![
                "checkpoint",
                "tsa-request",
                &note,
                "--log-key",
                &vkey,
                "--nonce",
                "x",
            ],
            1,
            "--nonce",
        ),
        (vec!["checkpoint", "upgrade", &garbage], 1, ""),
        (
            verify(&note, &vkey, &["--threshold", "x", "--witness", &w1_vkey]),
            1,
            "--threshold",
        ),
        (verify(&note, &vkey, &["--witness", &garbage]), 1, ""),
        (
            verify(&note, &vkey, &["--revoked-at", "x"]),
            1,
            "Unix seconds",
        ),
        (
            verify(&note, &vkey, &["--require", "everything"]),
            1,
            "--require takes",
        ),
        (
            verify(&note, &vkey, &["--wal", &short]),
            1,
            "FAILED   WAL: has 2 entries",
        ),
        (
            verify(&note, &vkey, &["--wal", &other]),
            1,
            "do not reproduce the checkpoint root",
        ),
        (
            verify(&note, &vkey, &["--prev", &small]),
            1,
            "does not name --prev",
        ),
        (
            verify(&note, &vkey, &["--ots", &garbage]),
            1,
            "FAILED   OpenTimestamps",
        ),
        (verify(&note, &vkey, &["--tsr", &tsr]), 1, "--tsa-cert"),
        (
            verify(&note, &vkey, &["--tsr", &tsr, "--tsa-cert", &tsa_cert]),
            1,
            "FAILED   RFC 3161",
        ),
        (
            verify(&note, &vkey, &["--revoked-at", "1"]),
            1,
            "FAILED   revoked key",
        ),
    ];
    for (args, code, says) in &cases {
        let out = cli(args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(*code), "{args:?}\n{text}");
        assert!(text.contains(says), "{args:?} should say {says:?}\n{text}");
    }
    // The prev link that is larger than the checkpoint it precedes.
    let out = cli(&[
        "checkpoint",
        "verify",
        &s.p("small.checkpoint"),
        "--log-key",
        &vkey,
        "--prev",
        &note,
    ]);
    assert!(
        stdout(&out).contains("larger than this checkpoint"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_tsa_request_is_written_for_the_signed_note_with_its_nonce() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    let note = s.p("c.checkpoint");
    let out = cli(&[
        "checkpoint",
        "tsa-request",
        &note,
        "--log-key",
        &s.p("log.vkey"),
        "--nonce",
        "42",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout(&out).trim(), "42");
    let tsq = std::fs::read(format!("{note}.signed.tsq")).unwrap();
    let signed = std::fs::read(format!("{note}.signed")).unwrap();
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&signed);
    assert!(
        tsq.windows(32).any(|w| w == digest.as_slice()),
        "the request carries the digest"
    );
    // Without --nonce, a random one is chosen and printed.
    let out = cli(&[
        "checkpoint",
        "tsa-request",
        &note,
        "--log-key",
        &s.p("log.vkey"),
    ]);
    assert!(
        stdout(&out).trim().parse::<u64>().is_ok(),
        "{}",
        stdout(&out)
    );
}

/// A calendar that cannot be reached costs the timestamp and nothing else:
/// the tool says so, exits 1 and writes no proof.
#[test]
fn an_unreachable_calendar_writes_no_proof() {
    if Command::new("curl").arg("--version").output().is_err() {
        return;
    }
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let calendar = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let note = s.p("c.checkpoint");
    let out = cli(&[
        "checkpoint",
        "stamp",
        &note,
        "--log-key",
        &s.p("log.vkey"),
        "--calendar",
        &calendar,
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no calendar accepted"));
    assert!(!Path::new(&format!("{note}.signed.ots")).exists());
}

/// Without `--now` a witness dates its cosignature by the system clock.
#[test]
fn a_witness_dates_by_the_clock_when_not_told_the_time() {
    let s = Setup::new();
    let wal = s.p("decisions.wal.jsonl");
    append(Path::new(&wal), 1, 3, 100_000);
    s.checkpoint(&wal, "c.checkpoint", None);
    let req = ok(&[
        "checkpoint",
        "request",
        &wal,
        "--note",
        &s.p("c.checkpoint"),
        "--old",
        "0",
    ]);
    let req_path = s.p("c.req");
    std::fs::write(&req_path, req).unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    ok(&[
        "witness",
        "cosign",
        &req_path,
        "--key",
        &s.p("w1.skey"),
        "--log",
        &format!("{ORIGIN}={}", s.p("log.vkey")),
        "--state",
        &s.p("w1.state.json"),
        "--append-to",
        &s.p("c.checkpoint"),
    ]);
    let note = SignedNote::parse(&std::fs::read_to_string(s.p("c.checkpoint")).unwrap()).unwrap();
    let w1 = calybris_core::checkpoint::NoteVerifier::parse(
        std::fs::read_to_string(s.p("w1.vkey")).unwrap().trim(),
    )
    .unwrap();
    let t = note.cosignature_time(&w1).unwrap();
    assert!(t >= before && t < before + 600, "{t} vs {before}");
}

/// The bundle in `tests/fixtures/bundle` is checked twice, by two programs
/// that share no code: here by this tool, and in `scripts/tests` by
/// `scripts/verify_bundle.py`, which needs nothing but Python.
#[test]
fn the_committed_bundle_verifies_with_the_tool_as_it_does_without_it() {
    let dir = format!("{}/tests/fixtures/bundle", env!("CARGO_MANIFEST_DIR"));
    let f = |name: &str| format!("{dir}/{name}");
    let out = cli(&[
        "checkpoint",
        "verify",
        &f("000001.checkpoint"),
        "--log-key",
        &f("log.vkey"),
        "--witness",
        &f("witness.vkey"),
        "--wal",
        &f("decisions.wal.jsonl"),
        "--require",
        "witnessed",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("RESULT: INDEPENDENTLY WITNESSED"));
    let note =
        SignedNote::parse(&std::fs::read_to_string(f("000001.checkpoint")).unwrap()).unwrap();
    let log = calybris_core::checkpoint::NoteVerifier::parse(
        std::fs::read_to_string(f("log.vkey")).unwrap().trim(),
    )
    .unwrap();
    assert_eq!(
        note.signed_by(&log).unwrap(),
        std::fs::read_to_string(f("000001.checkpoint.signed")).unwrap()
    );
}
