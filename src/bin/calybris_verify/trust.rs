//! `calybris-verify checkpoint …` and `calybris-verify witness …`: signed
//! checkpoints over a WAL, witness cosigning, OpenTimestamps and RFC 3161.
//!
//! ```text
//! calybris-verify checkpoint keygen   --name NAME --kind log|witness --out PREFIX
//! calybris-verify checkpoint create   <wal> --origin ORIGIN --key LOG.skey [--prev PREV] [--out FILE] [--hmac-key-hex HEX]
//! calybris-verify checkpoint request  <wal> --note FILE --old N [--hmac-key-hex HEX]
//! calybris-verify witness cosign      <request> --key W.skey --log ORIGIN=LOG.vkey --state STATE.json [--now UNIX] [--append-to NOTE]
//! calybris-verify checkpoint stamp    <note> --log-key LOG.vkey [--calendar URL ...]
//! calybris-verify checkpoint upgrade  <note.signed.ots> [--allow-calendar PATTERN ...]
//! calybris-verify checkpoint tsa-request <note> --log-key LOG.vkey [--nonce N]
//! calybris-verify checkpoint verify   <note> --log-key LOG.vkey
//!                                     [--witness W.vkey ... --threshold K]
//!                                     [--wal WAL [--hmac-key-hex HEX]] [--prev PREV]
//!                                     [--ots NOTE.signed.ots [--block-height H --block-header HEX --block-hash HASH]]
//!                                     [--tsr NOTE.signed.tsr --tsa-cert CERT.pem [--nonce N]]
//!                                     [--revoked-at UNIX] [--require witnessed|timestamped|bitcoin|full]
//! ```
//!
//! The network is reached only by `stamp` and `upgrade`, through the system
//! `curl` (present on Windows 10 and later, macOS and Linux), so the library
//! stays free of an HTTP stack. Everything `verify` checks is offline.
//!
//! `verify` never lets the operator's own signature pass for more than it is.
//! Its last line names what was established — `SIGNATURE VERIFIED ONLY`,
//! `INDEPENDENTLY WITNESSED`, `TIMESTAMP VERIFIED` or `FULL VERIFICATION
//! COMPLETE` — and `--require` turns a missing level into a failure.
//! Timestamps are taken over the log-signed note (`<note>.signed`), so they
//! date the signature and not only the body; a Bitcoin block counts only once
//! `--block-hash` from a node you trust confirms it.
//!
//! Exit codes: 0 no check failed and every `--require` was met; 1 a check
//! failed or a requirement was not met; 2 usage; 3 nothing failed but a
//! timestamp is still pending, or its block is not confirmed.

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use calybris_core::audit::{existed_by, Covers, KeyStatus, TimeEvidence, WitnessPolicy};
use calybris_core::checkpoint::{Checkpoint, LogSigner, NoteVerifier, SignedNote, WitnessSigner};
use calybris_core::merkle::{
    consistency_proof, leaf_from_entry_hash, leaf_hash, root_of, Hash, TreeHead,
};
use calybris_core::ots::{self, DetachedTimestamp, Status};
use calybris_core::wal::{visit_verified_wal, visit_verified_wal_keyed};
use calybris_core::witness::{AddCheckpoint, FileStore, Witness};
use sha2::{Digest, Sha256};

const EXIT_INCOMPLETE: u8 = 3;

type Fail = String;

struct Flags {
    positional: Vec<String>,
    pairs: Vec<(String, String)>,
}

impl Flags {
    fn parse(args: &[String], valued: &[&str]) -> Result<Self, Fail> {
        let mut positional = Vec::new();
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                pairs.push((a.clone(), v.clone()));
            } else if a.starts_with("--") {
                return Err(format!("unknown option {a}"));
            } else {
                positional.push(a.clone());
            }
        }
        Ok(Self { positional, pairs })
    }

    fn one(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn need(&self, name: &str) -> Result<&str, Fail> {
        self.one(name).ok_or_else(|| format!("{name} is required"))
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn target(&self) -> Result<&str, Fail> {
        match self.positional.as_slice() {
            [one] => Ok(one),
            _ => Err("expected exactly one file argument".into()),
        }
    }
}

fn read_text(path: &str) -> Result<String, Fail> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn read_key_text(path: &str) -> Result<String, Fail> {
    Ok(read_text(path)?.trim().to_owned())
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), Fail> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {path}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    calybris_core::digest::bytes_to_hex(bytes)
}

fn unhex(s: &str) -> Result<Vec<u8>, Fail> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected hexadecimal".into());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked hex"))
        .collect())
}

fn random<const N: usize>() -> Result<[u8; N], Fail> {
    let mut b = [0_u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("no system randomness: {e}"))?;
    Ok(b)
}

/// `YYYY-MM-DD HH:MM:SS UTC` for a Unix time.
fn utc(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    // Howard Hinnant's days-from-civil, inverted.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// The Merkle leaf hashes of a WAL: one per entry, over its `entry_hash`.
fn wal_leaves(path: &str, hmac_key: Option<&[u8]>) -> Result<Vec<Hash>, Fail> {
    let mut leaves = Vec::new();
    let mut bad = None;
    let mut visit =
        |entry: calybris_core::wal::WalEntry<serde_json::Value>| match leaf_from_entry_hash(
            &entry.entry_hash,
        ) {
            Ok(data) => leaves.push(leaf_hash(&data)),
            Err(e) => bad = Some(e.to_string()),
        };
    let result = match hmac_key {
        Some(k) => visit_verified_wal_keyed(Path::new(path), k, &mut visit),
        None => visit_verified_wal(Path::new(path), &mut visit),
    };
    result.map_err(|e| format!("WAL {path}: {e}"))?;
    if let Some(e) = bad {
        return Err(format!("WAL {path}: {e}"));
    }
    Ok(leaves)
}

fn hmac_key(f: &Flags) -> Result<Option<Vec<u8>>, Fail> {
    f.one("--hmac-key-hex")
        .map(super::parse_hex_key)
        .transpose()
}

fn open_note(path: &str) -> Result<(SignedNote, Checkpoint), Fail> {
    let note = SignedNote::parse(&read_text(path)?).map_err(|e| format!("{path}: {e}"))?;
    let cp = note.checkpoint().map_err(|e| format!("{path}: {e}"))?;
    Ok((note, cp))
}

fn prev_line(prev_body: &str) -> String {
    format!("prev {}", hex(&Sha256::digest(prev_body.as_bytes())))
}

fn keygen(f: &Flags) -> Result<ExitCode, Fail> {
    let name = f.need("--name")?;
    let out = f.need("--out")?;
    let seed = random::<32>()?;
    let (skey, vkey) = match f.need("--kind")? {
        "log" => {
            let s = LogSigner::from_seed(name, &seed).map_err(|e| e.to_string())?;
            (s.to_skey(), s.verifier().to_vkey())
        }
        "witness" => {
            let s = WitnessSigner::from_seed(name, &seed).map_err(|e| e.to_string())?;
            (s.to_skey(), s.verifier().to_vkey())
        }
        other => return Err(format!("--kind must be log or witness, not {other}")),
    };
    write_file(&format!("{out}.skey"), format!("{skey}\n").as_bytes())?;
    write_file(&format!("{out}.vkey"), format!("{vkey}\n").as_bytes())?;
    println!("{vkey}");
    eprintln!("wrote {out}.skey (secret: keep it off shared disks) and {out}.vkey (public)");
    Ok(ExitCode::SUCCESS)
}

fn create(f: &Flags) -> Result<ExitCode, Fail> {
    let wal = f.target()?;
    let key = hmac_key(f)?;
    let leaves = wal_leaves(wal, key.as_deref())?;
    let head = TreeHead {
        size: leaves.len() as u64,
        root: root_of(&leaves),
    };
    let mut cp = Checkpoint::new(f.need("--origin")?, head).map_err(|e| e.to_string())?;
    if let Some(prev) = f.one("--prev") {
        let (_, prev_cp) = open_note(prev)?;
        if prev_cp.origin() != cp.origin() {
            return Err("--prev is a checkpoint of another log".into());
        }
        if prev_cp.size() > head.size
            || (prev_cp.size() > 0
                && root_of(&leaves[..prev_cp.size() as usize]) != *prev_cp.root())
        {
            return Err("this WAL does not extend the --prev checkpoint".into());
        }
        cp = cp
            .with_extension(&prev_line(&prev_cp.body()))
            .map_err(|e| e.to_string())?;
    }
    let signer =
        LogSigner::from_skey(&read_key_text(f.need("--key")?)?).map_err(|e| e.to_string())?;
    let note = signer.sign(&cp).render();
    match f.one("--out") {
        Some(out) => write_file(out, note.as_bytes())?,
        None => print!("{note}"),
    }
    eprintln!(
        "checkpoint {} size {}; digest to timestamp {}",
        cp.origin(),
        cp.size(),
        hex(&cp.digest())
    );
    Ok(ExitCode::SUCCESS)
}

fn request(f: &Flags) -> Result<ExitCode, Fail> {
    let wal = f.target()?;
    let leaves = wal_leaves(wal, hmac_key(f)?.as_deref())?;
    let note_text = read_text(f.need("--note")?)?;
    let (_, cp) = open_note(f.need("--note")?)?;
    let old: u64 = f
        .need("--old")?
        .parse()
        .map_err(|_| "--old must be a number")?;
    if cp.size() != leaves.len() as u64 || *cp.root() != root_of(&leaves) {
        return Err("the note is not a checkpoint of this WAL".into());
    }
    if old > cp.size() {
        return Err("--old is larger than the checkpoint".into());
    }
    let proof = if old == 0 || old == cp.size() {
        Vec::new()
    } else {
        consistency_proof(&leaves, old).map_err(|e| e.to_string())?
    };
    print!(
        "{}",
        AddCheckpoint {
            old_size: old,
            proof,
            note: note_text,
        }
        .render()
    );
    Ok(ExitCode::SUCCESS)
}

fn cosign(f: &Flags) -> Result<ExitCode, Fail> {
    let req = AddCheckpoint::parse(&read_text(f.target()?)?).map_err(|e| e.to_string())?;
    let signer =
        WitnessSigner::from_skey(&read_key_text(f.need("--key")?)?).map_err(|e| e.to_string())?;
    let mut witness = Witness::new(signer, FileStore::new(f.need("--state")?));
    for spec in f.all("--log") {
        let (origin, path) = spec.split_once('=').ok_or("--log takes ORIGIN=VKEYFILE")?;
        let key = NoteVerifier::parse(&read_key_text(path)?).map_err(|e| e.to_string())?;
        witness.add_log(origin, key);
    }
    let now = match f.one("--now") {
        Some(t) => t.parse().map_err(|_| "--now must be Unix seconds")?,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "the system clock is before 1970")?
            .as_secs(),
    };
    match witness.add_checkpoint(&req, now) {
        Ok(sig) => {
            print!("{}", sig.line());
            if let Some(path) = f.one("--append-to") {
                let mut note = SignedNote::parse(&read_text(path)?).map_err(|e| e.to_string())?;
                note.add_signature(sig).map_err(|e| e.to_string())?;
                write_file(path, note.render().as_bytes())?;
                eprintln!("cosignature appended to {path}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("REFUSED ({}): {e}", e.http_status());
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Runs `curl` with `args`, feeding `body` on stdin when given. `None` for a
/// 404, the calendar's way of saying "not yet".
fn curl(url: &str, body: Option<&[u8]>) -> Result<Option<Vec<u8>>, Fail> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--max-time",
        "30",
        "--max-filesize",
        "65536",
        "--write-out",
        "\n%{http_code}",
        "--header",
        "Accept: application/vnd.opentimestamps.v1",
        "--user-agent",
        "calybris-verify",
    ]);
    if body.is_some() {
        cmd.args(["--data-binary", "@-"]);
    }
    cmd.arg(url)
        .stdin(if body.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("cannot run curl: {e}"))?;
    if let Some(b) = body {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(b)
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "curl {url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let split = out
        .stdout
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or("curl gave no status")?;
    let code = String::from_utf8_lossy(&out.stdout[split + 1..]).to_string();
    let body = out.stdout[..split].to_vec();
    match code.as_str() {
        "200" => Ok(Some(body)),
        "404" => Ok(None),
        other => Err(format!("{url} answered HTTP {other}")),
    }
}

fn print_status(status: &Status) {
    match status {
        Status::Pending { calendars } => println!(
            "OTS PENDING: accepted by {}; not yet in Bitcoin, run `checkpoint upgrade` in a few hours",
            calendars.join(", ")
        ),
        Status::Anchored { heights } => println!(
            "OTS ANCHORED at Bitcoin block {heights:?}; verify with --block-height, --block-header and --block-hash from a node you trust"
        ),
    }
}

/// The log-signed note as bytes, written next to the note as `<note>.signed`:
/// what `stamp` and `tsa-request` timestamp, so the timestamp covers the log's
/// signature and not only the body.
fn signed_bytes(f: &Flags, path: &str) -> Result<(String, String), Fail> {
    let (note, _) = open_note(path)?;
    let log =
        NoteVerifier::parse(&read_key_text(f.need("--log-key")?)?).map_err(|e| e.to_string())?;
    let signed = note.signed_by(&log).map_err(|e| format!("{path}: {e}"))?;
    let out = format!("{path}.signed");
    write_file(&out, signed.as_bytes())?;
    Ok((out, signed))
}

fn stamp(f: &Flags) -> Result<ExitCode, Fail> {
    let path = f.target()?;
    let (signed_path, signed) = signed_bytes(f, path)?;
    let mut proof = DetachedTimestamp::new(Sha256::digest(signed.as_bytes()).into());
    let commitment = proof.prepare_submission(random::<16>()?);
    let calendars = f.all("--calendar");
    let calendars: Vec<&str> = if calendars.is_empty() {
        ots::DEFAULT_CALENDARS.to_vec()
    } else {
        calendars
    };
    let mut accepted = 0;
    for cal in calendars {
        match curl(&ots::calendar_submit_path(cal), Some(&commitment)) {
            Ok(Some(body)) => match proof.merge_calendar_response(&commitment, &body) {
                Ok(()) => accepted += 1,
                Err(e) => eprintln!("{cal}: unusable answer: {e}"),
            },
            Ok(None) => eprintln!("{cal}: not found"),
            Err(e) => eprintln!("{cal}: {e}"),
        }
    }
    if accepted == 0 {
        return Err("no calendar accepted the checkpoint".into());
    }
    let out = format!("{signed_path}.ots");
    write_file(&out, &proof.serialize())?;
    eprintln!("wrote {signed_path} (the stamped bytes) and {out} ({accepted} calendars)");
    print_status(&proof.status());
    Ok(ExitCode::from(EXIT_INCOMPLETE))
}

fn upgrade(f: &Flags) -> Result<ExitCode, Fail> {
    let path = f.target()?;
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut proof = DetachedTimestamp::parse(&raw).map_err(|e| e.to_string())?;
    // A calendar used with `stamp --calendar` is not on the default list;
    // `--allow-calendar` admits it (and any other pattern) for the upgrade.
    let mut allowed: Vec<&str> = ots::DEFAULT_UPGRADE_ALLOWLIST.to_vec();
    allowed.extend(f.all("--allow-calendar"));
    let mut changed = false;
    for (commitment, uri) in proof.pending() {
        let url = match ots::calendar_upgrade_path(&uri, &commitment, &allowed) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("skipping: {e} (add it with --allow-calendar if you trust it)");
                continue;
            }
        };
        match curl(&url, None) {
            Ok(Some(body)) => match proof.merge_calendar_response(&commitment, &body) {
                Ok(()) => changed = true,
                Err(e) => eprintln!("{uri}: unusable answer: {e}"),
            },
            Ok(None) => eprintln!("{uri}: not yet committed"),
            Err(e) => eprintln!("{uri}: {e}"),
        }
    }
    if changed {
        write_file(path, &proof.serialize())?;
    }
    let status = proof.status();
    print_status(&status);
    Ok(if matches!(status, Status::Pending { .. }) {
        ExitCode::from(EXIT_INCOMPLETE)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(feature = "preview-tsa")]
fn tsa_request(f: &Flags) -> Result<ExitCode, Fail> {
    let path = f.target()?;
    let (signed_path, signed) = signed_bytes(f, path)?;
    let nonce = match f.one("--nonce") {
        Some(n) => n.parse().map_err(|_| "--nonce must be a number")?,
        None => u64::from_be_bytes(random::<8>()?),
    };
    let digest: [u8; 32] = Sha256::digest(signed.as_bytes()).into();
    let der = calybris_core::tsa::request(&digest, Some(nonce)).map_err(|e| e.to_string())?;
    let out = format!("{signed_path}.tsq");
    write_file(&out, &der)?;
    println!("{nonce}");
    eprintln!(
        "wrote {out}; nonce {nonce} (pass it to verify). Send it with:\n  curl -H \"Content-Type: application/timestamp-query\" --data-binary @{out} -o {signed_path}.tsr https://freetsa.org/tsr"
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "preview-tsa"))]
fn tsa_request(_: &Flags) -> Result<ExitCode, Fail> {
    Err("built without the preview-tsa feature".into())
}

/// What a verification established, beyond "no check failed".
#[derive(Default)]
struct Report {
    failed: bool,
    incomplete: bool,
    /// A quorum of the witnesses named with --witness cosigned.
    witnessed: bool,
    /// An RFC 3161 token verified, or a Bitcoin block confirmed.
    timestamped: bool,
    /// The Bitcoin block was confirmed against --block-hash.
    bitcoin: bool,
    evidence: Vec<TimeEvidence>,
}

impl Report {
    fn ok(&mut self, what: &str, detail: &str) {
        println!("  ok       {what}: {detail}");
    }
    fn fail(&mut self, what: &str, detail: &str) {
        self.failed = true;
        println!("  FAILED   {what}: {detail}");
    }
    fn pending(&mut self, what: &str, detail: &str) {
        self.incomplete = true;
        println!("  PENDING  {what}: {detail}");
    }
    fn note(&mut self, what: &str, detail: &str) {
        println!("  note     {what}: {detail}");
    }
}

/// What `--require` asked for and was not established.
fn unmet(f: &Flags, r: &Report) -> Result<Vec<&'static str>, Fail> {
    let mut missing = Vec::new();
    for req in f.all("--require").iter().flat_map(|v| v.split(',')) {
        let (name, met) = match req.trim() {
            "witnessed" => ("witnessed", r.witnessed),
            "timestamped" => ("timestamped", r.timestamped),
            "bitcoin" => ("bitcoin", r.bitcoin),
            "full" => ("full", r.witnessed && r.timestamped),
            other => {
                return Err(format!(
                    "--require takes witnessed, timestamped, bitcoin or full, not {other:?}"
                ))
            }
        };
        if !met && !missing.contains(&name) {
            missing.push(name);
        }
    }
    Ok(missing)
}

fn verify(f: &Flags) -> Result<ExitCode, Fail> {
    let path = f.target()?;
    let (note, cp) = open_note(path)?;
    let mut r = Report::default();
    println!(
        "checkpoint {} size {} root {}",
        cp.origin(),
        cp.size(),
        hex(cp.root())
    );

    let log =
        NoteVerifier::parse(&read_key_text(f.need("--log-key")?)?).map_err(|e| e.to_string())?;
    match note.verify(&log) {
        Ok(()) => r.ok("log signature", log.name()),
        Err(e) => r.fail("log signature", &e.to_string()),
    }
    // What a timestamp over the signature is a timestamp of. `None` when the
    // log signature does not verify, which has already failed the run.
    let signed = note.signed_by(&log).ok();
    check_witnesses(f, &note, &log, &mut r)?;
    if let Some(wal) = f.one("--wal") {
        check_wal(f, wal, &cp, &mut r)?;
    }
    if let Some(prev) = f.one("--prev") {
        check_prev(prev, &cp, &mut r)?;
    }
    let stamped = Stamped {
        signature: signed.map(|s| Sha256::digest(s.as_bytes()).into()),
        content: cp.digest(),
    };
    if let Some(ots_path) = f.one("--ots") {
        check_ots(f, ots_path, &stamped, &mut r)?;
    }
    if let Some(tsr) = f.one("--tsr") {
        verify_tsr(f, tsr, &stamped, &mut r)?;
    }

    match existed_by(&r.evidence) {
        Some(t) => println!("  existed by {} (earliest independent evidence)", utc(t)),
        None => println!("  existed by: no independent time evidence"),
    }
    if let Some(revoked) = f.one("--revoked-at") {
        let at: u64 = revoked
            .parse()
            .map_err(|_| "--revoked-at must be Unix seconds")?;
        match (KeyStatus::Revoked { at }).accepts(&r.evidence) {
            Ok(()) => r.ok(
                "revoked key",
                &format!("signature proven before its revocation at {}", utc(at)),
            ),
            Err(e) => r.fail("revoked key", &e.to_string()),
        }
    }

    let missing = unmet(f, &r)?;
    Ok(verdict(&r, &missing))
}

fn verdict(r: &Report, missing: &[&str]) -> ExitCode {
    if r.failed {
        println!("RESULT: FAILED");
        return ExitCode::FAILURE;
    }
    if !missing.is_empty() {
        println!("RESULT: REQUIREMENT NOT MET: {}", missing.join(", "));
        return ExitCode::FAILURE;
    }
    if r.incomplete {
        println!("RESULT: INCOMPLETE — a timestamp is still pending or unconfirmed");
        return ExitCode::from(EXIT_INCOMPLETE);
    }
    match (r.witnessed, r.timestamped) {
        (true, true) => println!("RESULT: FULL VERIFICATION COMPLETE — signature, independent witnesses, independent timestamp"),
        (true, false) => println!("RESULT: INDEPENDENTLY WITNESSED — no independent timestamp was checked"),
        (false, true) => println!("RESULT: TIMESTAMP VERIFIED — no independent witness was checked"),
        (false, false) => println!("RESULT: SIGNATURE VERIFIED ONLY — the operator's own signature; nothing independent was checked"),
    }
    ExitCode::SUCCESS
}

fn check_witnesses(
    f: &Flags,
    note: &SignedNote,
    log: &NoteVerifier,
    r: &mut Report,
) -> Result<(), Fail> {
    let witness_files = f.all("--witness");
    if witness_files.is_empty() {
        return Ok(());
    }
    let keys = witness_files
        .iter()
        .map(|p| NoteVerifier::parse(&read_key_text(p)?).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold: usize = f
        .one("--threshold")
        .map_or(Ok(keys.len()), str::parse)
        .map_err(|_| "--threshold must be a number")?;
    let policy = WitnessPolicy::new(keys, threshold).map_err(|e| e.to_string())?;
    match calybris_core::audit::verify_checkpoint(&note.render(), log, &policy) {
        Ok(w) => {
            let names: Vec<String> = w
                .cosigned
                .iter()
                .map(|c| format!("{} at {}", c.witness, utc(c.time)))
                .collect();
            r.ok(
                "witnesses",
                &format!(
                    "{} of {} required: {}",
                    w.cosigned.len(),
                    threshold,
                    names.join("; ")
                ),
            );
            r.witnessed = true;
            r.evidence.push(TimeEvidence::witnesses(w.seen_by()));
        }
        Err(e) => r.fail("witnesses", &e.to_string()),
    }
    Ok(())
}

fn check_wal(f: &Flags, wal: &str, cp: &Checkpoint, r: &mut Report) -> Result<(), Fail> {
    let leaves = wal_leaves(wal, hmac_key(f)?.as_deref())?;
    let n = cp.size() as usize;
    if leaves.len() < n {
        r.fail(
            "WAL",
            &format!("has {} entries, the checkpoint {n}", leaves.len()),
        );
    } else if root_of(&leaves[..n]) != *cp.root() {
        r.fail(
            "WAL",
            "its first entries do not reproduce the checkpoint root",
        );
    } else {
        r.ok(
            "WAL",
            &format!(
                "its first {n} entries reproduce the root ({} entries in total)",
                leaves.len()
            ),
        );
    }
    Ok(())
}

fn check_prev(prev: &str, cp: &Checkpoint, r: &mut Report) -> Result<(), Fail> {
    let (_, prev_cp) = open_note(prev)?;
    let expected = prev_line(&prev_cp.body());
    if cp.extensions().contains(&expected) {
        r.ok(
            "prev link",
            &format!("names checkpoint of size {}", prev_cp.size()),
        );
    } else {
        r.fail("prev link", "the checkpoint does not name --prev");
    }
    if prev_cp.size() > cp.size() {
        r.fail("prev link", "--prev is larger than this checkpoint");
    }
    Ok(())
}

/// The two digests a timestamp may be over: the log-signed note, which dates
/// the signature, or the body alone, which dates only the content.
struct Stamped {
    signature: Option<[u8; 32]>,
    content: [u8; 32],
}

impl Stamped {
    fn covers(&self, digest: &[u8; 32]) -> Option<Covers> {
        if self.signature.as_ref() == Some(digest) {
            Some(Covers::Signature)
        } else if *digest == self.content {
            Some(Covers::Content)
        } else {
            None
        }
    }
}

fn describe(covers: Covers) -> &'static str {
    match covers {
        Covers::Signature => "covers the log's signature",
        Covers::Content => "covers the body only, not the signature",
    }
}

fn check_ots(f: &Flags, ots_path: &str, stamped: &Stamped, r: &mut Report) -> Result<(), Fail> {
    let raw = std::fs::read(ots_path).map_err(|e| format!("cannot read {ots_path}: {e}"))?;
    let proof = match DetachedTimestamp::parse(&raw) {
        Ok(p) => p,
        Err(e) => {
            r.fail("OpenTimestamps", &e.to_string());
            return Ok(());
        }
    };
    let Some(covers) = stamped.covers(&proof.digest()) else {
        r.fail(
            "OpenTimestamps",
            "the proof is for neither this signed note nor its body",
        );
        return Ok(());
    };
    let (height, header) = match (f.one("--block-height"), f.one("--block-header")) {
        (Some(h), Some(hdr)) => (h, hdr),
        (None, None) => {
            report_ots_status(&proof.status(), r);
            return Ok(());
        }
        _ => return Err("--block-height and --block-header go together".into()),
    };
    let height: u64 = height
        .parse()
        .map_err(|_| "--block-height must be a number")?;
    let header: [u8; 80] = unhex(header)?
        .try_into()
        .map_err(|_| "--block-header must be 80 bytes of hex")?;
    let checked = match proof.verify_bitcoin(height, &header) {
        Ok(h) => h,
        Err(e) => {
            r.fail("OpenTimestamps", &e.to_string());
            return Ok(());
        }
    };
    let Some(trusted) = f.one("--block-hash") else {
        r.pending(
            "OpenTimestamps",
            &format!(
                "header valid for block {} ({}), but nothing confirmed it is on the main chain; \
                 give --block-hash from `bitcoin-cli getblockhash {}` on your own node",
                checked.height, checked.block_hash, checked.height
            ),
        );
        return Ok(());
    };
    match checked.confirm(trusted) {
        Ok(v) => {
            r.ok(
                "OpenTimestamps",
                &format!(
                    "in Bitcoin block {} ({}) at {}; {}",
                    v.height,
                    v.block_hash,
                    utc(v.block_time),
                    describe(covers)
                ),
            );
            r.timestamped = true;
            r.bitcoin = true;
            r.evidence.push(TimeEvidence::bitcoin(v.block_time, covers));
        }
        Err(e) => r.fail("OpenTimestamps", &e.to_string()),
    }
    Ok(())
}

fn report_ots_status(status: &Status, r: &mut Report) {
    match status {
        Status::Pending { calendars } => r.pending(
            "OpenTimestamps",
            &format!(
                "calendars {} have not committed it to Bitcoin yet",
                calendars.join(", ")
            ),
        ),
        Status::Anchored { heights } => r.pending(
            "OpenTimestamps",
            &format!(
                "anchored at block {heights:?}; give --block-height, --block-header and --block-hash to verify"
            ),
        ),
    }
}

#[cfg(feature = "preview-tsa")]
fn verify_tsr(f: &Flags, tsr: &str, stamped: &Stamped, r: &mut Report) -> Result<(), Fail> {
    use calybris_core::tsa::{verify_response, PinnedTsa};
    let raw = std::fs::read(tsr).map_err(|e| format!("cannot read {tsr}: {e}"))?;
    let pins = f
        .all("--tsa-cert")
        .iter()
        .map(|p| PinnedTsa::from_pem(&read_text(p)?).map_err(|e| format!("{p}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    if pins.is_empty() {
        return Err("--tsr needs at least one --tsa-cert".into());
    }
    let nonce = f
        .one("--nonce")
        .map(str::parse)
        .transpose()
        .map_err(|_| "--nonce must be a number")?;
    // Try the signed note first; fall back to the body, for tokens made
    // before stamps covered the signature.
    let attempts = [
        stamped.signature.map(|d| (d, Covers::Signature)),
        Some((stamped.content, Covers::Content)),
    ];
    let mut last_err = None;
    for (digest, covers) in attempts.into_iter().flatten() {
        match verify_response(&raw, &digest, nonce, &pins) {
            Ok(v) => {
                r.ok(
                    "RFC 3161",
                    &format!(
                        "{} by {} (accuracy {} s); {}",
                        utc(v.gen_time),
                        v.signer,
                        v.accuracy_seconds,
                        describe(covers)
                    ),
                );
                r.timestamped = true;
                r.evidence
                    .push(TimeEvidence::rfc3161(v.existed_by(), covers));
                if covers == Covers::Content {
                    r.note(
                        "RFC 3161",
                        "restamp with `checkpoint tsa-request` to date the signature too",
                    );
                }
                return Ok(());
            }
            Err(calybris_core::tsa::TsaError::ImprintMismatch) => {
                last_err = Some(calybris_core::tsa::TsaError::ImprintMismatch);
            }
            Err(e) => {
                r.fail("RFC 3161", &e.to_string());
                return Ok(());
            }
        }
    }
    let e = last_err.map_or_else(|| "no digest to check".to_owned(), |e| e.to_string());
    r.fail("RFC 3161", &e);
    Ok(())
}

#[cfg(not(feature = "preview-tsa"))]
fn verify_tsr(_: &Flags, _: &str, _: &Stamped, _: &mut Report) -> Result<(), Fail> {
    Err("built without the preview-tsa feature; --tsr is unavailable".into())
}

const VALUED: &[&str] = &[
    "--name",
    "--kind",
    "--out",
    "--origin",
    "--key",
    "--prev",
    "--hmac-key-hex",
    "--note",
    "--old",
    "--log",
    "--state",
    "--now",
    "--append-to",
    "--calendar",
    "--nonce",
    "--log-key",
    "--witness",
    "--threshold",
    "--wal",
    "--ots",
    "--block-height",
    "--block-header",
    "--tsr",
    "--tsa-cert",
    "--revoked-at",
    "--block-hash",
    "--require",
    "--allow-calendar",
];

/// Entry point for `checkpoint …` and `witness …`; `args` excludes the
/// command word.
pub fn run(command: &str, args: &[String]) -> ExitCode {
    let Some((sub, rest)) = args.split_first() else {
        return usage_error("missing subcommand");
    };
    let flags = match Flags::parse(rest, VALUED) {
        Ok(f) => f,
        Err(e) => return usage_error(&e),
    };
    let result = match (command, sub.as_str()) {
        ("checkpoint", "keygen") => keygen(&flags),
        ("checkpoint", "create") => create(&flags),
        ("checkpoint", "request") => request(&flags),
        ("checkpoint", "stamp") => stamp(&flags),
        ("checkpoint", "upgrade") => upgrade(&flags),
        ("checkpoint", "tsa-request") => tsa_request(&flags),
        ("checkpoint", "verify") => verify(&flags),
        ("witness", "cosign") => cosign(&flags),
        _ => return usage_error(&format!("unknown command {command} {sub}")),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("error: {message}\n");
    eprintln!("{}", USAGE);
    ExitCode::from(2)
}

pub const USAGE: &str = "\
\x20 calybris-verify checkpoint keygen   --name NAME --kind log|witness --out PREFIX
\x20 calybris-verify checkpoint create   <wal> --origin ORIGIN --key LOG.skey [--prev PREV] [--out FILE]
\x20 calybris-verify checkpoint request  <wal> --note FILE --old N
\x20 calybris-verify witness cosign      <request> --key W.skey --log ORIGIN=LOG.vkey --state STATE.json [--append-to NOTE]
\x20 calybris-verify checkpoint stamp    <note> --log-key LOG.vkey [--calendar URL ...]
\x20 calybris-verify checkpoint upgrade  <note.signed.ots> [--allow-calendar PATTERN ...]
\x20 calybris-verify checkpoint tsa-request <note> --log-key LOG.vkey
\x20 calybris-verify checkpoint verify   <note> --log-key LOG.vkey [--witness W.vkey ... --threshold K]
\x20                                     [--wal WAL] [--prev PREV]
\x20                                     [--ots F --block-height H --block-header HEX --block-hash HASH]
\x20                                     [--tsr F --tsa-cert PEM --nonce N] [--revoked-at UNIX]
\x20                                     [--require witnessed|timestamped|bitcoin|full]
\x20 The result names what was established: SIGNATURE VERIFIED ONLY, INDEPENDENTLY
\x20 WITNESSED, TIMESTAMP VERIFIED or FULL VERIFICATION COMPLETE. Exit code 1 if a
\x20 check failed or a --require was not met; 3 if a timestamp is still pending.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formats_known_instants() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_432_827_678), "2015-05-28 15:41:18 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(4_107_542_399), "2100-02-28 23:59:59 UTC");
    }

    #[test]
    fn flags_take_values_and_refuse_unknown_options() {
        let args: Vec<String> = ["f", "--witness", "a", "--witness", "b", "--threshold", "2"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let f = Flags::parse(&args, VALUED).unwrap();
        assert_eq!(f.target().unwrap(), "f");
        assert_eq!(f.all("--witness"), ["a", "b"]);
        assert_eq!(f.one("--threshold"), Some("2"));
        assert!(Flags::parse(&["--bogus".to_owned()], VALUED).is_err());
        assert!(Flags::parse(&["--key".to_owned()], VALUED).is_err());
    }
}
