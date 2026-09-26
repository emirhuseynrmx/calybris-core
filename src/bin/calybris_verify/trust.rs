//! `calybris-verify checkpoint …` and `calybris-verify witness …`: signed
//! checkpoints over a WAL, witness cosigning, OpenTimestamps and RFC 3161.
//!
//! ```text
//! calybris-verify checkpoint keygen   --name NAME --kind log|witness --out PREFIX
//! calybris-verify checkpoint create   <wal> --origin ORIGIN --key LOG.skey [--prev PREV] [--out FILE] [--hmac-key-hex HEX]
//! calybris-verify checkpoint request  <wal> --note FILE --old N [--hmac-key-hex HEX]
//! calybris-verify witness init        --state STATE.json
//! calybris-verify witness cosign      <request> --key W.skey --log ORIGIN=LOG.vkey --state STATE.json [--now UNIX] [--append-to NOTE]
//! calybris-verify checkpoint stamp    <note> --log-key LOG.vkey [--calendar URL ...]
//! calybris-verify checkpoint upgrade  <note.signed.ots> [--allow-calendar PATTERN ...]
//! calybris-verify checkpoint tsa-request <note> --log-key LOG.vkey [--nonce N]
//! calybris-verify checkpoint verify   <note> --log-key LOG.vkey
//!                                     [--witness W.vkey ... --threshold K]
//!                                     [--wal WAL [--hmac-key-hex HEX]] [--prev PREV]
//!                                     [--ots NOTE.signed.ots [--block-height H --block-header HEX --block-hash HASH]]
//!                                     [--tsr NOTE.signed.tsr --tsa-cert CERT.pem [--nonce N]]
//!                                     [--revoked-at UNIX [--revoked-at-height H]]
//!                                     [--require witnessed|timestamped|bitcoin|full]
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

use calybris_core::audit::{
    anchored_by, existed_by, Covers, KeyStatus, TimeEvidence, WitnessPolicy,
};
use calybris_core::checkpoint::{
    Checkpoint, LogSigner, NoteSignature, NoteVerifier, SignedNote, WitnessSigner,
};
use calybris_core::merkle::MerkleTree;
use calybris_core::ots::{self, DetachedTimestamp, Status};
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

/// Creates `path`, which must not exist yet, so that only its owner can read
/// it, then writes `bytes` to it and syncs.
///
/// On Unix the file is created with mode `0600` in the same call that creates
/// it, so it is never readable by anyone else whatever the umask. On Windows
/// it is created empty, its inherited access is replaced by one entry for its
/// owner (`icacls /inheritance:r /grant:r *S-1-3-4:F`, S-1-3-4 being OWNER
/// RIGHTS), and only then is the secret written. If any step fails the file
/// is removed again.
fn write_new_secret(path: &str, bytes: &[u8]) -> Result<(), Fail> {
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    let file = open
        .open(path)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    fill_or_remove(path, file, |file| fill_secret(file, path, bytes))
}

/// Creates `path`, which must not exist yet, and writes `bytes` to it; a
/// file this call created is removed again if the write fails.
fn write_new_public(path: &str, bytes: &[u8]) -> Result<(), Fail> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("cannot create {path}: {e}"))?;
    fill_or_remove(path, file, |file| write_and_sync(file, path, bytes))
}

/// Runs `fill` on `file`, which this process has just created at `path`,
/// and removes `path` if it fails, so no partial file is left behind. `fill`
/// owns the file, so it is closed before the removal.
fn fill_or_remove(
    path: &str,
    file: std::fs::File,
    fill: impl FnOnce(std::fs::File) -> Result<(), Fail>,
) -> Result<(), Fail> {
    let filled = fill(file);
    if filled.is_err() {
        let _ = std::fs::remove_file(path);
    }
    filled
}

fn write_and_sync(mut file: std::fs::File, path: &str, bytes: &[u8]) -> Result<(), Fail> {
    use std::io::Write as _;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {path}: {e}"))
}

/// Restricts the new, still empty `file` to its owner where the platform
/// needs a separate step for that, then writes the secret and syncs.
fn fill_secret(file: std::fs::File, path: &str, bytes: &[u8]) -> Result<(), Fail> {
    #[cfg(windows)]
    restrict_to_owner(path)?;
    write_and_sync(file, path, bytes)
}

/// Replaces the access list of `path` with a single entry giving its owner
/// full control, through the system's own `icacls`.
#[cfg(windows)]
fn restrict_to_owner(path: &str) -> Result<(), Fail> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let icacls = Path::new(&root).join("System32").join("icacls.exe");
    let out = Command::new(&icacls)
        .args([path, "/inheritance:r", "/grant:r", "*S-1-3-4:F", "/q"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", icacls.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "cannot restrict {path} to its owner: {}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Writes a new key pair: the secret through [`write_new_secret`], the public
/// key through [`write_new_public`]. Neither file may exist; an existing key
/// is never replaced. If either cannot be written, whatever this call created
/// is removed, so a failed keygen leaves neither file behind.
fn write_key_pair(skey_path: &str, skey: &str, vkey_path: &str, vkey: &str) -> Result<(), Fail> {
    for path in [skey_path, vkey_path] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{path} already exists; keygen never replaces a key"
            ));
        }
    }
    write_new_secret(skey_path, format!("{skey}\n").as_bytes())?;
    if let Err(e) = write_new_public(vkey_path, format!("{vkey}\n").as_bytes()) {
        return Err(match std::fs::remove_file(skey_path) {
            Ok(()) => format!("{e}; removed {skey_path}"),
            Err(r) => format!(
                "{e}; and cannot remove {skey_path}: {r}. \
                 Delete it: its public key was never written"
            ),
        });
    }
    Ok(())
}

fn unix_now() -> Result<u64, Fail> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the system clock is before 1970")?
        .as_secs())
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

/// Validate the WAL once; reuse its cached roots for prefix/proof queries.
fn wal_tree(path: &str, hmac_key: Option<&[u8]>) -> Result<MerkleTree, Fail> {
    MerkleTree::from_verified_wal(Path::new(path), hmac_key).map_err(|e| format!("WAL {path}: {e}"))
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
    write_key_pair(&format!("{out}.skey"), &skey, &format!("{out}.vkey"), &vkey)?;
    println!("{vkey}");
    eprintln!(
        "wrote {out}.skey (secret, readable by its owner only: keep it off shared disks) \
         and {out}.vkey (public)"
    );
    Ok(ExitCode::SUCCESS)
}

fn create(f: &Flags) -> Result<ExitCode, Fail> {
    let wal = f.target()?;
    let key = hmac_key(f)?;
    let tree = wal_tree(wal, key.as_deref())?;
    let head = tree.head(tree.len()).map_err(|e| e.to_string())?;
    let mut cp = Checkpoint::new(f.need("--origin")?, head).map_err(|e| e.to_string())?;
    if let Some(prev) = f.one("--prev") {
        let (_, prev_cp) = open_note(prev)?;
        if prev_cp.origin() != cp.origin() {
            return Err("--prev is a checkpoint of another log".into());
        }
        if prev_cp.size() > head.size
            || (prev_cp.size() > 0
                && tree.head(prev_cp.size()).map_err(|e| e.to_string())?.root != *prev_cp.root())
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
    let tree = wal_tree(wal, hmac_key(f)?.as_deref())?;
    let note_text = read_text(f.need("--note")?)?;
    let (_, cp) = open_note(f.need("--note")?)?;
    let old: u64 = f
        .need("--old")?
        .parse()
        .map_err(|_| "--old must be a number")?;
    if cp.size() != tree.len()
        || *cp.root() != tree.head(tree.len()).map_err(|e| e.to_string())?.root
    {
        return Err("the note is not a checkpoint of this WAL".into());
    }
    if old > cp.size() {
        return Err("--old is larger than the checkpoint".into());
    }
    let proof = if old == 0 || old == cp.size() {
        Vec::new()
    } else {
        tree.consistency_proof(old, tree.len())
            .map_err(|e| e.to_string())?
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

/// Starts a new witness's state file; never overwrites one.
fn init(f: &Flags) -> Result<ExitCode, Fail> {
    let state = f.need("--state")?;
    FileStore::create(state)?;
    eprintln!("wrote {state}: an empty witness state; back it up with the witness key");
    Ok(ExitCode::SUCCESS)
}

/// The note `--append-to` names, checked before the witness signs: its path
/// and the checkpoint text the cosignature will be over.
struct AppendTarget<'a> {
    path: &'a str,
    text: String,
}

/// Reads the `--append-to` note and checks it can take this witness's
/// cosignature of `req`: the same checkpoint text, and no cosignature from
/// this key yet. Done before signing, so a wrong file is refused while the
/// witness state is still untouched.
fn append_target<'a>(
    path: &'a str,
    req: &AddCheckpoint,
    signer: &WitnessSigner,
) -> Result<AppendTarget<'a>, Fail> {
    let note = SignedNote::parse(&read_text(path)?).map_err(|e| format!("{path}: {e}"))?;
    let requested = SignedNote::parse(&req.note).map_err(|e| format!("the request: {e}"))?;
    if note.text() != requested.text() {
        return Err(format!(
            "{path} is not the checkpoint in the request; nothing was signed"
        ));
    }
    let me = signer.verifier();
    if note
        .signatures()
        .iter()
        .any(|s| s.name == me.name() && s.key_hash == me.key_hash())
    {
        return Err(format!(
            "{path} already carries a signature from {}; nothing was signed",
            me.name()
        ));
    }
    if note.signatures().len() >= calybris_core::checkpoint::MAX_SIGNATURES {
        return Err(format!(
            "{path} has no room for another signature; nothing was signed"
        ));
    }
    Ok(AppendTarget {
        path,
        text: note.text().to_owned(),
    })
}

/// Adds `sig` to the note at the target's path.
///
/// Several witnesses may append to one note at once, so the read, the check
/// and the replacement happen under an exclusive lock on `<note>.lock`: the
/// note is read again under the lock, must still be the checkpoint that was
/// signed, and takes the cosignature beside whatever lines others added
/// meanwhile. Nobody's cosignature is lost to a later writer. A note that
/// now holds another checkpoint is left as it is; the cosignature is on
/// standard output either way.
fn append_cosignature(target: AppendTarget<'_>, sig: NoteSignature) -> Result<(), Fail> {
    let path = target.path;
    let _lock = lock_beside(path)?;
    let mut note = SignedNote::parse(&read_text(path)?).map_err(|e| format!("{path}: {e}"))?;
    if note.text() != target.text {
        return Err(format!(
            "{path} was changed to another checkpoint while the witness was signing, \
             so it was left as it is; the cosignature is on standard output"
        ));
    }
    note.add_signature(sig)
        .map_err(|e| format!("{path}: {e}"))?;
    replace_file(path, note.render().as_bytes())
}

/// Takes an exclusive lock on `<path>.lock`, created if missing and never
/// removed (removing it would let two writers lock two different files). The
/// lock is released when the returned file is dropped.
fn lock_beside(path: &str) -> Result<std::fs::File, Fail> {
    use fs2::FileExt as _;
    let lock_path = format!("{path}.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open {lock_path}: {e}"))?;
    lock.lock_exclusive()
        .map_err(|e| format!("cannot lock {lock_path}: {e}"))?;
    Ok(lock)
}

/// Replaces `path` with `bytes` through a new file beside it and a rename, so
/// a reader sees the old note or the new one and never a partial write.
fn replace_file(path: &str, bytes: &[u8]) -> Result<(), Fail> {
    use std::io::Write as _;
    let tmp = format!("{path}.{}.tmp", hex(&random::<8>()?));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write {path}: {e}")
    })
}

fn cosign(f: &Flags) -> Result<ExitCode, Fail> {
    let req = AddCheckpoint::parse(&read_text(f.target()?)?).map_err(|e| e.to_string())?;
    let signer =
        WitnessSigner::from_skey(&read_key_text(f.need("--key")?)?).map_err(|e| e.to_string())?;
    let target = f
        .one("--append-to")
        .map(|path| append_target(path, &req, &signer))
        .transpose()?;
    let state = f.need("--state")?;
    let store = FileStore::open(state)
        .map_err(|e| format!("{e}\n(a new witness starts with `witness init --state {state}`)"))?;
    let mut witness = Witness::new(signer, store);
    for spec in f.all("--log") {
        let (origin, path) = spec.split_once('=').ok_or("--log takes ORIGIN=VKEYFILE")?;
        let key = NoteVerifier::parse(&read_key_text(path)?).map_err(|e| e.to_string())?;
        witness.add_log(origin, key);
    }
    let now = match f.one("--now") {
        Some(t) => t.parse().map_err(|_| "--now must be Unix seconds")?,
        None => unix_now()?,
    };
    match witness.add_checkpoint(&req, now) {
        Ok(sig) => {
            print!("{}", sig.line());
            if let Some(target) = target {
                let path = target.path;
                append_cosignature(target, sig)?;
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

/// How `stamp` and `upgrade` reach a calendar: fetch `url`, posting `body`
/// when given; `Ok(None)` for a 404. [`curl`] in the tool, a stand-in in tests.
type Fetch<'a> = &'a dyn Fn(&str, Option<&[u8]>) -> Result<Option<Vec<u8>>, Fail>;

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
    stamp_with(f, &curl)
}

fn stamp_with(f: &Flags, fetch: Fetch<'_>) -> Result<ExitCode, Fail> {
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
        match fetch(&ots::calendar_submit_path(cal), Some(&commitment)) {
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
    upgrade_with(f, &curl)
}

fn upgrade_with(f: &Flags, fetch: Fetch<'_>) -> Result<ExitCode, Fail> {
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
        match fetch(&url, None) {
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
    #[cfg(feature = "preview-tsa")]
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
        Some(t) => println!(
            "  existed by {} (earliest witness or RFC 3161 time)",
            utc(t)
        ),
        None => println!("  existed by: no witness or RFC 3161 time"),
    }
    if let Some(height) = anchored_by(&r.evidence) {
        println!(
            "  anchored in Bitcoin block {height} (dated by height, not by the block's own time)"
        );
    }
    check_revocation(f, &mut r)?;

    let missing = unmet(f, &r)?;
    Ok(verdict(&r, &missing))
}

/// `--revoked-at UNIX [--revoked-at-height H]`: whether the signature is
/// proven to predate the revocation. A Bitcoin anchor counts only against
/// the height the chain had reached then, never by its block's own time.
fn check_revocation(f: &Flags, r: &mut Report) -> Result<(), Fail> {
    let height = f
        .one("--revoked-at-height")
        .map(|h| {
            h.parse::<u64>()
                .map_err(|_| "--revoked-at-height must be a block height")
        })
        .transpose()?;
    let Some(revoked) = f.one("--revoked-at") else {
        if height.is_some() {
            return Err("--revoked-at-height goes with --revoked-at".into());
        }
        return Ok(());
    };
    let at: u64 = revoked
        .parse()
        .map_err(|_| "--revoked-at must be Unix seconds")?;
    let status = KeyStatus::Revoked {
        at,
        bitcoin_height: height,
    };
    match status.accepts(&r.evidence) {
        Ok(()) => r.ok(
            "revoked key",
            &format!("signature proven before its revocation at {}", utc(at)),
        ),
        Err(e) => r.fail("revoked key", &e.to_string()),
    }
    Ok(())
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
    // A cosignature dated ahead of this machine's clock by more than the
    // allowed skew is not counted.
    match calybris_core::audit::verify_checkpoint_at(
        &note.render(),
        log,
        &policy,
        unix_now()?,
        calybris_core::audit::DEFAULT_MAX_CLOCK_SKEW,
    ) {
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
    let tree = wal_tree(wal, hmac_key(f)?.as_deref())?;
    let n = cp.size();
    if tree.len() < n {
        r.fail(
            "WAL",
            &format!("has {} entries, the checkpoint {n}", tree.len()),
        );
    } else if tree.head(n).map_err(|e| e.to_string())?.root != *cp.root() {
        r.fail(
            "WAL",
            "its first entries do not reproduce the checkpoint root",
        );
    } else {
        r.ok(
            "WAL",
            &format!(
                "its first {n} entries reproduce the root ({} entries in total)",
                tree.len()
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
                    "in Bitcoin block {} ({}), whose miner dated it {}; {}",
                    v.height,
                    v.block_hash,
                    utc(v.block_time),
                    describe(covers)
                ),
            );
            r.timestamped = true;
            r.bitcoin = true;
            r.evidence
                .push(TimeEvidence::bitcoin(v.height, v.block_time, covers));
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
    "--revoked-at-height",
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
        ("witness", "init") => init(&flags),
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
\x20 calybris-verify witness init        --state STATE.json
\x20 calybris-verify witness cosign      <request> --key W.skey --log ORIGIN=LOG.vkey --state STATE.json [--append-to NOTE]
\x20 calybris-verify checkpoint stamp    <note> --log-key LOG.vkey [--calendar URL ...]
\x20 calybris-verify checkpoint upgrade  <note.signed.ots> [--allow-calendar PATTERN ...]
\x20 calybris-verify checkpoint tsa-request <note> --log-key LOG.vkey
\x20 calybris-verify checkpoint verify   <note> --log-key LOG.vkey [--witness W.vkey ... --threshold K]
\x20                                     [--wal WAL] [--prev PREV]
\x20                                     [--ots F --block-height H --block-header HEX --block-hash HASH]
\x20                                     [--tsr F --tsa-cert PEM --nonce N]
\x20                                     [--revoked-at UNIX [--revoked-at-height H]]
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

    use calybris_core::merkle::TreeHead;

    fn keygen_in(dir: &Path, kind: &str) -> Result<ExitCode, Fail> {
        let out = dir.join("k");
        keygen(&flags(&[
            "--name",
            "k.example",
            "--kind",
            kind,
            "--out",
            out.to_str().unwrap(),
        ]))
    }

    #[test]
    fn keygen_writes_a_secret_only_its_owner_can_read() {
        for kind in ["log", "witness"] {
            let dir = tempfile::tempdir().unwrap();
            keygen_in(dir.path(), kind).unwrap();
            let skey = dir.path().join("k.skey");
            let text = std::fs::read_to_string(&skey).unwrap();
            assert!(text.starts_with("PRIVATE+KEY+k.example+"), "{text}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&skey).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{kind}: mode {mode:o}");
            }
            #[cfg(windows)]
            {
                // No inherited entry is left: only the one for its owner.
                let out = Command::new("icacls").arg(&skey).output().unwrap();
                let acl = String::from_utf8_lossy(&out.stdout);
                assert!(out.status.success(), "{acl}");
                assert!(!acl.contains("(I)"), "{acl}");
            }
        }
    }

    #[test]
    fn keygen_never_replaces_either_file_of_a_key() {
        let dir = tempfile::tempdir().unwrap();
        keygen_in(dir.path(), "witness").unwrap();
        let skey = std::fs::read(dir.path().join("k.skey")).unwrap();
        let vkey = std::fs::read(dir.path().join("k.vkey")).unwrap();
        let err = keygen_in(dir.path(), "witness").unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read(dir.path().join("k.skey")).unwrap(), skey);
        assert_eq!(std::fs::read(dir.path().join("k.vkey")).unwrap(), vkey);

        // A public key alone at the path is not replaced either, and no
        // secret is written beside it.
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("k.vkey"), b"somebody's key\n").unwrap();
        assert!(keygen_in(other.path(), "log").is_err());
        assert!(!other.path().join("k.skey").exists());
        assert_eq!(
            std::fs::read(other.path().join("k.vkey")).unwrap(),
            b"somebody's key\n"
        );
    }

    #[test]
    fn a_keygen_that_fails_halfway_leaves_no_secret_behind() {
        let dir = tempfile::tempdir().unwrap();
        let skey = dir.path().join("k.skey");
        // The public key's directory does not exist, so the secret is
        // written and the public key then fails.
        let vkey = dir.path().join("missing").join("k.vkey");
        let err = write_key_pair(
            skey.to_str().unwrap(),
            "PRIVATE+KEY+k.example+00000000+AA",
            vkey.to_str().unwrap(),
            "k.example+00000000+AA",
        )
        .unwrap_err();
        assert!(err.contains("removed"), "{err}");
        assert!(!skey.exists());
        assert!(!vkey.exists());

        // A note that cannot be replaced is reported, with nothing left.
        let note = dir.path().join("missing").join("c.checkpoint");
        let err = replace_file(note.to_str().unwrap(), b"note").unwrap_err();
        assert!(err.starts_with("cannot write"), "{err}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // A file this call created and then could not write is removed: here
        // the handle is read-only, so the write fails after the creation.
        let partial = dir.path().join("k.vkey");
        std::fs::write(&partial, b"").unwrap();
        let read_only = std::fs::File::open(&partial).unwrap();
        let p = partial.to_str().unwrap();
        let err = fill_or_remove(p, read_only, |f| write_and_sync(f, p, b"k.example+1+AA\n"))
            .unwrap_err();
        assert!(err.starts_with("cannot write"), "{err}");
        assert!(!partial.exists());

        // A secret that cannot be created leaves nothing either.
        let nowhere = dir.path().join("missing").join("k.skey");
        assert!(write_new_secret(nowhere.to_str().unwrap(), b"secret").is_err());
        assert!(!nowhere.exists());
    }

    /// Another witness's line added while this one signs is kept beside it;
    /// a note turned into another checkpoint meanwhile is left alone.
    #[test]
    fn a_note_changed_while_the_witness_signs_keeps_every_cosignature() {
        let dir = tempfile::tempdir().unwrap();
        let (note, _) = note_in(dir.path());
        let text = std::fs::read_to_string(&note).unwrap();
        let req = AddCheckpoint {
            old_size: 0,
            proof: Vec::new(),
            note: text.clone(),
        };
        let w = WitnessSigner::from_seed("w.example", &[5; 32]).unwrap();
        let other = WitnessSigner::from_seed("other.example", &[6; 32]).unwrap();
        let body = SignedNote::parse(&text).unwrap().text().to_owned();

        let target = append_target(&note, &req, &w).unwrap();
        let mut changed = SignedNote::parse(&text).unwrap();
        changed
            .add_signature(other.cosign(&body, 1).unwrap())
            .unwrap();
        std::fs::write(&note, changed.render()).unwrap();
        append_cosignature(target, w.cosign(&body, 2).unwrap()).unwrap();
        let done = SignedNote::parse(&std::fs::read_to_string(&note).unwrap()).unwrap();
        assert_eq!(done.cosignature_time(w.verifier()), Ok(2));
        assert_eq!(done.cosignature_time(other.verifier()), Ok(1));

        // Replaced by a checkpoint of another size, it is not touched.
        let dup = append_target(&note, &req, &other).err().unwrap();
        assert!(dup.contains("already carries"), "{dup}");
        let third = WitnessSigner::from_seed("third.example", &[7; 32]).unwrap();
        let target = append_target(&note, &req, &third).unwrap();
        let log = LogSigner::from_seed("decisions.example/log", &[1; 32]).unwrap();
        let bigger = Checkpoint::new(
            "decisions.example/log",
            TreeHead {
                size: 4,
                root: [8; 32],
            },
        )
        .unwrap();
        let replaced = log.sign(&bigger).render();
        std::fs::write(&note, &replaced).unwrap();
        let err = append_cosignature(target, third.cosign(&body, 3).unwrap()).unwrap_err();
        assert!(err.contains("changed to another checkpoint"), "{err}");
        assert_eq!(std::fs::read_to_string(&note).unwrap(), replaced);

        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }

    /// Witnesses that all pass the check before signing and then append at
    /// the same moment each end up in the note: the lock makes every
    /// read-and-replace see the lines written before it.
    #[test]
    fn witnesses_appending_at_once_each_keep_their_cosignature() {
        const N: usize = 12;
        let dir = tempfile::tempdir().unwrap();
        let (note, _) = note_in(dir.path());
        let text = std::fs::read_to_string(&note).unwrap();
        let body = SignedNote::parse(&text).unwrap().text().to_owned();
        let req = AddCheckpoint {
            old_size: 0,
            proof: Vec::new(),
            note: text,
        };
        let signers: Vec<WitnessSigner> = (0..N)
            .map(|i| {
                let seed = [u8::try_from(60 + i).unwrap(); 32];
                WitnessSigner::from_seed(&format!("w{i}.example"), &seed).unwrap()
            })
            .collect();
        let start = std::sync::Barrier::new(N);
        std::thread::scope(|scope| {
            let handles: Vec<_> = signers
                .iter()
                .map(|w| {
                    let (note, req, body, start) = (&note, &req, &body, &start);
                    scope.spawn(move || {
                        let target = append_target(note, req, w).unwrap();
                        let sig = w.cosign(body, 5).unwrap();
                        start.wait();
                        append_cosignature(target, sig)
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap().unwrap();
            }
        });
        let done = SignedNote::parse(&std::fs::read_to_string(&note).unwrap()).unwrap();
        assert_eq!(done.signatures().len(), N + 1);
        for w in &signers {
            assert_eq!(done.cosignature_time(w.verifier()), Ok(5));
        }
    }

    #[test]
    fn an_append_target_that_is_not_a_note_or_is_full_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (note, _) = note_in(dir.path());
        let text = std::fs::read_to_string(&note).unwrap();
        let req = AddCheckpoint {
            old_size: 0,
            proof: Vec::new(),
            note: text.clone(),
        };
        let w = WitnessSigner::from_seed("w.example", &[5; 32]).unwrap();
        let junk = dir.path().join("junk");
        std::fs::write(&junk, "not a note\n").unwrap();
        assert!(append_target(junk.to_str().unwrap(), &req, &w).is_err());

        let body = SignedNote::parse(&text).unwrap().text().to_owned();
        let mut full = SignedNote::parse(&text).unwrap();
        for i in 1..calybris_core::checkpoint::MAX_SIGNATURES {
            let seed = [u8::try_from(i).unwrap(); 32];
            let s = WitnessSigner::from_seed(&format!("w{i}.example"), &seed).unwrap();
            full.add_signature(s.cosign(&body, 1).unwrap()).unwrap();
        }
        std::fs::write(&note, full.render()).unwrap();
        let err = append_target(&note, &req, &w).err().unwrap();
        assert!(err.contains("no room"), "{err}");
    }

    fn flags(args: &[&str]) -> Flags {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        Flags::parse(&args, VALUED).unwrap()
    }

    fn fixture(path: &str) -> String {
        format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"))
    }

    /// A signed checkpoint note and its log key, written into `dir`.
    fn note_in(dir: &Path) -> (String, String) {
        let log = LogSigner::from_seed("decisions.example/log", &[1; 32]).unwrap();
        let cp = Checkpoint::new(
            "decisions.example/log",
            TreeHead {
                size: 3,
                root: [7; 32],
            },
        )
        .unwrap();
        let note = dir.join("c.checkpoint");
        let vkey = dir.join("log.vkey");
        std::fs::write(&note, log.sign(&cp).render()).unwrap();
        std::fs::write(&vkey, log.verifier().to_vkey()).unwrap();
        (
            note.to_str().unwrap().to_owned(),
            vkey.to_str().unwrap().to_owned(),
        )
    }

    /// A calendar's answer: `ops`, then a pending attestation naming `uri`.
    fn pending_answer(ops: &[u8], uri: &str) -> Vec<u8> {
        let mut body = ops.to_vec();
        body.push(0x00);
        body.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
        body.push(u8::try_from(uri.len() + 1).unwrap());
        body.push(u8::try_from(uri.len()).unwrap());
        body.extend_from_slice(uri.as_bytes());
        body
    }

    /// An upgrade: SHA-256, then a Bitcoin attestation at `height` (< 128).
    fn anchored_answer(height: u8) -> Vec<u8> {
        let mut body = vec![0x08, 0x00];
        body.extend_from_slice(&[0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
        body.extend_from_slice(&[1, height]);
        body
    }

    const ALICE: &str = "https://alice.btc.calendar.opentimestamps.org";
    const BOB: &str = "https://bob.btc.calendar.opentimestamps.org";

    #[test]
    fn stamp_keeps_what_calendars_accept_and_fails_when_none_does() {
        let dir = tempfile::tempdir().unwrap();
        let (note, vkey) = note_in(dir.path());
        let fetch = |url: &str, body: Option<&[u8]>| -> Result<Option<Vec<u8>>, Fail> {
            assert_eq!(body.map(<[u8]>::len), Some(32), "a commitment is posted");
            match url {
                "https://a.example/digest" => Ok(Some(pending_answer(&[], ALICE))),
                "https://b.example/digest" => Ok(Some(b"\xff".to_vec())),
                "https://c.example/digest" => Ok(None),
                _ => Err("connection refused".into()),
            }
        };
        let mut args = vec![note.as_str(), "--log-key", vkey.as_str()];
        for c in [
            "https://a.example",
            "https://b.example/",
            "https://c.example",
            "https://d.example",
        ] {
            args.extend(["--calendar", c]);
        }
        let code = stamp_with(&flags(&args), &fetch).unwrap();
        assert_eq!(code, ExitCode::from(EXIT_INCOMPLETE));
        let proof = DetachedTimestamp::parse(&std::fs::read(format!("{note}.signed.ots")).unwrap())
            .unwrap();
        assert_eq!(
            proof.status(),
            Status::Pending {
                calendars: vec![ALICE.to_owned()]
            }
        );
        let signed = std::fs::read_to_string(format!("{note}.signed")).unwrap();
        assert_eq!(
            proof.digest(),
            <[u8; 32]>::from(Sha256::digest(signed.as_bytes()))
        );

        let nobody = |_: &str, _: Option<&[u8]>| -> Result<Option<Vec<u8>>, Fail> { Ok(None) };
        let err = stamp_with(&flags(&[&note, "--log-key", &vkey]), &nobody).unwrap_err();
        assert!(err.contains("no calendar accepted"), "{err}");
        // A key that did not sign the note stamps nothing.
        let other = dir.path().join("other.vkey");
        let stranger = LogSigner::from_seed("decisions.example/log", &[2; 32]).unwrap();
        std::fs::write(&other, stranger.verifier().to_vkey()).unwrap();
        assert!(stamp_with(
            &flags(&[&note, "--log-key", other.to_str().unwrap()]),
            &nobody
        )
        .is_err());
    }

    #[test]
    fn upgrade_merges_an_anchoring_answer_and_skips_calendars_it_does_not_trust() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.ots");
        let path = path.to_str().unwrap();
        let mut proof = DetachedTimestamp::new([9; 32]);
        let commitment = proof.prepare_submission([3; 16]);
        for (i, uri) in [ALICE, BOB, "https://evil.example"].into_iter().enumerate() {
            // A distinct first operation per calendar, as real calendars answer.
            let ops = [0xf0, 1, u8::try_from(i).unwrap(), 0x08];
            proof
                .merge_calendar_response(&commitment, &pending_answer(&ops, uri))
                .unwrap();
        }
        std::fs::write(path, proof.serialize()).unwrap();
        let before = std::fs::read(path).unwrap();

        let nothing_yet = |url: &str, body: Option<&[u8]>| -> Result<Option<Vec<u8>>, Fail> {
            assert!(body.is_none());
            assert!(!url.contains("evil"), "an untrusted calendar was asked");
            if url.starts_with(ALICE) {
                Ok(Some(b"\xff".to_vec()))
            } else if url.starts_with(BOB) {
                Ok(None)
            } else {
                Err("unreachable".into())
            }
        };
        let code = upgrade_with(&flags(&[path]), &nothing_yet).unwrap();
        assert_eq!(code, ExitCode::from(EXIT_INCOMPLETE));
        assert_eq!(
            std::fs::read(path).unwrap(),
            before,
            "nothing new, nothing written"
        );

        let alice_commits = |url: &str, _: Option<&[u8]>| -> Result<Option<Vec<u8>>, Fail> {
            Ok(url.starts_with(ALICE).then(|| anchored_answer(5)))
        };
        let code = upgrade_with(&flags(&[path]), &alice_commits).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        let upgraded = DetachedTimestamp::parse(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(upgraded.status(), Status::Anchored { heights: vec![5] });

        std::fs::write(path, b"not a proof").unwrap();
        assert!(upgrade_with(&flags(&[path]), &alice_commits).is_err());
        assert!(upgrade_with(&flags(&["/nonexistent/p.ots"]), &alice_commits).is_err());
    }

    /// The whole Bitcoin path against a real proof: the 2015 hello-world
    /// stamp in block 358391, whose header is a fixture.
    #[test]
    fn a_real_bitcoin_proof_is_confirmed_only_with_the_right_block_hash() {
        let ots_path = fixture("ots/hello-world.txt.ots");
        let digest: [u8; 32] =
            Sha256::digest(std::fs::read(fixture("ots/hello-world.txt")).unwrap()).into();
        let header = std::fs::read_to_string(fixture("ots/block358391.hex")).unwrap();
        let header = header.trim();
        let proof = DetachedTimestamp::parse(&std::fs::read(&ots_path).unwrap()).unwrap();
        let hash = proof
            .verify_bitcoin(358_391, &unhex(header).unwrap().try_into().unwrap())
            .unwrap()
            .block_hash;
        let stamped = Stamped {
            signature: Some(digest),
            content: [0; 32],
        };
        let run = |args: &[&str], stamped: &Stamped| {
            let mut r = Report::default();
            let res = check_ots(&flags(args), &ots_path, stamped, &mut r);
            (res, r)
        };
        let bitcoin = ["--block-height", "358391", "--block-header", header];

        let (res, r) = run(&[&bitcoin[..], &["--block-hash", &hash]].concat(), &stamped);
        res.unwrap();
        assert!(r.timestamped && r.bitcoin && !r.failed && !r.incomplete);
        assert_eq!(r.evidence[0].covers, Covers::Signature);
        assert_eq!(verdict(&r, &[]), ExitCode::SUCCESS);

        // Against a revocation the block counts by its height only. Its own
        // time (2015) is long before this revocation, and still does not.
        let revoke = |args: &[&str]| {
            let mut again = Report {
                evidence: r.evidence.clone(),
                ..Report::default()
            };
            let res = check_revocation(&flags(args), &mut again);
            (res, again.failed)
        };
        assert_eq!(revoke(&["--revoked-at", "1700000000"]), (Ok(()), true));
        let at = ["--revoked-at", "1700000000", "--revoked-at-height"];
        assert_eq!(revoke(&[&at[..], &["358391"]].concat()), (Ok(()), false));
        assert_eq!(revoke(&[&at[..], &["358390"]].concat()), (Ok(()), true));
        assert!(revoke(&["--revoked-at-height", "358391"]).0.is_err());
        assert!(revoke(&[&at[..], &["x"]].concat()).0.is_err());
        assert_eq!(revoke(&[]), (Ok(()), false));

        let body_only = Stamped {
            signature: None,
            content: digest,
        };
        let (res, r) = run(
            &[&bitcoin[..], &["--block-hash", &hash]].concat(),
            &body_only,
        );
        res.unwrap();
        assert_eq!(r.evidence[0].covers, Covers::Content);

        let (_, r) = run(&bitcoin, &stamped);
        assert!(
            r.incomplete && !r.timestamped,
            "an unconfirmed header dates nothing"
        );
        let (_, r) = run(
            &[&bitcoin[..], &["--block-hash", &"00".repeat(32)]].concat(),
            &stamped,
        );
        assert!(r.failed);
        let (_, r) = run(
            &["--block-height", "358390", "--block-header", header],
            &stamped,
        );
        assert!(r.failed);
        let (_, r) = run(&[], &stamped);
        assert!(r.incomplete, "anchored, but no header given");
        let other = Stamped {
            signature: Some([1; 32]),
            content: [2; 32],
        };
        let (_, r) = run(&bitcoin, &other);
        assert!(r.failed, "a proof for another file");

        for bad in [
            &["--block-height", "358391"][..],
            &["--block-height", "x", "--block-header", header],
            &["--block-height", "1", "--block-header", "zz"],
            &["--block-height", "1", "--block-header", "00"],
        ] {
            assert!(run(bad, &stamped).0.is_err(), "{bad:?}");
        }
        let mut r = Report::default();
        assert!(check_ots(&flags(&[]), "/nonexistent.ots", &stamped, &mut r).is_err());
        let garbage = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(garbage.path(), b"junk").unwrap();
        check_ots(
            &flags(&[]),
            garbage.path().to_str().unwrap(),
            &stamped,
            &mut r,
        )
        .unwrap();
        assert!(r.failed);
    }

    #[test]
    fn a_pending_proof_is_reported_as_pending() {
        let mut proof = DetachedTimestamp::new([9; 32]);
        let commitment = proof.prepare_submission([3; 16]);
        proof
            .merge_calendar_response(&commitment, &pending_answer(&[], ALICE))
            .unwrap();
        let mut r = Report::default();
        report_ots_status(&proof.status(), &mut r);
        assert!(r.incomplete && !r.timestamped);
        print_status(&proof.status());
        print_status(&Status::Anchored { heights: vec![1] });
    }

    #[cfg(feature = "preview-tsa")]
    #[test]
    fn a_pinned_token_dates_what_it_covers_and_nothing_else() {
        let tsr = fixture("rfc3161/rsa.tsr");
        let cert = fixture("rfc3161/rsa.crt");
        let digest: [u8; 32] =
            Sha256::digest(std::fs::read(fixture("rfc3161/body.txt")).unwrap()).into();
        let run = |args: &[&str], stamped: &Stamped, tsr: &str| {
            let mut r = Report::default();
            let res = verify_tsr(&flags(args), tsr, stamped, &mut r);
            (res, r)
        };
        let pinned = ["--tsa-cert", cert.as_str()];
        let signed = Stamped {
            signature: Some(digest),
            content: [0; 32],
        };
        let (res, r) = run(&pinned, &signed, &tsr);
        res.unwrap();
        assert!(r.timestamped && !r.failed);
        assert_eq!(r.evidence[0].covers, Covers::Signature);

        let body = Stamped {
            signature: Some([1; 32]),
            content: digest,
        };
        let (_, r) = run(&pinned, &body, &tsr);
        assert!(r.timestamped);
        assert_eq!(r.evidence[0].covers, Covers::Content);

        let neither = Stamped {
            signature: None,
            content: [2; 32],
        };
        let (_, r) = run(&pinned, &neither, &tsr);
        assert!(r.failed && !r.timestamped);
        let (_, r) = run(&[&pinned[..], &["--nonce", "1"]].concat(), &signed, &tsr);
        assert!(r.failed, "a nonce the request did not carry");
        let (_, r) = run(
            &["--tsa-cert", &fixture("rfc3161/wrongkey.crt")],
            &signed,
            &tsr,
        );
        assert!(r.failed);

        assert!(run(&[], &signed, &tsr).0.is_err(), "no pinned certificate");
        assert!(
            run(&[&pinned[..], &["--nonce", "x"]].concat(), &signed, &tsr)
                .0
                .is_err()
        );
        assert!(
            run(&["--tsa-cert", &tsr], &signed, &tsr).0.is_err(),
            "not a PEM"
        );
        assert!(run(&pinned, &signed, "/nonexistent.tsr").0.is_err());
    }

    /// Every combination of what was checked, and every requirement: the
    /// result line and exit code never claim more than was established.
    #[test]
    fn the_verdict_names_exactly_what_was_established() {
        for bits in 0..32_u8 {
            let r = Report {
                failed: bits & 1 != 0,
                incomplete: bits & 2 != 0,
                witnessed: bits & 4 != 0,
                timestamped: bits & 8 != 0,
                bitcoin: bits & 16 != 0,
                evidence: Vec::new(),
            };
            for req in [
                "witnessed",
                "timestamped",
                "bitcoin",
                "full",
                "witnessed,timestamped",
            ] {
                let missing = unmet(&flags(&["--require", req]), &r).unwrap();
                let met = match req {
                    "witnessed" => r.witnessed,
                    "timestamped" => r.timestamped,
                    "bitcoin" => r.bitcoin,
                    _ => r.witnessed && r.timestamped,
                };
                assert_eq!(missing.is_empty(), met, "{req} with {bits:05b}");
                let code = verdict(&r, &missing);
                let expected = if r.failed || !met {
                    ExitCode::FAILURE
                } else if r.incomplete {
                    ExitCode::from(EXIT_INCOMPLETE)
                } else {
                    ExitCode::SUCCESS
                };
                assert_eq!(code, expected, "{req} with {bits:05b}");
            }
            assert!(unmet(&flags(&[]), &r).unwrap().is_empty());
        }
        assert!(unmet(&flags(&["--require", "everything"]), &Report::default()).is_err());
    }

    #[test]
    fn curl_reads_a_body_a_404_and_refuses_anything_else() {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        if Command::new("curl").arg("--version").output().is_err() {
            eprintln!("no curl on this machine; skipped");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::default();
                reader.read_line(&mut line).unwrap();
                let path = line.split(' ').nth(1).unwrap().to_owned();
                let mut length = 0;
                loop {
                    let mut h = String::default();
                    reader.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let (status, reply) = match path.as_str() {
                    "/digest" => ("200 OK", body),
                    "/timestamp/ab" => ("404 Not Found", Vec::new()),
                    _ => ("500 Internal Server Error", Vec::new()),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        assert_eq!(
            curl(&format!("{base}/digest"), Some(b"posted\nbytes")).unwrap(),
            Some(b"posted\nbytes".to_vec())
        );
        assert_eq!(curl(&format!("{base}/timestamp/ab"), None).unwrap(), None);
        let err = curl(&format!("{base}/other"), None).unwrap_err();
        assert!(err.contains("HTTP 500"), "{err}");
        server.join().unwrap();

        // Nothing listens on a port that was just released.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/digest", closed.local_addr().unwrap());
        drop(closed);
        assert!(curl(&url, Some(b"x")).unwrap_err().starts_with("curl "));
    }
}
