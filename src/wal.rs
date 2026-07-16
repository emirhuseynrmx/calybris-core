//! Hash-chained Write-Ahead Log — tamper-evident, crash-detecting.
//!
//! Each entry's hash chains to the previous, forming a tamper-evident log.
//! Optionally keyed with HMAC-SHA256: without a key the chain detects
//! accidental corruption; with a key an attacker cannot recompute
//! consistent hashes without possessing the secret.
//!
//! The chain is validated on startup before accepting new decisions.
//! Generic over the decision type: any `Serialize` type works.

use crate::digest::{bytes_to_hex, digest_to_hex, policy_digest};
use crate::kernel::{KernelDecision, KernelInput, PolicySnapshot};
use crate::verify::{audit_bundle, verified_audit_bundle, verify_decision, VerifyResult};
use fs2::FileExt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Minimum HMAC-SHA256 key length accepted by keyed WAL APIs.
pub const MIN_HMAC_KEY_BYTES: usize = 32;
/// Maximum encoded WAL line accepted by readers.
pub const MAX_WAL_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_WAL_PAYLOAD_BYTES: usize = MAX_WAL_ENTRY_BYTES - 512;

/// A single entry in the hash-chained WAL.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalEntry<T> {
    /// Monotonically increasing sequence number (starts at 1).
    pub sequence: u64,
    /// Hash of the previous entry (or `"genesis"` for the first).
    pub previous_hash: String,
    /// Hash of this entry (SHA-256 or HMAC-SHA256 of `previous_hash` + `data`).
    pub entry_hash: String,
    /// The decision or record stored in this entry.
    pub data: T,
}

/// Trusted head of a WAL at a point in time.
///
/// Persist this outside the WAL file. Verification against an anchor detects
/// clean suffix truncation that an internally consistent hash-chain prefix
/// cannot detect by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalAnchor {
    pub schema_version: String,
    pub sequence: u64,
    pub last_hash: String,
    pub keyed: bool,
}

/// Stable schema for serialized WAL anchors.
pub const WAL_ANCHOR_SCHEMA: &str = "calybris.wal-anchor.v1";

/// WAL error types.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("WAL JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("WAL chain broken at sequence {sequence}: expected {expected}, found {found}")]
    ChainBroken {
        sequence: u64,
        expected: String,
        found: String,
    },
    #[error("WAL duplicate sequence: {0}")]
    DuplicateSequence(u64),
    #[error("WAL audit failed at sequence {sequence}: {reason}")]
    AuditFailed { sequence: u64, reason: String },
}

fn wal_io_error(kind: std::io::ErrorKind, message: impl Into<String>) -> WalError {
    WalError::Io(std::io::Error::new(kind, message.into()))
}

impl WalAnchor {
    /// Verify an already chain-validated WAL head against this anchor.
    pub fn verify_head(
        &self,
        found_sequence: u64,
        found_hash: String,
        keyed: bool,
    ) -> Result<(u64, String), WalError> {
        if self.schema_version != WAL_ANCHOR_SCHEMA {
            return Err(WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown WAL anchor schema: {}", self.schema_version),
            )));
        }
        if self.keyed != keyed {
            return Err(wal_io_error(
                std::io::ErrorKind::InvalidInput,
                "WAL anchor keyed mode does not match verifier mode",
            ));
        }
        if found_sequence != self.sequence || found_hash != self.last_hash {
            return Err(wal_io_error(
                std::io::ErrorKind::InvalidData,
                format!(
                    "WAL anchor mismatch: expected sequence {} hash {}, found sequence {} hash {}",
                    self.sequence, self.last_hash, found_sequence, found_hash
                ),
            ));
        }
        Ok((self.sequence, self.last_hash.clone()))
    }
}

fn validate_hmac_key(key: &[u8]) -> Result<(), WalError> {
    if key.len() < MIN_HMAC_KEY_BYTES {
        return Err(wal_io_error(
            std::io::ErrorKind::InvalidInput,
            format!(
                "WAL HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes, found {}",
                key.len()
            ),
        ));
    }
    Ok(())
}

fn read_bounded_line<R: BufRead>(reader: &mut R, buffer: &mut Vec<u8>) -> Result<usize, WalError> {
    buffer.clear();
    let read = Read::by_ref(reader)
        .take((MAX_WAL_ENTRY_BYTES + 1) as u64)
        .read_until(b'\n', buffer)?;
    if buffer.len() > MAX_WAL_ENTRY_BYTES {
        return Err(wal_io_error(
            std::io::ErrorKind::InvalidData,
            format!(
                "WAL entry exceeds {MAX_WAL_ENTRY_BYTES} bytes: found {}",
                buffer.len()
            ),
        ));
    }
    Ok(read)
}

/// Full audit record: policy/input/decision digests + replay flag + optional metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedRecord<M> {
    pub audit: crate::verify::AuditBundle,
    pub input: KernelInput,
    pub decision: KernelDecision,
    pub metadata: M,
}

/// Result of replay-verifying one audited WAL entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalReplayVerdict {
    pub sequence: u64,
    pub replay_valid: bool,
    pub policy_digest_match: bool,
    pub input_digest_match: bool,
    pub decision_digest_match: bool,
}

impl<M> WalWriter<AuditedRecord<M>>
where
    M: Serialize,
{
    /// Append a fully audited decision record (bundle + input + decision + metadata).
    pub fn append_audited(
        &mut self,
        snapshot: &PolicySnapshot,
        input: KernelInput,
        decision: KernelDecision,
        metadata: M,
    ) -> Result<WalEntry<AuditedRecord<M>>, WalError> {
        let audit = audit_bundle(snapshot, input, &decision);
        let record = AuditedRecord {
            audit,
            input,
            decision,
            metadata,
        };
        self.append(record)
    }

    /// Verify and append an audited decision record.
    ///
    /// Unlike [`append_audited`](Self::append_audited), this method fails closed
    /// before writing when `decision` does not exactly replay from
    /// `snapshot.prescribe(input)`.
    pub fn append_verified_audited(
        &mut self,
        snapshot: &PolicySnapshot,
        input: KernelInput,
        decision: KernelDecision,
        metadata: M,
    ) -> Result<WalEntry<AuditedRecord<M>>, WalError> {
        let audit = verified_audit_bundle(snapshot, input, &decision).map_err(|result| {
            WalError::AuditFailed {
                sequence: self.sequence.saturating_add(1),
                reason: format!("verify_decision failed: {result:?}"),
            }
        })?;
        let record = AuditedRecord {
            audit,
            input,
            decision,
            metadata,
        };
        self.append(record)
    }
}

/// Append an audited record to any WAL writer.
pub fn append_audited<M>(
    wal: &mut WalWriter<AuditedRecord<M>>,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: KernelDecision,
    metadata: M,
) -> Result<WalEntry<AuditedRecord<M>>, WalError>
where
    M: Serialize,
{
    wal.append_audited(snapshot, input, decision, metadata)
}

/// Verify and append an audited record to any audited WAL writer.
///
/// This is the fail-closed convenience function for deployment boundaries where
/// an invalid decision must not enter the WAL.
pub fn append_verified_audited<M>(
    wal: &mut WalWriter<AuditedRecord<M>>,
    snapshot: &PolicySnapshot,
    input: KernelInput,
    decision: KernelDecision,
    metadata: M,
) -> Result<WalEntry<AuditedRecord<M>>, WalError>
where
    M: Serialize,
{
    wal.append_verified_audited(snapshot, input, decision, metadata)
}

fn compute_hash(
    previous_hash: &str,
    data_json: &str,
    key: Option<&[u8]>,
) -> Result<String, WalError> {
    match key {
        Some(k) => {
            validate_hmac_key(k)?;
            let mut mac = HmacSha256::new_from_slice(k).map_err(|_| {
                WalError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid HMAC key length",
                ))
            })?;
            mac.update(previous_hash.as_bytes());
            mac.update(data_json.as_bytes());
            Ok(bytes_to_hex(&mac.finalize().into_bytes()))
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(previous_hash.as_bytes());
            hasher.update(data_json.as_bytes());
            Ok(bytes_to_hex(&hasher.finalize()))
        }
    }
}

#[cfg(test)]
fn hash_entry<T: Serialize>(
    previous_hash: &str,
    data: &T,
    key: Option<&[u8]>,
) -> Result<String, WalError> {
    let payload = serde_json::to_string(data)?;
    compute_hash(previous_hash, &payload, key)
}

/// Hash-chained WAL writer.
/// Hash-chained, tamper-evident Write-Ahead Log writer.
///
/// Without a key, the chain detects accidental corruption (bit rot, truncation).
/// With an HMAC key ([`open_keyed`](WalWriter::open_keyed)), an attacker who
/// modifies the file cannot recompute valid hashes.
///
/// The chain is validated on every [`open`](WalWriter::open) call.
pub struct WalWriter<T> {
    file: File,
    _writer_lock: File,
    sequence: u64,
    last_hash: String,
    hmac_key: Option<Vec<u8>>,
    poisoned: AtomicBool,
    _phantom: std::marker::PhantomData<T>,
}

fn acquire_writer_lock(path: &Path) -> Result<File, WalError> {
    let lock_path = writer_lock_path(path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.try_lock_exclusive().map_err(|_| {
        wal_io_error(
            std::io::ErrorKind::WouldBlock,
            format!("WAL already has an active writer: {}", path.display()),
        )
    })?;
    Ok(lock_file)
}

fn configured_lock_dir() -> Result<PathBuf, std::io::Error> {
    if let Some(path) = std::env::var_os("CALYBRIS_WAL_LOCK_DIR").filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }

    #[cfg(windows)]
    if let Some(path) = std::env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("calybris").join("wal-locks"));
    }

    #[cfg(not(windows))]
    if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("calybris").join("wal-locks"));
    }

    if let Some(path) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path)
            .join(".cache")
            .join("calybris")
            .join("wal-locks"));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no secure WAL lock directory; set CALYBRIS_WAL_LOCK_DIR",
    ))
}

pub(crate) fn writer_lock_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let identity = match file_id::get_file_id(path)? {
        file_id::FileId::Inode {
            device_id,
            inode_number,
        } => format!("inode-{device_id:016x}-{inode_number:016x}"),
        file_id::FileId::LowRes {
            volume_serial_number,
            file_index,
        } => format!("lowres-{volume_serial_number:08x}-{file_index:016x}"),
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => format!("highres-{volume_serial_number:016x}-{file_id:032x}"),
    };
    let lock_dir = configured_lock_dir()?;
    std::fs::create_dir_all(&lock_dir)?;
    Ok(lock_dir.join(format!("{identity}.lock")))
}

impl<T: Serialize> WalWriter<T> {
    /// Open or create a WAL file. Validates existing chain on open.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        Self::open_inner(path, None)
    }

    /// Open or create a WAL file with HMAC-SHA256 keying.
    /// Every entry's hash is computed with the key — an attacker who
    /// modifies the file cannot recompute valid hashes without it.
    pub fn open_keyed(path: &Path, key: &[u8]) -> Result<Self, WalError> {
        Self::open_inner(path, Some(key.to_vec()))
    }

    fn open_inner(path: &Path, hmac_key: Option<Vec<u8>>) -> Result<Self, WalError> {
        if let Some(key) = hmac_key.as_deref() {
            validate_hmac_key(key)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let writer_lock = acquire_writer_lock(path)?;
        let mut read_file = file.try_clone()?;
        read_file.seek(SeekFrom::Start(0))?;
        let (sequence, last_hash) =
            validate_chain_reader(BufReader::new(read_file), hmac_key.as_deref())?;

        Ok(Self {
            file,
            _writer_lock: writer_lock,
            sequence,
            last_hash,
            hmac_key,
            poisoned: AtomicBool::new(false),
            _phantom: std::marker::PhantomData,
        })
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Append a decision to the WAL. Returns the entry with proof.
    ///
    /// Writes to the OS buffer but does **not** fsync. Call [`Self::sync`] or
    /// [`Self::flush_and_sync`] explicitly when you need crash durability.
    /// This keeps the hot path fast (~1µs per append) while letting
    /// callers batch durability when appropriate.
    #[must_use = "check the returned entry for the hash chain link"]
    pub fn append(&mut self, data: T) -> Result<WalEntry<T>, WalError> {
        if self.is_poisoned() {
            return Err(wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        let next_sequence = self.sequence.checked_add(1).ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;
        // Serialize data once — reuse for both hash computation and file write.
        let data_json = serde_json::to_string(&data)?;
        if data_json.len() > MAX_WAL_PAYLOAD_BYTES {
            return Err(wal_io_error(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "WAL entry exceeds {MAX_WAL_PAYLOAD_BYTES} bytes: found {}",
                    data_json.len()
                ),
            ));
        }
        let entry_hash = compute_hash(&self.last_hash, &data_json, self.hmac_key.as_deref())?;
        let previous_hash = self.last_hash.clone();

        // Build the line manually to avoid serializing data a second time.
        // Format: {"sequence":N,"previous_hash":"...","entry_hash":"...","data":...}
        if let Err(error) = writeln!(
            self.file,
            "{{\"sequence\":{},\"previous_hash\":\"{}\",\"entry_hash\":\"{}\",\"data\":{}}}",
            next_sequence, previous_hash, entry_hash, data_json
        ) {
            self.poison();
            return Err(WalError::Io(error));
        }

        self.sequence = next_sequence;
        self.last_hash = entry_hash.clone();

        Ok(WalEntry {
            sequence: self.sequence,
            previous_hash,
            entry_hash,
            data,
        })
    }

    /// Flush userspace buffer to OS and fsync to disk.
    /// Call after a batch of appends for crash durability.
    pub fn flush_and_sync(&mut self) -> Result<(), WalError> {
        if self.is_poisoned() {
            return Err(wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        if let Err(error) = self.file.flush().and_then(|()| self.file.sync_data()) {
            self.poison();
            return Err(WalError::Io(error));
        }
        Ok(())
    }

    /// Flush userspace buffer to OS (no fsync).
    pub fn flush(&mut self) -> Result<(), WalError> {
        if self.is_poisoned() {
            return Err(wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        if let Err(error) = self.file.flush() {
            self.poison();
            return Err(WalError::Io(error));
        }
        Ok(())
    }

    /// Sync data to disk (fsync). Assumes buffer is already flushed.
    pub fn sync(&self) -> Result<(), WalError> {
        if self.is_poisoned() {
            return Err(wal_io_error(
                std::io::ErrorKind::Other,
                "WAL writer is poisoned after an earlier I/O failure",
            ));
        }
        if let Err(error) = self.file.sync_data() {
            self.poison();
            return Err(WalError::Io(error));
        }
        Ok(())
    }

    /// Current sequence number (equals the number of entries written).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Alias for [`sequence`](Self::sequence) — total entries written.
    pub fn entry_count(&self) -> u64 {
        self.sequence
    }

    /// Last hash in the chain.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Capture the current trusted WAL head.
    #[must_use]
    pub fn anchor(&self) -> WalAnchor {
        WalAnchor {
            schema_version: WAL_ANCHOR_SCHEMA.to_string(),
            sequence: self.sequence,
            last_hash: self.last_hash.clone(),
            keyed: self.hmac_key.is_some(),
        }
    }

    /// Validate the hash chain in an existing WAL file (unkeyed).
    pub fn validate_chain(path: &Path) -> Result<(u64, String), WalError> {
        validate_chain_inner(path, None)
    }
}

/// Validate the hash chain, optionally with an HMAC key.
/// Uses serde_json's preserve_order feature so re-serializing the data
/// field produces the same JSON bytes as the original write.
fn validate_chain_inner(path: &Path, key: Option<&[u8]>) -> Result<(u64, String), WalError> {
    if let Some(key) = key {
        validate_hmac_key(key)?;
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    validate_chain_reader(reader, key)
}

fn validate_chain_reader<R: BufRead>(
    mut reader: R,
    key: Option<&[u8]>,
) -> Result<(u64, String), WalError> {
    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;

    let mut line = Vec::new();
    while read_bounded_line(&mut reader, &mut line)? != 0 {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let entry: WalEntry<serde_json::Value> = serde_json::from_slice(&line)?;

        if entry.sequence != expected_sequence {
            return Err(WalError::DuplicateSequence(entry.sequence));
        }

        if entry.previous_hash != expected_prev_hash {
            return Err(WalError::ChainBroken {
                sequence: entry.sequence,
                expected: expected_prev_hash,
                found: entry.previous_hash,
            });
        }

        let data_str = serde_json::to_string(&entry.data)?;
        let computed = compute_hash(&entry.previous_hash, &data_str, key)?;
        // Constant-time comparison to prevent timing side-channel on keyed WAL
        if computed
            .as_bytes()
            .ct_eq(entry.entry_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(WalError::ChainBroken {
                sequence: entry.sequence,
                expected: computed,
                found: entry.entry_hash,
            });
        }

        last_hash = entry.entry_hash;
        last_sequence = entry.sequence;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;
        expected_prev_hash = last_hash.clone();
    }

    Ok((last_sequence, last_hash))
}

fn read_verified_wal_inner<T: for<'de> Deserialize<'de>>(
    path: &Path,
    key: Option<&[u8]>,
) -> Result<Vec<WalEntry<T>>, WalError> {
    let mut entries = Vec::new();
    visit_verified_wal_inner(path, key, |entry| entries.push(entry))?;
    Ok(entries)
}

fn visit_verified_wal_inner<T, F>(
    path: &Path,
    key: Option<&[u8]>,
    mut visit: F,
) -> Result<(u64, String), WalError>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(WalEntry<T>),
{
    if let Some(key) = key {
        validate_hmac_key(key)?;
    }
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;
    let mut last_hash = "genesis".to_string();

    let mut line = Vec::new();
    while read_bounded_line(&mut reader, &mut line)? != 0 {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let value_entry: WalEntry<serde_json::Value> = serde_json::from_slice(&line)?;

        if value_entry.sequence != expected_sequence {
            return Err(WalError::DuplicateSequence(value_entry.sequence));
        }

        if value_entry.previous_hash != expected_prev_hash {
            return Err(WalError::ChainBroken {
                sequence: value_entry.sequence,
                expected: expected_prev_hash,
                found: value_entry.previous_hash,
            });
        }

        let data_str = serde_json::to_string(&value_entry.data)?;
        let computed = compute_hash(&value_entry.previous_hash, &data_str, key)?;
        if computed
            .as_bytes()
            .ct_eq(value_entry.entry_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(WalError::ChainBroken {
                sequence: value_entry.sequence,
                expected: computed,
                found: value_entry.entry_hash,
            });
        }

        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WAL sequence overflow",
            ))
        })?;
        last_sequence = value_entry.sequence;
        last_hash = value_entry.entry_hash;
        expected_prev_hash = last_hash.clone();

        // Parse the typed entry from the already-validated line. This avoids a
        // validate-then-reopen race while keeping the public API generic over T.
        visit(serde_json::from_slice(&line)?);
    }

    Ok((last_sequence, last_hash))
}

/// Read a WAL file **without** chain verification.
///
/// Use [`read_verified_wal`] or [`read_verified_wal_keyed`] if you need
/// tamper detection. This function is faster but trusts the data.
pub fn read_wal<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<WalEntry<T>>, WalError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();

    let mut line = Vec::new();
    while read_bounded_line(&mut reader, &mut line)? != 0 {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let entry: WalEntry<T> = serde_json::from_slice(&line)?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Verify the hash chain integrity of a WAL file (unkeyed).
pub fn verify_wal(path: &Path) -> Result<(u64, String), WalError> {
    validate_chain_inner(path, None)
}

/// Verify the hash chain integrity of a WAL file with HMAC key.
pub fn verify_wal_keyed(path: &Path, key: &[u8]) -> Result<(u64, String), WalError> {
    validate_chain_inner(path, Some(key))
}

pub(crate) fn verify_anchor(
    found_sequence: u64,
    found_hash: String,
    anchor: &WalAnchor,
    keyed: bool,
) -> Result<(u64, String), WalError> {
    anchor.verify_head(found_sequence, found_hash, keyed)
}

/// Verify an unkeyed WAL against a trusted external head anchor.
pub fn verify_wal_against_anchor(
    path: &Path,
    anchor: &WalAnchor,
) -> Result<(u64, String), WalError> {
    let (sequence, hash) = verify_wal(path)?;
    verify_anchor(sequence, hash, anchor, false)
}

/// Verify a keyed WAL against a trusted external head anchor.
pub fn verify_wal_keyed_against_anchor(
    path: &Path,
    key: &[u8],
    anchor: &WalAnchor,
) -> Result<(u64, String), WalError> {
    let (sequence, hash) = verify_wal_keyed(path, key)?;
    verify_anchor(sequence, hash, anchor, true)
}

/// Read a WAL file AND verify its chain integrity (unkeyed).
pub fn read_verified_wal<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<Vec<WalEntry<T>>, WalError> {
    read_verified_wal_inner(path, None)
}

/// Read a WAL file AND verify its chain integrity with HMAC key.
pub fn read_verified_wal_keyed<T: for<'de> Deserialize<'de>>(
    path: &Path,
    key: &[u8],
) -> Result<Vec<WalEntry<T>>, WalError> {
    read_verified_wal_inner(path, Some(key))
}

/// Stream an unkeyed WAL through `visit` after validating each entry.
///
/// Memory use is constant with respect to WAL length.
pub fn visit_verified_wal<T, F>(path: &Path, visit: F) -> Result<(u64, String), WalError>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(WalEntry<T>),
{
    visit_verified_wal_inner(path, None, visit)
}

/// Stream a keyed WAL through `visit` after validating each entry.
///
/// Memory use is constant with respect to WAL length.
pub fn visit_verified_wal_keyed<T, F>(
    path: &Path,
    key: &[u8],
    visit: F,
) -> Result<(u64, String), WalError>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(WalEntry<T>),
{
    visit_verified_wal_inner(path, Some(key), visit)
}

/// Replay-verify every audited entry against `snapshot` (chain + digests + prescribe).
///
/// Metadata is ignored during replay (`serde_json::Value`).
pub fn replay_audited_wal(
    path: &Path,
    snapshot: &PolicySnapshot,
) -> Result<Vec<WalReplayVerdict>, WalError> {
    replay_audited_wal_keyed::<serde_json::Value>(path, snapshot, None)
}

/// Replay-verify audited WAL with optional HMAC key.
pub fn replay_audited_wal_keyed<M>(
    path: &Path,
    snapshot: &PolicySnapshot,
    key: Option<&[u8]>,
) -> Result<Vec<WalReplayVerdict>, WalError>
where
    M: for<'de> Deserialize<'de>,
{
    let entries = read_verified_wal_inner::<AuditedRecord<M>>(path, key)?;
    let expected_policy = digest_to_hex(&policy_digest(snapshot));

    let mut verdicts = Vec::with_capacity(entries.len());
    for entry in entries {
        let bundle = &entry.data.audit;
        let replay = verify_decision(snapshot, entry.data.input, &entry.data.decision);
        let replay_valid = replay == VerifyResult::Valid;
        let policy_digest_match = bundle.policy_digest_hex == expected_policy;
        let input_digest_match = bundle.input_digest_hex
            == digest_to_hex(&crate::digest::input_digest(&entry.data.input));
        let decision_digest_match = bundle.decision_digest_hex
            == digest_to_hex(&crate::digest::decision_digest(&entry.data.decision));

        if !replay_valid || !policy_digest_match || !input_digest_match || !decision_digest_match {
            return Err(WalError::AuditFailed {
                sequence: entry.sequence,
                reason: format!(
                    "replay_valid={replay_valid} policy_match={policy_digest_match} input_match={input_digest_match} decision_match={decision_digest_match}"
                ),
            });
        }

        verdicts.push(WalReplayVerdict {
            sequence: entry.sequence,
            replay_valid,
            policy_digest_match,
            input_digest_match,
            decision_digest_match,
        });
    }
    Ok(verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TEST_HMAC_KEY: &[u8; 32] = b"calybris-test-hmac-key-000000001";
    const OTHER_HMAC_KEY: &[u8; 32] = b"calybris-test-hmac-key-000000002";

    fn temp_wal(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(format!("{name}.jsonl"));
        (dir, path)
    }

    fn assert_io_error<T>(
        result: Result<T, WalError>,
        expected_kind: std::io::ErrorKind,
        expected_message: &str,
    ) {
        match result {
            Err(WalError::Io(error)) => {
                assert_eq!(error.kind(), expected_kind);
                assert!(
                    error.to_string().contains(expected_message),
                    "unexpected error: {error}"
                );
            }
            Err(error) => panic!("expected WAL I/O error, got: {error}"),
            Ok(_) => panic!("expected WAL I/O error, got success"),
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TestDecision {
        model: String,
        cost: i64,
    }

    #[test]
    fn append_and_read() {
        let (_dir, path) = temp_wal("append");

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        wal.append(TestDecision {
            model: "gpt-4o".into(),
            cost: 100,
        })
        .unwrap();
        wal.append(TestDecision {
            model: "mini".into(),
            cost: 10,
        })
        .unwrap();
        wal.sync().unwrap();

        assert_eq!(wal.sequence(), 2);

        let entries = read_wal::<TestDecision>(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data.model, "gpt-4o");
        assert_eq!(entries[1].data.model, "mini");
        assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
    }

    #[test]
    fn verified_visitor_streams_entries_and_returns_head() {
        let (_dir, path) = temp_wal("visitor");
        let expected_head = {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            for cost in [1, 2, 3] {
                wal.append(TestDecision {
                    model: "streamed".into(),
                    cost,
                })
                .unwrap();
            }
            wal.flush_and_sync().unwrap();
            wal.last_hash().to_string()
        };

        let mut costs = Vec::new();
        let head = visit_verified_wal::<TestDecision, _>(&path, |entry| {
            costs.push(entry.data.cost);
        })
        .unwrap();
        assert_eq!(costs, vec![1, 2, 3]);
        assert_eq!(head, (3, expected_head));
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("intentional serialize failure"))
        }
    }

    #[test]
    fn append_serialize_error_does_not_advance_writer_state() {
        let (_dir, path) = temp_wal("append_serialize_error");

        let mut wal = WalWriter::<FailingSerialize>::open(&path).unwrap();
        assert!(wal.append(FailingSerialize).is_err());
        assert_eq!(wal.sequence(), 0);
        assert_eq!(wal.last_hash(), "genesis");
    }

    #[test]
    fn chain_validates_on_reopen() {
        let (_dir, path) = temp_wal("reopen");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_eq!(wal.sequence(), 2);
        wal.append(TestDecision {
            model: "c".into(),
            cost: 3,
        })
        .unwrap();
        assert_eq!(wal.sequence(), 3);
    }

    #[test]
    fn tampered_entry_detected() {
        let (_dir, path) = temp_wal("tamper");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        let result = WalWriter::<TestDecision>::open(&path);
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_starts_fresh() {
        let (_dir, path) = temp_wal("empty");

        let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_eq!(wal.sequence(), 0);
        assert_eq!(wal.last_hash(), "genesis");

        wal.append(TestDecision {
            model: "first".into(),
            cost: 42,
        })
        .unwrap();
        assert_eq!(wal.sequence(), 1);
        assert_ne!(wal.last_hash(), "genesis");
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn different_data_different_hash() {
        let h1 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "y".into(),
                cost: 5,
            },
            None,
        )
        .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hmac_keyed_chain_validates() {
        let (_dir, path) = temp_wal("hmac-basic");
        let key = TEST_HMAC_KEY;

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 10,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 20,
            })
            .unwrap();
            wal.sync().unwrap();
        }

        let wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
        assert_eq!(wal.sequence(), 2);

        let (count, _) = verify_wal_keyed(&path, key).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn short_hmac_keys_are_rejected_even_for_empty_wals() {
        let (_dir, path) = temp_wal("hmac-short-key");
        assert_io_error(
            WalWriter::<TestDecision>::open_keyed(&path, b"too-short"),
            std::io::ErrorKind::InvalidInput,
            "at least 32 bytes, found 9",
        );
        std::fs::write(&path, "").unwrap();
        assert_io_error(
            verify_wal_keyed(&path, b""),
            std::io::ErrorKind::InvalidInput,
            "at least 32 bytes, found 0",
        );
    }

    #[test]
    fn hmac_wrong_key_rejects() {
        let (_dir, path) = temp_wal("hmac-wrongkey");

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, TEST_HMAC_KEY).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
        }

        let result = WalWriter::<TestDecision>::open_keyed(&path, OTHER_HMAC_KEY);
        assert!(result.is_err());

        let result = WalWriter::<TestDecision>::open(&path);
        assert!(result.is_err());
    }

    #[test]
    fn hmac_tamper_detected() {
        let (_dir, path) = temp_wal("hmac-tamper");
        let key = TEST_HMAC_KEY;

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        let result = verify_wal_keyed(&path, key);
        assert!(result.is_err());
    }

    #[test]
    fn hmac_different_key_different_hash() {
        let h1 = compute_hash("prev", "{\"x\":1}", Some(TEST_HMAC_KEY)).unwrap();
        let h2 = compute_hash("prev", "{\"x\":1}", Some(OTHER_HMAC_KEY)).unwrap();
        let h3 = compute_hash("prev", "{\"x\":1}", None).unwrap();
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn read_verified_keyed_works() {
        let (_dir, path) = temp_wal("hmac-read-verified");
        let key = TEST_HMAC_KEY;

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
            wal.append(TestDecision {
                model: "x".into(),
                cost: 42,
            })
            .unwrap();
        }

        let entries = read_verified_wal_keyed::<TestDecision>(&path, key).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data.model, "x");
    }

    #[test]
    fn audited_append_replay_roundtrip() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("audited-replay");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, "meta".to_string())
                .unwrap();
            wal.sync().unwrap();
        }

        let verdicts = replay_audited_wal(&path, &snapshot).unwrap();
        assert_eq!(verdicts.len(), 1);
        assert!(verdicts[0].replay_valid);
    }

    #[test]
    fn verified_audited_append_replay_roundtrip() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("verified-audited-replay");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            append_verified_audited(&mut wal, &snapshot, input, decision, "meta".to_string())
                .unwrap();
            wal.sync().unwrap();
        }

        let verdicts = replay_audited_wal(&path, &snapshot).unwrap();
        assert_eq!(verdicts.len(), 1);
        assert!(verdicts[0].replay_valid);
    }

    #[test]
    fn verified_audited_append_rejects_tampered_decision_without_advancing() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("verified-audited-tamper");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let mut decision = snapshot.prescribe(input);
        decision.selected_model_id = 999;

        let mut wal = WalWriter::open(&path).unwrap();
        let result = wal.append_verified_audited(&snapshot, input, decision, ());
        assert!(matches!(
            result,
            Err(WalError::AuditFailed { sequence: 1, .. })
        ));
        assert_eq!(wal.sequence(), 0);
        assert_eq!(wal.last_hash(), "genesis");

        let entries = read_wal::<AuditedRecord<()>>(&path).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn audited_replay_fails_on_input_digest_mismatch() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("audited-input-tamper");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, ()).unwrap();
            wal.sync().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen(
            &digest_to_hex(&crate::digest::input_digest(&input)),
            "0000000000000000000000000000000000000000000000000000000000000000",
            1,
        );
        std::fs::write(&path, tampered).unwrap();

        let result = replay_audited_wal(&path, &snapshot);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_sequence_rejected() {
        let (_dir, path) = temp_wal("dup-seq");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let duplicate = content.lines().next().unwrap();
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{duplicate}").unwrap();

        let result = verify_wal(&path);
        assert!(matches!(result, Err(WalError::DuplicateSequence(1))));
    }

    #[test]
    fn previous_hash_mismatch_rejected() {
        let (_dir, path) = temp_wal("prev-hash");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
            wal.append(TestDecision {
                model: "b".into(),
                cost: 2,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        let tampered = lines[1].replacen(
            "\"previous_hash\":\"",
            "\"previous_hash\":\"0000000000000000000000000000000000000000000000000000000000000000",
            1,
        );
        std::fs::write(&path, format!("{}\n{}\n", lines[0], tampered)).unwrap();

        let result = verify_wal(&path);
        assert!(matches!(result, Err(WalError::ChainBroken { .. })));
    }

    #[test]
    fn truncated_last_line_rejected() {
        let (_dir, path) = temp_wal("truncated");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
        }

        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        write!(file, "{{\"sequence\":2,\"previous").unwrap();

        let result = verify_wal(&path);
        assert!(result.is_err());
    }

    #[test]
    fn oversized_wal_line_is_rejected_before_json_parsing() {
        let (_dir, path) = temp_wal("oversized-line");
        std::fs::write(&path, vec![b'x'; MAX_WAL_ENTRY_BYTES + 1]).unwrap();
        assert_io_error(
            verify_wal(&path),
            std::io::ErrorKind::InvalidData,
            "WAL entry exceeds",
        );
    }

    #[test]
    fn oversized_append_does_not_advance_writer() {
        let (_dir, path) = temp_wal("oversized-append");
        let mut wal = WalWriter::<String>::open(&path).unwrap();
        assert_io_error(
            wal.append("x".repeat(MAX_WAL_ENTRY_BYTES)),
            std::io::ErrorKind::InvalidInput,
            "WAL entry exceeds",
        );
        assert_eq!(wal.sequence(), 0);
        assert_eq!(wal.last_hash(), "genesis");
    }

    #[test]
    fn clean_suffix_truncation_requires_external_anchor() {
        let (_dir, path) = temp_wal("suffix-anchor");
        let anchor = {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            for cost in [10, 20, 30] {
                wal.append(TestDecision {
                    model: "candidate".into(),
                    cost,
                })
                .unwrap();
            }
            wal.flush_and_sync().unwrap();
            wal.anchor()
        };

        let content = std::fs::read_to_string(&path).unwrap();
        let retained = content.lines().take(2).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&path, retained).unwrap();

        assert_eq!(verify_wal(&path).unwrap().0, 2);
        assert_io_error(
            verify_wal_against_anchor(&path, &anchor),
            std::io::ErrorKind::InvalidData,
            "WAL anchor mismatch",
        );
    }

    #[test]
    fn second_writer_for_same_file_is_rejected() {
        let (_dir, path) = temp_wal("writer-lock");
        let _first = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_io_error(
            WalWriter::<TestDecision>::open(&path),
            std::io::ErrorKind::WouldBlock,
            "active writer",
        );
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn hard_link_alias_shares_the_same_writer_lock() {
        let (_dir, path) = temp_wal("hard-link");
        std::fs::write(&path, "").unwrap();
        let alias = path.with_file_name("hard-link-alias.jsonl");
        std::fs::hard_link(&path, &alias).unwrap();
        let _writer = WalWriter::<TestDecision>::open(&path).unwrap();
        assert_io_error(
            WalWriter::<TestDecision>::open(&alias),
            std::io::ErrorKind::WouldBlock,
            "active writer",
        );
    }

    #[test]
    fn keyed_anchor_verifies_only_with_the_keyed_path() {
        let (_dir, path) = temp_wal("keyed-anchor-mode");
        let anchor = {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, TEST_HMAC_KEY).unwrap();
            wal.append(TestDecision {
                model: "candidate".into(),
                cost: 10,
            })
            .unwrap();
            wal.flush_and_sync().unwrap();
            wal.anchor()
        };

        assert!(verify_wal_against_anchor(&path, &anchor).is_err());
        verify_wal_keyed_against_anchor(&path, TEST_HMAC_KEY, &anchor).unwrap();
    }

    #[test]
    fn malformed_json_line_rejected() {
        let (_dir, path) = temp_wal("malformed");
        std::fs::write(&path, "not valid json\n").unwrap();
        let result = verify_wal(&path);
        assert!(matches!(result, Err(WalError::Json(_))));
    }

    #[test]
    fn wal_json_rejects_unknown_fields() {
        let anchor = WalAnchor {
            schema_version: WAL_ANCHOR_SCHEMA.to_string(),
            sequence: 1,
            last_hash: "11".repeat(32),
            keyed: true,
        };
        let mut value = serde_json::to_value(anchor).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("trusted".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<WalAnchor>(value).is_err());

        let entry = serde_json::json!({
            "sequence": 1,
            "previous_hash": "genesis",
            "entry_hash": "11".repeat(32),
            "data": {"model": "candidate", "cost": 10},
            "trusted": true
        });
        assert!(serde_json::from_value::<WalEntry<TestDecision>>(entry).is_err());
    }

    #[test]
    fn audited_replay_fails_on_policy_digest_mismatch() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("audited-policy-tamper");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, ()).unwrap();
            wal.sync().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen(
            &digest_to_hex(&policy_digest(&snapshot)),
            "0000000000000000000000000000000000000000000000000000000000000000",
            1,
        );
        std::fs::write(&path, tampered).unwrap();

        let result = replay_audited_wal(&path, &snapshot);
        assert!(result.is_err());
    }

    #[test]
    fn audited_replay_fails_on_decision_digest_mismatch() {
        use crate::kernel::*;

        let (_dir, path) = temp_wal("audited-decision-tamper");

        let models = vec![KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9000,
            risk_ceiling_bps: 9500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 100,
            output_cost_microunits_per_million_tokens: 400,
        }];
        let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models).unwrap();
        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: 1,
            input_tokens: 500,
            output_tokens: 200,
            business_value_microunits: 50_000,
            budget_limit_microunits: 10_000_000,
            risk_bps: 500,
            confidence_bps: 8000,
            minimum_quality_bps: 5000,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        let decision = snapshot.prescribe(input);

        {
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_audited(&snapshot, input, decision, ()).unwrap();
            wal.sync().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen(
            &digest_to_hex(&crate::digest::decision_digest(&decision)),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            1,
        );
        std::fs::write(&path, tampered).unwrap();

        let result = replay_audited_wal(&path, &snapshot);
        assert!(result.is_err());
    }

    #[test]
    fn json_field_reorder_breaks_chain() {
        let (_dir, path) = temp_wal("json-reorder");

        {
            let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
            wal.append(TestDecision {
                model: "x".into(),
                cost: 42,
            })
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let reordered =
            content.replace("\"model\":\"x\",\"cost\":42", "\"cost\":42,\"model\":\"x\"");
        assert_ne!(reordered, content);
        std::fs::write(&path, reordered).unwrap();
        let result = verify_wal(&path);
        assert!(result.is_err());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn keyed_wal_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            count in 1_usize..30,
        ) {
            let (_dir, path) = temp_wal(&format!("keyed-{count}"));

            {
                let mut wal = WalWriter::<TestDecision>::open_keyed(&path, &key).unwrap();
                for i in 0..count {
                    wal.append(TestDecision {
                        model: format!("m{i}"),
                        cost: i as i64,
                    }).unwrap();
                }
            }

            let entries = read_verified_wal_keyed::<TestDecision>(&path, &key).unwrap();
            prop_assert_eq!(entries.len(), count);
        }

        #[test]
        fn arbitrary_data_survives_roundtrip(
            model in "[a-z]{1,20}",
            cost in any::<i64>(),
            count in 1_usize..50,
        ) {
            let (_dir, path) = temp_wal(&format!("fuzz-{cost}-{count}"));

            {
                let mut wal = WalWriter::<TestDecision>::open(&path).unwrap();
                for i in 0..count {
                    wal.append(TestDecision {
                        model: format!("{model}{i}"),
                        cost: cost.wrapping_add(i as i64),
                    }).unwrap();
                }
            }

            let wal = WalWriter::<TestDecision>::open(&path).unwrap();
            prop_assert_eq!(wal.sequence() as usize, count);

            let entries = read_verified_wal::<TestDecision>(&path).unwrap();
            prop_assert_eq!(entries.len(), count);
        }
    }
}
