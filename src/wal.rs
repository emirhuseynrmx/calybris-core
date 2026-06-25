//! Hash-chained Write-Ahead Log — tamper-evident, crash-recoverable.
//!
//! Each entry's hash chains to the previous, forming a tamper-evident log.
//! Optionally keyed with HMAC-SHA256: without a key the chain detects
//! accidental corruption; with a key an attacker cannot recompute
//! consistent hashes without possessing the secret.
//!
//! The chain is validated on startup before accepting new decisions.
//! Generic over the decision type: any `Serialize + Clone` works.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// A single WAL entry with hash chain link.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalEntry<T> {
    pub sequence: u64,
    pub previous_hash: String,
    pub entry_hash: String,
    pub data: T,
}

/// WAL error types.
#[derive(Debug)]
pub enum WalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    ChainBroken {
        sequence: u64,
        expected: String,
        found: String,
    },
    DuplicateSequence(u64),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "WAL I/O error: {e}"),
            Self::Json(e) => write!(f, "WAL JSON error: {e}"),
            Self::ChainBroken {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "WAL chain broken at sequence {sequence}: expected {expected}, found {found}"
            ),
            Self::DuplicateSequence(s) => write!(f, "WAL duplicate sequence: {s}"),
        }
    }
}

impl std::error::Error for WalError {}

impl From<std::io::Error> for WalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for WalError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn compute_hash(previous_hash: &str, data_json: &str, key: Option<&[u8]>) -> String {
    match key {
        Some(k) => {
            let mut mac =
                HmacSha256::new_from_slice(k).expect("HMAC-SHA256 accepts any key length");
            mac.update(previous_hash.as_bytes());
            mac.update(data_json.as_bytes());
            hex_encode(&mac.finalize().into_bytes())
        }
        None => {
            let mut hasher = Sha256::new();
            hasher.update(previous_hash.as_bytes());
            hasher.update(data_json.as_bytes());
            hex_encode(&hasher.finalize())
        }
    }
}

fn hash_entry<T: Serialize>(
    previous_hash: &str,
    data: &T,
    key: Option<&[u8]>,
) -> Result<String, WalError> {
    let payload = serde_json::to_string(data)?;
    Ok(compute_hash(previous_hash, &payload, key))
}

/// Hash-chained WAL writer.
pub struct WalWriter<T> {
    file: File,
    sequence: u64,
    last_hash: String,
    hmac_key: Option<Vec<u8>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Serialize + Clone> WalWriter<T> {
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
        let (sequence, last_hash) = if path.exists() {
            validate_chain_inner(path, hmac_key.as_deref())?
        } else {
            (0, "genesis".to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file,
            sequence,
            last_hash,
            hmac_key,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append a decision to the WAL. Returns the entry with proof.
    pub fn append(&mut self, data: T) -> Result<WalEntry<T>, WalError> {
        self.sequence += 1;
        let entry_hash = hash_entry(&self.last_hash, &data, self.hmac_key.as_deref())?;

        let entry = WalEntry {
            sequence: self.sequence,
            previous_hash: self.last_hash.clone(),
            entry_hash: entry_hash.clone(),
            data,
        };

        let line = serde_json::to_string(&entry)?;
        writeln!(self.file, "{}", line)?;
        self.file.flush()?;

        self.last_hash = entry_hash;
        Ok(entry)
    }

    /// Sync data to disk (fsync).
    pub fn sync(&self) -> Result<(), WalError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Last hash in the chain.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
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
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_sequence = 1_u64;
    let mut expected_prev_hash = "genesis".to_string();
    let mut last_hash = "genesis".to_string();
    let mut last_sequence = 0_u64;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: WalEntry<serde_json::Value> = serde_json::from_str(&line)?;

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
        let computed = compute_hash(&entry.previous_hash, &data_str, key);
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
        expected_sequence += 1;
        expected_prev_hash = last_hash.clone();
    }

    Ok((last_sequence, last_hash))
}

/// Read a WAL file without chain verification.
pub fn read_wal<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<WalEntry<T>>, WalError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: WalEntry<T> = serde_json::from_str(&line)?;
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

/// Read a WAL file AND verify its chain integrity (unkeyed).
pub fn read_verified_wal<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<Vec<WalEntry<T>>, WalError> {
    validate_chain_inner(path, None)?;
    read_wal(path)
}

/// Read a WAL file AND verify its chain integrity with HMAC key.
pub fn read_verified_wal_keyed<T: for<'de> Deserialize<'de>>(
    path: &Path,
    key: &[u8],
) -> Result<Vec<WalEntry<T>>, WalError> {
    validate_chain_inner(path, Some(key))?;
    read_wal(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "target/test-wal-{}-{}.jsonl",
            name,
            std::process::id()
        ))
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TestDecision {
        model: String,
        cost: i64,
    }

    #[test]
    fn append_and_read() {
        let path = temp_path("append");
        let _ = std::fs::remove_file(&path);

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

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn chain_validates_on_reopen() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);

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

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_entry_detected() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);

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

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_starts_fresh() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);

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

        let _ = std::fs::remove_file(&path);
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

    // ── HMAC tests ──

    #[test]
    fn hmac_keyed_chain_validates() {
        let path = temp_path("hmac-basic");
        let _ = std::fs::remove_file(&path);
        let key = b"calybris-secret-key-2026";

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

        // Reopen with same key succeeds
        let wal = WalWriter::<TestDecision>::open_keyed(&path, key).unwrap();
        assert_eq!(wal.sequence(), 2);

        // verify_wal_keyed also works
        let (count, _) = verify_wal_keyed(&path, key).unwrap();
        assert_eq!(count, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_wrong_key_rejects() {
        let path = temp_path("hmac-wrongkey");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = WalWriter::<TestDecision>::open_keyed(&path, b"correct-key").unwrap();
            wal.append(TestDecision {
                model: "a".into(),
                cost: 1,
            })
            .unwrap();
        }

        // Wrong key → chain broken
        let result = WalWriter::<TestDecision>::open_keyed(&path, b"wrong-key");
        assert!(result.is_err());

        // No key → also fails (HMAC hash != plain SHA-256 hash)
        let result = WalWriter::<TestDecision>::open(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_tamper_detected() {
        let path = temp_path("hmac-tamper");
        let _ = std::fs::remove_file(&path);
        let key = b"audit-key";

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

        // Tamper data
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        // Even with the correct key, tamper is detected
        let result = verify_wal_keyed(&path, key);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hmac_different_key_different_hash() {
        let h1 = compute_hash("prev", "{\"x\":1}", Some(b"key-a"));
        let h2 = compute_hash("prev", "{\"x\":1}", Some(b"key-b"));
        let h3 = compute_hash("prev", "{\"x\":1}", None);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn read_verified_keyed_works() {
        let path = temp_path("hmac-read-verified");
        let _ = std::fs::remove_file(&path);
        let key = b"read-key";

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

        let _ = std::fs::remove_file(&path);
    }
}
