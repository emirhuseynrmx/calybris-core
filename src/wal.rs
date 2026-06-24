//! Hash-chained Write-Ahead Log — tamper-evident, crash-recoverable.
//!
//! Each entry includes the SHA-256 hash of the previous entry.
//! Modify any record and the chain breaks.
//! The chain is validated on startup before accepting new decisions.
//!
//! Generic over the decision type: any `Serialize + Clone` works.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

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

/// Compute SHA-256 hash of data.
fn hash_entry<T: Serialize>(previous_hash: &str, data: &T) -> String {
    let payload = serde_json::to_string(data).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hash-chained WAL writer.
pub struct WalWriter<T> {
    file: File,
    sequence: u64,
    last_hash: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Serialize + Clone> WalWriter<T> {
    /// Open or create a WAL file. Validates existing chain on open.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        let (sequence, last_hash) = if path.exists() {
            Self::validate_chain(path)?
        } else {
            (0, "genesis".to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file,
            sequence,
            last_hash,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Append a decision to the WAL. Returns the entry with proof.
    pub fn append(&mut self, data: T) -> Result<WalEntry<T>, WalError> {
        self.sequence += 1;
        let entry_hash = hash_entry(&self.last_hash, &data);

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

    /// Validate the hash chain in an existing WAL file.
    /// Returns (last_sequence, last_hash) on success.
    pub fn validate_chain(path: &Path) -> Result<(u64, String), WalError> {
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

            // Parse as generic JSON to extract chain fields
            let raw: serde_json::Value = serde_json::from_str(&line)?;
            let sequence = raw["sequence"].as_u64().unwrap_or(0);
            let previous_hash = raw["previous_hash"].as_str().unwrap_or("").to_string();
            let entry_hash = raw["entry_hash"].as_str().unwrap_or("").to_string();

            if sequence != expected_sequence {
                return Err(WalError::DuplicateSequence(sequence));
            }

            if previous_hash != expected_prev_hash {
                return Err(WalError::ChainBroken {
                    sequence,
                    expected: expected_prev_hash,
                    found: previous_hash,
                });
            }

            // Verify hash: extract the raw "data" JSON substring from the line
            // to avoid serde_json::Value key reordering
            let data_start = line.find("\"data\":").map(|i| i + 7);
            let data_json = data_start.map(|start| {
                // Find the matching closing brace/bracket
                let sub = &line[start..line.len().saturating_sub(1)]; // strip trailing }
                sub.to_string()
            });
            let data_str = data_json.unwrap_or_default();
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, previous_hash.as_bytes());
            sha2::Digest::update(&mut hasher, data_str.as_bytes());
            let digest = sha2::Digest::finalize(hasher);
            let computed: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
            if computed != entry_hash {
                return Err(WalError::ChainBroken {
                    sequence,
                    expected: computed,
                    found: entry_hash,
                });
            }

            last_hash = entry_hash;
            last_sequence = sequence;
            expected_sequence += 1;
            expected_prev_hash = last_hash.clone();
        }

        Ok((last_sequence, last_hash))
    }
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

/// Verify the hash chain integrity of a WAL file.
/// Returns (entry_count, last_hash) on success, or an error describing the break.
pub fn verify_wal(path: &Path) -> Result<(u64, String), WalError> {
    // Reuse the same validation logic as WalWriter::open
    WalWriter::<serde_json::Value>::validate_chain(path)
}

/// Read a WAL file AND verify its chain integrity.
/// Returns entries only if the entire chain is valid.
pub fn read_verified_wal<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<Vec<WalEntry<T>>, WalError> {
    // Verify first
    WalWriter::<serde_json::Value>::validate_chain(path)?;
    // Then read
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

        // Reopen — should validate chain and continue
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

        // Tamper with the file
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"cost\":2", "\"cost\":999", 1);
        std::fs::write(&path, tampered).unwrap();

        // Reopen should fail
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
        );
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn different_data_different_hash() {
        let h1 = hash_entry(
            "prev",
            &TestDecision {
                model: "x".into(),
                cost: 5,
            },
        );
        let h2 = hash_entry(
            "prev",
            &TestDecision {
                model: "y".into(),
                cost: 5,
            },
        );
        assert_ne!(h1, h2);
    }
}
