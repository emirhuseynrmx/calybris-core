//! A WAL line is read back after a crash, from a file anyone could have edited.
//!
//! The property: decoding one line never panics, and a decoded entry never
//! claims a hash it did not carry.

#![no_main]

use calybris_core::wal::WalEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // One line, the way the reader sees it.
    for line in data.split(|byte| *byte == b'\n') {
        let Ok(entry) = serde_json::from_slice::<WalEntry<serde_json::Value>>(line) else {
            continue;
        };

        // Hex-ish fields are the ones a reader compares. Reading them must not
        // panic regardless of what they contain.
        let _ = entry.entry_hash.len();
        let _ = entry.previous_hash.len();

        if let Ok(encoded) = serde_json::to_vec(&entry) {
            if let Ok(again) = serde_json::from_slice::<WalEntry<serde_json::Value>>(&encoded) {
                assert_eq!(entry.sequence, again.sequence);
                assert_eq!(entry.entry_hash, again.entry_hash);
                assert_eq!(entry.previous_hash, again.previous_hash);
            }
        }
    }
});
