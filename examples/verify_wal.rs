use calybris_core::wal::{read_verified_wal, read_verified_wal_keyed, WalWriter};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Decision {
    model: String,
    action: String,
    cost_microcents: i64,
}

fn main() {
    // ── Unkeyed WAL (detects accidental corruption) ──
    let path = PathBuf::from("example_wal.jsonl");

    {
        let mut wal = WalWriter::<Decision>::open(&path).unwrap();
        for i in 0..5 {
            let entry = wal
                .append(Decision {
                    model: format!("model-{}", i % 3),
                    action: if i % 2 == 0 { "allow" } else { "downgrade" }.into(),
                    cost_microcents: (i + 1) * 1000,
                })
                .unwrap();
            println!(
                "Written: seq={} hash={}...",
                entry.sequence,
                &entry.entry_hash[..12]
            );
        }
        wal.sync().unwrap();
    }

    let entries = read_verified_wal::<Decision>(&path).unwrap();
    println!("\nVerified {} unkeyed entries:", entries.len());
    for entry in &entries {
        println!(
            "  [{}] {} -> {} ({}uc) prev={}...",
            entry.sequence,
            entry.data.model,
            entry.data.action,
            entry.data.cost_microcents,
            &entry.previous_hash[..entry.previous_hash.len().min(8)],
        );
    }

    let wal = WalWriter::<Decision>::open(&path).unwrap();
    println!("\nReopened: seq={}, chain valid", wal.sequence());
    let _ = std::fs::remove_file(&path);

    // ── HMAC-keyed WAL (tamper-evident against attackers) ──
    let keyed_path = PathBuf::from("example_wal_keyed.jsonl");
    let key = b"my-secret-audit-key";

    {
        let mut wal = WalWriter::<Decision>::open_keyed(&keyed_path, key).unwrap();
        for i in 0..3 {
            wal.append(Decision {
                model: format!("model-{}", i),
                action: "allow".into(),
                cost_microcents: (i + 1) * 500,
            })
            .unwrap();
        }
        wal.sync().unwrap();
    }

    let entries = read_verified_wal_keyed::<Decision>(&keyed_path, key).unwrap();
    println!("\nVerified {} HMAC-keyed entries.", entries.len());

    // Wrong key correctly fails
    let result = read_verified_wal_keyed::<Decision>(&keyed_path, b"wrong-key");
    println!(
        "Wrong key: {}",
        if result.is_err() {
            "correctly rejected"
        } else {
            "BUG"
        }
    );

    let _ = std::fs::remove_file(&keyed_path);
}
