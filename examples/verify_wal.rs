use calybris_core::wal::{read_verified_wal, WalWriter};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Decision {
    model: String,
    action: String,
    cost_microcents: i64,
}

fn main() {
    let path = PathBuf::from("example_wal.jsonl");

    // Write some decisions
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

    // Read and verify chain integrity
    let entries = read_verified_wal::<Decision>(&path).unwrap();
    println!("\nVerified {} entries:", entries.len());
    for entry in &entries {
        println!(
            "  [{}] {} → {} ({}µ¢) prev={}...",
            entry.sequence,
            entry.data.model,
            entry.data.action,
            entry.data.cost_microcents,
            &entry.previous_hash[..entry.previous_hash.len().min(8)],
        );
    }

    // Reopen — chain validates automatically
    let wal = WalWriter::<Decision>::open(&path).unwrap();
    println!("\nReopened: seq={}, chain valid ✓", wal.sequence());

    let _ = std::fs::remove_file(&path);
}
