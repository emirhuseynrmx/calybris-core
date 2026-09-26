//! What the trust layer costs, measured: Merkle trees at 100 thousand, 1
//! million and 10 million records, checkpoint signing, witness cosigning (in
//! memory and with a durable state file), RFC 3161 and OpenTimestamps
//! verification, and hybrid signatures one by one against a batch.
//!
//! None of this is on the decision path; the last line measures that path
//! for comparison. Numbers are medians over the stated repetitions, on
//! whatever machine runs this, in release mode:
//!
//! ```sh
//! cargo run --release --example trust_costs --features preview-pq,preview-tsa
//! cargo run --release --example trust_costs --features preview-pq,preview-tsa -- --max 1000000
//! ```
//!
//! `docs/BENCHMARKS.md` records one run and the machine it ran on.

use std::hint::black_box;
use std::time::{Duration, Instant};

use calybris_core::checkpoint::{Checkpoint, LogSigner, WitnessSigner};
use calybris_core::hybrid::{self, HybridSigner};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, root_of, verify_consistency, verify_inclusion,
    Hash, MerkleTree,
};
use calybris_core::ots::DetachedTimestamp;
use calybris_core::tsa::{verify_response, PinnedTsa};
use calybris_core::wal::WalWriter;
use calybris_core::witness::{AddCheckpoint, FileStore, MemoryStore, Witness};
use sha2::{Digest as _, Sha256};

const ORIGIN: &str = "bench.example/log";

/// Median time of one call, over `reps` calls after one warm-up.
fn median(reps: usize, mut f: impl FnMut(usize)) -> Duration {
    f(0);
    let mut times: Vec<Duration> = (0..reps)
        .map(|i| {
            let t = Instant::now();
            f(i);
            t.elapsed()
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

fn once(f: impl FnOnce()) -> Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

fn show(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 10_000 {
        format!("{ns} ns")
    } else if ns < 10_000_000 {
        format!("{:.1} µs", ns as f64 / 1e3)
    } else if ns < 10_000_000_000 {
        format!("{:.1} ms", ns as f64 / 1e6)
    } else {
        format!("{:.2} s", ns as f64 / 1e9)
    }
}

fn row(what: &str, cost: String, note: &str) {
    println!("| {what} | {cost} | {note} |");
}

/// Deterministic spread of indices, without a random number generator.
fn spread(i: usize, n: u64) -> u64 {
    (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % n
}

fn merkle(n: usize) {
    let leaves: Vec<Hash> = (0..n as u64).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    let size = n as u64;
    let mut tree = MerkleTree::default();
    let build = once(|| {
        for h in &leaves {
            tree.push(*h);
        }
    });
    let free_root = once(|| {
        black_box(root_of(&leaves));
    });
    let head = tree.head(size).unwrap();
    let mib = |bytes: u64| format!("{:.0} MiB", bytes as f64 / (1 << 20) as f64);
    println!("\n**{n} records**\n");
    println!("| Operation | Time | Note |\n|---|---|---|");
    row(
        "Build the cached tree",
        show(build),
        &format!(
            "{} allocated for cached hashes; the leaf hashes alone are {}",
            mib(tree.allocated_hash_bytes() as u64),
            mib(size * 32)
        ),
    );
    row(
        "Root from leaves, uncached",
        show(free_root),
        "`root_of`, every hash recomputed",
    );
    row(
        "Root from the cached tree",
        show(median(1_000, |i| {
            black_box(tree.head(size - (i as u64 % 1_000)).unwrap());
        })),
        "`MerkleTree::head`, any size",
    );
    let incl = median(10_000, |i| {
        black_box(tree.inclusion_proof(spread(i, size), size).unwrap());
    });
    row(
        "Inclusion proof, cached",
        show(incl),
        "`MerkleTree::inclusion_proof`",
    );
    let reps = if n > 1_000_000 { 3 } else { 9 };
    row(
        "Inclusion proof, uncached",
        show(median(reps, |i| {
            black_box(inclusion_proof(&leaves, spread(i, size)).unwrap());
        })),
        "`merkle::inclusion_proof`, linear in the tree",
    );
    let proof = tree.inclusion_proof(size / 3, size).unwrap();
    row(
        "Inclusion proof, verify",
        show(median(10_000, |_| {
            verify_inclusion(&head, size / 3, &leaves[n / 3], &proof).unwrap();
        })),
        &format!("{} hashes in the proof", proof.len()),
    );
    row(
        "Consistency proof, cached",
        show(median(10_000, |i| {
            black_box(
                tree.consistency_proof(1 + spread(i, size - 1), size)
                    .unwrap(),
            );
        })),
        "`MerkleTree::consistency_proof`",
    );
    row(
        "Consistency proof, uncached",
        show(median(reps, |i| {
            black_box(consistency_proof(&leaves, 1 + spread(i, size - 1)).unwrap());
        })),
        "`merkle::consistency_proof`",
    );
    let old = tree.head(size / 2 + 1).unwrap();
    let cproof = tree.consistency_proof(old.size, size).unwrap();
    row(
        "Consistency proof, verify",
        show(median(10_000, |_| {
            verify_consistency(&old, &head, &cproof).unwrap();
        })),
        &format!("{} hashes in the proof", cproof.len()),
    );
}

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn trust() {
    println!("\n**Checkpoints, witnesses and timestamps**\n");
    println!("| Operation | Time | Note |\n|---|---|---|");
    let n = 1_000_000_u64;
    let leaves: Vec<Hash> = (0..n).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    let tree = MerkleTree::from_leaf_hashes(&leaves);
    let log = LogSigner::from_seed(ORIGIN, &[1; 32]).unwrap();
    let cp = Checkpoint::new(ORIGIN, tree.head(n).unwrap()).unwrap();
    row(
        "Sign a checkpoint",
        show(median(2_000, |_| {
            black_box(log.sign(&cp));
        })),
        "Ed25519 over the C2SP body",
    );
    let note = log.sign(&cp);
    row(
        "Verify a checkpoint's log signature",
        show(median(2_000, |_| note.verify(log.verifier()).unwrap())),
        "",
    );

    // A witness following the log in steps of 1,000 records.
    let steps: Vec<AddCheckpoint> = (0..200_u64)
        .map(|k| {
            let size = n - 200_000 + k * 1_000;
            let head = tree.head(size).unwrap();
            let old = if k == 0 { 0 } else { size - 1_000 };
            AddCheckpoint {
                old_size: old,
                proof: if old == 0 {
                    Vec::new()
                } else {
                    tree.consistency_proof(old, size).unwrap()
                },
                note: log.sign(&Checkpoint::new(ORIGIN, head).unwrap()).render(),
            }
        })
        .collect();
    let signer = || WitnessSigner::from_seed("w.example", &[2; 32]).unwrap();
    let mut w = Witness::new(signer(), MemoryStore::default());
    w.add_log(ORIGIN, log.verifier().clone());
    let mut k = 0;
    let memory = median(199, |_| {
        black_box(w.add_checkpoint(&steps[k], 1).unwrap());
        k += 1;
    });
    row(
        "Witness cosigns, state in memory",
        show(memory),
        "parse, log signature, consistency proof, cosign",
    );
    let dir = tempfile::tempdir().unwrap();
    let mut w = Witness::new(
        signer(),
        FileStore::create(dir.path().join("w.json")).unwrap(),
    );
    w.add_log(ORIGIN, log.verifier().clone());
    let mut k = 0;
    let durable = median(199, |_| {
        black_box(w.add_checkpoint(&steps[k], 1).unwrap());
        k += 1;
    });
    row(
        "Witness cosigns, state in a file",
        show(durable),
        "plus lock, fsync and atomic rename, on this machine's disk",
    );
    let mut cosigned = log.sign(&cp);
    let line = signer().cosign(cosigned.text(), 1).unwrap();
    cosigned.add_signature(line).unwrap();
    let wv = signer().verifier().clone();
    row(
        "Verify a cosignature",
        show(median(2_000, |_| {
            black_box(cosigned.cosignature_time(&wv).unwrap());
        })),
        "",
    );

    let body = fixture("rfc3161/body.txt");
    let digest: [u8; 32] = Sha256::digest(&body).into();
    for (tsr, crt, what) in [
        ("rsa.tsr", "rsa.crt", "RSA-2048"),
        ("p256.tsr", "p256.crt", "ECDSA P-256"),
        ("p384.tsr", "p384.crt", "ECDSA P-384"),
    ] {
        let resp = fixture(&format!("rfc3161/{tsr}"));
        let pin =
            PinnedTsa::from_pem(&String::from_utf8(fixture(&format!("rfc3161/{crt}"))).unwrap())
                .unwrap();
        row(
            &format!("Verify an RFC 3161 token, {what}"),
            show(median(500, |_| {
                black_box(
                    verify_response(&resp, &digest, None, std::slice::from_ref(&pin)).unwrap(),
                );
            })),
            "DER parse, imprint, signed attributes, signature",
        );
    }
    let ots = fixture("ots/hello-world.txt.ots");
    let hex = String::from_utf8(fixture("ots/block358391.hex")).unwrap();
    let hex = hex.trim();
    let header: [u8; 80] = (0..80)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let hash = DetachedTimestamp::parse(&ots)
        .unwrap()
        .verify_bitcoin(358_391, &header)
        .unwrap()
        .block_hash;
    row(
        "Verify an OpenTimestamps proof against a block",
        show(median(2_000, |_| {
            let p = DetachedTimestamp::parse(&ots).unwrap();
            black_box(
                p.verify_bitcoin(358_391, &header)
                    .unwrap()
                    .confirm(&hash)
                    .unwrap(),
            );
        })),
        "parse, replay the path, header work, confirm the hash",
    );
}

fn hybrid_costs() {
    println!("\n**Hybrid signatures (Ed25519 + ML-DSA-65)**\n");
    println!("| Operation | Time | Note |\n|---|---|---|");
    let signer = HybridSigner::from_seeds(&[3; 32], &[4; 32]);
    let public = signer.public_key();
    let digest = [5_u8; 32];
    let one = median(200, |_| {
        black_box(signer.sign(&digest).unwrap());
    });
    row("Sign one digest", show(one), "");
    let sig = signer.sign(&digest).unwrap();
    let verify_one = median(200, |_| hybrid::verify(&public, &digest, &sig).unwrap());
    row("Verify one signature", show(verify_one), "");
    let digests: Vec<[u8; 32]> = (0..10_000_u32)
        .map(|i| Sha256::digest(i.to_be_bytes()).into())
        .collect();
    let batch = median(9, |_| {
        black_box(signer.sign_batch(&digests).unwrap());
    });
    row(
        "Sign a batch of 10,000 digests",
        show(batch),
        &format!(
            "{} per digest, against {} one by one",
            show(batch / 10_000),
            show(one)
        ),
    );
    let (b, items) = signer.sign_batch(&digests).unwrap();
    let checked = hybrid::verify_batch(&public, &b).unwrap();
    row(
        "Verify one item of a checked batch",
        show(median(10_000, |i| {
            checked
                .verify_item(&digests[i % 10_000], &items[i % 10_000])
                .unwrap();
        })),
        "after one batch signature check",
    );
}

fn kernel() {
    let models: Vec<KernelModel> = (1..=22_u16)
        .map(|id| KernelModel {
            model_id: u32::from(id),
            provider_id: 0,
            quality_bps: 9_000 - id,
            risk_ceiling_bps: 10_000,
            enabled: 1,
            p95_latency_ms: 10,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 1_000,
            output_cost_microunits_per_million_tokens: 1_000,
        })
        .collect();
    let policy = PolicySnapshot::try_new_trusted(1, 1, 9_000, 0, 0, 0, models).unwrap();
    let input = |seq: u64| KernelInput {
        request_sequence: seq,
        requested_model_id: 1,
        input_tokens: 100,
        output_tokens: 100,
        business_value_microunits: 10_000_000,
        budget_limit_microunits: 1_000_000_000,
        risk_bps: 0,
        confidence_bps: 10_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    };
    let per = median(9, |r| {
        for seq in 0..10_000_u64 {
            black_box(policy.prescribe(black_box(input(seq + r as u64))));
        }
    }) / 10_000;
    let dir = tempfile::tempdir().unwrap();
    let mut wal = WalWriter::open(&dir.path().join("d.wal.jsonl")).unwrap();
    let n = 20_000_u64;
    let started = Instant::now();
    for seq in 0..n {
        let x = input(seq);
        wal.append_verified_audited(&policy, x, policy.prescribe(x), "bench")
            .unwrap();
    }
    let appended = started.elapsed() / n as u32;
    let synced = median(20, |i| {
        let x = input(n + i as u64);
        wal.append_verified_audited(&policy, x, policy.prescribe(x), "bench")
            .unwrap();
        wal.flush_and_sync().unwrap();
    });
    println!("\n**For comparison, the decision path**\n");
    println!("| Operation | Time | Note |\n|---|---|---|");
    row(
        "`prescribe`, 22 candidates",
        show(per),
        "unchanged by any of the above",
    );
    row(
        "Decide, replay-verify and append to the WAL",
        show(appended),
        "`append_verified_audited`, written but not synced",
    );
    row(
        "The same, synced to disk each time",
        show(synced),
        "`flush_and_sync` per decision, on this machine's disk",
    );
}

fn main() {
    // Only `--max N` is read, and never the program name.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args
    let max: usize = args
        .iter()
        .position(|a| a == "--max")
        .and_then(|i| args.get(i + 1))
        .map_or(10_000_000, |v| v.parse().expect("--max takes a number"));
    for n in [100_000, 1_000_000, 10_000_000] {
        if n <= max {
            merkle(n);
        }
    }
    trust();
    hybrid_costs();
    kernel();
}
