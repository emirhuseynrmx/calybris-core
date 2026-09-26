# Benchmarks

Performance numbers and how to reproduce them. Throughput is hardware- and
workload-dependent; the point of this page is that every figure has a command
you can run yourself, not a marketing number.

## Reported figure

| Metric | Value |
|--------|-------|
| `prescribe` throughput | ~8.6M decisions/sec |
| Latency per decision | ~115 ns |
| Catalog size | 22 models (synthetic) |
| Measured by | CodSpeed CI, Linux x86_64, release profile |
| Bench | `benches/kernel_bench.rs` (Criterion / codspeed-criterion-compat) |
| Rust | stable (MSRV 1.85) |

The live CodSpeed number and its per-commit history are on the badge in the
README (CodSpeed runs on fixed CI hardware for run-to-run comparability, so
its absolute ns/op reflects that runner, not your machine).

## Proof-surface costs (0.5.0)

Off the `prescribe` hot path. Indicative medians measured on an AMD Ryzen 7
5700X (local release build, `cargo bench --bench proof_bench`, short run) — not
the CI runner, so treat them as orders of magnitude and reproduce on your
hardware. Two-model policy.

| Operation | Median | Notes |
|-----------|--------|-------|
| `policy_digest` | ~185 ns | scales with catalog size |
| `input_digest` | ~91 ns | fixed 13-field layout |
| `decision_digest` | ~92 ns | fixed layout |
| `issue_certificate` | ~2.4 µs | replay + all three digests |
| `verify_certificate` | ~2.4 µs | recompute digests + replay |
| `sign_policy` (Ed25519) | ~21 µs | signing dominates; do it per policy, not per decision |
| `verify_signed_policy` (Ed25519) | ~tens of µs | run the bench for your number |

Takeaway: digests and certificates are cheap enough to compute per decision;
Ed25519 signing is ~100x costlier, so sign a **policy** once, not every request.

## What the headline figure covers, and what a logged decision costs (1.3.0)

The ~8.6M/s above is `prescribe` alone, in memory: no WAL, no signature, no
disk. What a production decision costs depends on what is logged with it. One
run of `examples/trust_costs.rs` on a 4-vCPU Intel Xeon at 2.1 GHz (Linux,
release build, stable Rust), medians:

| Per decision | Time | What it includes |
|---|---|---|
| `prescribe`, 22 candidates | 202 ns | the kernel only |
| `append_verified_audited` | 12.8 µs | decide, replay-verify, digest, serialize, append to the WAL; not synced |
| the same with `flush_and_sync` every time | 4.0 ms | one fsync per decision, bound by this machine's disk |

So a durably logged decision is disk-bound, and syncing in groups (one fsync
per batch of appends) is what makes it fast. None of the trust layer below runs
per decision: it runs per checkpoint, and one checkpoint covers every record
before it.

### Merkle trees at scale

`MerkleTree` (new in 1.3.0) keeps every complete subtree's hash; the free
functions recompute from the leaves.

| Records | Build the tree | Memory held | Root, any size | Proof, cached | Proof, uncached | Verify a proof |
|---|---|---|---|---|---|---|
| 100 thousand | 17 ms | 6 MiB | 1.0 µs | 1.0 µs | 14 ms | 2.3 µs |
| 1 million | 172 ms | 61 MiB | 1.5 µs | 1.4 µs | 139 ms | 2.7 µs |
| 10 million | 2.1 s | 610 MiB | 1.3 µs | 2.1 µs | 1.4 s | 3.3 µs |

Inclusion and consistency proofs cost the same within a few percent; the
table shows inclusion. Memory is 64 bytes per record: the leaf hashes plus
every interior node. A cached proof is `O(log² n)` and stays around two
microseconds at ten million records, where recomputing one takes over a
second.

### Checkpoints, witnesses and timestamps

| Operation | Time |
|---|---|
| Sign a checkpoint (Ed25519) | 17 µs |
| Verify the log's signature | 45 µs |
| Witness cosigns, state in memory (parse, signature, consistency proof, cosign) | 73 µs |
| Witness cosigns, state in a file (plus lock, fsync, atomic rename) | 535 µs |
| Verify a cosignature | 44 µs |
| Verify an RFC 3161 token: RSA-2048 / P-256 / P-384 | 331 µs / 247 µs / 1.1 ms |
| Verify an OpenTimestamps proof against a block header | 8.3 µs |

### Hybrid signatures (Ed25519 + ML-DSA-65, `preview-pq`)

| Operation | Time |
|---|---|
| Sign one digest | 1.1 ms |
| Verify one signature | 217 µs |
| Sign a batch of 10,000 digests | 7.2 ms (0.7 µs per digest) |
| Verify one item of an already checked batch | 2.1 µs |

A batch costs one hybrid signature and a Merkle tree, so per digest it is
about 1,500 times cheaper than signing each.

## Reproduce locally

```bash
# Full Criterion benchmark on your own hardware:
cargo bench --bench kernel_bench

# Budget-engine benchmark:
cargo bench --bench budget_bench

# Proof surfaces (digests, certificates, Ed25519 signing):
cargo bench --bench proof_bench --features wal,provenance

# Trust layer and a logged decision, at 100k, 1M and 10M records (needs ~1.5 GB):
cargo run --release --example trust_costs --features preview-pq,preview-tsa

# Release acceptance torture suite (fails when a gate regresses):
cargo test --release --test production_torture --features full -- \
  --ignored --nocapture --test-threads=1
```

## Production torture gate (0.5.7)

The release gate is intentionally broader and more hostile than the README
hot-path figure. It combines:

- checked decisions over a 64-model catalog with near-maximum integer inputs;
- fail-closed replay/audit bundles;
- a 25,000-step state-proof trajectory;
- signed receipts carrying state and WAL evidence;
- strict rejection of forward-incompatible receipt JSON;
- 25,000 keyed, audited WAL appends, one durability barrier, streaming
  verification, and clean-suffix truncation detection against a trusted anchor;
- same-tenant budget contention across 4-16 threads; and
- snapshot, digest, and conservation proof over 25,000 tenants.

The thresholds are deliberately conservative enough for shared CI runners but
strict enough to detect order-of-magnitude regressions. This suite is a release
acceptance test, not a claim that every deployment will see the same latency.

Criterion writes HTML reports to `target/criterion/`. Record your environment
alongside the result so the number is meaningful to a reader:

```text
Commit:        <git rev-parse --short HEAD>
CPU:           <e.g. AMD Ryzen 7 5700X, Intel i7-1185G7>
OS / Rust:     <uname; rustc --version>
Command:       cargo bench --bench kernel_bench
Catalog size:  22 models
Input:         single prescribe over a fixed synthetic catalog
Result:        <ns/op and decisions/sec>
```

## What the benchmark does and does not measure

- **Measures:** the allocation-free hot path — `PolicySnapshot::prescribe`
  over an in-memory catalog. This is the number relevant to routing/guardrail
  latency budgets.
- **Does not measure:** digest computation, WAL append + fsync, or audit
  bundle construction. Those are off the hot path and dominated by I/O; profile
  them against your storage, not this figure.
- **Not representative of:** the Python binding (PyO3 marshalling adds
  per-call overhead) or batched throughput with the GIL released — benchmark
  those separately if they are on your critical path.
