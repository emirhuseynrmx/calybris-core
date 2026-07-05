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

## Reproduce locally

```bash
# Full Criterion benchmark on your own hardware:
cargo bench --bench kernel_bench

# Budget-engine benchmark:
cargo bench --bench budget_bench

# Proof surfaces (digests, certificates, Ed25519 signing):
cargo bench --bench proof_bench --features wal,provenance
```

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
