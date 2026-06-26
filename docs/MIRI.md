# Miri (Undefined Behavior Detection)

[Miri](https://github.com/rust-lang/miri) interprets Rust MIR to detect undefined behavior: invalid atomics, stacked borrows violations, memory leaks in test code, and related soundness issues.

Calybris uses Miri **alongside** Loom:

| Tool | What it checks |
|------|----------------|
| **Loom** | Concurrent interleavings of budget CAS + mutex paths (`cfg(loom)`) |
| **Miri** | UB in safe Rust under sequential / single-threaded execution |

They are complementary — Loom does not replace Miri, and Miri does not exhaustively model all thread schedules.

**Goal of Miri in this crate:** UB detection in safe Rust (atomics, memory model). It is **not** a substitute for full test coverage or exhaustive concurrency exploration.

## Why some tests are skipped under Miri

Miri CI deliberately runs a **subset** of the test suite. Skips are intentional trade-offs, not gaps left by accident.

| Skipped under Miri | Reason | Covered elsewhere |
|--------------------|--------|-------------------|
| `wal::` unit tests | Real file I/O (`CreateFileW` / temp files) — Miri support is limited on some platforms | `audit_pipeline` integration test (E2E WAL under Miri on Linux CI) |
| Proptests (`aggressive_mixed`, `random_ops`, `arbitrary_*`, `digests_stable`) | Slow under MIR interpretation; property coverage is not Miri’s strength | `PROPTEST_CASES=10000` job in `security.yml` |
| Concurrent budget tests | Miri is not designed for exhaustive thread interleaving | Loom (`budget_loom`, 6 scenarios) + `cargo test` stress tests |
| `prescriptive_kernel_latency_guard` | Release-only timing benchmark, not a correctness property | Ignored in normal `cargo test` too |

WAL **hash-chain logic** that does not touch the filesystem still runs indirectly via `audit_pipeline`. Expanding Miri to every `wal::` unit test would duplicate that path with little extra assurance.

We do **not** plan to remove these skips entirely. If Miri coverage grows, it will be for **new** pure-logic paths (no I/O, no heavy proptest), not by forcing file-I/O or Loom-owned concurrency tests through Miri.

## CI

The `Security` workflow runs Miri on **nightly** for:

- `cargo miri test --lib --all-features` (WAL unit tests, proptests, concurrency skipped)
- `cargo miri test --test audit_pipeline` (WAL E2E on Linux)

Concurrent unit tests are `#[cfg_attr(miri, ignore)]`; use Loom for those scenarios. WAL **unit** tests are skipped under Miri (`--skip wal::`); file I/O is covered by the audit pipeline integration test instead.

## Local reproduction

```bash
rustup toolchain install nightly
rustup component add miri --toolchain nightly
cargo +nightly miri setup

# Library (matches CI filters)
cargo +nightly miri test --lib --all-features -- \
  --skip wal:: \
  --skip aggressive_mixed \
  --skip random_ops \
  --skip arbitrary_ \
  --skip digests_stable \
  --skip prescriptive_kernel

# E2E audit path (temp files; needs isolation disabled)
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --test audit_pipeline
```

## Limits

- Miri runs on **nightly** only (not MSRV 1.85).
- Multi-threaded stress tests are skipped — covered by Loom + standard `cargo test`.
- Proptests are skipped under Miri in CI (run via `PROPTEST_CASES=10000 cargo test` instead).
- `#![forbid(unsafe_code)]` — Miri still validates atomic ordering and safe API usage.