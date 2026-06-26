# Miri (Undefined Behavior Detection)

[Miri](https://github.com/rust-lang/miri) interprets Rust MIR to detect undefined behavior: invalid atomics, stacked borrows violations, memory leaks in test code, and related soundness issues.

Calybris uses Miri **alongside** Loom:

| Tool | What it checks |
|------|----------------|
| **Loom** | Concurrent interleavings of budget CAS + mutex paths (`cfg(loom)`) |
| **Miri** | UB in safe Rust under sequential / single-threaded execution |

They are complementary — Loom does not replace Miri, and Miri does not exhaustively model all thread schedules.

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