# Contributing to Calybris Core

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
cargo test
cargo bench
cargo clippy -- -D warnings
```

## Before Submitting a PR

1. **All tests pass**: `cargo test`
2. **No clippy warnings**: `cargo clippy -- -D warnings`
3. **Formatted**: `cargo fmt --check`
4. **No unsafe**: The crate uses `#![forbid(unsafe_code)]` — this is non-negotiable

## What We're Looking For

- Bug fixes (especially edge cases in integer arithmetic)
- Performance improvements (with benchmark proof)
- Documentation improvements
- New proptest/fuzz scenarios
- Examples showing real-world usage

## Architecture

```
src/
  lib.rs      — crate root, feature flags, module re-exports
  digest.rs   — canonical SHA-256 digests (policy, input, decision, ledger)
  kernel.rs   — allocation-free integer decision kernel
  verify.rs   — audit bundles, replay verification, certificates
  finance.rs  — ledger digest, conservation proofs (HFT microcents)
  budget.rs   — CAS atomic per-tenant budget engine
  wal.rs      — HMAC-SHA256 hash-chained write-ahead log + audited replay
benches/
  kernel_bench.rs  — prescribe latency
  budget_bench.rs  — reserve/commit latency
examples/
  simple_kernel.rs
  route_decision.rs
  replay_audit.rs
  finance_hft.rs
  verify_wal.rs
```

## Design Principles

- **No floating-point in the kernel**: All values are basis points (1/10,000) or microunits (1/1,000,000)
- **No allocation in `prescribe()`**: The hot path must be zero-alloc
- **Fail-closed**: If the engine can't safely evaluate, it rejects
- **Deterministic replay**: Same inputs → same outputs, across platforms
- **Conservation invariant**: `remaining + reserved + committed = initial` after completed budget ops (budget)

## Commit Messages

Use conventional format:
```
feat(kernel): add latency-weighted utility scoring
fix(wal): handle empty file on first open
perf(budget): reduce lock contention with Arc<str>
docs(readme): update benchmark numbers
test(kernel): add proptest for extreme token counts
```

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
