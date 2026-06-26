<div align="center">
  <img src="https://raw.githubusercontent.com/emirhuseynrmx/calybris-core/main/assets/banner.png" alt="Calybris Core" width="100%" />
</div>

<br/>

# Calybris Core

[![CI](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml/badge.svg)](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/calybris-core)](https://crates.io/crates/calybris-core)
[![docs.rs](https://img.shields.io/docsrs/calybris-core)](https://docs.rs/calybris-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.83-orange)]()

A small Rust decision engine for auditable, deterministic policy decisions — with HFT-grade fixed-point financial accounting.

Calybris Core evaluates candidates under hard constraints, selects the highest-utility valid option, records decisions through tamper-evident primitives, and proves every decision and ledger state with canonical SHA-256 digests.

The first packaged use case is **LLM/model routing**. The core pattern is domain-neutral — any system that chooses between candidates under constraints can use the same primitives.

Built from five components:

1. **`kernel`** — Integer-only decision kernel. 11 constraint gates, ~115ns per decision. No floating-point, no allocation in the hot path.
2. **`verify`** — Level-2 proof: policy + input + decision digests, full replay, correctness certificates.
3. **`finance`** — Fixed-point ledger (`i64` microcents), conservation proofs, tamper-evident ledger digest.
4. **`wal`** — Hash-chained write-ahead log with `append_audited` and offline `replay_audited_wal`.
5. **`budget`** — CAS atomic budget engine. Conservation invariant: `remaining + reserved + committed = initial`.

`#![forbid(unsafe_code)]` · 48 unit tests · 2 doc tests · 6 direct dependencies · Apache-2.0

## Quick Start

```bash
cargo add calybris-core
```

```rust
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
use calybris_core::finance::prove_conservation;
use calybris_core::budget::BudgetEngine;

let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 0, models)?;
let input = KernelInput { /* ... */ };
let decision = snapshot.prescribe(input);

assert_eq!(verify_decision(&snapshot, input, &decision), VerifyResult::Valid);
let bundle = audit_bundle(&snapshot, input, &decision);
assert!(bundle.replay_valid);

let budget = BudgetEngine::new();
budget.ensure_tenant("desk-1", 100_000_000);
prove_conservation(&budget)?;
```

## Audit Pipeline

```
prescribe(input) → audit_bundle → WAL append_audited → replay_audited_wal
                         ↓
              policy_digest + input_digest + decision_digest
```

Every digest uses a versioned byte layout (`calypol1`, `calyinp1`, `calydcn1`) — not JSON — for cross-platform determinism.

## Financial Layer (HFT)

All money is `i64` **microcents** (1 cent = 1,000,000 microcents). No `f64`.

```rust
use calybris_core::budget::BudgetEngine;
use calybris_core::finance::{certify_ledger, prove_conservation, MICROCENTS_PER_CENT};

let engine = BudgetEngine::new();
engine.ensure_tenant("hft-desk", 1_000_000 * MICROCENTS_PER_CENT);
let (_, id) = engine.try_reserve("hft-desk", 10_000);  // CAS hot path
engine.commit(id.unwrap(), 9_500);

assert!(certify_ledger(&engine).conservation_balanced);
prove_conservation(&engine)?;  // remaining + reserved + committed == initial
```

`cargo bench --bench budget_bench` measures reserve/commit latency.

## Modules

### `kernel.rs`

```
utility = quality_adjusted_value - risk_penalty - cost - latency_penalty
```

`prescribe_batch`, `prescribe_with_trace`, `PolicySnapshot::validate()`, `try_new()`.

### `verify.rs`

`audit_bundle`, `verify_decision` (full `KernelDecision` equality), `certify_decision`, `counterfactual_utility`.

### `finance.rs`

`ledger_digest`, `FinancialCertificate`, `prove_conservation` — binds budget state to SHA-256.

### `wal.rs`

```rust
wal.append_audited(&snapshot, input, decision, metadata)?;
let verdicts = replay_audited_wal(&path, &snapshot)?;
```

Requires the `serde` feature (on by default).

### `budget.rs`

CAS `try_reserve` / `commit` / `release`, `snapshot()`, `verify_conservation()`, per-tenant `initial/committed/reserved` tracking.

## Examples

```bash
cargo run --example simple_kernel
cargo run --example route_decision
cargo run --example replay_audit      # full audit pipeline
cargo run --example finance_hft       # 50k reserve/commit + conservation proof
cargo run --example verify_wal
```

## Benchmarks

```
cargo bench
```

| Benchmark | Time | Notes |
|-----------|------|-------|
| prescribe (22 models) | 115 ns | ~8.6M/sec |
| budget try_reserve | ~tens of ns | CAS, no mutex on debit |
| budget reserve+commit | ~tens of ns | HFT accounting path |

## Tests

```
cargo test           # 48 unit + 2 doc tests
cargo test --release # includes latency guard (1 ignored in debug)
```

Proptest, 100-thread concurrency stress, HMAC WAL fuzz, audited WAL replay, conservation proofs.

## What This Crate Is Not

- Adaptive routing (Thompson Sampling)
- Policy evolution (automated catalog updates)
- HTTP gateway or API server

See [emirhuseyin.tech/engine](https://emirhuseyin.tech/engine) for the full proprietary engine.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).