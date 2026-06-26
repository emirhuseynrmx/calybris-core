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

A small Rust decision engine for auditable, deterministic policy decisions.

Calybris Core evaluates candidates under hard constraints, selects the highest-utility valid option, records decisions through tamper-evident primitives, and lets you independently verify that every decision matches the policy that produced it.

The first packaged use case is **LLM/model routing**: choosing between models under budget, latency, risk, quality, provider, and region constraints. The core pattern is domain-neutral — any system that chooses between candidates under constraints can use the same primitives.

Built from four components:

1. **`kernel`** — Integer-only decision kernel. 11 constraint gates, ~115ns per decision. No floating-point, no allocation in the hot path.
2. **`verify`** — Deterministic replay check, policy fingerprinting, and correctness certificates.
3. **`wal`** — Hash-chained write-ahead log. SHA-256 or HMAC-SHA256. Generic over any `Serialize` type.
4. **`budget`** — CAS atomic budget engine. Conservation invariant: `remaining + reserved + committed = initial`.

`#![forbid(unsafe_code)]` · 40 unit tests · 2 doc tests · 6 direct dependencies · Apache-2.0

## Quick Start

```bash
cargo add calybris-core
```

```rust
use calybris_core::kernel::*;
use calybris_core::verify::{certify_decision, verify_decision, VerifyResult};

let models = vec![/* your model catalog */];
let snapshot = PolicySnapshot::new(1, 1, 9600, 5500, 3500, 0, models);
let input = KernelInput { /* ... */ };

let decision = snapshot.prescribe(input);
// decision.action: ExecuteRequested | Substitute | Reject
// decision.selected_model_id: which model was chosen
// decision.expected_utility_microunits: why

assert_eq!(verify_decision(&snapshot, input, &decision), VerifyResult::Valid);
let cert = certify_decision(&snapshot, input, &decision);
assert!(cert.replay_valid);
```

Disable Serde (kernel + budget only, no WAL):

```bash
cargo add calybris-core --no-default-features
```

## Modules

### `kernel.rs`

The kernel scores every candidate model with:

```
utility = quality_adjusted_value - risk_penalty - cost - latency_penalty
```

All values are basis points (1/10,000) or microunits (1/1,000,000). The fast path uses `u64` with overflow guards; when inputs don't fit, it falls back to `u128`. Proptest verifies both paths agree on every random input.

Constraints checked per decision: risk ceiling, confidence floor, quality minimum, budget limit, latency cap, capability match, provider mask, region mask, cost, utility sign, optimality.

Public types implement `Display` and optional `Serialize`/`Deserialize` (behind the `serde` feature, enabled by default).

### `verify.rs`

Independently confirm that a recorded decision is consistent with the policy snapshot that should have produced it:

```rust
use calybris_core::verify::{certify_decision, snapshot_fingerprint, verify_decision};

let replay = verify_decision(&snapshot, input, &decision);
let fingerprint = snapshot_fingerprint(&snapshot); // SHA-256 policy binding
let cert = certify_decision(&snapshot, input, &decision);
```

`verify_decision` replays `snapshot.prescribe(input)` and compares the outcome. `certify_decision` binds the decision to a policy fingerprint and includes the replay result — useful for audit trails and WAL records.

### `wal.rs`

Requires the `serde` feature (on by default).

```rust
// Unkeyed — detects accidental corruption
let mut wal = WalWriter::open(&path)?;
let entry = wal.append(my_data)?;

// Keyed — attacker can't forge valid hashes
let mut wal = WalWriter::open_keyed(&path, b"secret")?;
```

Chain is validated on open. Constant-time comparison (`subtle`) on keyed WALs. `append()` writes to the OS buffer; call `flush_and_sync()` when you need crash durability.

### `budget.rs`

```rust
let engine = BudgetEngine::new();
engine.ensure_tenant("team-a", 100_000_000);
let (res, id) = engine.try_reserve("team-a", 25_000_000);
engine.commit(id.unwrap(), 20_000_000); // surplus refunded

engine.tenant_count();        // registered tenants
engine.active_reservations(); // uncommitted holds
```

`Arc<AtomicI64>` per tenant, cloned out before the CAS loop — no mutex held during contention. Lock ordering: reservations → budgets.

## Examples

```bash
cargo run --example simple_kernel   # minimal prescribe() demo
cargo run --example route_decision  # LLM routing + WAL audit trail
cargo run --example verify_wal      # hash-chain validation
```

## Benchmarks

```
cargo bench
```

| Benchmark | Time | Notes |
|-----------|------|-------|
| prescribe (22 models) | 115 ns | ~8.6M/sec |
| prescribe (4 models) | 36 ns | |
| prescribe (64 models) | 522 ns | Linear scaling |
| reject (risk gate) | 15 ns | Early exit |

Results from Criterion on one machine. Your numbers will differ.

## Tests

```
cargo test           # 40 unit + 2 doc tests
cargo test --release # includes latency guard (1 ignored in debug)
```

Includes proptest property-based verification, 100-thread concurrency stress, HMAC chain validation, decision replay checks, and WAL fuzz roundtrips.

## What This Crate Is Not

This is the open-source decision core. It doesn't include:

- Adaptive routing (Thompson Sampling)
- Policy evolution (counterfactual replay)
- HTTP gateway or API server
- Prompt classification models

Those are part of the proprietary engine. See [emirhuseyin.tech/engine](https://emirhuseyin.tech/engine) for the full architecture.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues labeled [`good first issue`](https://github.com/emirhuseynrmx/calybris-core/labels/good%20first%20issue) are a good starting point.

## License

Apache-2.0. See [LICENSE](LICENSE).