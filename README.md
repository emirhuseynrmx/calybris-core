<div align="center">
  <img src="https://raw.githubusercontent.com/emirhuseynrmx/calybris-core/main/assets/banner.png" alt="Calybris Core" width="100%" />
</div>

<br/>

# Calybris Core

[![CI](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml/badge.svg)](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/emirhuseynrmx/calybris-core/graph/badge.svg)](https://codecov.io/gh/emirhuseynrmx/calybris-core)
[![Crates.io](https://img.shields.io/crates/v/calybris-core)](https://crates.io/crates/calybris-core)
[![docs.rs](https://img.shields.io/docsrs/calybris-core)](https://docs.rs/calybris-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)]()

**Deterministic proof-carrying decision core** for systems that must explain and replay why an action was allowed, substituted, or rejected.

Not an LLM framework. Not an exchange or strategy engine. A domain-neutral primitive:

```
candidate + policy constraints → decision + digests + optional WAL + budget proof
```

`#![forbid(unsafe_code)]` · unit/proptest/Loom/Miri coverage · Apache-2.0

## Two Reference Use Cases

| Use case | What Calybris does |
|----------|-------------------|
| **LLM routing** | Select / substitute / reject models under budget, risk, quality, latency |
| **Pre-trade guard** | Admit / reject candidate orders under exposure, risk, and latency limits |

Calybris is **not** an exchange, market data feed, colocation stack, or alpha engine. It is a **deterministic pre-trade decision kernel** — integer-only constraints, replay verification, and fixed-point conservation proofs.

## When to use it

Use Calybris when a service has to make the same decision twice and prove it got the same answer:

- route an LLM request under budget, latency, provider, and quality constraints
- reject or substitute a candidate action before it crosses a risk boundary
- write an auditable decision record to a tamper-evident WAL
- reconcile budget state with fixed-point conservation proofs

Do not use it as a hosted API, trading strategy, exchange adapter, web framework, or model orchestration platform. Calybris is the deterministic core you put behind those systems.

## Try it locally

```bash
git clone https://github.com/emirhuseynrmx/calybris-core
cd calybris-core
cargo run --example quickstart
cargo run --example llm_routing
cargo run --example replay_audit
```

## Use as a dependency

```bash
cargo add calybris-core
```

```rust
use calybris_core::budget::BudgetEngine;
use calybris_core::finance::{prove_conservation, ConservationProof};
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};

let models = vec![
    KernelModel {
        model_id: 1,
        provider_id: 0,
        quality_bps: 9000,
        risk_ceiling_bps: 9500,
        enabled: 1,
        p95_latency_ms: 200,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: 250,
        output_cost_microunits_per_million_tokens: 1000,
    },
    KernelModel {
        model_id: 2,
        provider_id: 1,
        quality_bps: 7000,
        risk_ceiling_bps: 9500,
        enabled: 1,
        p95_latency_ms: 90,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: 25,
        output_cost_microunits_per_million_tokens: 125,
    },
];

let snapshot = PolicySnapshot::try_new(1, 1, 9600, 5500, 3500, 2, models)?;

let input = KernelInput {
    request_sequence: 1,
    requested_model_id: 1,
    input_tokens: 1000,
    output_tokens: 500,
    business_value_microunits: 100_000,
    budget_limit_microunits: 50_000_000,
    risk_bps: 1000,
    confidence_bps: 9000,
    minimum_quality_bps: 5000,
    max_p95_latency_ms: 1000,
    required_capabilities: 0,
    allowed_provider_mask: ALL_PROVIDERS,
    required_region_mask: 0,
};

let decision = snapshot.prescribe(input);
assert_eq!(verify_decision(&snapshot, input, &decision), VerifyResult::Valid);
assert!(audit_bundle(&snapshot, input, &decision).replay_valid);

let budget = BudgetEngine::new();
budget.ensure_tenant("desk-1", 100_000_000);
let proof: ConservationProof = prove_conservation(&budget)?;
assert_eq!(proof.ledger_digest_hex.len(), 64);
```

Kernel-only (no WAL):

```bash
cargo add calybris-core --no-default-features
```

## Architecture

1. **`kernel`** — Integer-only decision kernel (~115ns/decision). `prescribe_with_trace` exposes per-constraint rejection counts.
2. **`verify`** — Policy + input + decision digests, full replay, `DigestDecodeError` on public API.
3. **`finance`** — Ledger digest, `FinancialCertificate`, `ConservationProof`, `prove_conservation`, `certify_snapshot`.
4. **`wal`** — Tamper-evident hash chain, `append_audited`, fail-closed `replay_audited_wal`.
5. **`budget`** — CAS reserve/commit/release. Conservation holds after completed ops: `remaining + reserved + committed_lifetime == initial`. Loom + Miri in CI.
6. **`config`** — Runtime `EngineConfig` with builder pattern and validation.
7. **`builder`** — `InputBuilder`, `ModelBuilder`, `PolicyBuilder` — hard to misuse, safe defaults.
8. **`persistence`** — Atomic snapshot save/load, `checkpoint`, `restore`, crash recovery planning.
9. **`async_wal`** *(feature `async`)* — Tokio-based non-blocking WAL with HMAC, chain validation, configurable sync.
10. **`instrument`** *(feature `observability`)* — Structured `tracing` spans for prescribe, verify, budget, WAL.

## Audit Pipeline

```
prescribe → audit_bundle → append_audited → replay_audited_wal (fail-closed)
                ↓
     calypol1 / calyinp1 / calydcn1 digests
```

## Financial layer & policy

Fixed-point `i64` microcents (1 cent = 1,000,000). No `f64`.

- `committed_microcents` — **lifetime cumulative spend** (monotonic; never decreases)
- `reserved_microcents` — active holds awaiting commit/release
- `top_up_tenant` — add funds without resetting lifetime spend
- `restore_from_snapshot` — exclusive-recovery restore from frozen `BudgetSnapshot`
- `verify_conservation` — audit/reconciliation path (full snapshot)
- `PolicySnapshot::utility_for_model` — per-model utility (not prescribe winner/runner-up)

```rust
budget.ensure_tenant("desk", 100_000_000);
budget.top_up_tenant("desk", 50_000_000);
let proof = prove_conservation(&budget)?;
let cert = certify_ledger(&budget);
assert!(cert.conservation_balanced);
```

| Policy API | Use |
|------------|-----|
| `PolicySnapshot::try_new` | **Production** — validates catalog + BPS (`MAX_BPS`, etc.) |
| `PolicySnapshot::new_unchecked` | Tests / fuzz only — never serve without explicit `validate()` |
| `PolicySnapshot::new` | Deprecated alias for `new_unchecked` |

## Feature Flags

| Feature | What it adds | Dependencies |
|---------|-------------|--------------|
| `wal` *(default)* | Hash-chained WAL, HMAC-SHA256, audited append | `serde`, `hmac`, `subtle` |
| `async` | Tokio-based async WAL | `tokio` |
| `observability` | Structured tracing spans/events | `tracing` |
| `full` | All of the above | — |

```bash
cargo add calybris-core                        # default (wal)
cargo add calybris-core --features full        # everything
cargo add calybris-core --no-default-features  # kernel only
```

## Builder Ergonomics (v0.4.0)

```rust
use calybris_core::config::EngineConfig;
use calybris_core::builder::{InputBuilder, ModelBuilder, PolicyBuilder};

let config = EngineConfig::new()
    .latency_penalty(3)
    .hard_risk_limit(9_500)
    .default_exposure_cap(500_000_000);

let snapshot = PolicyBuilder::new(config)
    .epochs(1, 1)
    .model(ModelBuilder::new(1, 0).quality(9500).cost(250, 1000).build())
    .model(ModelBuilder::new(2, 1).quality(7000).cost(25, 125).build())
    .build()?;

let input = InputBuilder::new(1, 1)
    .tokens(1000, 500)
    .business_value(100_000)
    .risk(1000, 9000)
    .minimum_quality(5000)
    .build();

let decision = snapshot.prescribe(input);
```

## Persistence & Recovery

```rust
use calybris_core::persistence::{checkpoint, restore};

// Save engine state atomically
let snap = checkpoint(&budget, Path::new("budget.json"))?;

// After crash: restore from last checkpoint
let fresh = BudgetEngine::new();
restore(&fresh, Path::new("budget.json"))?;
```

## Examples

```bash
cargo run --example quickstart
cargo run --example production_gateway  # full pipeline: config→build→prescribe→verify→budget→WAL→checkpoint→recovery
cargo run --example llm_routing
cargo run --example hft_pretrade_guard
cargo run --example replay_audit
cargo run --example finance_hft       # throughput benchmark
cargo run --example route_decision    # legacy alias
```

## Tests & CI

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
RUSTFLAGS='--cfg loom' LOOM_MAX_PREEMPTIONS=3 cargo test --test budget_loom
cargo +nightly miri test --lib --all-features   # see docs/MIRI.md for CI filters
cargo doc --no-deps
```

**136 tests passing.** Tested on **Rust 1.85.0** (MSRV) and **stable**. Miri runs on **nightly** in CI (UB detection); 7 Loom exhaustive tests cover budget concurrency interleavings. **91.6% code coverage** (llvm-cov).

## Integration contract

Calybris verifies decisions and conservation proofs — it does **not** auto-invoke `verify_decision` in your hot path. **You** must call it at audit boundaries:

```
prescribe → verify_decision → (optional WAL / prove_conservation)
```

Recommended hooks: before `append_audited`, at reconciliation, before exporting a `FinancialCertificate`. Skipping verification is a deployment risk, not a library default. See [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md).

For fail-closed audit boundaries, use the verified helpers:

```rust
use calybris_core::verify::verified_audit_bundle;

let bundle = verified_audit_bundle(&snapshot, input, &decision)?;
assert!(bundle.replay_valid);
```

With the `wal` feature enabled, `append_verified_audited` verifies before writing. Invalid or tampered decisions do not enter the log:

```rust
use calybris_core::wal::WalWriter;

let mut wal = WalWriter::open(std::path::Path::new("decisions.jsonl"))?;
wal.append_verified_audited(&snapshot, input, decision, "metadata")?;
```

## External audit

Invariant docs, adversarial tests, Loom, Miri, and supply-chain checks are in place for third-party review. A paid external audit is still your responsibility — see [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md) §7.

## What This Crate Is Not

- Exchange gateway, market data, or order lifecycle
- Thompson Sampling / adaptive routing
- HTTP API server

See [emirhuseyin.tech/engine](https://emirhuseyin.tech/engine) for the full proprietary stack.

## License

Apache-2.0. See [LICENSE](LICENSE).
