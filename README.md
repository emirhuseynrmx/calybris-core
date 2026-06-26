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

`#![forbid(unsafe_code)]` · extensive unit/proptest/Loom coverage · Apache-2.0

## Two Reference Use Cases

| Use case | What Calybris does |
|----------|-------------------|
| **LLM routing** | Select / substitute / reject models under budget, risk, quality, latency |
| **Pre-trade guard** | Admit / reject candidate orders under exposure, risk, and latency limits |

```bash
cargo run --example llm_routing          # routing + rejection histogram + WAL
cargo run --example hft_pretrade_guard   # order admission + financial certificate
```

Calybris is **not** an exchange, market data feed, colocation stack, or alpha engine. It is a **deterministic pre-trade decision kernel** — integer-only constraints, replay verification, and fixed-point conservation proofs.

## Quick Start

```bash
cargo add calybris-core
cargo run --example quickstart
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
5. **`budget`** — CAS reserve/commit/release. Conservation: `remaining + reserved + committed_lifetime == initial`. Loom model tests in CI.

## Audit Pipeline

```
prescribe → audit_bundle → append_audited → replay_audited_wal (fail-closed)
                ↓
     calypol1 / calyinp1 / calydcn1 digests
```

## Financial Layer

Fixed-point `i64` microcents (1 cent = 1,000,000). No `f64`.

- `committed_microcents` — **lifetime cumulative spend** (monotonic; never decreases)
- `reserved_microcents` — active holds awaiting commit/release
- `top_up_tenant` — add funds without resetting lifetime spend
- `restore_from_snapshot` — crash recovery from frozen `BudgetSnapshot`
- `verify_conservation` — audit/reconciliation path (full snapshot)
- Loom model tests (`budget_loom`) — CAS concurrency verification under `RUSTFLAGS='--cfg loom'`

```rust
budget.ensure_tenant("desk", 100_000_000);
budget.top_up_tenant("desk", 50_000_000);
let proof = prove_conservation(&budget)?;
let cert = calybris_core::finance::certify_ledger(&budget)?;
assert_eq!(proof.ledger_digest_hex, cert.ledger_digest_hex);
assert_eq!(proof.snapshot_version, cert.snapshot_version);
```

Policy snapshots: use `PolicySnapshot::try_new(...)` in production (validates BPS ranges and catalog).

## Examples

```bash
cargo run --example quickstart
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
RUSTFLAGS='--cfg loom' cargo test --test budget_loom
cargo doc --no-deps
```

Tested on **Rust 1.85.0** (MSRV) and **stable**. Miri is on the hardening roadmap (Loom covers budget concurrency today).

## Integration contract

Calybris verifies decisions and conservation proofs — it does **not** auto-invoke `verify_decision` in your hot path. Callers must invoke verification at audit boundaries (pre-WAL append, reconciliation, external review). This keeps the kernel allocation-free and leaves control flow to the host system.

## What This Crate Is Not

- Exchange gateway, market data, or order lifecycle
- Thompson Sampling / adaptive routing
- HTTP API server

See [emirhuseyin.tech/engine](https://emirhuseyin.tech/engine) for the full proprietary stack.

## License

Apache-2.0. See [LICENSE](LICENSE).