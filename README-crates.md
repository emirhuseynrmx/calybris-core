<div align="center">
  <img src="https://raw.githubusercontent.com/emirhuseynrmx/calybris-core/main/assets/banner.png" alt="Calybris Core" width="100%" />
</div>

<br/>

# Calybris Core

[![CI](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml/badge.svg)](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/emirhuseynrmx/calybris-core?utm_source=badge)
[![codecov](https://codecov.io/gh/emirhuseynrmx/calybris-core/graph/badge.svg)](https://codecov.io/gh/emirhuseynrmx/calybris-core)
[![Crates.io](https://img.shields.io/crates/v/calybris-core)](https://crates.io/crates/calybris-core)
[![docs.rs](https://img.shields.io/docsrs/calybris-core)](https://docs.rs/calybris-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange)]()

**A deterministic decision engine: it selects under explicit constraints, and makes
the decision verifiable afterwards.**

Given a frozen catalog, a policy snapshot, and a typed request, Calybris returns
one action plus an audit bundle that replays to the same answer.

```text
catalog + policy + request  ->  decision + audit bundle
```

Integer-only hot path — no `f64` anywhere in it. No hosted dependency.
`#![forbid(unsafe_code)]`.

## What this crate is

A **proof-carrying decision kernel**: not an OMS, not an LLM gateway, not a
matching engine. You bring the catalog — suppliers, carriers, venues, models —
and the kernel evaluates hard constraints, picks the best eligible candidate,
and emits digests you can replay and verify offline.

The kernel does not know what a candidate *is*. Supplier routing, carrier
selection, model routing and pre-trade admission are reference mappings onto one
API, not four products.

Two claims it does not make. It does not find the best commercial outcome; it
selects by the rules you wrote, and a wrong rule produces a wrong decision you
can at least see. And it proves the *integrity of the trail*, not the truth of
your inputs.

## Quick start

```toml
[dependencies]
calybris-core = "0.6"
```

```rust
use calybris_core::kernel::*;
use calybris_core::verify::{verified_audit_bundle, verify_decision, VerifyResult};

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

let decision = snapshot.prescribe_checked(input)?;
assert_eq!(verify_decision(&snapshot, input, &decision), VerifyResult::Valid);

// Fail-closed: this returns a bundle only after the decision replays exactly.
// The bare `audit_bundle` returns one with `replay_valid = false` instead of refusing.
let bundle = verified_audit_bundle(&snapshot, input, &decision)
    .expect("decision must replay to be audited");
assert!(bundle.replay_valid);
```

`cargo run --example quickstart` runs this end to end and prints the bundle.
`cargo run --example llm_routing` and `--example pretrade_guard` are two of the
reference mappings.

## What gets proved

```text
policy digest + input digest + decision digest + replay result
```

The proof format is a written contract, not an implementation detail.
[`docs/CALY_PROOF.md`](docs/CALY_PROOF.md) specifies every digest and chain
byte-exactly, and golden and conformance vectors pin them across versions and
platforms, so an independent reimplementation can prove itself against a fixed
reference.

The crate ships a **`calybris-verify`** binary so a third party can check a
decision trail without running your engine:

```bash
cargo install calybris-core
calybris-verify chain decisions.wal.jsonl --anchor trusted-head.json
calybris-verify audit decisions.wal.jsonl --policy policy.json --json
```

The trail carries fail-closed receipts (`verify_receipt_full` binds replay,
claims, trusted signature, state anchor and WAL anchor in one call), canonical
trusted policy construction, state trajectories, ledger digests bound to WAL
watermarks, per-record policy resolution across rotations, suffix-truncation
detection, and domain-separated Ed25519 policy provenance.

The verification path builds for `wasm32-unknown-unknown`
(`--no-default-features`).

[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is explicit about scope: the
system proves trail *integrity*, not confidentiality, policy quality, or input
truth.

## Modules

| Module | Role |
|--------|------|
| `kernel` | Integer-only decision kernel; `prescribe`, `prescribe_with_trace` for per-constraint rejection counts |
| `digest` | Canonical tagged byte digests — policy / input / decision / ledger / state |
| `verify` | Replay verification and audit bundles; fail-closed `verified_audit_bundle` |
| `receipt` | Canonical claims digest and `verify_receipt_full` |
| `state` | Domain-state trajectories, anchored and complete verification |
| `provenance` | Ed25519-signed policies, domain-separated *(feature)* |
| `wal` | Hash-chained WAL; keyed HMAC, trusted head anchors, single-writer enforcement |
| `budget` | CAS reserve/commit/release; `remaining + reserved + committed == initial` (Loom + Miri) |
| `finance` | Ledger digests, conservation proofs and certificates |
| `persistence` | Atomic snapshots and WAL-verified generation checkpoints |
| `async_wal` / `instrument` | Tokio WAL *(feature `async`)*, tracing spans *(feature `observability`)* |

## 0.6.0

This release adds a typed decision surface over the same kernel, published
separately as the `calybris` Python package: a fixed-quote adapter, a bounded
policy comparison that identifies both policies it compared, and an atomic
budget lifecycle report. The Rust decision and replay protocol is unchanged, and
`calybris-core` remains the contract that surface is built on.

Two reporting defects were fixed here. The kernel dropped its rejection
histogram on the trace path, so a rejected decision reported every gate as zero.
The Python budget counted an unabsorbed overrun as a settled attempt, which
skewed its reservation-accuracy figures. Neither touched the ledger. See the
[CHANGELOG](CHANGELOG.md).

## Performance

CodSpeed CI (Linux x86_64, release): ~**8.6M** `prescribe`/sec, ~115 ns/decision
on a 22-model synthetic catalog. Hardware and workload dependent — provenance
and a reproduction recipe are in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md); run
`cargo bench --bench kernel_bench` on your own hardware.

## Documentation

The full README, the Python surface and the adapter walkthroughs live in the
[repository](https://github.com/emirhuseynrmx/calybris-core).

| Doc | Contents |
|-----|----------|
| [`docs/AUDIT_GUIDE.md`](docs/AUDIT_GUIDE.md) | Module map, audit commands, external review checklist |
| [`docs/CALY_PROOF.md`](docs/CALY_PROOF.md) | CALY-PROOF v1 digest and proof contract |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, trust boundaries, attackers |
| [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md) | HMAC / Ed25519 key custody and rotation |
| [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md) | Invariants I1-I10 and test mapping |
| [`docs/ADAPTERS.md`](docs/ADAPTERS.md) | Every reference mapping with its commands |
| [`docs/DECISIONS_0.6.0.md`](docs/DECISIONS_0.6.0.md) | The 0.6.0 decision surface, units and identities |
| [`docs/MIRI.md`](docs/MIRI.md) | UB detection scope in CI |

MSRV 1.85. Apache-2.0.
