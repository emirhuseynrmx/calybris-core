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

**Deterministic, auditable decision primitive for high-stakes routing & guardrails.**

Given a frozen catalog, a policy snapshot, and a typed request, Calybris returns
one action plus an audit bundle that replays to the same answer.

```text
catalog + policy + request  ->  decision + audit bundle
```

Integer-only Rust hot path. No hosted dependency. No `unsafe` in project code.

## What is this?

Calybris is a **proof-carrying decision kernel**: not an OMS, not an LLM gateway,
not a matching engine. You bring the catalog (suppliers, models, venues); the
kernel evaluates hard constraints, picks the best eligible candidate, and emits
digests you can replay and verify offline.

Same primitive, different adapters: supplier routing, model routing, and
pre-trade admission are **reference mappings** onto one API, not three products.

## When to use / when not to

| Use Calybris when... | Do **not** use it for... |
|----------------------|--------------------------|
| Decisions must be deterministic and replay-auditable | Inventory, WMS, label printing, carrier booking |
| You need hard gates (budget, risk, latency, region, capability) in your control plane | A hosted routing API or managed decision service |
| Post-mortems and compliance need proof bundles, not log grep | Live market data, order matching, exchange connectivity |

## Stability model

| Layer | Status | Notes |
|-------|--------|-------|
| **`calybris-core` (Rust)** | **Stable** | crates.io: this is the contract |
| **`calybris` (Python)** | **Production-capable / pre-1.0 API** | First-class PyO3 surface for decisions, signed policy provenance, state proofs, receipts, keyed WAL, anchors, and replay |
| **`calybris_commerce` (Python)** | Experimental / pre-1.0 | Thicker **adapter** (orders, suppliers, batch routing), still calls the same Rust kernel; API may change |

Rust still owns correctness and replay semantics; Python calls those exact Rust
implementations rather than reimplementing security-sensitive logic. Starting
with 0.5.7, the core Python package exposes the production trust boundary and is
tested as an installed abi3 wheel. The Python API remains pre-1.0, so pin minor
versions even though its runtime integrity guarantees match the Rust core.
See the [0.5.7 trust-release migration](docs/TRUST_RELEASE_0.5.7.md) for the
canonical production path and CALY-PROOF v1 compatibility boundary.

## Quickstart (~5 minutes)

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
cargo run --example quickstart
```

That example builds a two-model policy, prescribes one request, verifies replay,
and prints an audit bundle. For Python:

```bash
pip install maturin pydantic
maturin develop --release
python bindings/python/examples/quickstart.py
```

## What gets proved

Calybris can bind the full decision path:

```text
policy digest + input digest + decision digest + replay result
```

Since 0.5.0 the proof format is a written contract, not an implementation
detail: [docs/CALY_PROOF.md](docs/CALY_PROOF.md) specifies every digest and
chain byte-exactly, golden vectors pin them across versions and platforms, and
the bundled **`calybris-verify`** CLI lets an auditor check a decision trail:
chain integrity, digests, and full kernel replay against a policy artifact
without running your engine.

```bash
cargo install calybris-core   # ships the calybris-verify binary
calybris-verify chain decisions.wal.jsonl
calybris-verify chain decisions.wal.jsonl --anchor trusted-head.json
calybris-verify audit decisions.wal.jsonl --policy policy.json
calybris-verify audit rotated.wal.jsonl --policy policy-v1.json --policy policy-v2.json --json
```

0.5.7 hardens the production trust boundary:

- `receipt::verify_receipt_full` verifies replay, claims, trusted signature,
  state anchor, and WAL anchor as one fail-closed operation.
- Trusted policy construction canonicalizes catalog order, reserves model ID 0,
  and rejects catalogs that cannot fit public decision counters.
- Ledger digests bind WAL watermarks and reservation allocator state;
  coordinated checkpoints commit immutable snapshot/anchor generations behind
  one atomic manifest, with an additive loader that verifies the actual WAL.
- Library and CLI WAL replay resolve the exact policy per record across policy
  rotations; CLI `--json` verdicts use standards-compliant JSON escaping.
- `WalAnchor` detects clean suffix truncation when the trusted head is stored
  outside the WAL file.
- Sync and async WAL writers enforce one active writer per file.
- Keyed WAL APIs reject HMAC keys shorter than 32 bytes.
- `prescribe_checked` and checked batch/trace APIs validate untrusted Rust inputs.
- Python exposes the same signed policies, state-chain transitions, decision
  receipts, keyed audited WAL, durable anchors, and replay verification.

0.5.0 adds:

- `state` — record `state_digest_before/after` per decision;
  `verify_complete_trajectory` binds genesis and the expected terminal step,
  while `verify_trajectory` remains an unanchored compatibility-fragment check.
- `provenance` (feature) — bind a policy digest to an Ed25519 signer and
  timestamp, non-transferable across policies.
- `certificate` — CALY-PROOF v1 compatibility envelope; its optional signature
  attests policy provenance only. Use signed receipts to bind full evidence.
- Golden and conformance vectors pin the byte-exact contract, so an independent
  reimplementation can prove itself against a fixed reference.

The verification path builds for `wasm32-unknown-unknown`
(`--no-default-features`).

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is explicit about scope: the system
proves trail *integrity*, not confidentiality, policy quality, or input truth.

## Architecture at a glance

| Module | Role |
|--------|------|
| `kernel` | Integer-only decision kernel (~115 ns/decision); `prescribe`, `prescribe_with_trace` for per-constraint rejection counts |
| `digest` | Canonical tagged byte digests — policy / input / decision / ledger / state |
| `verify` | Full replay verification and audit bundles; fail-closed `verified_audit_bundle` |
| `certificate` | Compatibility envelope for 0.5.0 certificate artifacts |
| `receipt` | Canonical claims digest + `verify_receipt_full` binding replay, signature, state, and WAL evidence *(0.5.7)* |
| `state` | Domain-state trajectories; complete genesis/final-step verification plus anchored fragment verification |
| `provenance` | Ed25519-signed policies, domain-separated *(0.5.0, feature)* |
| `wal` | Hash-chained WAL; keyed HMAC, trusted head anchors, and single-writer enforcement |
| `budget` | CAS reserve/commit/release; `remaining + reserved + committed == initial` (Loom + Miri) |
| `finance` | Ledger digests, conservation proofs and certificates |
| `proof` | Compatibility packaging for CALY-PROOF v1 attachments; new production integrations should use `receipt` |
| `builder` / `config` | Hard-to-misuse constructors with validation |
| `persistence` | Atomic snapshots, bounded artifact reads, and WAL-verified generation checkpoints; directory-fsync guarantee is platform-specific |
| `async_wal` / `instrument` | Tokio WAL *(feature `async`)*, tracing spans *(feature `observability`)* |

Ships a `calybris-verify` auditor CLI (`chain` / `audit` / `policy`, `--json`) so a
third party can verify a decision trail without running your engine.

## Install

```bash
# Rust (stable surface)
cargo add calybris-core

# Python (production-capable core binding; pre-1.0 API)
pip install calybris
```

Local Python build: `maturin develop --release` or see [docs/PYTHON.md](docs/PYTHON.md).

## Examples & adapters

Reference integrations that map domain objects onto the kernel:

| Question | Rust | Python |
|----------|------|--------|
| Which model/provider? | `cargo run --example llm_routing` | `quickstart.py`, `batch_routing.py` |
| Which venue admits an order? | `cargo run --example pretrade_guard` | `pretrade_budget_guard.py` |
| Which supplier fulfills? | - | `orion_market.py`, `novamart_benchmark.py` |

Full command list and code samples: **[docs/ADAPTERS.md](docs/ADAPTERS.md)**

## Performance

CodSpeed CI (Linux x86_64, release): ~**8.6M** `prescribe`/sec, ~115 ns/decision,
22-model synthetic catalog. Hardware and workload dependent — provenance and a
reproduction recipe are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md); run
`cargo bench --bench kernel_bench` on your own hardware.

0.5.7 carries a release-blocking production torture suite covering a
64-model checked kernel, state trajectories, signed receipts, keyed audited WAL,
suffix-truncation detection, contended budgets, and a 25,000-tenant ledger.

## Security posture

- `#![forbid(unsafe_code)]` — no `unsafe` in project code.
- Fail-closed audit boundaries: `verified_audit_bundle` / `append_verified_audited`
  refuse to emit or log a decision that does not replay exactly.
- Tamper-evident WAL: SHA-256 hash chain, optional HMAC-SHA256 with constant-time
  comparison (`subtle`).
- Trusted `WalAnchor` verification detects a cleanly removed WAL suffix; the
  hash chain alone validates only the records still present.
- Anchored recovery APIs refuse to build a recovery plan from a valid but
  incomplete WAL prefix.
- `visit_verified_wal*` streams verified entries, so CLI audit and recovery
  planning do not retain the complete log in memory.
- Signed decision receipts bind optional state and WAL evidence to the exact
  replay-verified decision.
- Ed25519-signed policy provenance, domain-separated so a signature is
  non-transferable across policies, signers, and timestamps *(0.5.0)*.
- Byte-exact proof contract ([docs/CALY_PROOF.md](docs/CALY_PROOF.md)) locked by
  golden + conformance vectors and cross-checked in Rust and Python *(0.5.0)*.
- Concurrency and UB: 7 Loom exhaustive interleavings on budget ops; Miri on
  nightly for the library tests.
- Security CI: Semgrep Rust/Python/secrets/security-audit, `cargo-audit`, and
  `cargo-deny`; feature matrix covers default / no-default / async / full.
- Documented boundaries: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (what it does
  **not** guarantee) and [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) (key
  custody and rotation).

Deployment security remains the caller's job: key storage, tenant isolation,
inventory/capacity freshness, and an external audit.

## Deep dive

| Doc | Contents |
|-----|----------|
| [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md) | Module map, audit commands, external review checklist |
| [docs/CALY_PROOF.md](docs/CALY_PROOF.md) | CALY-PROOF v1 digest and proof contract |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, attackers |
| [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | HMAC / Ed25519 key custody and rotation |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Throughput provenance and reproduction |
| [docs/MIGRATING_0.5.5_TO_0.5.7.md](docs/MIGRATING_0.5.5_TO_0.5.7.md) | Fail-closed persisted-ledger migration and rollback |
| [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) | Invariants I1-I10 and test mapping |
| [docs/MIRI.md](docs/MIRI.md) | UB detection scope in CI |
| [docs/PYTHON.md](docs/PYTHON.md) | Python wrappers vs Rust core, commerce API notes |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, supported versions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test gate, PR expectations |

## License

Apache-2.0. See [LICENSE](LICENSE).
