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

Integer-only Rust hot path. No hosted dependency. No `unsafe` in project code.

## What is this?

Calybris is a **proof-carrying decision kernel**: not an OMS, not an LLM gateway,
not a matching engine. You bring the catalog — suppliers, carriers, venues,
models — and the kernel evaluates hard constraints, picks the best eligible
candidate, and emits digests you can replay and verify offline.

The kernel does not know what a candidate *is*. Supplier routing, carrier
selection, model routing and pre-trade admission are **reference mappings onto
one API**, not four products.

Two claims it does not make. It does not find the best commercial outcome; it
selects by the rules you wrote, and a wrong rule produces a wrong decision you
can at least see. And it proves the *integrity of the trail*, not the truth of
your inputs.

## In this release — 0.6.0

A typed decision surface on the kernel that was already there, and a way to ask
what a policy change would have done.

| | |
|---|---|
| **`DecisionEngine`** | One already-priced job in, one selected candidate plus a replay-verified audit bundle out. No new selection algorithm: a fixed quote is mapped onto the native cost rate, so the kernel prices it without a second pricing path. |
| **`compare_policies`** | Replay identical frozen requests through two policies and count what changed. Both policies are identified in the result by native digest and epoch, so a comparison whose stored detail was capped still says which two produced it. |
| **`AgentBudget.lifecycle_report()`** | Balance, unresolved work and its next action, corrections, denials and reservation accuracy — read under one lock, so the parts cannot disagree with each other. |

0.5.8 and 0.5.9 were never published, so this is the whole distance from 0.5.7.
Units, identities and the exact limits of the rejection trace are in
[docs/DECISIONS_0.6.0.md](docs/DECISIONS_0.6.0.md); the full list is in the
[CHANGELOG](CHANGELOG.md).

## When to use / when not to

| Use Calybris when... | Do **not** use it for... |
|----------------------|--------------------------|
| Decisions must be deterministic and replay-auditable | Inventory, WMS, label printing, carrier booking |
| You need hard gates (budget, risk, latency, region, capability) in your control plane | A hosted routing API or managed decision service |
| Post-mortems and compliance need proof bundles, not log grep | Live market data, order matching, exchange connectivity |
| You want to know what a policy change *would* have done before shipping it | Deciding what the policy should be — that is your judgement, not the kernel's |

## Quickstart (~5 minutes)

```bash
pip install calybris
```

The shortest path to a decision is the typed adapter: fixed quotes in, one
selected candidate plus a replay-verified proof out.

```python
from calybris import Candidate, DecisionEngine, DecisionRequest, EngineConfig

day = 86_400_000
catalog = [
    Candidate(candidate_id=1, provider_id=0, quality_bps=9000, risk_ceiling_bps=8000,
              lead_time_ms=8 * day, region_mask=1, quoted_cost_microunits=80_000_000),
    Candidate(candidate_id=2, provider_id=1, quality_bps=9500, risk_ceiling_bps=8000,
              lead_time_ms=3 * day, region_mask=1, quoted_cost_microunits=100_000_000),
]

# Lead time is a hard deadline here, not something to trade off against price,
# so its scoring penalty is switched off. Leave the default on and a delivery
# measured in days outweighs any realistic order value.
engine = DecisionEngine(catalog, config=EngineConfig(latency_penalty_microunits_per_ms=0))

request = DecisionRequest(
    request_sequence=1,
    budget_microunits=120_000_000,
    business_value_microunits=200_000_000,
    maximum_lead_time_ms=5 * day,
)
result = engine.decide(request)

result.status                     # "selected"
result.selected_candidate_id      # 2 — the cheaper quote misses the deadline
engine.verify(request, result)    # recomputed against the same catalog and policy
```

Quotes, budget and business value are integers in one currency and scale that
you choose; nothing converts between currencies. Lead time is milliseconds in a
`u32`, which caps it at roughly 49.7 days. When no candidate clears every gate,
`status` is `"rejected"` and `selected_candidate_id` is `None` — never a
fictitious zero.

`verify` does not read a self-declared flag. It rebuilds the whole result from
the catalog, policy and request you hand it, which is why those are what you
persist alongside the decision.

`python examples/supplier_decision.py` runs the full version offline, including a
policy comparison. The candidates are suppliers there; the kernel does not know
that.

### Asking what a policy change would do

```python
from calybris import compare_policies

stricter = DecisionEngine(catalog, config=EngineConfig(
    latency_penalty_microunits_per_ms=0, minimum_confidence_bps=9500,
))
comparison = compare_policies(engine, stricter, historical_requests)

comparison.total            # requests replayed
comparison.changed          # outcomes that moved
comparison.newly_rejected   # requests that now clear nothing
comparison.policy_changed   # True — compares native identity, not just config
```

This is a replay, not a forecast. It says what the two rule sets do to the same
inputs; it does not demonstrate realized savings or supplier performance.

### The Rust surface

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
cargo run --example quickstart
```

That example builds a two-model policy, prescribes one request, verifies replay,
and prints an audit bundle.

### Budget control

**AgentBudget** sits beside the decision rather than in front of it: one shared
budget across paid calls, with pre-call reservations, explicit uncertain-usage
reconciliation, documented corrections for an overrun the budget could not
absorb, and bounded immutable reports. `python examples/agent_budget.py` needs no
provider credentials. See [docs/AGENT_BUDGET.md](docs/AGENT_BUDGET.md) for the
same-process, non-streaming support boundary.

## Use cases

Each is a runnable example in this repository, not a pitch.

**Choosing among fixed quotes.** Suppliers or subcontractors have quoted a
already-priced job. Which one clears the budget, the deadline, the quality floor
and the required capabilities — and can you show why, months later?
→ `python examples/supplier_decision.py`

**Model and provider routing.** A gateway picks among premium, fast, and budget
providers under quality, latency, risk, provider, and budget ceilings. Every
decision is verified before it enters the audited WAL, so "why did this request
get the premium model" is answered from the proof rather than from log
archaeology.
→ `cargo run --example llm_routing`

**Pre-trade admission.** A desk runs a VWAP algo at the cash open. Each child
order clears a policy gate (an eligible venue under risk, latency, quality, and
fee caps) and an exposure gate (notional reserved against the desk budget,
routing fees committed on admit). The ledger carries the conservation proof
`remaining + reserved + committed == initial`, in checked integers. Calybris owns
the two gates and the proof — not the OMS, the market-data feed, or the matching
engine.
→ `cargo run --example pretrade_guard`

**Fulfillment and supplier routing at volume.** 10,000 orders across 8 courier
networks with distinct SLAs, regional coverage, and risk tolerances.
Substitutions are recorded as decisions, so "why this courier, for this order"
stays answerable months later.
→ `python bindings/python/examples/orion_market.py`

**Defending a policy change with numbers.** The same catalog evaluated under
strict, medium, and relaxed profiles, reporting fulfillment and substitution
rates, cost percentiles, batch and single-decision throughput, resident memory,
and the audit success and tamper-detection counts for the resulting trail.
→ `python bindings/python/examples/novamart_benchmark.py`

The domain objects differ. The kernel, the digests, and the replay contract do
not.

## What gets proved

Calybris binds the full decision path:

```text
policy digest + input digest + decision digest + replay result
```

The proof format is a written contract, not an implementation detail.
[docs/CALY_PROOF.md](docs/CALY_PROOF.md) specifies every digest and chain
byte-exactly, golden and conformance vectors pin them across versions and
platforms so an independent reimplementation can prove itself against a fixed
reference, and the bundled **`calybris-verify`** CLI lets an auditor check a
decision trail without running your engine.

```bash
cargo install calybris-core   # ships the calybris-verify binary
calybris-verify chain decisions.wal.jsonl
calybris-verify chain decisions.wal.jsonl --anchor trusted-head.json
calybris-verify audit decisions.wal.jsonl --policy policy.json
calybris-verify audit rotated.wal.jsonl --policy policy-v1.json --policy policy-v2.json --json
```

What the trail carries:

- **Receipts.** `receipt::verify_receipt_full` verifies replay, claims, trusted
  signature, state anchor and WAL anchor as one fail-closed operation.
- **Trusted policies.** Construction canonicalizes catalog order, reserves model
  ID 0 as the rejection sentinel, and refuses catalogs that cannot fit the
  public decision counters.
- **State trajectories.** `state_digest_before/after` per decision;
  `verify_complete_trajectory` binds genesis and the expected terminal step,
  while `verify_trajectory` remains an unanchored fragment check.
- **Ledger and checkpoints.** Ledger digests bind WAL watermarks and reservation
  allocator state; coordinated checkpoints commit immutable snapshot and anchor
  generations behind one atomic manifest, with a loader that verifies the actual
  WAL.
- **Policy rotation.** Library and CLI WAL replay resolve the exact policy per
  record across rotations.
- **Truncation.** `WalAnchor` detects a cleanly removed WAL suffix when the
  trusted head is stored outside the WAL file.
- **Signed provenance.** Ed25519 policy signatures are domain-separated, so a
  signature is non-transferable across policies, signers and timestamps.

Python exposes the same signed policies, state-chain transitions, decision
receipts, keyed audited WAL, durable anchors and replay verification. The
verification path builds for `wasm32-unknown-unknown`
(`--no-default-features`).

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is explicit about scope: the system
proves trail *integrity*, not confidentiality, policy quality, or input truth.

## Architecture at a glance

| Module | Role |
|--------|------|
| `kernel` | Integer-only decision kernel (~115 ns/decision); `prescribe`, `prescribe_with_trace` for per-constraint rejection counts |
| `digest` | Canonical tagged byte digests — policy / input / decision / ledger / state |
| `verify` | Full replay verification and audit bundles; fail-closed `verified_audit_bundle` |
| `receipt` | Canonical claims digest + `verify_receipt_full` binding replay, signature, state, and WAL evidence |
| `state` | Domain-state trajectories; complete genesis/final-step verification plus anchored fragment verification |
| `provenance` | Ed25519-signed policies, domain-separated *(feature)* |
| `wal` | Hash-chained WAL; keyed HMAC, trusted head anchors, and single-writer enforcement |
| `budget` | CAS reserve/commit/release; `remaining + reserved + committed == initial` (Loom + Miri) |
| `finance` | Ledger digests, conservation proofs and certificates |
| `certificate` / `proof` | CALY-PROOF v1 compatibility envelopes; new integrations should use `receipt` |
| `builder` / `config` | Hard-to-misuse constructors with validation |
| `persistence` | Atomic snapshots, bounded artifact reads, and WAL-verified generation checkpoints; the directory-fsync guarantee is platform-specific |
| `async_wal` / `instrument` | Tokio WAL *(feature `async`)*, tracing spans *(feature `observability`)* |

On the Python side, `calybris.decisions` is the typed fixed-quote adapter and
`calybris.agent` is the shared budget. Both call the Rust implementations rather
than reimplementing security-sensitive logic.

Ships a `calybris-verify` auditor CLI (`chain` / `audit` / `policy`, `--json`) so a
third party can verify a decision trail without running your engine.

## Stability model

| Layer | Status | Notes |
|-------|--------|-------|
| **`calybris-core` (Rust)** | **Stable** | crates.io: this is the contract |
| **`calybris` (Python)** | **Production-capable / pre-1.0 API** | Decisions, policy comparison, shared budget, signed policy provenance, state proofs, receipts, keyed WAL, anchors and replay |
| **`calybris_commerce` (Python)** | Experimental / pre-1.0 | Thicker **adapter** (orders, suppliers, batch routing), still calls the same Rust kernel; API may change |

Rust owns correctness and replay semantics. The core Python package exposes the
production trust boundary and is tested as an installed abi3 wheel. The Python
API remains pre-1.0, so pin minor versions even though its runtime integrity
guarantees match the Rust core. See the
[0.5.7 trust-release migration](docs/TRUST_RELEASE_0.5.7.md) for the canonical
production path and the CALY-PROOF v1 compatibility boundary.

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
| Which fixed quote wins? | - | `examples/supplier_decision.py` |
| What would this policy change have done? | - | `examples/supplier_decision.py` |
| What has this run spent, and what is still open? | - | `examples/agent_budget.py` |
| Which model/provider? | `cargo run --example llm_routing` | `quickstart.py`, `batch_routing.py` |
| Which venue admits an order? | `cargo run --example pretrade_guard` | `pretrade_budget_guard.py` |
| Which supplier fulfills, at volume? | - | `orion_market.py`, `novamart_benchmark.py` |

Full command list and code samples: **[docs/ADAPTERS.md](docs/ADAPTERS.md)**

## Performance

CodSpeed CI (Linux x86_64, release): ~**8.6M** `prescribe`/sec, ~115 ns/decision,
22-model synthetic catalog. Hardware and workload dependent — provenance and a
reproduction recipe are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md); run
`cargo bench --bench kernel_bench` on your own hardware.

A release-blocking production torture suite, introduced in 0.5.7 and still
enforced, covers a 64-model checked kernel, state trajectories, signed receipts,
keyed audited WAL, suffix-truncation detection, contended budgets, and a
25,000-tenant ledger.

## Security posture

- `#![forbid(unsafe_code)]` — no `unsafe` in project code.
- Fail-closed audit boundaries: `verified_audit_bundle` / `append_verified_audited`
  refuse to emit or log a decision that does not replay exactly.
- Tamper-evident WAL: SHA-256 hash chain, optional HMAC-SHA256 with constant-time
  comparison (`subtle`). Keyed WAL APIs reject keys shorter than 32 bytes.
- Trusted `WalAnchor` verification detects a cleanly removed WAL suffix; the
  hash chain alone validates only the records still present.
- Anchored recovery APIs refuse to build a recovery plan from a valid but
  incomplete WAL prefix.
- `visit_verified_wal*` streams verified entries, so CLI audit and recovery
  planning do not retain the complete log in memory.
- Sync and async WAL writers enforce one active writer per file.
- `prescribe_checked` and the checked batch and trace APIs validate untrusted
  Rust inputs.
- Signed decision receipts bind optional state and WAL evidence to the exact
  replay-verified decision.
- Byte-exact proof contract ([docs/CALY_PROOF.md](docs/CALY_PROOF.md)) locked by
  golden and conformance vectors, cross-checked in Rust and Python.
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
| [docs/DECISIONS_0.6.0.md](docs/DECISIONS_0.6.0.md) | Decision API, units, identities, policy comparison and its limits |
| [docs/AGENT_BUDGET.md](docs/AGENT_BUDGET.md) | Shared budget, reservations, corrections, lifecycle report, support boundary |
| [docs/ADAPTERS.md](docs/ADAPTERS.md) | Every reference mapping with its commands and code |
| [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md) | Module map, audit commands, external review checklist |
| [docs/CALY_PROOF.md](docs/CALY_PROOF.md) | CALY-PROOF v1 digest and proof contract |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, attackers |
| [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | HMAC / Ed25519 key custody and rotation |
| [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) | Invariants I1-I10 and test mapping |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | Throughput provenance and reproduction |
| [docs/MIRI.md](docs/MIRI.md) | UB detection scope in CI |
| [docs/PYTHON.md](docs/PYTHON.md) | Python wrappers vs Rust core, commerce API notes |
| [docs/TRUST_RELEASE_0.5.7.md](docs/TRUST_RELEASE_0.5.7.md) | Production trust boundary and CALY-PROOF v1 compatibility |
| [docs/MIGRATING_0.5.5_TO_0.5.7.md](docs/MIGRATING_0.5.5_TO_0.5.7.md) | Fail-closed persisted-ledger migration and rollback |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, supported versions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test gate, PR expectations |

## License

Apache-2.0. See [LICENSE](LICENSE).
