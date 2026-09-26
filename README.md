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
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/emirhuseynrmx)

**A deterministic decision engine: it selects under explicit constraints, and makes
the decision verifiable afterwards.**

## In 30 seconds

Software makes choices for businesses all day: which supplier gets the order,
which carrier ships the parcel, which AI model answers the customer. When
someone later asks *"why that one?"*, most systems can only show a log that
anyone with access could have edited.

Calybris makes those choices by rules you write down — budget, risk,
deadline — and keeps a receipt for every one. Months later, on another
computer, the receipt reproduces exactly the same decision. Change a single
record and the numbers stop matching.

New in 1.3.0: you do not have to take the operator's word for it either.
A public timestamping service and the Bitcoin blockchain can date the log, and
other organisations can co-sign it, so nobody — including whoever runs it —
can rewrite the past or backdate a decision without it showing.

**Try it in your browser, nothing to install:** [calybris.tech/try](https://calybris.tech/try/)

> **1.3.0: you no longer have to trust whoever runs the log.** Signed
> checkpoints that independent witnesses co-sign, proof when a log shows
> different histories to different people, and timestamps from RFC 3161
> authorities and Bitcoin — behind the `preview` flags, outside the stability
> promise until reviewed. Every decision is exactly what 1.2.0 made. See
> [In this release](#in-this-release--130).
>
> **Since 1.0.0 the API and the formats are stable.**
>
> The version number is the promise, not a boast. `0.x` means *expect breaking
> changes*; from 1.0.0 on there are none to expect within 1.x. The public API,
> the decision semantics, the digest formats and the replay behaviour are
> documented in [docs/DECISION_SEMANTICS.md](docs/DECISION_SEMANTICS.md),
> specified byte by byte in [docs/SPECIFICATION.md](docs/SPECIFICATION.md), and
> pinned by tests. A decision made under 1.0.0 replays identically under every
> later 1.x.
>
> Development continues. New capabilities arrive in 1.x releases as additions;
> anything that would break a caller or change a digest waits for a major
> version. [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) says exactly what a 1.x
> release may and may not change.

Given a frozen catalog, a policy snapshot, and a typed request, Calybris returns
one action plus an audit bundle that replays to the same answer.

```text
catalog + policy + request  ->  decision + audit bundle
```

Integer-only Rust hot path. No hosted dependency. No `unsafe` in the kernel.

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

## In this release — 1.3.0

Up to 1.2.0, Calybris assumed one party is honest about which log is *the* log and
when each record was written: whoever runs it. 1.3.0 removes that assumption.
Every decision, digest and receipt is exactly what 1.2.0 made; the additions
sit behind the `preview` flags (see [docs/PREVIEW.md](docs/PREVIEW.md)), and
[docs/TRUST.md](docs/TRUST.md) walks through all of it.

| | |
|---|---|
| **Who else saw this log?** | `checkpoint` + `witness` — the log's state as a signed C2SP checkpoint, co-signed by witnesses that sign only a checkpoint extending everything they signed before. The formats are the ones Go's checksum database and Sigsum witnesses already use, pinned byte for byte against the Go reference. |
| **Was I shown the same log as everyone else?** | `audit` — a quorum of witnesses you trust; two conflicting checkpoints become proof anyone can check. A property test plays forked histories against real witnesses in every order. |
| **When did it exist?** | `tsa` (feature `preview-tsa`) verifies RFC 3161 tokens against a TSA certificate you pin; `ots` verifies OpenTimestamps proofs against a Bitcoin block header, and says *Pending* until one exists. Tested with FreeTSA, DigiCert and a 2015 Bitcoin proof. |
| **If a signing key is stolen** | Witnesses keep the past from being rewritten, timestamps keep it from being backdated, and `audit::KeyStatus` counts a revoked key only for signatures that independent evidence dates before its revocation. |
| **From the command line** | `calybris-verify checkpoint create / stamp / verify` and `witness cosign`: sign, witness, timestamp and audit a WAL without writing code. `verify` names exactly what it established, from *signature only* to *full verification*, and `--require` fails when independence is missing. |
| **What is not there yet** | The witnesses are the mechanism, not yet the parties: today no one but the maintainer runs a witness for a Calybris log. RFC 3161 authorities and Bitcoin are independent already. |
| **Post-quantum, in bulk** | `hybrid::HybridSigner::sign_batch` — one hybrid signature for a whole batch. NIST ACVP vectors pin the ML-DSA-65 calls; the implementation is still **unaudited** ([docs/AUDIT_SCOPE.md](docs/AUDIT_SCOPE.md)). |

## Added in 1.2.0

Every 1.0 decision, digest and receipt is unchanged. What 1.2.0 adds are the
questions a decision raises afterwards, behind the `preview` feature flag
(released, but not yet under the stability promise — see
[docs/PREVIEW.md](docs/PREVIEW.md)):

| | |
|---|---|
| **What would it take?** | `counterfactual::what_would_win` — the smallest single change to a losing candidate (quality, latency, price, risk ceiling) after which the kernel selects it; `decision_margin` — how far the winner can move before it loses. Runs the real kernel, so it cannot disagree with `prescribe`. Python: `PolicySnapshot.what_would_win`. |
| **Is it in the log?** | `merkle` — RFC 9162 inclusion and consistency proofs over log records, matching the Certificate Transparency reference vectors. One decision is checked without the whole log, and a rewritten history cannot prove itself consistent with a published head. |
| **Would another policy do better?** | `exploration` takes a small, keyed, replayable share of near-best alternatives and records exactly how likely each was; `ope` then estimates what a different policy would have achieved from those outcomes — and says so plainly when the log cannot answer. |
| **Settle once** | `budget::Reservation` — double spends and use after delegation are compile errors. |
| **Signatures that outlast Ed25519** | `hybrid` (feature `preview-pq`) — Ed25519 + ML-DSA-65, valid only when both verify. The ML-DSA implementation is unaudited, hence its own flag. |

## Settled in 1.0.0

Everything here is something the crate had to settle before it could promise not to break it.

| | |
|---|---|
| **`explain()`** | One row per candidate in the catalog: which gate turned it away, what was measured against what limit, and for the ones that survived, the terms that add up to the utility the kernel ranked on. It runs the same evaluation `prescribe` does, so it cannot become a second opinion about the decision. |
| **`Outcome`** | What happened after a decision — applied, abandoned or still running — bound to the policy, the input and the decision together, with the selection probability that an off-policy estimate needs and that cannot be recovered afterwards. The kernel does not read these back; it defines the shape so that two callers write the same one. |
| **Stable semantics** | Gate order, tie-break, units, ceilings and digest layouts are written down in [docs/DECISION_SEMANTICS.md](docs/DECISION_SEMANTICS.md), specified byte by byte in [docs/SPECIFICATION.md](docs/SPECIFICATION.md) and pinned by tests, and [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) says what a 1.x release may and may not change. |

`PolicySnapshot::new`, deprecated since 0.3.9, is gone: shipping it in a 1.0.0
would have made it permanent. Every public error enum is now `#[non_exhaustive]`
so a security fix can add a variant; the enums that carry decision semantics are
exhaustive for the opposite reason. The full list is in the
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
| **`calybris` (Python)** | **Production-capable / stable API** | Decisions, policy comparison, shared budget, signed policy provenance, state proofs, receipts, keyed WAL, anchors and replay |
| **`calybris-ffi` (C)** | **Stable ABI** | The decision path over a stable C ABI, for callers that are neither Rust nor Python. Adds no behaviour; a C caller decides the same way and recomputes the same digests. See [calybris-ffi/README.md](calybris-ffi/README.md). |
| **`calybris_commerce` (Python)** | Experimental | Thicker **adapter** (orders, suppliers, batch routing), still calls the same Rust kernel; API may change |

Rust owns correctness and replay semantics. The core Python package exposes the
production trust boundary and is tested as an installed abi3 wheel. Its runtime
integrity guarantees match the Rust core, and as of 1.0.0 its API is stable —
pin the exact version anyway, so that a rebuild is a decision rather than a
surprise. [docs/PYTHON.md](docs/PYTHON.md) covers the production path and the
CALY-PROOF v1 compatibility boundary.

## Install

```bash
# Rust (stable surface)
cargo add calybris-core

# Python (production-capable core binding; stable API)
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

- `#![forbid(unsafe_code)]` in `calybris-core` — the kernel cannot contain
  `unsafe`, and the compiler enforces it rather than a review convention.
  The one exception is `calybris-ffi`, which exists to be a C boundary and
  therefore handles raw pointers; it is a separate crate for exactly that
  reason, so the unsafe is confined to a few hundred reviewable lines instead
  of being available everywhere.
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
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Every digest layout, byte by byte — what a second implementation would be written against |
| [docs/INVARIANTS.md](docs/INVARIANTS.md) | Every property the crate promises, with the test that fails when it stops being true |
| [fuzz/README.md](fuzz/README.md) | The fuzz targets, what would count as a finding in each, and why they only run on Linux |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | What a 1.x release may and may not change, and how a defect that needs a format change is handled |
| [docs/DECISION_SEMANTICS.md](docs/DECISION_SEMANTICS.md) | Decision API, units, identities, policy comparison and its limits |
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
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, supported versions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, test gate, PR expectations |

## Sponsoring

Calybris Core is built and maintained by one person. If it saves you work, or you
want the preview modules reviewed and stabilised sooner, you can support it on
GitHub Sponsors.

<a href="https://github.com/sponsors/emirhuseynrmx"><img src="https://img.shields.io/badge/Sponsor_Calybris-%E2%9D%A4-db61a2?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor Calybris on GitHub Sponsors" /></a>

## License

Apache-2.0. See [LICENSE](LICENSE).
