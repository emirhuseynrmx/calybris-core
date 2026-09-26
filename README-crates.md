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
calybris-core = "1.3"
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
// `try_new_trusted` for new code; `try_new` exists to replay older policies.
let snapshot = PolicySnapshot::try_new_trusted(1, 1, 9600, 5500, 3500, 2, models)?;

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
| **Stable semantics** | Gate order, tie-break, units, ceilings and digest layouts are written down in [`docs/DECISION_SEMANTICS.md`](docs/DECISION_SEMANTICS.md), specified byte by byte in [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) and pinned by tests, and [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) says what a 1.x release may and may not change. |

`PolicySnapshot::new`, deprecated since 0.3.9, is gone: shipping it in a 1.0.0
would have made it permanent. Every public error enum is now `#[non_exhaustive]`
so a security fix can add a variant; the enums that carry decision semantics are
exhaustive for the opposite reason. The full list is in the
[CHANGELOG](CHANGELOG.md).

## Performance

CodSpeed CI (Linux x86_64, release): ~**8.6M** `prescribe`/sec, ~115 ns/decision
on a 22-model synthetic catalog. Hardware and workload dependent — provenance
and a reproduction recipe are in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md); run
`cargo bench --bench kernel_bench` on your own hardware.

## Sponsoring

Calybris Core is built and maintained by one person. If it saves you work, or you
want the preview modules reviewed and stabilised sooner, you can support it on
GitHub Sponsors.

<a href="https://github.com/sponsors/emirhuseynrmx"><img src="https://img.shields.io/badge/Sponsor_Calybris-%E2%9D%A4-db61a2?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor Calybris on GitHub Sponsors" /></a>

## Documentation

The full README, the Python surface and the adapter walkthroughs live in the
[repository](https://github.com/emirhuseynrmx/calybris-core).

| Doc | Contents |
|-----|----------|
| [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) | Every digest layout, byte by byte — what a second implementation would be written against |
| [`docs/INVARIANTS.md`](docs/INVARIANTS.md) | Every property the crate promises, with the test that fails when it stops being true |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | What a 1.x release may and may not change |
| [`docs/DECISION_SEMANTICS.md`](docs/DECISION_SEMANTICS.md) | Units, ceilings, gate order, tie-break — the decision contract |
| [`docs/AUDIT_GUIDE.md`](docs/AUDIT_GUIDE.md) | Module map, audit commands, external review checklist |
| [`docs/CALY_PROOF.md`](docs/CALY_PROOF.md) | CALY-PROOF v1 digest and proof contract |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, trust boundaries, attackers |
| [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md) | HMAC / Ed25519 key custody and rotation |
| [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md) | Invariants I1-I10 and test mapping |
| [`docs/ADAPTERS.md`](docs/ADAPTERS.md) | Every reference mapping with its commands |
| [`docs/DECISION_SEMANTICS.md`](docs/DECISION_SEMANTICS.md) | The decision surface, units and identities |
| [`docs/MIRI.md`](docs/MIRI.md) | UB detection scope in CI |

MSRV 1.85. Apache-2.0.
