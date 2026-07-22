# External Audit Guide

Quick reference for reviewers assessing `calybris-core` before production use.

## 1. Clone and reproduce

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
rustc --version   # MSRV: 1.85.0
```

## 2. Mandatory commands

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo test --locked --test audit_pipeline
CALYBRIS_LOOM=1 LOOM_MAX_PREEMPTIONS=3 cargo test --locked --features loom-model --test budget_loom
```

Extended property testing (recommended before release):

```bash
PROPTEST_CASES=10000 cargo test --locked --all-features
```

Miri (UB detection — nightly toolchain):

```bash
cargo +nightly miri setup
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --locked --lib --all-features
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --locked --test audit_pipeline
```

See [MIRI.md](MIRI.md) for CI-equivalent `--skip` filters and **why** those tests are skipped (WAL I/O → `audit_pipeline`; concurrency → Loom; proptests → 10k job).

## 3. Module map

| Module | Security role | Start here |
|--------|---------------|------------|
| `kernel` | Decision logic | `prescribe`, `PolicySnapshot::validate` |
| `digest` | Canonical hashing | `policy_digest`, `input_digest`, `decision_digest` |
| `verify` | Replay + certificates | `verify_decision`, `verified_audit_bundle` |
| `proof` | Evidence packaging | `ProofEnvelope`, `seal` |
| `receipt` | Production evidence binding | `issue_receipt`, `verify_receipt`, `sign_receipt` |
| `persistence` | Crash recovery | `checkpoint_with_wal`, `recovery_plan`, `restore` |
| `wal` | Single-writer, anchored tamper-evident log | `WalWriter::anchor`, `verify_wal_keyed_against_anchor`, `replay_audited_wal_keyed` |
| `budget` | CAS conservation | `debit_if_available`, `verify_conservation`, `restore_from_snapshot` |
| `finance` | Ledger binding | `prove_conservation`, `ConservationProof`, `certify_snapshot`, `ledger_digest` |

## 4. Adversarial test inventory

| Category | Location | Count (approx.) |
|----------|----------|-----------------|
| Kernel proptest (ref ≡ optimized) | `src/kernel.rs` | 4 proptests |
| Policy validation | `src/kernel.rs` | 4 unit tests |
| WAL tamper / chain | `src/wal.rs` | 14+ unit, 2 proptests |
| Receipt claim/signature binding | `src/receipt.rs`, `tests/receipt_pipeline.rs` | 4+ tests |
| Budget concurrency + proptest | `src/budget.rs` | 20+ unit, 2 proptests |
| Budget Loom model tests | `tests/budget_loom.rs` | 8 Loom tests (`CALYBRIS_LOOM=1`, `loom-model`) |
| Verify / decode hex | `src/verify.rs` | 10+ unit, 1 proptest |
| Digest sensitivity | `src/digest.rs` | 3+ unit, 1 proptest |
| Finance conservation | `src/finance.rs` | 5 unit |
| E2E pipeline | `tests/audit_pipeline.rs` | 1 integration |
| Miri UB detection | CI `security.yml` + [MIRI.md](MIRI.md) | lib + audit_pipeline |

## 5. Policy API — production vs escape hatch

| Constructor | Validates? | When to use |
|-------------|------------|-------------|
| `PolicySnapshot::try_new` | Yes (catalog + BPS ranges) | **Production** policy load |
| `PolicySnapshot::new_unchecked` | No | Tests, fuzz fixtures, deliberate invalid-policy experiments |
| `PolicySnapshot::new` | No (deprecated) | Legacy; migrate to `try_new` or `new_unchecked` |

Never serve traffic from `new_unchecked` without a separate `validate()` call that you handle explicitly.

## 6. Caller integration contract

Calybris does **not** call `verify_decision` inside `prescribe` or budget hot paths. Your system must:

1. `prescribe` → obtain `KernelDecision`
2. **`verify_decision`** at audit boundary (before WAL append, before external export)
3. **`append_verified_audited`** — fail-closed WAL write (verifies before writing)
4. Optional: `prove_conservation` / `certify_ledger` / `ProofEnvelope`

Use `append_verified_audited` at production boundaries. `append_audited` (unverified) is an escape hatch for tests and pre-verified internal paths — not for production audit boundaries.

Skipping step 2 is a deployment choice, not a library default — document it in your threat model.

At untrusted Rust boundaries prefer `prescribe_checked`,
`prescribe_with_trace_checked`, or `prescribe_batch_checked`. The unchecked
hot-path methods require the caller to have already validated `KernelInput`.
Keyed WAL deployments must supply at least 32 bytes of HMAC key material.

For WAL completeness, persist `WalWriter::anchor()` outside the WAL and audit
with `verify_wal_against_anchor` / `verify_wal_keyed_against_anchor` or
`calybris-verify chain <wal> --anchor <anchor.json>`.
Use `save_wal_anchor` for file-fsynced atomic anchor replacement. Parent
directory fsync failures are propagated on Unix; portable Rust does not expose
the same directory-fsync guarantee on Windows.
Crash recovery should use `recovery_plan_against_anchor` or
`recovery_plan_keyed_against_anchor` when log completeness matters.
For large logs, use `visit_verified_wal` / `visit_verified_wal_keyed` to
process entries with constant memory.

## 7. External audit readiness (0.5.0)

This release is structured for third-party review:

- Documented invariants I1–I10 with test mapping
- Adversarial WAL/budget/verify tests + 10k proptest CI job
- Loom budget concurrency (7 scenarios)
- Miri UB pass on lib + E2E audit pipeline
- `THREAT_MODEL.md`, `SECURITY_INVARIANTS.md`, supply-chain (`cargo audit`, `cargo deny`)

**Not included:** formal proof, paid external audit report, or operational runbooks — engage a reviewer with the commands in section 2.

## 8. Out of scope for this crate

- Network APIs, TLS, authn/z
- Secret storage (you provide HMAC key bytes)
- Rate limiting, multi-region replication
- Paid third-party audit (bring your own reviewer)

## 9. Supporting documents

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, attackers, trust boundaries
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — formal properties + test mapping
- [MIRI.md](MIRI.md) — Miri setup, CI filters, Loom complement
- [../SECURITY.md](../SECURITY.md) — vulnerability disclosure

## 10. Suggested audit focus areas

1. **WAL keyed vs unkeyed** — confirm your deployment uses `open_keyed` / `read_verified_wal_keyed`.
2. **`read_wal` footgun** — grep your codebase for unverified reads.
3. **Overrun semantics** — failed overrun does not refund reserved amount (conservation by design).
4. **Digest version tags** — changing tags is a breaking audit event; document in changelog.
5. **Feature flags** — `default = ["wal"]`; minimal surface is `--no-default-features` (kernel + budget + verify only).

## 11. Reporting findings

See [SECURITY.md](../SECURITY.md). Include reproduction commands and affected invariant (I1–I10).
