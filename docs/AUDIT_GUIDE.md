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
RUSTFLAGS='--cfg loom' LOOM_MAX_PREEMPTIONS=3 cargo test --locked --test budget_loom
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
| `verify` | Replay + certificates | `verify_decision`, `audit_bundle` |
| `wal` | Tamper-evident log | `validate_chain_inner`, `replay_audited_wal_keyed` |
| `budget` | CAS conservation | `debit_if_available`, `verify_conservation`, `restore_from_snapshot` |
| `finance` | Ledger binding | `prove_conservation`, `ConservationProof`, `certify_snapshot`, `ledger_digest` |

## 4. Adversarial test inventory

| Category | Location | Count (approx.) |
|----------|----------|-----------------|
| Kernel proptest (ref ≡ optimized) | `src/kernel.rs` | 4 proptests |
| Policy validation | `src/kernel.rs` | 4 unit tests |
| WAL tamper / chain | `src/wal.rs` | 14+ unit, 2 proptests |
| Budget concurrency + proptest | `src/budget.rs` | 20+ unit, 2 proptests |
| Budget Loom model tests | `tests/budget_loom.rs` | 7 Loom tests (`RUSTFLAGS='--cfg loom'`) |
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
3. Optional: `audit_bundle` + `append_audited` + `prove_conservation` / `certify_ledger`

Skipping step 2 is a deployment choice, not a library default — document it in your threat model.

## 7. External audit readiness (0.3.9)

This release is structured for third-party review:

- Documented invariants I1–I8 with test mapping
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

See [SECURITY.md](../SECURITY.md). Include reproduction commands and affected invariant (I1–I8).
