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
```

Extended property testing (recommended before release):

```bash
PROPTEST_CASES=10000 cargo test --locked --all-features
```

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
| Budget Loom model tests | `tests/budget_loom.rs` | 6 Loom tests (`RUSTFLAGS='--cfg loom'`) |
| Verify / decode hex | `src/verify.rs` | 10+ unit, 1 proptest |
| Digest sensitivity | `src/digest.rs` | 3+ unit, 1 proptest |
| Finance conservation | `src/finance.rs` | 5 unit |
| E2E pipeline | `tests/audit_pipeline.rs` | 1 integration |

## 5. Out of scope for this crate

- Network APIs, TLS, authn/z
- Secret storage (you provide HMAC key bytes)
- Rate limiting, multi-region replication
- Miri — roadmap item (Loom + `cfg(loom)` sync primitives cover budget concurrency in CI)

## 6. Supporting documents

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, attackers, trust boundaries
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — formal properties + test mapping
- [../SECURITY.md](../SECURITY.md) — vulnerability disclosure

## 7. Suggested audit focus areas

1. **WAL keyed vs unkeyed** — confirm your deployment uses `open_keyed` / `read_verified_wal_keyed`.
2. **`read_wal` footgun** — grep your codebase for unverified reads.
3. **Overrun semantics** — failed overrun does not refund reserved amount (conservation by design).
4. **Digest version tags** — changing tags is a breaking audit event; document in changelog.
5. **Feature flags** — `default = ["wal"]`; minimal surface is `--no-default-features` (kernel + budget + verify only).

## 8. Reporting findings

See [SECURITY.md](../SECURITY.md). Include reproduction commands and affected invariant (I1–I8).