# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.9] - 2026-06-26

### Fixed
- `THREAT_MODEL` / `SECURITY.md`: Loom/Miri residual risk wording aligned with CI reality
- `restore_from_snapshot` exclusive-recovery contract + rejects ghost reservations, negatives, unbalanced snapshots
- `certify_ledger` binds `committed_since_last_certificate` to frozen snapshot total via `rotate_certificate_baseline`
- `ensure_tenant` rejects negative budgets in release builds
- Conservation docs: holds after completed operations, not mid-flight snapshots (I6)
- `prove_conservation` / `certify_ledger` bind digest, conservation status, and version to one frozen snapshot
- Concurrent exposure cap enforced via per-tenant `AtomicI64` reserved totals (CAS)
- `lib.rs` / `Cargo.toml` positioning: pre-trade primitives, not exchange/HFT-gateway claims

### Added
- Miri CI job (nightly) — UB detection on lib tests + `audit_pipeline` ([docs/MIRI.md](docs/MIRI.md))
- Audit guide: policy `new_unchecked` escape hatch, caller `verify_decision` contract, external audit readiness checklist
- `BudgetSnapshot::version` — epoch embedded in snapshot and ledger digest
- `conservation_status_for_snapshot` — audit path without extra engine reads
- `PolicySnapshot::new_unchecked`, BPS range validation in `validate()` (`MAX_BPS`, `MAX_RISK_PENALTY_MULTIPLIER_BPS`)
- Loom sync primitives in budget core (`src/sync.rs` under `cfg(loom)`)
- Loom tests: exposure cap concurrent, snapshot restore after mutation
- README integration contract (`verify_decision` at audit boundaries)

### Changed
- `certify_snapshot` takes frozen snapshot only (version from `snapshot.version`)
- `ledger_digest` includes snapshot version
- `PolicySnapshot::new` deprecated — use `try_new` or `new_unchecked`
- `hft_pretrade_guard` separates exposure hold vs routing fee commit

## [0.3.8] - 2026-06-26

### Added
- `ConservationProof` — structured `prove_conservation` result with digest + totals + snapshot version
- `BudgetEngine::restore_from_snapshot`, `set_max_reserved_microcents`, exposure limit on `try_reserve`
- `certify_snapshot` — immutable financial certificate from frozen `BudgetSnapshot`
- Enriched `FinancialCertificate`: snapshot version, totals, `committed_since_last_certificate`
- Aggressive budget proptest (`aggressive_mixed_ops_maintain_conservation`)
- Loom concurrency tests (`tests/budget_loom.rs`) + CI job
- Expanded `budget_bench`: contention, top-up, snapshot/digest at scale

### Changed
- `prove_conservation` returns `Result<ConservationProof, ConservationStatus>` (was `Result<String, _>`)

## [0.3.7] - 2026-06-26

### Fixed
- Pin `criterion` to 0.5 (0.8 requires rustc 1.86; MSRV stays 1.85)
- Dependabot: ignore all `criterion` bumps until MSRV ≥ 1.86

### Changed
- GitHub Actions: `actions/checkout@v7`, `actions/cache@v6`

## [0.3.6] - 2026-06-26

### Changed
- `sha2` 0.11 + `hmac` 0.13 (must bump together — `digest` 0.11 API)
- `criterion` 0.8 (dev/bench only)
- Dependabot: group `sha2`/`hmac`/`subtle`; ignore criterion major auto-bumps

### Fixed
- `hmac::KeyInit` import for `new_from_slice` under hmac 0.13

## [0.3.5] - 2026-06-26

### Fixed
- `cargo-deny` CI: use `deny.toml` (not `cargo-deny.toml`) with SPDX allow list for MIT/Apache-2.0/Unlicense deps

### Added
- Adversarial tests: WAL chain attacks (duplicate sequence, hash mismatch, truncation, JSON reorder), budget conservation proptest, `PolicyError` coverage, `decode_hex32` fuzz, digest sensitivity
- Integration test `tests/audit_pipeline.rs` — end-to-end prescribe → WAL → replay → conservation
- Audit package: `docs/THREAT_MODEL.md`, `docs/SECURITY_INVARIANTS.md`, `docs/AUDIT_GUIDE.md`
- Security CI: `cargo audit`, `cargo deny`, Dependabot, weekly 10k-case proptest job

### Changed
- Expanded `SECURITY.md` with scope, supported versions, audit commands, known limitations

## [0.3.4] - 2026-06-26

### Changed
- MSRV raised to **1.85** (transitive deps such as `indexmap` 2.14 / `clap_lex` 1.1 use edition2024)
- CI split into two jobs: `MSRV (1.85.0)` and `Stable`

## [0.3.3] - 2026-06-26

### Fixed
- Pin `indexmap` to 2.13 in `Cargo.lock` (superseded by MSRV 1.85 in 0.3.4)
- CI uses `--locked` for reproducible builds

### Added
- `top_up_tenant()` — add funds without resetting lifetime `committed_microcents`
- `TopUpResult` enum
- Examples: `llm_routing`, `hft_pretrade_guard` (canonical use-case demos)
- CI: Rust 1.83.0 + stable matrix, `--no-default-features` test, `cargo doc`, all examples

### Changed
- README repositioned: proof-carrying decision core (LLM routing + pre-trade guard)
- Documented `committed_microcents` as lifetime cumulative spend
- Documented overrun fail-closed behavior and `ensure_tenant` vs `top_up_tenant`
- `WalWriter<T>` bound relaxed to `T: Serialize` (no unnecessary `Clone`)

## [0.3.2] - 2026-06-26

### Fixed
- Public `DigestDecodeError` replaces private `hex::FromHexError` on `AuditBundle` decode APIs
- `replay_audited_wal_keyed` returns `Err` on input or decision digest mismatch (fail-closed audit)
- `route_decision` example no longer swallows WAL append errors

### Changed
- WAL module docs: "crash-detecting" instead of "crash-recoverable"
- Feature split: `default = ["wal"]`, `wal = ["serde", "hmac", "subtle"]` — kernel-only via `--no-default-features`
- README Quick Start is fully runnable (`examples/quickstart.rs`)

## [0.3.1] - 2026-06-26

### Added
- `digest` module: versioned canonical SHA-256 digests for policy, input, decision, ledger
- `AuditBundle` with policy + input + decision digest binding and full replay flag
- `verify_decision` now checks complete `KernelDecision` equality and decision digest
- `counterfactual_utility()` for alternative model analysis
- `finance` module: `ledger_digest`, `FinancialCertificate`, `prove_conservation`
- `BudgetEngine::snapshot()`, `verify_conservation()`, `initial/committed/reserved_microcents`
- `TenantLedger`, `BudgetSnapshot`, `ConservationStatus` types
- `PolicySnapshot::validate()`, `try_new()`, `prescribe_batch()`, `prescribe_with_trace()`
- `RejectionHistogram`, `DecisionTrace`, `PolicyError`
- WAL `AuditedRecord`, `append_audited`, `replay_audited_wal` / `replay_audited_wal_keyed`
- Examples: `replay_audit`, `finance_hft`
- Benchmark: `budget_bench` (reserve / reserve+commit latency)

### Changed
- `CorrectnessCertificate` includes input and decision fingerprints
- `snapshot_fingerprint` now uses canonical sorted policy digest
- Budget engine tracks per-tenant initial and committed microcents for conservation proofs

## [0.3.0] - 2026-06-26

### Added
- `verify` module: `verify_decision`, `snapshot_fingerprint`, `certify_decision`
- `Display` for `KernelAction` and `KernelReason`
- Optional `serde` feature (default on); WAL behind `serde`
- `tenant_count()`, `active_reservations()`, `entry_count()`

## [0.2.1] - 2026-06-26

### Changed
- WAL `append()` serializes data once instead of twice (~2x faster)
- `compute_hash` returns `Result` instead of panicking on invalid HMAC key
- Comprehensive rustdoc on every public struct, enum, field, and function
- Budget `ReservationRecord` derives `Debug`
- `debug_assert` on negative initial budget in `ensure_tenant`

### Fixed
- `hash_entry` moved to `#[cfg(test)]` (was dead code in production)
- `write!` with trailing newline replaced by `writeln!`

## [0.2.0] - 2026-06-26

### Added
- HMAC-SHA256 keyed WAL mode (`open_keyed`, `verify_wal_keyed`, `read_verified_wal_keyed`)
- Constant-time hash comparison using `subtle` crate
- Criterion benchmarks: prescribe (22 models), model scaling (4-64), reject path
- `flush_and_sync()` method for batched WAL durability
- `MAX_PROVIDER_ID` constant (replaces magic number 64)
- `#[must_use]` on `WalWriter::append`
- `thiserror` derive for WAL error types
- Proptest fuzz: random data + random lengths WAL roundtrip
- Doc comments on kernel, WAL, and budget public APIs
- Banner image for README

### Changed
- WAL `append()` no longer calls `flush()` on every write (hot path optimization)
- Budget engine uses `HashMap<Arc<str>, _>` instead of `HashMap<String, _>`
- `prescribe_reference` now rejects `provider_id > MAX_PROVIDER_ID` unconditionally
- MSRV set to 1.83
- Release profile: LTO enabled, codegen-units=1
- Benchmarks migrated from manual timing to Criterion

### Fixed
- WAL chain validation: replaced fragile raw substring extraction with `serde_json` `preserve_order`
- `hash_entry` no longer uses `unwrap_or_default()` — errors propagate properly
- `prescribe_reference` provider_id >= 64 asymmetry with optimized `prescribe`

## [0.1.0] - 2026-06-24

### Added
- Integer-only prescriptive decision kernel (8.6M decisions/sec, 22 models)
- 11 constraint gates: risk, confidence, quality, budget, latency, capability, provider, region, cost, utility, optimality
- SHA-256 hash-chained write-ahead log (generic over any `Serialize + Deserialize` type)
- CAS atomic budget engine with conservation invariant
- Proptest property-based verification (kernel + cost + scaled terms)
- 30 tests including concurrency stress (100 threads)
- Two examples: `simple_kernel`, `verify_wal`
- Kernel benchmark (1M iterations)
- Apache-2.0 license
- `#![forbid(unsafe_code)]`
