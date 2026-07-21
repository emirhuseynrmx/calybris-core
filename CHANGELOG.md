# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.7] - 2026-07-22

### Added
- Canonical trusted policy construction with stable catalog ordering, reserved
  rejection sentinel `model_id=0`, and a hard limit matching public decision counters.
- Full receipt verification that combines replay, claims integrity, trusted-key
  signature verification, state anchoring, and WAL anchoring in one fail-closed call.
- Recovery-aware ledger digests bind the exact WAL high watermark while preserving
  legacy digest identity for snapshots that carry no WAL claim.
- Linearizable budget snapshots during concurrent reserve, commit, release, top-up,
  and tenant mutations.
- Generation-based coordinated checkpoints: WAL fsync, immutable snapshot and anchor
  files, then an atomically committed manifest verified on recovery.
- Atomic JSON persistence uses collision-resistant, exclusively created temporary
  files and cleans up abandoned files on every error path, including concurrent writers.
- Policy-rotating audited WAL replay through a record-level `PolicyResolver`.
- `calybris-verify audit` accepts repeated `--policy` artifacts and resolves the
  exact policy epoch, catalog epoch, and digest for every WAL record.
- CLI `--json` verdicts use the JSON serializer so paths and OS errors containing
  control characters remain valid single-line JSON.
- Sync and async WAL verification hashes the original JSON `data` lexeme rather
  than a deserialized/re-serialized value, eliminating key-order, whitespace,
  and numeric-lexeme ambiguity.
- Async WAL writers reject oversized payloads before hashing or allocating the
  encoded entry, matching the synchronous writer's resource-exhaustion guard.
- Checked state-chain advancement that rejects step-counter exhaustion.
- Strict Python schemas: unknown-field rejection, strict types, bounded Rust-width
  integers, literal schema versions, and lowercase SHA-256 digest validation.

### Security
- Financial certificates recompute conservation from the frozen snapshot and no
  longer trust a caller-provided boolean claim.
- Python policy creation now uses the canonical trusted constructor.
- Commerce percentage-to-basis-point conversion uses decimal rounding instead of
  binary-float truncation.
- Added adversarial tests for catalog permutations, reserved sentinels, counter
  limits, receipt mutation, WAL watermark binding, checkpoint generations,
  concurrent snapshot isolation, policy rotation, and state-step overflow.

### Compatibility
- Existing CALY-PROOF v1 constructors and artifact surfaces remain available for
  replay compatibility. New integrations should use trusted policy construction,
  decision receipts, `verify_full`, and coordinated checkpoint APIs.
- The release is patch-semver compatible with 0.5.5; no existing public Rust item
  was removed or changed incompatibly.

## [0.5.5] - 2026-07-16

### Added
- **Decision receipts** (`receipt` module): canonical `calyrcp1\0` claims digest binds
  policy/input/decision digests to optional state and WAL evidence. The optional
  `calyrcs1\0` Ed25519 signature covers the complete receipt, not only the policy.
- **Anchored WAL verification**: `WalAnchor`, `WalWriter::anchor`,
  `verify_wal_against_anchor`, keyed and async equivalents, plus
  `calybris-verify --anchor`. A trusted external head detects clean suffix truncation.
- Cross-platform single-writer WAL lock shared by sync and async writers.
- File-identity writer locks cover canonical, symlink, and hardlink aliases
  without using a predictable shared temporary directory.
- Poisoned-writer fail-closed behavior after append/flush/sync I/O failures.
- Keyed WAL APIs reject HMAC keys shorter than 32 bytes.
- Anchored recovery planning rejects clean suffix truncation before restore.
- Fsync-backed atomic `save_wal_anchor` / `load_wal_anchor` persistence.
- Streaming verified WAL visitors keep CLI audit and recovery planning at
  constant memory with respect to log length.
- Sync and async WAL readers reject encoded entries larger than 16 MiB before
  JSON parsing, limiting single-line memory denial of service.
- Checked Rust decision APIs: `prescribe_checked`, `prescribe_with_trace_checked`,
  and `prescribe_batch_checked`.
- First-class Python production APIs for Ed25519-signed policy provenance,
  state trajectories, signed decision receipts, keyed audited WAL writes,
  trusted WAL anchors, anchored chain verification, and full WAL replay.
- Python adversarial coverage for untrusted keys, receipt mutation, duplicate
  writers, invalid metadata, weak HMAC keys, and clean suffix truncation.
- Release-only production torture benchmark covering a fully evaluated 64-model
  checked kernel, 25,000-step state trajectory, signed receipts, 25,000 keyed
  audited WAL records, trusted-anchor truncation rejection, contended budgets,
  and a 25,000-tenant ledger.

### Security
- Receipt issuance now returns `ReceiptError` for malformed or zero-position
  state/WAL anchors instead of panicking.
- Security artifact deserializers reject unknown JSON fields to prevent unsigned
  semantic-confusion claims beside verified data.
- Python artifact representations are UTF-8 and short-input safe for untrusted
  receipt, signed-policy, and WAL-anchor JSON.
- Python production APIs expose a stable `CalybrisError` hierarchy for receipt,
  provenance, WAL, persistence, state-trajectory, and artifact-validation failures.
- Receipt verification detects mutation of state step/digests, WAL sequence/hash,
  schema, signer identity, timestamp, key, or any decision-binding digest.
- Hex decoders reject malformed multi-byte UTF-8 without panicking.
- Updated `crossbeam-epoch` to 0.9.20, resolving RUSTSEC-2026-0204 in the benchmark
  dependency graph.
- Threat model now distinguishes internal hash-chain validation from externally
  anchored suffix-truncation detection.
- Semgrep Rust/Python/secrets/security-audit scanning is a blocking Security CI job.
- Bandit and pip-audit are blocking Python security CI jobs.
- Every third-party GitHub Action in CI, security, benchmark, and release
  workflows is pinned to an immutable 40-character commit SHA.
- Loom activation now uses the crate-scoped `CALYBRIS_LOOM` build switch plus
  the `loom-model` dependency feature instead of global `RUSTFLAGS`, preventing
  test-only cfg flags from leaking into third-party dependencies.

### Changed
- Version 0.5.5 for Rust and Python packages.
- Python package status moves from experimental/alpha to production-capable
  beta. Runtime integrity matches the Rust core; the public API remains pre-1.0.
- Release automation runs full preflight tests, validates distributions, emits
  SHA-256 checksums, creates GitHub build attestations, and publishes release assets.
- Python CI covers CPython 3.10 through 3.14.
- Production examples use checked input evaluation and decision receipts.
- Removed stale `finance_hft` and `hft_pretrade_guard` examples from the package.

## [0.5.0] - 2026-07-04

### Added
- **CALY-PROOF v1 specification** (`docs/CALY_PROOF.md`): byte-exact contract for every
  digest (policy/input/decision/ledger/state), the audit bundle binding, and the
  hash-chained WAL (unkeyed and HMAC-keyed) — so independent implementations can verify
  Calybris decision trails without running Calybris.
- **Golden vectors** (`tests/fixtures/caly_proof_v1.json` + `tests/golden_caly_proof.rs`):
  pinned byte-exact digests and WAL chain hashes. A vector mismatch is a breaking
  proof-format change requiring a new digest tag, never a silent re-pin.
- **`calybris-verify` auditor CLI** (`cargo install calybris-core --features wal`):
  `chain` (tamper/truncation detection), `audit` (per-entry digest checks; with
  `--policy` a full kernel replay of every decision), `policy` (canonical digest of a
  policy artifact). Exit codes 0/1/2; end-to-end tests cover tamper and wrong-policy
  rejection.
- **Stateful decision proofs** (`state` module): `StateChain` tracks a domain-state
  digest trajectory; `stateful_audit_bundle` (fail-closed) records
  `state_digest_before/after` per decision; `verify_trajectory` rejects dropped,
  reordered, or forged transitions. New `calystt1\0` digest tag.
- **Signed policy provenance** (`provenance` feature, Ed25519): `sign_policy` /
  `verify_signed_policy` / `verify_signed_policy_with_key` bind a policy digest to an
  accountable signer and timestamp with domain separation (`calysig1\0`); signatures are
  non-transferable across policies, signers, and timestamps.
- WASM portability: the verification path compiles for `wasm32-unknown-unknown` with
  `--no-default-features`.
- **Python cross-language golden test** (`python/tests/test_golden_caly_proof.py`): the binding
  reads the *same* `tests/fixtures/caly_proof_v1.json` and reproduces the Rust reference's
  policy/input/decision digests byte for byte through the PyO3 surface — a runnable trust artifact
  that also catches field-marshalling bugs in the binding.
- **Conformance vector suite** (`tests/fixtures/caly_proof_conformance_v1.json`): one shared policy
  with inputs exercising every decision outcome (execute, substitute, and each rejection reason),
  pinned byte-exactly and asserted by both the Rust (`tests/conformance_caly_proof.rs`) and Python
  (`python/tests/test_conformance_caly_proof.py`) suites — the contract a third-party
  reimplementation (Go, TypeScript, browser) proves itself against.
- **Decision certificates** (`certificate` module): bind an audit bundle + optional state
  trajectory + WAL position + Ed25519 signer into one canonically-serializable, fail-closed
  envelope — the notarized receipt for a single decision. `issue_certificate` /
  `verify_certificate` (digests + replay, always available, incl. wasm) and
  `verify_certificate_signature` (feature `provenance`).
- **`calybris-verify --json`**: one-line machine-readable verdict on every verb for CI/compliance
  pipelines.
- **THREAT_MODEL.md**: documented what the proof system guarantees and — explicitly — what it does
  not (no confidentiality, does not prove the policy was good, cannot vouch for unseen inputs,
  caller key custody, caller-supplied timestamps), plus the certificate/signature-splicer attacker.

### Python packaging
- **abi3 wheels** (`abi3-py310`): the binding builds against the CPython stable ABI, so one
  wheel per platform covers Python 3.10+ — the release matrix drops from ~16 wheels to 5 and
  survives future CPython releases without a rebuild.
- **Type stubs** (`python/calybris/_core.pyi`): full signatures for the PyO3 classes
  (`KernelModel`, `KernelInput`, `KernelDecision`, `PolicySnapshot`, `BudgetEngine`) and module
  constants, so mypy and IDEs see the Rust-backed types. Writing the stubs surfaced and fixed two
  real type-precision gaps (`prescribe_with_trace` returns a tuple; `verify_status` returns a
  `Literal`).
- **Release workflow** (`.github/workflows/release.yml`): `maturin-action` builds the abi3 wheel
  matrix (Linux x86_64/aarch64, macOS x86_64/arm64, Windows) plus an sdist and publishes to PyPI
  via Trusted Publishing (OIDC, no token); a repository guard ensures only the canonical public
  repo can publish.
- Kernel-only crate artifact: `python/` and `pyproject.toml` are excluded from the crates.io
  package (78 → 59 files).

### Fixed
- CALY-PROOF §4 now shows the audit bundle `schema_version` exactly as the code emits it
  (`calybris.audit.v1`); the spec and implementation must not disagree on a proof contract.
- `SECURITY.md`, `.github/SECURITY.md`, and `docs/AUDIT_GUIDE.md` updated to the 0.5.x support line
  (was stale at 0.4.x / 0.4.5).
- Examples (`quickstart`, `llm_routing`, `pretrade_guard`, `replay_audit`) now use the fail-closed
  `verified_audit_bundle` / `append_verified_audited` path; the non-verifying `audit_bundle` is
  documented as the escape hatch, not the demonstrated default.
- Miri CI skips `async_wal::` (Tokio + filesystem tests are outside Miri's UB-detection scope).
- Added `docs/BENCHMARKS.md`: provenance and a reproduction recipe for the throughput figure,
  plus measured proof-surface costs (digests, certificates, Ed25519) via a new `proof_bench`.
- Added `docs/KEY_MANAGEMENT.md`: custody and rotation guidance for the HMAC WAL key and the
  Ed25519 policy signing key (the library holds neither).
- Golden-locked the two remaining proof tags: `tests/conformance_proof_surfaces.rs` pins the
  `calystt1` state digest and the `calysig1` Ed25519 signature — the signature vector doubles as a
  cross-platform determinism check.

### Changed
- `serde_json` now enables `float_roundtrip`: WAL chain verification re-serializes
  parsed payloads, and default f64 parsing can lose the final ulp on 17-significant-digit
  values, breaking byte-stable hashing for float-bearing payloads (CALY-PROOF §5.1).
- `full` feature now includes `provenance`.
- Version 0.5.0 (new public modules and binary).

## [0.4.5] - 2026-07-01

### Added
- Python bindings under `bindings/python`, built with PyO3 and maturin.
- Python API for `KernelModel`, `KernelInput`, `PolicySnapshot`, `KernelDecision`, batch prescription, replay verification, audit bundles, and policy fingerprints.
- `calybris_commerce` preview adapter for deterministic supplier / fulfillment routing.
- Typed commerce models: `SupplierSpec`, `OrderInput`, `RouteResult`, and `SupplierPolicy`.
- Batch commerce routing with optional audit bundles (`EcomEngine.route_batch`).
- `BatchRouteResult` wrapper for batch routing results with optional batch-level `rejection_histogram`.
- `trace_mode="summary"` for batch-level rejection reason counts (`trace_mode="compact"` is the default).
- Commerce property tests for determinism, budget safety, risk gates, SLA gates, and tamper detection.
- Workspace-level packaging metadata (`pyproject.toml`) so the binding can be built as a Python wheel without moving the Rust kernel.
- CI coverage for the Python binding crate.

### Changed
- `calybris_commerce.EcomEngine.route_batch` now returns `BatchRouteResult` instead of `list[RouteResult]`.
- Added `trace_mode="compact" | "summary"` for batch routing.
- Default compact mode keeps `rejection_histogram` empty and exposes only the primary rejection reason per rejected order.
- Renamed examples `hft_pretrade_guard` → `pretrade_guard`, `finance_hft` → `budget_guard` (no HFT positioning).
- README slimmed to quickstart + deep-dive links; adapter/Python detail moved to `docs/ADAPTERS.md` and `docs/PYTHON.md`.
- README reframed around the proof-carrying kernel; commerce/LLM/pre-trade documented as adapters.
- Security docs aligned (`0.4.x` supported); audit guide updated to 0.4.5.
- Core crate stays the default workspace member and keeps `#![forbid(unsafe_code)]`; PyO3 lives in a separate adapter crate.
- Version bump to 0.4.5.

## [0.4.0] - 2026-06-29

### Added
- `config` module: `EngineConfig` with builder pattern, validation, and safe defaults for latency penalty, risk limits, exposure caps, WAL sync, catalog size
- `builder` module: `InputBuilder`, `ModelBuilder`, `PolicyBuilder` — hard-to-misuse constructors with safe defaults
- `async_wal` module (feature `async`): Tokio-based non-blocking WAL with HMAC-SHA256, chain validation, configurable sync-on-append
- `persistence` module: atomic snapshot save/load (`checkpoint`, `restore`), crash `recovery_plan` with WAL entry counting
- `instrument` module (feature `observability`): structured `tracing` spans for `prescribe`, `verify`, budget ops, WAL; `EngineMetrics` struct for Prometheus/OTel export
- Feature flags: `async` (tokio WAL), `observability` (tracing), `full` (wal + async + observability)
- `production_gateway` example: full pipeline demo with 6 models, 3 tenants, config, builders, WAL, checkpoint, crash recovery
- Proptest coverage for config validation and builder→prescribe roundtrips
- 145+ tests passing (was 106)

### Changed
- Version bump to 0.4.0 (new public modules = minor version)
- README: feature flag table, builder ergonomics section, persistence/recovery docs, 136 test count, 91.6% coverage

## [0.3.12] - 2026-06-28

### Changed
- WAL and audit pipeline tests use `tempfile` crate instead of PID-based paths in `target/`
- Documented `latency_penalty_microunits_per_ms` dynamic overflow guard (i128 fallback via `all_latencies_fit`)
- Documented `reject()` intentionally empty `RejectionHistogram` on hard-limit rejections

### Added
- `tempfile` dev-dependency for proper test isolation

## [0.3.11] - 2026-06-28

### Added
- `KernelDecision::{is_executable,is_requested_execution,is_substitution,is_rejected}` helpers.
- `verify::VerifyError` compact error wrapper for fail-closed verification helpers.
- `verify::verified_audit_bundle`, which returns an audit bundle only after exact replay verification.
- `wal::WalWriter::append_verified_audited` and `wal::append_verified_audited`, fail-closed WAL append helpers for audited deployments.

### Changed
- README now includes a short "when to use it" section to make the crate boundary clearer on crates.io.
- GitHub Actions now use `actions/checkout@v7` and `actions/cache@v6`.
- Quickstart example header now uses ASCII punctuation for cleaner rustdoc rendering across terminals.

## [0.3.10] - 2026-06-27

### Fixed
- `top_up_tenant` holds `initial_microcents` lock through read → credit → write (fixes concurrent lost-update breaking I6)
- `conservation_status_for_snapshot` uses checked per-tenant sums (adversarial `BudgetSnapshot` no longer panics/wraps)
- `snapshot_totals` uses `i128` checked sums instead of `saturating_add` — overflow surfaces as `ConservationStatus::AggregateOverflow` / `aggregate_totals_representable: false` on certificates
- Rustdoc intra-doc links now build without broken-link warnings
- `WalWriter::append` advances sequence/hash state only after serialization and write succeed
- `ledger_digest` sorts tenants internally, so raw `BudgetSnapshot` order cannot change the canonical digest
- GitHub Actions use stable `actions/checkout@v4` and `actions/cache@v4`

### Changed
- Module docs: lock-order comment softened to scoped metadata locking + exclusive restore contract
- README separates local examples from dependency installation (`git clone` vs `cargo add`)
- Launch positioning avoids framework/exchange claims and keeps HFT language out of the top-level pitch

### Added
- Loom test `concurrent_two_topups_preserve_conservation_loom`
- `ConservationProof::aggregate_totals_representable`, `FinancialCertificate::aggregate_totals_representable`
- `BudgetEngine::try_total_committed_microcents`
- Regression tests for WAL append failure state, raw ledger ordering, and aggregate committed overflow

## [0.3.9] - 2026-06-26

### Changed
- `counterfactual_utility` delegates to `PolicySnapshot::utility_for_model` (true per-model evaluation)
- `docs/MIRI.md`: "Why some tests are skipped" — explicit Miri vs Loom vs proptest division

### Fixed
- `commit` holds `committed_microcents` lock from overflow check through final write (no panic under concurrent commits)
- `try_reserve` uses checked reserved-total increment; `BudgetReservation::Overflow` on `i64` saturation
- `rotate_certificate_baseline` monotonic — stale concurrent certs cannot regress baseline
- `restore_from_snapshot` rejects duplicate `tenant_id` in snapshot
- `top_up_tenant` / `commit` return `Overflow` on `i64` saturation (checked arithmetic)
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
