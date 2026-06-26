# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
