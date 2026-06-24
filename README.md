# Calybris Core

[![CI](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml/badge.svg)](https://github.com/emirhuseynrmx/calybris-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-zero%20unsafe-orange)]()

**Open-source deterministic proof-carrying decision core behind [Calybris Engine](https://emirhuseyin.tech/engine).**

This crate contains the core decision infrastructure. The full engine (adaptive routing, policy evolution, GOVERIS product) is proprietary.

## Quick Start

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
cargo test
cargo run --example simple_kernel
cargo run --example verify_wal
```

## Modules

### `kernel.rs` — Integer Decision Kernel

Allocation-free prescriptive decision kernel. No floating-point in the hot path.

- 8.6M decisions/sec on a single core
- 11 constraint gates (risk, confidence, quality, budget, latency, capability, provider, region)
- Utility-maximizing selection with counterfactual tracking
- Zero heap allocation per decision

### `budget.rs` — Atomic Budget Engine

Per-tenant budget management. All values in i64 microcents (1 cent = 1,000,000 microcents).

- CAS atomic reservation: Reserve → Commit → Release
- Conservation invariant: `remaining + reserved + committed = initial`
- CAS-based balance updates; metadata maps are mutex-protected

### `wal.rs` — Hash-Chained Write-Ahead Log

Generic, tamper-evident decision log. Each entry includes the SHA-256 hash of the previous entry.

- Generic over any `Serialize + Deserialize` type
- Chain validated on open — refuses to continue on broken chain
- Tamper detection: modify any record, chain breaks
- fsync support for crash durability
- For adversarial tamper evidence, persist or sign the final head hash outside the WAL file

## Benchmarks

| Metric | Value |
|--------|-------|
| Kernel throughput | 8.6M decisions/sec |
| HTTP gateway (full engine) | 6,084 req/sec |
| HTTP p99 (full engine) | 42ms |
| Real data (full engine) | 1.1M decisions, 0 runtime failures |

Public core includes 30 default-running tests, including property tests, plus 1 ignored release-only latency guard. The full proprietary engine has 336 tests (40% adversarial) against the complete stack.

Full methodology: [emirhuseyin.tech/engine/methodology.html](https://emirhuseyin.tech/engine/methodology.html)

## Examples

**Simple kernel decision:**
```rust
use calybris_core::kernel::*;

let snapshot = PolicySnapshot::new(1, 1, 9600, 5500, 3500, 0, models);
let decision = snapshot.prescribe(input);
println!("{:?} → model {}", decision.action, decision.selected_model_id);
```

**Hash-chained WAL:**
```rust
use calybris_core::wal::WalWriter;

let mut wal = WalWriter::open(&path)?;
let entry = wal.append(my_decision)?;
wal.sync()?;
// entry.entry_hash chains to previous — tamper-evident
```

**Budget reservation:**
```rust
use calybris_core::budget::BudgetEngine;

let engine = BudgetEngine::new();
engine.ensure_tenant("team-a", 100_000_000); // 100 cents in microcents
let (res, id) = engine.try_reserve("team-a", 25_000_000);
engine.commit(id.unwrap(), 20_000_000); // surplus refunded
```

## What's NOT included (proprietary)

- Adaptive routing (Thompson Sampling)
- Policy evolution (counterfactual replay)
- GBM prompt model (compiled to Rust)
- Quality tracker + warm-start floors
- Enterprise correctness certificate + optimality proof package
- GOVERIS HTTP gateway + audit reports

Available through [GOVERIS](https://emirhuseyin.tech/goveris/).

## Links

- [Calybris Engine](https://emirhuseyin.tech/engine) — full technical overview
- [GOVERIS Product](https://emirhuseyin.tech/goveris/) — AI cost governance
- [Benchmark Methodology](https://emirhuseyin.tech/engine/methodology.html)

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contact

emirhuseyininci@gmail.com

---

# 🇹🇷 Türkçe

## Calybris Core Nedir?

[Calybris Engine](https://emirhuseyin.tech/engine)'in açık kaynak karar çekirdeği.

```bash
git clone https://github.com/emirhuseynrmx/calybris-core.git
cd calybris-core
cargo test
```

### Modüller

- **kernel.rs** — Tam sayı karar kernel'i, 8.6M/s, sıfır bellek tahsisi
- **budget.rs** — CAS atomik bütçe motoru, i64 mikrosent, korunum kanıtlı
- **wal.rs** — SHA-256 hash-zincirli WAL, kurcalamaya dayanıklı, jenerik

### Dahil Olmayan (Tescilli)

- Adaptif yönlendirme (Thompson Sampling)
- Politika evrimi (counterfactual replay)
- GBM prompt modeli
- GOVERIS HTTP gateway + denetim raporları

Bu bileşenler [GOVERIS](https://emirhuseyin.tech/goveris/) üzerinden sunulmaktadır.
