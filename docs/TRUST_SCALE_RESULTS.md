# Cached Merkle scale measurements

Local measurement, 2026-09-26, Windows x86_64, Rust 1.85.0 release build.
Command: `cargo run --release --example trust_scale --features preview`.
Synthetic leaf payload is the little-endian u64 index; every measured proof
is verified after generation. Times are single-run wall clock observations,
not service latency guarantees or a comparison against another machine.

| Leaves | Build ms | Root µs | Inclusion µs | Consistency µs | Hash allocation bytes |
|---:|---:|---:|---:|---:|---:|
| 100,000 | 16.199 | 0.700 | 7.900 | 0.800 | 8,388,608 |
| 1,000,000 | 160.693 | 1.000 | 6.100 | 1.500 | 67,108,864 |
| 10,000,000 | 1743.543 | 2.000 | 7.700 | 2.500 | 1,073,741,696 |

Allocation counts Vec capacities for hash storage, excluding process/runtime
memory, and is not RSS. At 10 million leaves capacity growth costs about 1 GiB.
Construction is O(n); cached root/proof queries avoid rescanning all leaves.
The CLI still verifies the whole WAL when loading each snapshot, so end-to-end
checkpoint commands are O(n), not constant-time. A long-running service can
reuse the tree and append; durable cache persistence is not implemented here.

Cross-check tests compare every cached root and proof to the existing reference
functions for all historical prefixes and append boundaries. Stable kernel
decision code, digest/receipt formats and C ABI were not changed by this cache.
