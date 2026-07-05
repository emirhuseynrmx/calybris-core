# Adapters & examples

Calybris exposes one kernel API. The rows below are **reference mappings** —
demos and integration patterns, not separate products.

## LLM / model routing

Models are kernel candidates; requests carry budget, risk, quality, latency,
provider, region, and capability constraints.

```bash
cargo run --example llm_routing
python bindings/python/examples/quickstart.py
python bindings/python/examples/batch_routing.py
```

The Rust example covers substitution under budget pressure, hard-risk rejection,
per-constraint rejection histograms, and fail-closed audited WAL writes.

## Pre-trade guardrails

Two layers before a child order leaves your control plane:

1. **Policy gate** — route to an eligible venue (risk, latency, quality, fees).
2. **Exposure gate** — reserve notional; commit routing fees on admit.

```bash
cargo run --example pretrade_guard
python bindings/python/examples/pretrade_budget_guard.py
```

`pretrade_guard` walks a VWAP desk scenario: hard-risk block, venue failover,
exposure-cap block — with replay-checked audit bundles per child order.
`pretrade_budget_guard.py` covers the exposure layer via `BudgetGuard`.

## Commerce / supplier routing

`calybris_commerce` maps suppliers → kernel models and orders → kernel inputs.
It does not track stock or call carrier APIs.

```python
from calybris_commerce import (
    CAP_FRAGILE,
    EcomEngine,
    OrderInput,
    REGION_TR_IST,
    SupplierPolicy,
    SupplierSpec,
)

engine = (
    SupplierPolicy(policy_epoch=1, catalog_epoch=42)
    .return_risk_limit(max_pct=35.0)
    .confidence_floor(min_pct=60.0)
    .add_supplier(SupplierSpec(
        supplier_id=101,
        name="Same-Day",
        reliability_pct=99.0,
        risk_tolerance_pct=45.0,
        sla_hours=8,
        shipping_cost_microunits=7_500_000,
        capabilities=CAP_FRAGILE,
        region_mask=REGION_TR_IST,
    ))
    .build_engine()
)

order = OrderInput(
    order_id="NM-10001",
    order_sequence=10001,
    order_value_microunits=180_000_000,
    budget_limit_microunits=9_000_000,
    return_risk_pct=8.5,
    confidence_pct=91.0,
    required_capabilities=CAP_FRAGILE,
    required_regions=REGION_TR_IST,
    max_delivery_hours=24,
)

result = engine.route_order(order)
assert result.audit_bundle.replay_valid
```

Batch routing returns `BatchRouteResult` — use `.results`:

```python
batch = engine.route_batch(orders, audit=False, trace_mode="summary")
for row in batch.results:
    print(row.status, row.chosen_supplier_id)
print(batch.rejection_histogram)
```

Larger scenarios:

```bash
python bindings/python/examples/orion_market.py
python bindings/python/examples/swiftbite_routing.py
python bindings/python/examples/novamart_benchmark.py --orders 50000
```

## All Rust examples

```bash
cargo run --example quickstart
cargo run --example production_gateway
cargo run --example llm_routing
cargo run --example replay_audit
cargo run --example pretrade_guard
cargo run --example budget_guard
cargo run --example route_decision
cargo run --example simple_kernel
cargo run --example verify_wal      # requires wal feature
```

## Rust kernel (direct API)

```rust
use calybris_core::kernel::*;
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};

let policy = PolicySnapshot::try_new(/* epoch, limits, models */)?;
let input = KernelInput { /* sequence, tokens, constraints */ };
let decision = policy.prescribe(input);

assert_eq!(verify_decision(&policy, input, &decision), VerifyResult::Valid);
assert!(audit_bundle(&policy, input, &decision).replay_valid);
```

See `examples/quickstart.rs` and [docs.rs](https://docs.rs/calybris-core).

## Feature flags

| Feature | Adds |
|---------|------|
| `wal` | Hash-chained WAL, serde, HMAC (default) |
| `async` | Tokio async WAL |
| `observability` | `tracing` spans |
| `full` | All optional runtime features |

```bash
cargo add calybris-core --features full
cargo add calybris-core --no-default-features
```