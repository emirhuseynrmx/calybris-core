# Python bindings

## Rust core vs Python wrappers

| | Rust (`calybris-core`) | Python (`calybris`, `calybris_commerce`) |
|--|------------------------|------------------------------------------|
| **Role** | Decision kernel + proofs | Convenience wrappers over PyO3 |
| **Stability** | Stable (crates.io) | Experimental / pre-1.0 |
| **Who evaluates** | Rust `prescribe` | Same Rust code — Python never re-implements logic |
| **API changes** | Semver on crate | May change between minor releases until 1.0 |

**Mental model:** install Python for ergonomics and typed builders; trust the Rust
kernel for correctness. If you need a hard production contract, depend on
`calybris-core` directly (or pin Python wheels tightly).

## Packages

### `calybris`

Thin Pydantic v2 wrapper: `CalybrisEngine`, `PolicyBuilder`, `InputBuilder`,
`BudgetGuard`, audit helpers. Low-level types (`PolicySnapshot`, `KernelInput`)
are exposed for advanced callers.

```python
from calybris import CalybrisEngine, EngineConfig, InputBuilder, PolicyBuilder, ALL_REGIONS
from calybris.types import ModelSpec

config = EngineConfig(hard_risk_limit_bps=9_600, minimum_confidence_bps=5_500,
                      risk_penalty_multiplier_bps=3_500, latency_penalty_microunits_per_ms=2)
policy = (
    PolicyBuilder(config, policy_epoch=1, catalog_epoch=1)
    .add_model(ModelSpec(model_id=1, provider_id=0, quality_bps=9_000,
                         risk_ceiling_bps=9_500, p95_latency_ms=200, region_mask=ALL_REGIONS,
                         input_cost_microunits_per_million_tokens=250,
                         output_cost_microunits_per_million_tokens=1_000))
    .build()
)
request = (
    InputBuilder(request_sequence=1, requested_model_id=1)
    .tokens(input=1_000, output=500).budget(50_000_000).build()
)
engine = CalybrisEngine(policy)
decision = engine.prescribe(request)
bundle = engine.verified_audit_bundle(request, decision)
assert bundle.replay_valid
```

### `calybris_commerce`

**Adapter** with a larger surface: `SupplierPolicy`, `OrderInput`, `RouteResult`,
`EcomEngine.route_order` / `route_batch`, batch `trace_mode`, commerce-specific
units and masks. Still calls the same kernel underneath — not a second decision
engine.

Commerce encoding notes:

- `1 TL = 1_000_000 microunits`
- `sla_hours` / `max_delivery_hours` map to the kernel latency field (hours as the abstract SLA unit)
- `route_batch` returns `BatchRouteResult(results, rejection_histogram)`; default `trace_mode="compact"`
- `route_order(..., audit=True)` includes per-order rejection details; hard-limit rejects fall back to primary reason

See [ADAPTERS.md](ADAPTERS.md) for commerce examples.

## Build & install

```bash
pip install maturin pydantic
maturin develop --release          # editable local install
maturin build --release --out dist
python -m pip install dist/calybris-*.whl --force-reinstall
```

PyPI: `pip install calybris` (experimental).

## Test gate (Python)

```bash
python -m maturin build --release --out dist
python -m pip install dist/calybris-*.whl --force-reinstall
ruff check python/calybris python/calybris_commerce python/tests
mypy python/calybris python/calybris_commerce
pytest python/tests -q
```

Compatibility import: `calybris_core` remains for older code paths.