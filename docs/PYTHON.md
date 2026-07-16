# Python bindings

## Rust core vs Python

| | Rust (`calybris-core`) | Python (`calybris`, `calybris_commerce`) |
|--|------------------------|------------------------------------------|
| **Role** | Decision kernel + proofs | Convenience wrappers over PyO3 |
| **Runtime integrity** | Production | Production-capable core binding; same Rust implementation |
| **API stability** | Stable (crates.io) | Pre-1.0; pin minor versions |
| **Who evaluates** | Rust `prescribe` | Same Rust code — Python never re-implements logic |
| **Security surfaces** | Decisions, proofs, receipts, provenance, state, WAL | Same surfaces exposed through PyO3 |

**Mental model:** Python is a first-class integration surface over the Rust
trust boundary, not a second implementation. The wheel remains pre-1.0 for API
evolution, so pin `calybris==0.5.5` in production.

Production exceptions share one stable base:

```python
from calybris import CalybrisError, ReceiptError

try:
    receipt.verify_signature(trusted_public_key)
except ReceiptError as exc:
    ...
except CalybrisError as exc:
    ...
```

Specialized classes include `ArtifactValidationError`,
`DecisionVerificationError`, `ReceiptError`, `ProvenanceError`, `WalError`,
`PersistenceError`, and `StateTrajectoryError`.

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

## Production audit path

```python
from calybris import (
    AuditedWal,
    CalybrisEngine,
    ReceiptState,
    StateChain,
    public_key_from_signing_key,
    verify_audited_wal,
)

engine = CalybrisEngine(policy)
decision = engine.prescribe(request)

state_chain = StateChain.genesis(initial_state_bytes)
transition = state_chain.advance(next_state_bytes)
state = ReceiptState.from_transition(transition)

with AuditedWal("decisions.wal", hmac_key=wal_key) as wal:
    entry = wal.append_verified(
        engine.policy,
        request,
        decision,
        metadata={"tenant": "acme"},
    )
    anchor = wal.anchor()
    anchor.save("trusted-head.json")

receipt = engine.issue_receipt(
    request,
    decision,
    state=state,
    wal=entry.receipt_anchor(),
)
receipt.sign(receipt_signing_key, "decision-service:prod", signed_at_epoch_ms)
receipt.verify(engine.policy, request, decision)
receipt.verify_signature(public_key_from_signing_key(receipt_signing_key))

verify_audited_wal(
    "decisions.wal",
    hmac_key=wal_key,
    anchor=anchor,
)
```

Production rules:

- Keep WAL HMAC, policy-signing, and receipt-signing keys distinct.
- Use at least 32 bytes for the WAL HMAC key.
- Pin trusted Ed25519 public keys; do not trust a key merely because it is
  embedded in an artifact.
- Store `WalAnchor` outside the WAL file.
- Use `append_verified`, not an unaudited log write.
- Supply canonical byte encodings for domain state.

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

PyPI: `pip install calybris`.

## Test gate (Python)

```bash
python -m maturin build --release --out dist
python -m pip install dist/calybris-*.whl --force-reinstall
ruff check python/calybris python/calybris_commerce python/tests
mypy python/calybris python/calybris_commerce
bandit -r python/calybris python/calybris_commerce -q
pip-audit . --strict
pytest python/tests -q
```

Compatibility import: `calybris_core` remains for older code paths.
