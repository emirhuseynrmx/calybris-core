"""Route a batch of requests, inspect substitutions, and collect audit bundles."""
from calybris import (
    ALL_REGIONS,
    CalybrisEngine,
    EngineConfig,
    InputBuilder,
    PolicyBuilder,
)
from calybris.types import ModelSpec

config = EngineConfig(hard_risk_limit_bps=8_000, minimum_confidence_bps=6_000)
policy = (
    PolicyBuilder(config, policy_epoch=2, catalog_epoch=5)
    .add_model(ModelSpec(model_id=10, provider_id=0, quality_bps=9_500, risk_ceiling_bps=9_000,
                         p95_latency_ms=300, region_mask=ALL_REGIONS,
                         input_cost_microunits_per_million_tokens=500,
                         output_cost_microunits_per_million_tokens=1_500))
    .add_model(ModelSpec(model_id=11, provider_id=1, quality_bps=7_500, risk_ceiling_bps=9_500,
                         p95_latency_ms=80, region_mask=ALL_REGIONS,
                         input_cost_microunits_per_million_tokens=30,
                         output_cost_microunits_per_million_tokens=150))
    .build()
)
engine = CalybrisEngine(policy)

requests = [
    InputBuilder(request_sequence=i, requested_model_id=10)
    .tokens(input=500 * i, output=200 * i)
    .budget(100_000_000)
    .value(100_000)
    .risk(bps=500, confidence_bps=8_500)
    .quality(minimum_bps=6_000)
    .build()
    for i in range(1, 6)
]

decisions = engine.prescribe_batch(requests)

print(f"Routed {len(decisions)} requests\n")
for req, dec in zip(requests, decisions):
    label = "EXECUTE" if dec.is_requested_execution() else "SUBSTITUTE" if dec.is_substitution() else "REJECT"
    print(f"  seq={req.request_sequence:2d}  model={dec.selected_model_id}  {label}  cost={dec.estimated_cost_microunits:>12,} microunits")

substitutions = [d for d in decisions if d.is_substitution()]
rejections = [d for d in decisions if d.is_rejected()]
print(f"\nSummary: {len(substitutions)} substitution(s), {len(rejections)} rejection(s)")
