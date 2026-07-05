"""Calybris quickstart — route a single request and verify the decision."""
from calybris import (
    ALL_REGIONS,
    CalybrisEngine,
    EngineConfig,
    InputBuilder,
    PolicyBuilder,
)
from calybris.types import ModelSpec

# 1. Define the policy
config = EngineConfig(
    hard_risk_limit_bps=9_600,
    minimum_confidence_bps=5_500,
    risk_penalty_multiplier_bps=3_500,
    latency_penalty_microunits_per_ms=2,
)

policy = (
    PolicyBuilder(config, policy_epoch=1, catalog_epoch=1)
    .add_model(
        ModelSpec(
            model_id=1,
            provider_id=0,
            quality_bps=9_000,
            risk_ceiling_bps=9_500,
            p95_latency_ms=200,
            region_mask=ALL_REGIONS,
            input_cost_microunits_per_million_tokens=250,
            output_cost_microunits_per_million_tokens=1_000,
        )
    )
    .add_model(
        ModelSpec(
            model_id=2,
            provider_id=1,
            quality_bps=7_000,
            risk_ceiling_bps=9_500,
            p95_latency_ms=90,
            region_mask=ALL_REGIONS,
            input_cost_microunits_per_million_tokens=25,
            output_cost_microunits_per_million_tokens=125,
        )
    )
    .build()
)

# 2. Build the engine
engine = CalybrisEngine(policy)
print(engine)

# 3. Build and route a request
request = (
    InputBuilder(request_sequence=1, requested_model_id=1)
    .tokens(input=1_000, output=500)
    .budget(50_000_000)
    .value(100_000)
    .risk(bps=1_000, confidence_bps=9_000)
    .quality(minimum_bps=5_000)
    .latency(max_p95_ms=1_000)
    .build()
)

decision = engine.prescribe(request)
print(decision)
print("action       :", decision.action)
print("model        :", decision.selected_model_id)
print("cost         :", decision.estimated_cost_microunits, "microunits")
print("is_executable:", decision.is_executable())

# 4. Verify and audit
model = engine.decision_model(decision)
print("\ndecision model:")
print(model.model_dump_json(indent=2))

bundle = engine.verified_audit_bundle(request, decision)
print("\naudit bundle:")
print(f"  policy  : {bundle.policy_digest_hex[:16]}...")
print(f"  input   : {bundle.input_digest_hex[:16]}...")
print(f"  decision: {bundle.decision_digest_hex[:16]}...")
print(f"  replay  : {bundle.replay_valid}")
