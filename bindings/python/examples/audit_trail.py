"""Write an audit trail and replay-verify every decision in it."""
import json
from calybris import (
    ALL_REGIONS,
    CalybrisEngine,
    EngineConfig,
    InputBuilder,
    PolicyBuilder,
    VerificationError,
)
from calybris.types import ModelSpec

config = EngineConfig(hard_risk_limit_bps=9_000)
policy = (
    PolicyBuilder(config, policy_epoch=3, catalog_epoch=1)
    .add_model(ModelSpec(model_id=1, provider_id=0, quality_bps=9_000, risk_ceiling_bps=9_500,
                         p95_latency_ms=200, region_mask=ALL_REGIONS,
                         input_cost_microunits_per_million_tokens=250,
                         output_cost_microunits_per_million_tokens=1_000))
    .build()
)
engine = CalybrisEngine(policy)
print(f"Policy fingerprint: {engine.fingerprint}")

# Route and build an audit log
audit_log: list[dict] = []
for seq in range(1, 4):
    req = (
        InputBuilder(request_sequence=seq, requested_model_id=1)
        .tokens(input=1_000, output=300)
        .budget(50_000_000)
        .value(100_000)
        .risk(bps=800, confidence_bps=9_000)
        .build()
    )
    dec = engine.prescribe(req)
    try:
        bundle = engine.verified_audit_bundle(req, dec)
    except VerificationError as exc:
        print(f"  seq={seq} AUDIT FAILURE: {exc}")
        continue

    entry = {
        "seq": seq,
        "action": dec.action,
        "model": dec.selected_model_id,
        "bundle": bundle.model_dump(),
    }
    audit_log.append(entry)
    print(f"  seq={seq}  action={dec.action}  replay_valid={bundle.replay_valid}")

print(f"\nAudit log ({len(audit_log)} entries):")
print(json.dumps(audit_log, indent=2))
