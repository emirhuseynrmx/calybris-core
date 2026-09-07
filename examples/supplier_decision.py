"""Fixed quotes for one outsourced job; no external calls or purchase placement."""

from calybris import Candidate, DecisionEngine, DecisionRequest, EngineConfig, compare_policies


def main():
    # Lead time uses milliseconds. The quotes and business value share one
    # chosen currency and scale. Nothing converts currencies automatically.
    day = 86_400_000
    catalog = [
        Candidate(
            candidate_id=1,
            provider_id=0,
            quality_bps=9000,
            risk_ceiling_bps=8000,
            lead_time_ms=8 * day,
            region_mask=1,
            capabilities=1,
            quoted_cost_microunits=80_000_000,
        ),
        Candidate(
            candidate_id=2,
            provider_id=1,
            quality_bps=9500,
            risk_ceiling_bps=8000,
            lead_time_ms=3 * day,
            region_mask=1,
            capabilities=1,
            quoted_cost_microunits=100_000_000,
        ),
    ]
    config = EngineConfig(latency_penalty_microunits_per_ms=0)
    engine = DecisionEngine(catalog, config=config)
    request = DecisionRequest(
        request_sequence=1,
        budget_microunits=120_000_000,
        business_value_microunits=200_000_000,
        maximum_lead_time_ms=5 * day,
        required_capabilities=1,
    )
    result = engine.decide(request)
    assert result.selected_candidate_id == 2
    assert engine.verify(request, result)
    print(result.model_dump_json(indent=2))
    stricter = DecisionEngine(
        catalog,
        config=EngineConfig(latency_penalty_microunits_per_ms=0, minimum_confidence_bps=10000),
        policy_epoch=2,
    )
    print(compare_policies(engine, stricter, [request]).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
