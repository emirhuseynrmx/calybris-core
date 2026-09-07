"""Domain-neutral, fixed-quote decisions using the existing Rust kernel.

No selection algorithm lives here. Quotes and business value use the same integer
microunits. One quoted job maps to one million native input units and zero output
units, making its native estimated cost exactly the quoted cost.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, Field

from calybris import _core
from calybris.builder import EngineConfig, InputBuilder, PolicyBuilder
from calybris.engine import CalybrisEngine
from calybris.types import (
    I64,
    SHA256_HEX,
    STRICT_CONFIG,
    U32,
    U64,
    AuditBundle,
    Decision,
    DecisionTrace,
    ModelSpec,
)

__all__ = [
    "Candidate",
    "DecisionEngine",
    "DecisionRequest",
    "DecisionResult",
    "PolicyChange",
    "PolicyComparison",
    "PolicyIdentity",
    "compare_policies",
]


class Candidate(BaseModel):
    """One fixed quote. Lead time uses milliseconds; masks retain native semantics."""

    model_config = STRICT_CONFIG
    candidate_id: int = Field(ge=1, le=2**32 - 1)
    provider_id: int = Field(ge=0, le=63)
    quality_bps: int = Field(ge=0, le=10000)
    risk_ceiling_bps: int = Field(ge=0, le=10000)
    lead_time_ms: U32
    region_mask: U64
    quoted_cost_microunits: U64
    capabilities: U64 = 0
    enabled: bool = True

    def _native_model(self) -> ModelSpec:
        return ModelSpec(
            model_id=self.candidate_id,
            provider_id=self.provider_id,
            quality_bps=self.quality_bps,
            risk_ceiling_bps=self.risk_ceiling_bps,
            p95_latency_ms=self.lead_time_ms,
            region_mask=self.region_mask,
            input_cost_microunits_per_million_tokens=self.quoted_cost_microunits,
            output_cost_microunits_per_million_tokens=0,
            capabilities=self.capabilities,
            enabled=self.enabled,
        )


class DecisionRequest(BaseModel):
    """An immutable request for one fixed-quote job, not a schedule optimizer."""

    model_config = STRICT_CONFIG
    request_sequence: U64
    budget_microunits: U64
    business_value_microunits: I64
    requested_candidate_id: U32 = 0
    risk_bps: int = Field(default=0, ge=0, le=10000)
    confidence_bps: int = Field(default=10000, ge=0, le=10000)
    minimum_quality_bps: int = Field(default=0, ge=0, le=10000)
    maximum_lead_time_ms: U32 = 0
    required_capabilities: U64 = 0
    allowed_provider_mask: U64 = 2**64 - 1
    required_region_mask: U64 = 0

    def _native_input(self) -> _core.KernelInput:
        return (
            InputBuilder(
                request_sequence=self.request_sequence,
                requested_model_id=self.requested_candidate_id,
            )
            .tokens(input=1_000_000, output=0)
            .budget(self.budget_microunits)
            .value(self.business_value_microunits)
            .risk(bps=self.risk_bps, confidence_bps=self.confidence_bps)
            .quality(minimum_bps=self.minimum_quality_bps)
            .latency(max_p95_ms=self.maximum_lead_time_ms)
            .capabilities(self.required_capabilities)
            .providers(self.allowed_provider_mask)
            .regions(self.required_region_mask)
            .build()
        )


class DecisionResult(BaseModel):
    """Native decision and verified proof; trace is an aggregate rejection histogram."""

    model_config = STRICT_CONFIG
    schema_version: Literal["calybris.decision.v1"] = "calybris.decision.v1"
    status: Literal["selected", "rejected"]
    selected_candidate_id: U32 | None
    catalog_digest: SHA256_HEX
    decision: Decision
    trace: DecisionTrace
    proof: AuditBundle


class DecisionEngine:
    """Immutable canonical catalog plus native policy. Safe for independent callers."""

    def __init__(
        self,
        candidates: Iterable[Candidate],
        *,
        config: EngineConfig | None = None,
        policy_epoch: int = 1,
        catalog_epoch: int = 1,
    ) -> None:
        items: list[Candidate] = []
        for item in candidates:
            if len(items) >= 65535:
                raise ValueError("catalog exceeds 65535 candidates")
            items.append(Candidate.model_validate(item.model_dump()))
        self._candidates = tuple(sorted(items, key=lambda item: item.candidate_id))
        self._config = EngineConfig.model_validate((config or EngineConfig()).model_dump())
        payload = {
            "schema_version": "calybris.catalog.v1",
            "candidates": [item.model_dump() for item in self._candidates],
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        self._catalog_digest = hashlib.sha256(encoded).hexdigest()
        builder = PolicyBuilder(
            self._config, policy_epoch=policy_epoch, catalog_epoch=catalog_epoch
        )
        for item in self._candidates:
            builder.add_model(item._native_model())
        self._engine = CalybrisEngine(builder.build())

    @property
    def catalog_digest(self) -> str:
        """Adapter catalog SHA256; distinct from the native policy digest."""
        return self._catalog_digest

    @property
    def policy_digest(self) -> str:
        """Native policy-snapshot fingerprint. Two engines agree only if this does."""
        return self._engine.fingerprint

    @property
    def policy_epoch(self) -> int:
        """Caller-assigned policy version carried by the native snapshot."""
        return self._engine.policy_epoch

    @property
    def catalog_epoch(self) -> int:
        """Caller-assigned catalog version carried by the native snapshot."""
        return self._engine.catalog_epoch

    @property
    def config(self) -> EngineConfig:
        """Frozen native scoring configuration."""
        return self._config

    def decide(self, request: DecisionRequest) -> DecisionResult:
        """Select once with the native kernel, then replay-verify the decision."""
        request = DecisionRequest.model_validate(request.model_dump())
        native = request._native_input()
        raw, trace = self._engine.prescribe_with_trace(native)
        decision = self._engine.decision_model(raw)
        return DecisionResult(
            status="selected" if decision.is_executable() else "rejected",
            selected_candidate_id=decision.selected_model_id if decision.is_executable() else None,
            catalog_digest=self.catalog_digest,
            decision=decision,
            trace=trace,
            proof=self._engine.verified_audit_bundle(native, raw),
        )

    def verify(self, request: DecisionRequest, result: DecisionResult) -> bool:
        """Recompute and compare the entire result using this trusted engine/input."""
        return self.decide(request) == result


class PolicyChange(BaseModel):
    """One changed outcome. Input identity is carried by both native audit bundles."""

    model_config = STRICT_CONFIG
    index: int = Field(ge=0)
    before: DecisionResult
    after: DecisionResult


class PolicyIdentity(BaseModel):
    """Which policy a side of the comparison actually ran.

    The configuration alone does not identify a policy: two engines can share every
    configured field and still differ by epoch, and a reader holding only the
    configuration cannot tell that apart from no change at all.
    """

    model_config = STRICT_CONFIG
    policy_digest: SHA256_HEX
    policy_epoch: int = Field(ge=0)
    catalog_epoch: int = Field(ge=0)


class PolicyComparison(BaseModel):
    """Bounded replay comparison, not a causal or realized-savings estimate."""

    model_config = STRICT_CONFIG
    schema_version: Literal["calybris.policy-comparison.v1"] = "calybris.policy-comparison.v1"
    catalog_digest: SHA256_HEX
    before_policy: PolicyIdentity
    after_policy: PolicyIdentity
    policy_changed: bool
    total: int = Field(ge=0)
    changed: int = Field(ge=0)
    newly_rejected: int = Field(ge=0)
    changes: tuple[PolicyChange, ...]
    changes_truncated: bool
    changed_fields: tuple[str, ...]
    before_config: EngineConfig
    after_config: EngineConfig


def _identity(engine: DecisionEngine) -> PolicyIdentity:
    return PolicyIdentity(
        policy_digest=engine.policy_digest,
        policy_epoch=engine.policy_epoch,
        catalog_epoch=engine.catalog_epoch,
    )


def _outcome(result: DecisionResult) -> tuple[int, int, int, int, int]:
    d = result.decision
    return (
        d.action_code,
        d.reason_code,
        d.selected_model_id,
        d.estimated_cost_microunits,
        d.expected_utility_microunits,
    )


def compare_policies(
    before: DecisionEngine,
    after: DecisionEngine,
    requests: Iterable[DecisionRequest],
    *,
    max_requests: int = 10000,
    max_changes: int = 100,
) -> PolicyComparison:
    """Replay identical requests/catalog; cap stored details without truncating totals.

    ``changed_fields`` names policy configuration differences, not proven causal
    attribution to a particular knob. An input exceeding max_requests raises;
    a partial comparison is never returned as complete.
    """
    for name, value in (("max_requests", max_requests), ("max_changes", max_changes)):
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    if before.catalog_digest != after.catalog_digest:
        raise ValueError("policy comparison requires the same catalog")
    changes: list[PolicyChange] = []
    total = changed = newly_rejected = 0
    for index, request in enumerate(requests):
        if index >= max_requests:
            raise ValueError("request count exceeds max_requests")
        frozen = DecisionRequest.model_validate(request.model_dump())
        old, new = before.decide(frozen), after.decide(frozen)
        total += 1
        newly_rejected += int(old.status == "selected" and new.status == "rejected")
        if _outcome(old) != _outcome(new):
            changed += 1
            if len(changes) < max_changes:
                changes.append(PolicyChange(index=index, before=old, after=new))
    old_config, new_config = before.config.model_dump(), after.config.model_dump()
    before_policy = _identity(before)
    after_policy = _identity(after)
    return PolicyComparison(
        catalog_digest=before.catalog_digest,
        before_policy=before_policy,
        after_policy=after_policy,
        policy_changed=before_policy != after_policy,
        total=total,
        changed=changed,
        newly_rejected=newly_rejected,
        changes=tuple(changes),
        changes_truncated=changed > len(changes),
        changed_fields=tuple(sorted(k for k in old_config if old_config[k] != new_config[k])),
        before_config=before.config,
        after_config=after.config,
    )
