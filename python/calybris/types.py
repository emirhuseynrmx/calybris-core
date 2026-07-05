"""Typed, immutable Python representations of Calybris kernel objects.

All models are ``frozen=True`` — the kernel is deterministic and these values
must not be mutated after the fact.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ModelSpec(BaseModel):
    """A candidate model in the decision catalog.

    Maps 1-to-1 to the Rust ``KernelModel`` struct. All cost and quality
    values use the same units as the Rust kernel.
    """

    model_config = ConfigDict(frozen=True)

    model_id: int = Field(..., ge=0, description="Unique model identifier.")
    provider_id: int = Field(..., ge=0, le=63, description="Provider index (0–63).")
    quality_bps: int = Field(
        ...,
        ge=0,
        le=10_000,
        description="Quality score in basis points (0 = worst, 10 000 = best).",
    )
    risk_ceiling_bps: int = Field(
        ..., ge=0, le=10_000, description="Maximum request risk this model can handle."
    )
    enabled: bool = Field(
        default=True, description="Disabled models are skipped during evaluation."
    )
    p95_latency_ms: int = Field(..., ge=0, description="95th-percentile latency in milliseconds.")
    capabilities: int = Field(default=0, ge=0, description="Capability bitmask.")
    region_mask: int = Field(..., ge=0, description="Region availability bitmask.")
    input_cost_microunits_per_million_tokens: int = Field(
        ..., ge=0, description="Input cost per million tokens (1 cent = 1 000 000 microunits)."
    )
    output_cost_microunits_per_million_tokens: int = Field(
        ..., ge=0, description="Output cost per million tokens."
    )


class Decision(BaseModel):
    """The kernel's routing decision for a single request.

    Returned by :meth:`CalybrisEngine.prescribe`. All fields mirror the Rust
    ``KernelDecision`` struct.
    """

    model_config = ConfigDict(frozen=True)

    request_sequence: int
    action: str
    action_code: int
    reason: str
    reason_code: int
    selected_model_id: int
    selected_model_index: int
    estimated_cost_microunits: int
    expected_utility_microunits: int
    counterfactual_model_id: int
    counterfactual_utility_microunits: int
    evaluated_models: int
    eligible_models: int
    policy_epoch: int
    catalog_epoch: int

    def is_executable(self) -> bool:
        """True when a model was selected (execute or substitute)."""
        return self.action_code in (1, 2)

    def is_requested_execution(self) -> bool:
        """True when the caller's requested model was selected."""
        return self.action_code == 1

    def is_substitution(self) -> bool:
        """True when a different model with higher utility was selected."""
        return self.action_code == 2

    def is_rejected(self) -> bool:
        """True when no model passed all constraints."""
        return self.action_code == 3

    def __str__(self) -> str:
        return (
            f"Decision(seq={self.request_sequence}, action='{self.action}', "
            f"model={self.selected_model_id}, reason='{self.reason}')"
        )


class VerifyResult(BaseModel):
    """Result of verifying a decision against its inputs.

    ``status`` is always present. Additional fields appear only when the
    verification fails:

    - ``"mismatch"``: ``expected_action``, ``actual_action``,
      ``expected_model_id``, ``actual_model_id``, ``expected_reason``,
      ``actual_reason``.
    - ``"digest_mismatch"``: ``expected_hex``, ``actual_hex``.
    """

    model_config = ConfigDict(frozen=True)

    status: Literal["valid", "mismatch", "digest_mismatch"]
    expected_action: str | None = None
    actual_action: str | None = None
    expected_model_id: int | None = None
    actual_model_id: int | None = None
    expected_reason: str | None = None
    actual_reason: str | None = None
    expected_hex: str | None = None
    actual_hex: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.status == "valid"

    def __bool__(self) -> bool:
        return self.is_valid


class DecisionTrace(BaseModel):
    """Per-constraint rejection histogram from a prescribe evaluation."""

    model_config = ConfigDict(frozen=True)

    disabled: int = 0
    quality: int = 0
    risk_ceiling: int = 0
    latency: int = 0
    capability: int = 0
    provider: int = 0
    region: int = 0
    budget: int = 0
    utility: int = 0
    evaluated_models: int
    eligible_models: int


class ProofEnvelope(BaseModel):
    """Single proof package binding a decision to digests and optional evidence."""

    model_config = ConfigDict(frozen=True)

    proof_version: int
    policy_digest_hex: str
    input_digest_hex: str
    decision_digest_hex: str
    replay_valid: bool
    wal_sequence: int | None = None
    wal_entry_hash: str | None = None
    budget_snapshot_version: int | None = None
    ledger_digest_hex: str | None = None
    action: str
    reason: str
    selected_model_id: int
    counterfactual_model_id: int
    estimated_cost_microunits: int
    expected_utility_microunits: int


class AuditBundle(BaseModel):
    """Binds a decision to its policy and input via SHA-256 digests.

    ``replay_valid`` means the Rust kernel reproduced the same decision when
    given the same input — this is the fail-closed proof of determinism.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(
        default="calybris.audit.v1",
        description="Stable schema tag for long-term audit storage.",
    )
    digest_algorithm: str = Field(
        default="sha256",
        description="Digest algorithm used for all bundle fields.",
    )
    proof_version: int = Field(default=1, description="Proof format version.")
    policy_epoch: int = Field(default=0, description="Policy epoch at decision time.")
    catalog_epoch: int = Field(default=0, description="Catalog epoch at decision time.")
    created_by: str = Field(default="calybris", description="Producer label.")
    policy_digest_hex: str = Field(
        ..., description="Hex-encoded canonical policy digest (64 chars)."
    )
    input_digest_hex: str = Field(..., description="Hex-encoded canonical input digest (64 chars).")
    decision_digest_hex: str = Field(
        ..., description="Hex-encoded canonical decision digest (64 chars)."
    )
    replay_valid: bool = Field(
        ..., description="True when prescribe(input) == decision on all fields."
    )
