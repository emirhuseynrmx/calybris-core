"""Typed, immutable Python representations of Calybris kernel objects.

All models are ``frozen=True`` — the kernel is deterministic and these values
must not be mutated after the fact.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

STRICT_CONFIG = ConfigDict(frozen=True, extra="forbid", strict=True)
U16 = Annotated[int, Field(ge=0, le=2**16 - 1)]
U32 = Annotated[int, Field(ge=0, le=2**32 - 1)]
U64 = Annotated[int, Field(ge=0, le=2**64 - 1)]
I64 = Annotated[int, Field(ge=-(2**63), le=2**63 - 1)]
SHA256_HEX = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ModelSpec(BaseModel):
    """A candidate model in the decision catalog.

    Maps 1-to-1 to the Rust ``KernelModel`` struct. All cost and quality
    values use the same units as the Rust kernel.
    """

    model_config = STRICT_CONFIG

    model_id: int = Field(..., ge=1, le=2**32 - 1, description="Unique model identifier.")
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
    p95_latency_ms: U32 = Field(..., description="95th-percentile latency in milliseconds.")
    capabilities: U64 = Field(default=0, description="Capability bitmask.")
    region_mask: U64 = Field(..., description="Region availability bitmask.")
    input_cost_microunits_per_million_tokens: int = Field(
        ..., ge=0, le=2**64 - 1, description="Input cost per million tokens (1 cent = 1 000 000 microunits)."
    )
    output_cost_microunits_per_million_tokens: int = Field(
        ..., ge=0, le=2**64 - 1, description="Output cost per million tokens."
    )


class Decision(BaseModel):
    """The kernel's routing decision for a single request.

    Returned by :meth:`CalybrisEngine.prescribe`. All fields mirror the Rust
    ``KernelDecision`` struct.
    """

    model_config = STRICT_CONFIG

    request_sequence: U64
    action: str
    action_code: int = Field(ge=0, le=255)
    reason: str
    reason_code: U16
    selected_model_id: U32
    selected_model_index: U16
    estimated_cost_microunits: U64
    expected_utility_microunits: I64
    counterfactual_model_id: U32
    counterfactual_utility_microunits: I64
    evaluated_models: U16
    eligible_models: U16
    policy_epoch: U64
    catalog_epoch: U64

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

    model_config = STRICT_CONFIG

    status: Literal["valid", "mismatch", "digest_mismatch"]
    expected_action: str | None = None
    actual_action: str | None = None
    expected_model_id: U32 | None = None
    actual_model_id: U32 | None = None
    expected_reason: str | None = None
    actual_reason: str | None = None
    expected_hex: SHA256_HEX | None = None
    actual_hex: SHA256_HEX | None = None

    @property
    def is_valid(self) -> bool:
        return self.status == "valid"

    def __bool__(self) -> bool:
        return self.is_valid


class DecisionTrace(BaseModel):
    """Per-constraint rejection histogram from a prescribe evaluation."""

    model_config = STRICT_CONFIG

    disabled: U16 = 0
    quality: U16 = 0
    risk_ceiling: U16 = 0
    latency: U16 = 0
    capability: U16 = 0
    provider: U16 = 0
    region: U16 = 0
    budget: U16 = 0
    utility: U16 = 0
    evaluated_models: U16
    eligible_models: U16


class ProofEnvelope(BaseModel):
    """Single proof package binding a decision to digests and optional evidence."""

    model_config = STRICT_CONFIG

    proof_version: Literal[1]
    policy_digest_hex: SHA256_HEX
    input_digest_hex: SHA256_HEX
    decision_digest_hex: SHA256_HEX
    replay_valid: bool
    wal_sequence: U64 | None = None
    wal_entry_hash: SHA256_HEX | None = None
    budget_snapshot_version: U64 | None = None
    ledger_digest_hex: SHA256_HEX | None = None
    action: str
    reason: str
    selected_model_id: U32
    counterfactual_model_id: U32
    estimated_cost_microunits: U64
    expected_utility_microunits: I64


class AuditBundle(BaseModel):
    """Binds a decision to its policy and input via SHA-256 digests.

    ``replay_valid`` means the Rust kernel reproduced the same decision when
    given the same input — this is the fail-closed proof of determinism.
    """

    model_config = STRICT_CONFIG

    schema_version: Literal["calybris.audit.v1"] = Field(
        default="calybris.audit.v1",
        description="Stable schema tag for long-term audit storage.",
    )
    digest_algorithm: Literal["sha256"] = Field(
        default="sha256",
        description="Digest algorithm used for all bundle fields.",
    )
    proof_version: Literal[1] = Field(default=1, description="Proof format version.")
    policy_epoch: U64 = Field(default=0, description="Policy epoch at decision time.")
    catalog_epoch: U64 = Field(default=0, description="Catalog epoch at decision time.")
    created_by: Literal["calybris"] = Field(default="calybris", description="Producer label.")
    policy_digest_hex: SHA256_HEX = Field(
        ..., description="Hex-encoded canonical policy digest (64 chars)."
    )
    input_digest_hex: SHA256_HEX = Field(..., description="Hex-encoded canonical input digest (64 chars).")
    decision_digest_hex: SHA256_HEX = Field(
        ..., description="Hex-encoded canonical decision digest (64 chars)."
    )
    replay_valid: bool = Field(
        ..., description="True when prescribe(input) == decision on all fields."
    )
