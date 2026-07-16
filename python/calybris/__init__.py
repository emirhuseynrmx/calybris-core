"""Calybris — deterministic routing and guardrails with full audit support.

Quick start::

    from calybris import CalybrisEngine, EngineConfig, PolicyBuilder, InputBuilder, ALL_REGIONS
    from calybris.types import ModelSpec

    config = EngineConfig(hard_risk_limit_bps=9_600, minimum_confidence_bps=5_500)
    policy = (
        PolicyBuilder(config, policy_epoch=1, catalog_epoch=1)
        .add_model(ModelSpec(model_id=1, provider_id=0, quality_bps=9_000,
                             risk_ceiling_bps=9_500, p95_latency_ms=200,
                             region_mask=ALL_REGIONS,
                             input_cost_microunits_per_million_tokens=250,
                             output_cost_microunits_per_million_tokens=1_000))
        .build()
    )
    engine = CalybrisEngine(policy)

    request = InputBuilder(request_sequence=1, requested_model_id=1) \\
        .tokens(input=1_000, output=500).budget(50_000_000) \\
        .value(100_000) \\
        .risk(bps=1_000, confidence_bps=9_000).build()

    decision = engine.prescribe(request)
    bundle   = engine.verified_audit_bundle(request, decision)

    assert bundle.replay_valid
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("calybris")
except PackageNotFoundError:
    __version__ = "0.0.0+local"

from calybris.audit import (
    AuditedWal,
    plan_recovery,
    replay_verify_audited_wal,
    verify_audited_wal,
    verify_state_trajectory,
)
from calybris.builder import EngineConfig, InputBuilder, PolicyBuilder
from calybris.engine import CalybrisEngine
from calybris.errors import (
    ArtifactValidationError,
    CalybrisError,
    DecisionVerificationError,
    InputValidationError,
    PersistenceError,
    PolicyValidationError,
    ProvenanceError,
    ReceiptError,
    StateTrajectoryError,
    VerificationError,
    WalError,
)
from calybris.finance import (
    MICROCENTS_PER_CENT,
    BudgetGuard,
    BudgetReservationResult,
    BudgetSettlementResult,
    BudgetSnapshot,
    BudgetTopUpResult,
    ConservationCheck,
    ConservationProof,
    FinancialCertificate,
    TenantLedger,
)
from calybris.types import (
    AuditBundle,
    Decision,
    DecisionTrace,
    ModelSpec,
    ProofEnvelope,
    VerifyResult,
)

from . import _core
from ._core import (
    ACTION_EXECUTE_REQUESTED,
    ACTION_REJECT,
    ACTION_SUBSTITUTE,
    ALL_PROVIDERS,
    ALL_REGIONS,
    REASON_ALTERNATIVE_MAXIMIZES_UTILITY,
    REASON_BUDGET_CONSTRAINT,
    REASON_CAPABILITY_CONSTRAINT,
    REASON_CONFIDENCE_HARD_LIMIT,
    REASON_LATENCY_CONSTRAINT,
    REASON_NO_ENABLED_MODEL,
    REASON_NON_POSITIVE_UTILITY,
    REASON_PROVIDER_CONSTRAINT,
    REASON_QUALITY_CONSTRAINT,
    REASON_REGION_CONSTRAINT,
    REASON_REQUESTED_MODEL_MAXIMIZES_UTILITY,
    REASON_RISK_CEILING_CONSTRAINT,
    REASON_RISK_HARD_LIMIT,
    BudgetEngine,
    DecisionReceipt,
    KernelDecision,
    KernelInput,
    KernelModel,
    PolicySnapshot,
    ReceiptState,
    ReceiptWal,
    SignedPolicy,
    StateChain,
    StatefulAuditBundle,
    StateTransition,
    WalAnchor,
    WalEntry,
    public_key_from_signing_key,
)

__all__ = [
    "__version__",
    # High-level API
    "CalybrisEngine",
    "EngineConfig",
    "PolicyBuilder",
    "InputBuilder",
    "AuditedWal",
    "verify_audited_wal",
    "replay_verify_audited_wal",
    "plan_recovery",
    "verify_state_trajectory",
    # Typed models
    "ModelSpec",
    "Decision",
    "VerifyResult",
    "AuditBundle",
    "DecisionTrace",
    "ProofEnvelope",
    "BudgetGuard",
    "BudgetReservationResult",
    "BudgetSettlementResult",
    "BudgetTopUpResult",
    "ConservationCheck",
    "TenantLedger",
    "BudgetSnapshot",
    "ConservationProof",
    "FinancialCertificate",
    # Errors
    "CalybrisError",
    "ArtifactValidationError",
    "DecisionVerificationError",
    "ReceiptError",
    "ProvenanceError",
    "WalError",
    "PersistenceError",
    "StateTrajectoryError",
    "InputValidationError",
    "PolicyValidationError",
    "VerificationError",
    # Raw Rust types (low-level / zero-copy paths)
    "_core",
    "PolicySnapshot",
    "KernelInput",
    "KernelDecision",
    "KernelModel",
    "BudgetEngine",
    "DecisionReceipt",
    "ReceiptState",
    "ReceiptWal",
    "SignedPolicy",
    "StateChain",
    "StatefulAuditBundle",
    "StateTransition",
    "WalAnchor",
    "WalEntry",
    "public_key_from_signing_key",
    # Constants
    "MICROCENTS_PER_CENT",
    "ALL_PROVIDERS",
    "ALL_REGIONS",
    "ACTION_EXECUTE_REQUESTED",
    "ACTION_SUBSTITUTE",
    "ACTION_REJECT",
    "REASON_REQUESTED_MODEL_MAXIMIZES_UTILITY",
    "REASON_ALTERNATIVE_MAXIMIZES_UTILITY",
    "REASON_RISK_HARD_LIMIT",
    "REASON_CONFIDENCE_HARD_LIMIT",
    "REASON_NO_ENABLED_MODEL",
    "REASON_QUALITY_CONSTRAINT",
    "REASON_LATENCY_CONSTRAINT",
    "REASON_CAPABILITY_CONSTRAINT",
    "REASON_PROVIDER_CONSTRAINT",
    "REASON_REGION_CONSTRAINT",
    "REASON_BUDGET_CONSTRAINT",
    "REASON_NON_POSITIVE_UTILITY",
    "REASON_RISK_CEILING_CONSTRAINT",
]
