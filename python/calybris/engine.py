"""High-level engine wrapper around a validated PolicySnapshot."""

from __future__ import annotations

from typing import Literal

from calybris import _core
from calybris.errors import InputValidationError, VerificationError
from calybris.types import AuditBundle, Decision, DecisionTrace, ProofEnvelope, VerifyResult


class CalybrisEngine:
    """Routes requests through a deterministic decision kernel.

    Wraps a ``PolicySnapshot`` and converts raw Rust objects into typed Python
    models on the way out. The engine itself is stateless — every call
    is a pure function of the policy and the input.

    Usage::

        engine = CalybrisEngine(policy)
        decision = engine.prescribe(request)
        bundle = engine.verified_audit_bundle(request, decision)
        assert bundle.replay_valid
    """

    def __init__(self, policy: _core.PolicySnapshot) -> None:
        self._policy = policy

    @property
    def fingerprint(self) -> str:
        """64-char hex SHA-256 fingerprint of the policy catalog."""
        return self._policy.fingerprint()

    @property
    def policy_epoch(self) -> int:
        return self._policy.policy_epoch

    @property
    def catalog_epoch(self) -> int:
        return self._policy.catalog_epoch

    @property
    def model_count(self) -> int:
        return self._policy.model_count()

    @property
    def policy(self) -> _core.PolicySnapshot:
        """The immutable Rust policy snapshot used by this engine."""
        return self._policy

    def prescribe(self, request: _core.KernelInput) -> _core.KernelDecision:
        """Evaluate ``request`` and return the kernel's decision.

        The returned ``KernelDecision`` is the raw Rust object — use it
        directly with :meth:`verify`, :meth:`audit_bundle`, and
        :meth:`verified_audit_bundle` for zero-copy audit paths.
        Call ``.as_dict()`` or :meth:`decision_model` to convert to Python
        types when you need serialization or attribute access.
        """
        try:
            return self._policy.prescribe(request)
        except ValueError as exc:
            raise InputValidationError(str(exc)) from exc

    def prescribe_with_trace(
        self,
        request: _core.KernelInput,
    ) -> tuple[_core.KernelDecision, DecisionTrace]:
        """Evaluate ``request`` and return ``(decision, rejection_trace)``.

        The trace contains per-constraint rejection counts from the same kernel
        evaluation, plus ``evaluated_models`` and ``eligible_models``. Use it
        for audit UI, benchmark summaries, or compliance explanations.
        """
        try:
            decision, trace = self._policy.prescribe_with_trace(request)
        except ValueError as exc:
            raise InputValidationError(str(exc)) from exc
        return decision, DecisionTrace.model_validate(dict(trace))

    def utility_for_model(
        self,
        request: _core.KernelInput,
        model_id: int,
    ) -> int | None:
        """Return the kernel utility for ``model_id``, or ``None`` if ineligible."""
        return self._policy.utility_for_model(request, model_id)

    def counterfactual_utility(
        self,
        request: _core.KernelInput,
        model_id: int,
    ) -> int | None:
        """Return counterfactual utility for ``model_id`` under the same input."""
        return self._policy.counterfactual_utility(request, model_id)

    def proof_envelope(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
    ) -> ProofEnvelope:
        """Build a :class:`ProofEnvelope` with digests and decision summary."""
        raw = self._policy.proof_envelope(request, decision)
        return ProofEnvelope.model_validate(raw)

    def prescribe_batch(self, requests: list[_core.KernelInput]) -> list[_core.KernelDecision]:
        """Evaluate many requests; releases the GIL for the batch computation."""
        return self._policy.prescribe_batch(requests)

    def decision_model(self, decision: _core.KernelDecision) -> Decision:
        """Convert a raw ``KernelDecision`` to a typed, immutable :class:`Decision` model."""
        return Decision.model_validate(decision.as_dict())

    def prescribe_as_model(self, request: _core.KernelInput) -> Decision:
        """Convenience: prescribe and return a typed :class:`Decision` in one call."""
        return self.decision_model(self.prescribe(request))

    def verify(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
    ) -> VerifyResult:
        """Verify that ``decision`` is the correct output for ``request``.

        Returns a :class:`VerifyResult` with ``status == "valid"`` when the
        kernel replays to the same decision. On failure the result contains
        diagnostic fields (``expected_action``, ``actual_model_id``, etc.).
        """
        raw = self._policy.verify(request, decision)
        return VerifyResult.model_validate(raw)

    def verify_status(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
    ) -> Literal["valid", "mismatch", "digest_mismatch"]:
        """Return only the replay verification status string."""
        return self._policy.verify_status(request, decision)

    def audit_bundle(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
    ) -> AuditBundle:
        """Build an :class:`AuditBundle` binding this decision to its policy and input.

        ``replay_valid`` may be ``False`` if the decision was tampered with.
        Use :meth:`verified_audit_bundle` at audit boundaries that require a
        fail-closed proof.
        """
        raw = self._policy.audit_bundle(request, decision)
        return AuditBundle.model_validate(raw)

    def verified_audit_bundle(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
    ) -> AuditBundle:
        """Build an :class:`AuditBundle` and raise if replay fails.

        Raises :exc:`VerificationError` when ``prescribe(request)`` does not
        reproduce ``decision``. Safe to call at audit log write-time.
        """
        try:
            raw = self._policy.verified_audit_bundle(request, decision)
        except ValueError as exc:
            verify_result = self.verify(request, decision)
            raise VerificationError(str(exc), verify_result.model_dump()) from exc
        return AuditBundle.model_validate(raw)

    def sign_policy(
        self,
        signing_key: bytes,
        signer_id: str,
        signed_at_epoch_ms: int,
    ) -> _core.SignedPolicy:
        """Sign the exact policy digest with an Ed25519 seed.

        ``signing_key`` must be exactly 32 bytes. Keep it in a KMS/HSM-backed
        secret path in production; Calybris never persists it.
        """
        return self._policy.sign_policy(signing_key, signer_id, signed_at_epoch_ms)

    def stateful_audit_bundle(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
        transition: _core.StateTransition,
    ) -> _core.StatefulAuditBundle:
        """Bind a replay-verified decision to one state-chain transition."""
        return self._policy.stateful_audit_bundle(request, decision, transition)

    def issue_receipt(
        self,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
        *,
        state: _core.ReceiptState | None = None,
        wal: _core.ReceiptWal | None = None,
    ) -> _core.DecisionReceipt:
        """Issue a receipt only after exact replay verification succeeds."""
        return self._policy.issue_receipt(request, decision, state=state, wal=wal)

    def __repr__(self) -> str:
        return (
            f"CalybrisEngine(policy_epoch={self.policy_epoch}, "
            f"catalog_epoch={self.catalog_epoch}, "
            f"models={self.model_count}, "
            f"fingerprint={self.fingerprint[:8]}...)"
        )
