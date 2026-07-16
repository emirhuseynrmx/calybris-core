from __future__ import annotations

from calybris._core import (
    ArtifactValidationError,
    CalybrisError,
    DecisionVerificationError,
    PersistenceError,
    ProvenanceError,
    ReceiptError,
    StateTrajectoryError,
    WalError,
)


class PolicyValidationError(CalybrisError):
    """Raised when a PolicySnapshot fails catalog or constraint validation."""


class InputValidationError(CalybrisError):
    """Raised when a KernelInput fails boundary validation before prescribe."""


class VerificationError(CalybrisError):
    """Raised by verified_audit_bundle when decision replay fails.

    Inspect ``result`` for the full diagnostic dict from ``verify()``.
    """

    def __init__(self, message: str, result: dict) -> None:
        super().__init__(message)
        self.result = result


__all__ = [
    "CalybrisError",
    "ArtifactValidationError",
    "DecisionVerificationError",
    "ReceiptError",
    "ProvenanceError",
    "WalError",
    "PersistenceError",
    "StateTrajectoryError",
    "PolicyValidationError",
    "InputValidationError",
    "VerificationError",
]
