from __future__ import annotations


class CalybrisError(Exception):
    """Base class for all Calybris errors."""


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
