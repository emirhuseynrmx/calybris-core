"""Builder pattern for assembling policies and requests.

All builders return ``self`` to support method chaining. ``build()`` produces
the final Rust-backed object (``PolicySnapshot`` or ``KernelInput``).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from calybris import _core
from calybris.errors import InputValidationError, PolicyValidationError
from calybris.types import STRICT_CONFIG, ModelSpec

_MAX_BPS = 10_000
_U32_MAX = 2**32 - 1
_U64_MAX = 2**64 - 1
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1


def _require_bps_range(field: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_BPS:
        raise InputValidationError(
            f"{field} must be an integer between 0 and {_MAX_BPS}, got {value!r}"
        )


def _require_non_negative(field: str, value: int) -> None:
    if value < 0:
        raise InputValidationError(f"{field} must be >= 0, got {value}")


def _require_int_range(field: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InputValidationError(
            f"{field} must be an integer between {minimum} and {maximum}, got {value!r}"
        )


class EngineConfig(BaseModel):
    """Policy tuning knobs passed to :class:`PolicyBuilder`.

    All values are in basis points (1 bps = 1/10 000) unless the field name
    says otherwise.
    """

    model_config = STRICT_CONFIG

    hard_risk_limit_bps: int = Field(
        default=9_600,
        ge=0,
        le=10_000,
        description="Requests with risk_bps at or above this are always rejected.",
    )
    minimum_confidence_bps: int = Field(
        default=5_500,
        ge=0,
        le=10_000,
        description="Requests with confidence_bps below this are always rejected.",
    )
    risk_penalty_multiplier_bps: int = Field(
        default=3_500,
        ge=0,
        le=50_000,
        description="Scales how much risk reduces expected utility.",
    )
    latency_penalty_microunits_per_ms: int = Field(
        default=2,
        ge=0,
        le=_U64_MAX,
        description="Cost subtracted from utility per millisecond of p95 latency.",
    )


class PolicyBuilder:
    """Assembles a :class:`PolicySnapshot` from an :class:`EngineConfig` and model list.

    Usage::

        policy = (
            PolicyBuilder(config, policy_epoch=1, catalog_epoch=1)
            .add_model(ModelSpec(...))
            .add_model(ModelSpec(...))
            .build()
        )
    """

    def __init__(
        self,
        config: EngineConfig,
        *,
        policy_epoch: int = 1,
        catalog_epoch: int = 1,
    ) -> None:
        _require_int_range("policy_epoch", policy_epoch, 0, _U64_MAX)
        _require_int_range("catalog_epoch", catalog_epoch, 0, _U64_MAX)
        self._config = config
        self._policy_epoch = policy_epoch
        self._catalog_epoch = catalog_epoch
        self._models: list[ModelSpec] = []

    def epoch(self, policy_epoch: int, catalog_epoch: int) -> PolicyBuilder:
        """Override the epoch numbers (defaults to 1/1)."""
        _require_int_range("policy_epoch", policy_epoch, 0, _U64_MAX)
        _require_int_range("catalog_epoch", catalog_epoch, 0, _U64_MAX)
        self._policy_epoch = policy_epoch
        self._catalog_epoch = catalog_epoch
        return self

    def add_model(self, model: ModelSpec) -> PolicyBuilder:
        """Add a model to the catalog."""
        self._models.append(model)
        return self

    def build(self) -> _core.PolicySnapshot:
        """Validate and return the assembled ``PolicySnapshot``.

        Raises :exc:`PolicyValidationError` when the catalog or constraint
        values are invalid (duplicate IDs, no enabled models, bps out of range).
        """
        try:
            rust_models = [
                _core.KernelModel(
                    m.model_id,
                    m.provider_id,
                    m.quality_bps,
                    m.risk_ceiling_bps,
                    1 if m.enabled else 0,
                    m.p95_latency_ms,
                    m.capabilities,
                    m.region_mask,
                    m.input_cost_microunits_per_million_tokens,
                    m.output_cost_microunits_per_million_tokens,
                )
                for m in self._models
            ]
            return _core.PolicySnapshot(
                self._policy_epoch,
                self._catalog_epoch,
                self._config.hard_risk_limit_bps,
                self._config.minimum_confidence_bps,
                self._config.risk_penalty_multiplier_bps,
                self._config.latency_penalty_microunits_per_ms,
                rust_models,
            )
        except (ValueError, OverflowError) as exc:
            raise PolicyValidationError(str(exc)) from exc


class InputBuilder:
    """Builds a ``KernelInput`` with named parameters and method chaining.

    ``budget()`` is required before :meth:`build` — budget is a first-class
    constraint in the kernel and must be set explicitly.

    Usage::

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
    """

    def __init__(self, *, request_sequence: int, requested_model_id: int) -> None:
        _require_int_range("request_sequence", request_sequence, 0, _U64_MAX)
        _require_int_range("requested_model_id", requested_model_id, 0, _U32_MAX)
        self._seq = request_sequence
        self._model_id = requested_model_id
        self._input_tokens: int = 0
        self._output_tokens: int = 0
        self._business_value: int = 0
        self._budget: int | None = None
        self._risk_bps: int = 0
        self._confidence_bps: int = 10_000
        self._min_quality_bps: int = 0
        self._max_latency_ms: int = 0
        self._required_capabilities: int = 0
        self._allowed_providers: int = _core.ALL_PROVIDERS
        self._required_regions: int = 0

    def tokens(self, *, input: int, output: int) -> InputBuilder:  # skipcq: PYL-W0622
        """Set input and output token counts.

        `input` shadows the builtin inside this method only. Renaming it would
        break every published `tokens(input=..., output=...)` call site.
        """
        _require_int_range("input_tokens", input, 0, _U32_MAX)
        _require_int_range("output_tokens", output, 0, _U32_MAX)
        self._input_tokens = input
        self._output_tokens = output
        return self

    def budget(self, limit_microunits: int) -> InputBuilder:
        """Set the maximum spend allowed, in microunits."""
        _require_int_range("budget_limit_microunits", limit_microunits, 0, _U64_MAX)
        self._budget = limit_microunits
        return self

    def value(self, business_value_microunits: int) -> InputBuilder:
        """Set the expected business value of this request, in microunits."""
        _require_int_range(
            "business_value_microunits", business_value_microunits, _I64_MIN, _I64_MAX
        )
        self._business_value = business_value_microunits
        return self

    def risk(self, *, bps: int, confidence_bps: int) -> InputBuilder:
        """Set the risk estimate and the confidence in that estimate."""
        _require_bps_range("risk_bps", bps)
        _require_bps_range("confidence_bps", confidence_bps)
        self._risk_bps = bps
        self._confidence_bps = confidence_bps
        return self

    def quality(self, *, minimum_bps: int) -> InputBuilder:
        """Set the minimum quality floor in basis points."""
        _require_bps_range("minimum_quality_bps", minimum_bps)
        self._min_quality_bps = minimum_bps
        return self

    def latency(self, *, max_p95_ms: int) -> InputBuilder:
        """Set the maximum acceptable p95 latency in milliseconds (0 = no limit)."""
        _require_int_range("max_p95_latency_ms", max_p95_ms, 0, _U32_MAX)
        self._max_latency_ms = max_p95_ms
        return self

    def capabilities(self, required: int) -> InputBuilder:
        """Set required capability bitmask (all bits must match)."""
        _require_int_range("required_capabilities", required, 0, _U64_MAX)
        self._required_capabilities = required
        return self

    def providers(self, allowed_mask: int) -> InputBuilder:
        """Restrict to specific providers via bitmask (default: ALL_PROVIDERS)."""
        _require_int_range("allowed_provider_mask", allowed_mask, 0, _U64_MAX)
        self._allowed_providers = allowed_mask
        return self

    def regions(self, required_mask: int) -> InputBuilder:
        """Require specific regions via bitmask (default: 0 = no restriction)."""
        _require_int_range("required_region_mask", required_mask, 0, _U64_MAX)
        self._required_regions = required_mask
        return self

    def build(self) -> _core.KernelInput:
        """Return the assembled ``KernelInput``.

        Raises :exc:`InputValidationError` when required fields are missing or
        out of range.
        """
        if self._budget is None:
            raise InputValidationError(
                "budget is required: call .budget(limit_microunits) before .build()"
            )
        try:
            return _core.KernelInput(
                self._seq,
                self._model_id,
                self._input_tokens,
                self._output_tokens,
                self._business_value,
                self._budget,
                self._risk_bps,
                self._confidence_bps,
                self._min_quality_bps,
                self._max_latency_ms,
                self._required_capabilities,
                self._allowed_providers,
                self._required_regions,
            )
        except (ValueError, OverflowError) as exc:
            raise InputValidationError(str(exc)) from exc
