"""Production audit primitives backed entirely by the Rust core."""

from __future__ import annotations

import json
from collections.abc import Mapping
from os import PathLike
from types import TracebackType
from typing import Any

from typing_extensions import Self

from . import _core
from .errors import ArtifactValidationError

MAX_WAL_METADATA_BYTES = 16 * 1024 * 1024 - 512
_MAX_METADATA_DEPTH = 100


def _preflight_metadata_size(value: Any, limit: int) -> None:
    """Bound obvious JSON size before ``json.dumps`` can allocate its output."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen: set[int] = set()
    estimated = 0
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_METADATA_DEPTH:
            raise ArtifactValidationError(
                f"metadata nesting exceeds {_MAX_METADATA_DEPTH} levels"
            )
        if isinstance(item, str):
            estimated += len(item.encode("utf-8")) + 2
        elif item is None or isinstance(item, (bool, int, float)):
            estimated += len(repr(item)) + 1
        elif isinstance(item, Mapping):
            identity = id(item)
            if identity in seen:
                raise ArtifactValidationError("metadata must not contain cycles")
            seen.add(identity)
            estimated += 2 + len(item)
            for key, nested in item.items():
                stack.append((key, depth + 1))
                stack.append((nested, depth + 1))
        elif isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in seen:
                raise ArtifactValidationError("metadata must not contain cycles")
            seen.add(identity)
            estimated += 2 + len(item)
            stack.extend((nested, depth + 1) for nested in item)
        else:
            # Let json.dumps produce the canonical type diagnostic below.
            estimated += 1
        if estimated > limit:
            raise ArtifactValidationError(f"metadata exceeds {limit} bytes")


def _canonical_metadata(metadata: Mapping[str, Any] | None) -> str:
    """Encode WAL metadata deterministically and reject non-standard floats."""
    value = {} if metadata is None else dict(metadata)
    _preflight_metadata_size(value, MAX_WAL_METADATA_BYTES)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactValidationError(f"metadata must be canonical JSON data: {exc}") from exc
    if len(encoded.encode("utf-8")) > MAX_WAL_METADATA_BYTES:
        raise ArtifactValidationError(f"metadata exceeds {MAX_WAL_METADATA_BYTES} bytes")
    return encoded


class AuditedWal:
    """Fail-closed, hash-chained decision WAL.

    Supply a secret of at least 32 bytes through ``hmac_key`` in production.
    The unkeyed mode detects accidental corruption but cannot stop an attacker
    who can rewrite the WAL from recomputing its SHA-256 chain.
    """

    def __init__(
        self,
        path: str | PathLike[str],
        *,
        hmac_key: bytes | None = None,
    ) -> None:
        self._inner = _core.AuditedWal(path, hmac_key=hmac_key)

    @property
    def sequence(self) -> int:
        return self._inner.sequence

    @property
    def entry_count(self) -> int:
        return self._inner.entry_count

    @property
    def last_hash(self) -> str:
        return self._inner.last_hash

    def append_verified(
        self,
        policy: _core.PolicySnapshot,
        request: _core.KernelInput,
        decision: _core.KernelDecision,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> _core.WalEntry:
        """Replay-verify and append atomically to the writer's logical chain."""
        return self._inner.append_verified(
            policy,
            request,
            decision,
            _canonical_metadata(metadata),
        )

    def flush(self) -> None:
        self._inner.flush()

    def sync(self) -> None:
        self._inner.sync()

    def flush_and_sync(self) -> None:
        self._inner.flush_and_sync()

    def anchor(self) -> _core.WalAnchor:
        """Capture the trusted head; store it outside the WAL file."""
        return self._inner.anchor()

    def close(self, *, sync: bool = True) -> None:
        self._inner.close(sync=sync)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc is None:
            self.close(sync=True)
            return
        try:
            self.close(sync=True)
        except BaseException as close_error:
            note = f"AuditedWal cleanup also failed: {close_error!r}"
            add_note = getattr(exc, "add_note", None)
            if callable(add_note):
                add_note(note)
            else:  # Python 3.10 compatibility for the package's declared floor.
                notes = list(getattr(exc, "__notes__", ()))
                notes.append(note)
                setattr(exc, "__notes__", notes)


def verify_audited_wal(
    path: str | PathLike[str],
    *,
    hmac_key: bytes | None = None,
    anchor: _core.WalAnchor | None = None,
) -> tuple[int, str]:
    """Verify chain integrity and optionally pin the exact trusted head."""
    return _core.verify_audited_wal(path, hmac_key=hmac_key, anchor=anchor)


def replay_verify_audited_wal(
    path: str | PathLike[str],
    policy: _core.PolicySnapshot,
    *,
    hmac_key: bytes | None = None,
    max_entries: int = 100_000,
    max_total_bytes: int = 256 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """Verify WAL entries under explicit aggregate memory/input limits."""
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 0:
        raise ArtifactValidationError("max_entries must be a non-negative integer")
    if (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or max_total_bytes < 0
    ):
        raise ArtifactValidationError("max_total_bytes must be a non-negative integer")
    return list(
        _core.replay_verify_audited_wal(
            path,
            policy,
            hmac_key=hmac_key,
            max_entries=max_entries,
            max_total_bytes=max_total_bytes,
        )
    )


def plan_recovery(
    snapshot_path: str | PathLike[str],
    wal_path: str | PathLike[str],
    *,
    hmac_key: bytes | None = None,
    anchor: _core.WalAnchor | None = None,
) -> dict[str, Any]:
    """Build a chain-verified, optionally anchored crash-recovery plan."""
    return dict(
        _core.plan_recovery(
            snapshot_path,
            wal_path,
            hmac_key=hmac_key,
            anchor=anchor,
        )
    )


def verify_state_trajectory(bundles: list[_core.StatefulAuditBundle]) -> None:
    """Verify structural adjacency inside an unanchored compatibility fragment.

    This does not replay or authenticate embedded audit bundles and does not
    prove genesis or an expected terminal step. New code should prefer the
    explicitly named :func:`verify_state_trajectory_linkage` surface.
    """
    _core.verify_state_trajectory(bundles)


def verify_state_trajectory_linkage(bundles: list[_core.StatefulAuditBundle]) -> None:
    """Verify structural linkage only; per-bundle replay remains separate."""
    _core.verify_state_trajectory(bundles)


def verify_complete_state_trajectory(
    initial_state_bytes: bytes,
    expected_final_step: int,
    bundles: list[_core.StatefulAuditBundle],
) -> None:
    """Verify structural linkage from trusted genesis to a trusted final step."""
    _core.verify_complete_state_trajectory(
        initial_state_bytes,
        expected_final_step,
        bundles,
    )


def verify_complete_state_trajectory_linkage(
    initial_state_bytes: bytes,
    expected_final_step: int,
    bundles: list[_core.StatefulAuditBundle],
) -> None:
    """Verify complete structural linkage; per-bundle replay remains separate."""
    verify_complete_state_trajectory(initial_state_bytes, expected_final_step, bundles)


def verify_state_trajectory_fragment(
    anchor_step: int,
    anchor_digest_hex: str,
    bundles: list[_core.StatefulAuditBundle],
) -> None:
    """Verify structural linkage for a fragment against a trusted anchor."""
    _core.verify_state_trajectory_fragment(anchor_step, anchor_digest_hex, bundles)


def verify_state_trajectory_fragment_linkage(
    anchor_step: int,
    anchor_digest_hex: str,
    bundles: list[_core.StatefulAuditBundle],
) -> None:
    """Verify anchored structural linkage; per-bundle replay remains separate."""
    verify_state_trajectory_fragment(anchor_step, anchor_digest_hex, bundles)
