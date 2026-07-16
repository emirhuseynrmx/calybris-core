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


def _canonical_metadata(metadata: Mapping[str, Any] | None) -> str:
    """Encode WAL metadata deterministically and reject non-standard floats."""
    try:
        return json.dumps(
            {} if metadata is None else dict(metadata),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactValidationError(f"metadata must be canonical JSON data: {exc}") from exc


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
        self.close(sync=True)


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
) -> list[dict[str, Any]]:
    """Verify every WAL entry's chain, digests, and decision replay."""
    return list(_core.replay_verify_audited_wal(path, policy, hmac_key=hmac_key))


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
    """Reject dropped, reordered, or disconnected state transitions."""
    _core.verify_state_trajectory(bundles)
