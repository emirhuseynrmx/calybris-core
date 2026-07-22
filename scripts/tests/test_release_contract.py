from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "release_contract.py"
SPEC = importlib.util.spec_from_file_location("release_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_contract)


def test_repository_release_manifests_are_aligned() -> None:
    root = Path(__file__).parents[2]
    assert release_contract.validate_manifests(root, "v0.5.7") == "0.5.7"


def test_mismatched_tag_is_rejected() -> None:
    root = Path(__file__).parents[2]
    with pytest.raises(SystemExit, match="tag/package mismatch"):
        release_contract.validate_manifests(root, "v0.5.8")


@pytest.mark.parametrize("tag", ["0.5.7", "v0.5", "v0.5.7+local", "release-v0.5.7"])
def test_noncanonical_tag_is_rejected(tag: str) -> None:
    root = Path(__file__).parents[2]
    with pytest.raises(SystemExit, match="not canonical SemVer"):
        release_contract.validate_manifests(root, tag)
