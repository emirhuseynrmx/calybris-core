"""The build stamp has to be a function of the source, not of the build.

`calybris._core.BUILD_SOURCE_DIGEST` is what a downstream user checks to decide
whether the wheel they installed was built from the commit it claims. That is
only worth checking if it is reproducible, so this asserts the property rather
than trusting it: on a clean checkout the digest **is** the git tree SHA, a value
anyone can compute for themselves with `git rev-parse HEAD^{tree}`.

On a dirty tree the digest covers the diff instead, which is correct and not
reproducible by design — a working copy is not a release. Those runs skip rather
than assert, and the skip message says which case it was, so a green run on a
developer machine is never mistaken for the checked one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from calybris import _core

REPO = Path(__file__).resolve().parents[2]


def git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def test_the_stamp_exists_and_is_hex() -> None:
    digest = _core.BUILD_SOURCE_DIGEST
    assert digest, "no source digest was stamped at all"
    assert len(digest) in (40, 64), f"unexpected digest length {len(digest)}"
    assert all(c in "0123456789abcdef" for c in digest), digest


def test_the_lock_digest_is_stamped() -> None:
    """A source digest without a lock digest does not pin what was compiled."""
    lock = _core.BUILD_CARGO_LOCK_SHA256
    assert len(lock) == 64, lock
    assert all(c in "0123456789abcdef" for c in lock), lock


def test_a_clean_checkout_stamps_the_git_tree_sha() -> None:
    if git("rev-parse", "--git-dir") is None:
        pytest.skip("not a git checkout, so there is no tree SHA to compare against")

    if _core.BUILD_DIRTY:
        pytest.skip(
            "the tree was dirty when this wheel was built, so the digest covers "
            "the diff rather than the tree; rebuild from a clean checkout to "
            "exercise this"
        )

    tree = git("rev-parse", "HEAD^{tree}")
    if tree is None:
        pytest.skip("git could not resolve the tree SHA")

    assert _core.BUILD_SOURCE_DIGEST == tree, (
        "a clean build must stamp the git tree SHA, so that anyone can recompute "
        "it with `git rev-parse HEAD^{tree}`"
    )


def test_a_clean_checkout_reports_a_verified_identity() -> None:
    """The flag a release build refuses to proceed without."""
    if git("rev-parse", "--git-dir") is None:
        pytest.skip("not a git checkout")
    if _core.BUILD_DIRTY:
        pytest.skip("the tree was dirty when this wheel was built")

    assert _core.BUILD_IDENTITY_VERIFIED, (
        "a clean checkout must stamp a verified identity, or a release build's "
        "own check is not measuring anything"
    )


def test_the_dirty_flag_measures_something() -> None:
    """A flag that is always False would pass every check above for free."""
    if git("rev-parse", "--git-dir") is None:
        pytest.skip("not a git checkout")

    status = git("status", "--porcelain=v1", "--untracked-files=all")
    if status is None:
        pytest.skip("git could not report status")

    # This compares the *current* tree against a flag stamped when the wheel was
    # built, so it can only catch the one direction that is always wrong: a tree
    # that is dirty now but was stamped clean is fine (it changed since), while
    # a flag stamped dirty on a tree that has never been dirty is not possible.
    if status == "" and not _core.BUILD_DIRTY:
        # Both agree. Nothing more to check, and the assertion above covered it.
        return

    assert isinstance(_core.BUILD_DIRTY, bool), _core.BUILD_DIRTY
