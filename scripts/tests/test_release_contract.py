from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

# `release_contract` reads Cargo.toml with `tomllib`, which is standard library only
# from 3.11. The wheel supports 3.10 and the release tooling does not have to, so the
# requirement is declared here rather than by dropping the directory from CI.
pytest.importorskip("tomllib", reason="the release contract tooling requires Python 3.11 or newer")

SCRIPT = Path(__file__).parents[1] / "release_contract.py"
SPEC = importlib.util.spec_from_file_location("release_contract", SCRIPT)
# Module setup rather than a test assertion: `assert` here would vanish under
# `python -O` and surface as an unrelated failure further down.
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load the release contract module from {SCRIPT}")
release_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_contract)


def test_repository_release_manifests_are_aligned() -> None:
    root = Path(__file__).parents[2]
    assert release_contract.validate_manifests(root, "v1.3.0") == "1.3.0"  # skipcq: BAN-B101


def test_mismatched_tag_is_rejected() -> None:
    root = Path(__file__).parents[2]
    with pytest.raises(SystemExit, match="tag/package mismatch"):
        release_contract.validate_manifests(root, "v0.5.7")


@pytest.mark.parametrize("tag", ["0.5.7", "v0.5", "v0.5.7+local", "release-v0.5.7"])
def test_noncanonical_tag_is_rejected(tag: str) -> None:
    root = Path(__file__).parents[2]
    with pytest.raises(SystemExit, match="not canonical SemVer"):
        release_contract.validate_manifests(root, tag)


def test_source_archive_rejects_flattened_and_native_artifacts(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Cargo.toml", "[package]\nversion='0.5.7'\n")
        archive.writestr("Cargo.toml", "[package]\nversion='0.5.7'\n")
        archive.writestr("_core.pyd", b"native")

    with pytest.raises(SystemExit, match="duplicate archive path|generated artifact"):
        release_contract.validate_source_archive(archive_path)


def test_source_archive_rejects_unexpected_files(tmp_path: Path) -> None:
    archive_path = tmp_path / "unexpected.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("docs/unreviewed.bin", b"unexpected")
    with pytest.raises(SystemExit, match="unexpected source archive path"):
        release_contract.validate_source_archive(archive_path)


def test_source_archive_roundtrip_preserves_required_paths(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    archive_path = tmp_path / "calybris-source.zip"
    release_contract.package_source_archive(root, archive_path, allow_dirty=True)
    release_contract.validate_source_archive(archive_path)

    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
    assert "src/lib.rs" in names  # skipcq: BAN-B101
    assert "bindings/python/src/lib.rs" in names  # skipcq: BAN-B101
    assert "python/calybris/__init__.py" in names  # skipcq: BAN-B101
    assert ".github/workflows/release.yml" in names  # skipcq: BAN-B101
    assert "proptest-regressions/budget.txt" in names  # skipcq: BAN-B101
    # skipcq: BAN-B101
    # skipcq: BAN-B101
    assert not any(name.startswith(release_contract.SOURCE_INTERNAL_PREFIXES) for name in names)
    denied = (".pyd", ".pdb", ".dll", ".so", ".dylib", ".whl")
    assert not any(name.endswith(denied) for name in names)  # skipcq: BAN-B101
    assert len(names) == len(set(names))  # skipcq: BAN-B101


def test_provenance_rejects_untracked_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[tuple[str, ...]] = []

    def fake_command(_root: Path, *command: str) -> str:
        commands.append(command)
        if command[:2] == ("git", "status"):
            return "?? generated.bin"
        return "unused"

    monkeypatch.setattr(release_contract, "_command", fake_command)
    with pytest.raises(SystemExit, match="source tree is dirty"):
        release_contract.write_provenance(tmp_path, tmp_path / "provenance.json", "0.5.7", None)
    # skipcq: BAN-B101
    # skipcq: BAN-B101
    assert ("git", "status", "--porcelain=v1", "--untracked-files=all") in commands


def test_every_workspace_member_ships_its_manifest() -> None:
    """A source archive that names a member without shipping it does not build.

    This is what went wrong once: Cargo.toml listed calybris-ffi as a workspace
    member and the archive did not contain the directory, so `cargo test
    --workspace` on an unpacked release failed. Parsed from Cargo.toml rather
    than listed here, so adding a crate cannot reintroduce it.
    """
    root = Path(__file__).parents[2]
    shipped = {name for _, name in release_contract.source_file_manifest(root)}

    for member in release_contract.workspace_members(root):
        manifest = "Cargo.toml" if member == "." else f"{member}/Cargo.toml"
        assert manifest in shipped, (  # skipcq: BAN-B101
            f"{member} is a workspace member but {manifest} is not in the "
            f"source archive, so `cargo test --workspace` would fail on it"
        )


def test_the_source_archive_omits_nothing_tracked() -> None:
    """The manifest builder skips what fails validation without saying so.

    That silence is how thirty-one files went missing at once. A tracked file is
    either shipped or deliberately withheld by a rule that names it; anything
    else is an omission, and this is where it surfaces.
    """
    omissions = release_contract.source_manifest_omissions(Path(__file__).parents[2])
    # The report is built first so the assertion is one line: the suppression
    # applies to the line an assert starts on, not the line it ends on.
    report = "\n  ".join(f"{name}: {reason}" for name, reason in omissions)
    assert omissions == [], f"the source archive would omit:\n  {report}"  # skipcq: BAN-B101
