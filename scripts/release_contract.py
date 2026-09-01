#!/usr/bin/env python3
"""Validate Calybris release versions and emit reproducible provenance metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path, PurePosixPath

import tomllib

TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
SOURCE_ROOT_FILES = {
    ".codecov.yml",
    ".gitignore",
    "Cargo.lock",
    "Cargo.toml",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "build.rs",
    "deny.toml",
    "pyproject.toml",
}
SOURCE_ROOTS = {
    ".github",
    "assets",
    "benches",
    "bindings",
    "docs",
    "examples",
    "proptest-regressions",
    "python",
    "scripts",
    "src",
    "tests",
}
SOURCE_DENIED_PARTS = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "target",
    "work",
}
SOURCE_DENIED_SUFFIXES = {
    ".dll",
    ".dylib",
    ".exe",
    ".egg-info",
    ".pdb",
    ".pyc",
    ".pyd",
    ".pyo",
    ".so",
    ".tar",
    ".whl",
    ".zip",
}
SOURCE_ALLOWED_SUFFIXES = {
    ".json",
    ".lock",
    ".md",
    ".pdf",
    ".png",
    ".py",
    ".pyi",
    ".rs",
    ".toml",
    ".typ",
    ".txt",
    ".typed",
    ".yml",
}
SOURCE_REQUIRED_FILES = {
    "Cargo.toml",
    "build.rs",
    "src/lib.rs",
    "bindings/python/Cargo.toml",
    "bindings/python/build.rs",
    "bindings/python/src/lib.rs",
    "python/calybris/__init__.py",
    "python/calybris/_core.pyi",
    "scripts/release_contract.py",
    ".github/workflows/release.yml",
    "proptest-regressions/budget.txt",
}
SOURCE_MAX_ENTRY_BYTES = 32 * 1024 * 1024
SOURCE_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def _toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate_manifests(root: Path, tag: str | None) -> str:
    root_manifest = _toml(root / "Cargo.toml")
    binding_manifest = _toml(root / "bindings" / "python" / "Cargo.toml")
    pyproject = _toml(root / "pyproject.toml")

    version = str(root_manifest["package"]["version"])
    binding_version = str(binding_manifest["package"]["version"])
    dependency_version = str(binding_manifest["dependencies"]["calybris-core-rs"]["version"])
    if binding_version != version or dependency_version != version:
        raise SystemExit(
            "version mismatch: "
            f"root={version} binding={binding_version} dependency={dependency_version}"
        )
    maturin_manifest = pyproject["tool"]["maturin"].get("manifest-path")
    if maturin_manifest != "bindings/python/Cargo.toml":
        raise SystemExit(f"unexpected maturin manifest-path: {maturin_manifest!r}")
    if "version" not in pyproject["project"].get("dynamic", []):
        raise SystemExit("pyproject version must be sourced dynamically from the binding manifest")

    if tag is not None:
        if TAG_PATTERN.fullmatch(tag) is None:
            raise SystemExit(f"release tag is not canonical SemVer: {tag!r}")
        if tag[1:] != version:
            raise SystemExit(f"tag/package mismatch: tag={tag[1:]} package={version}")
    return version


def _distribution_metadata(path: Path) -> tuple[str, str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(candidates) != 1:
                raise SystemExit(f"wheel has {len(candidates)} METADATA files: {path.name}")
            metadata = archive.read(candidates[0]).decode("utf-8")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            candidates = [
                member
                for member in archive.getmembers()
                if member.name.endswith("/PKG-INFO")
            ]
            if len(candidates) != 1:
                raise SystemExit(f"sdist has {len(candidates)} PKG-INFO files: {path.name}")
            extracted = archive.extractfile(candidates[0])
            if extracted is None:
                raise SystemExit(f"cannot read PKG-INFO: {path.name}")
            metadata = extracted.read().decode("utf-8")
    else:
        raise SystemExit(f"unexpected distribution file: {path.name}")
    parsed = Parser().parsestr(metadata)
    return parsed["Name"], parsed["Version"]


def validate_distributions(directory: Path, version: str) -> None:
    distributions = sorted(path for path in directory.iterdir() if path.is_file())
    if not any(path.suffix == ".whl" for path in distributions):
        raise SystemExit("release set contains no wheel")
    if not any(path.name.endswith(".tar.gz") for path in distributions):
        raise SystemExit("release set contains no sdist")
    for path in distributions:
        name, artifact_version = _distribution_metadata(path)
        if name != "calybris" or artifact_version != version:
            raise SystemExit(
                "distribution metadata mismatch in "
                f"{path.name}: name={name} version={artifact_version}"
            )


def _validate_source_name(name: str) -> PurePosixPath:
    if "\\" in name:
        raise SystemExit(f"source archive path is not POSIX-normalized: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise SystemExit(f"unsafe source archive path: {name!r}")
    if any(part in SOURCE_DENIED_PARTS or part.endswith(".egg-info") for part in path.parts):
        raise SystemExit(f"generated artifact path in source archive: {name!r}")
    if path.suffix.lower() in SOURCE_DENIED_SUFFIXES:
        raise SystemExit(f"generated artifact in source archive: {name!r}")
    if path.parts[0] in SOURCE_ROOT_FILES and len(path.parts) == 1:
        return path
    if path.parts[0] not in SOURCE_ROOTS or path.suffix.lower() not in SOURCE_ALLOWED_SUFFIXES:
        raise SystemExit(f"unexpected source archive path: {name!r}")
    return path


def source_file_manifest(root: Path) -> list[tuple[Path, str]]:
    """Return the explicit, sorted source-release manifest.

    The manifest is allowlisted by repository root and excludes every generated
    native, cache, package, and build artifact regardless of ignore rules.
    """
    root = root.resolve()
    files: list[tuple[Path, str]] = []
    for name in sorted(SOURCE_ROOT_FILES):
        candidate = root / name
        if candidate.is_file():
            files.append((candidate, name))
    for root_name in sorted(SOURCE_ROOTS):
        directory = root / root_name
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.rglob("*")):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            relative = candidate.relative_to(root).as_posix()
            try:
                _validate_source_name(relative)
            except SystemExit:
                continue
            files.append((candidate, relative))
    names = [name for _, name in files]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate source path in packaging manifest")
    missing = sorted(SOURCE_REQUIRED_FILES - set(names))
    if missing:
        raise SystemExit(f"source packaging manifest is missing required files: {missing}")
    return files


def source_manifest_digest(root: Path) -> str:
    digest = hashlib.sha256(b"calybris.source-manifest.v1\0")
    for source, relative in source_file_manifest(root):
        data = source.read_bytes()
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "little"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def validate_source_archive(path: Path) -> None:
    """Validate the strict, portable Calybris source-ZIP contract."""
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise SystemExit("duplicate archive path in source ZIP")
            for info in infos:
                _validate_source_name(info.filename)
                if info.file_size > SOURCE_MAX_ENTRY_BYTES:
                    raise SystemExit(f"source archive entry is too large: {info.filename!r}")
            if sum(info.file_size for info in infos) > SOURCE_MAX_TOTAL_BYTES:
                raise SystemExit("source archive exceeds the aggregate size limit")
            missing = sorted(SOURCE_REQUIRED_FILES - set(names))
            if missing:
                raise SystemExit(f"source archive is missing required files: {missing}")
            root_manifest = tomllib.loads(archive.read("Cargo.toml").decode("utf-8"))
            binding_manifest = tomllib.loads(
                archive.read("bindings/python/Cargo.toml").decode("utf-8")
            )
            root_version = str(root_manifest["package"]["version"])
            binding_version = str(binding_manifest["package"]["version"])
            if root_version != binding_version:
                raise SystemExit(
                    "source archive version mismatch: "
                    f"root={root_version} binding={binding_version}"
                )
            bad = archive.testzip()
            if bad is not None:
                raise SystemExit(f"source archive CRC failed: {bad}")
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"invalid source ZIP: {exc}") from exc


def package_source_archive(root: Path, output: Path, *, allow_dirty: bool = False) -> None:
    """Create a deterministic source ZIP with relative POSIX paths."""
    root = root.resolve()
    if not allow_dirty:
        status = _command(root, "git", "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            raise SystemExit("source tree is dirty; refusing source archive generation")
    manifest = source_file_manifest(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(f".{output.name}.tmp.{os.getpid()}")
    try:
        with zipfile.ZipFile(
            temp,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for source, relative in manifest:
                data = source.read_bytes()
                if len(data) > SOURCE_MAX_ENTRY_BYTES:
                    raise SystemExit(f"source file is too large: {relative!r}")
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100644 & 0xFFFF) << 16
                archive.writestr(info, data, compresslevel=9)
        validate_source_archive(temp)
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)


def _command(root: Path, *command: str) -> str:
    return subprocess.check_output(command, cwd=root, text=True).strip()


def write_provenance(root: Path, output: Path, version: str, tag: str | None) -> None:
    dirty = bool(_command(root, "git", "status", "--porcelain=v1", "--untracked-files=all"))
    if dirty:
        raise SystemExit("source tree is dirty; refusing provenance generation")
    payload = {
        "schema_version": "calybris.release-provenance.v1",
        "version": version,
        "tag": tag,
        "git_commit": _command(root, "git", "rev-parse", "HEAD"),
        "tracked_tree_dirty": False,
        "source_manifest_sha256": source_manifest_digest(root),
        "build_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "rustc": _command(root, "rustc", "--version", "--verbose"),
        "cargo": _command(root, "cargo", "--version", "--verbose"),
        "ci_run_id": os.environ.get("GITHUB_RUN_ID"),
        "ci_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "ci_run_url": (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
            f"{os.environ['GITHUB_RUN_ID']}"
            if all(
                os.environ.get(name)
                for name in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")
            )
            else None
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--tag")
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--source-zip", type=Path)
    parser.add_argument("--allow-dirty-source", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    tag = args.tag
    if tag is None and os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ.get("GITHUB_REF_NAME")
    version = validate_manifests(root, tag)
    if args.dist is not None:
        validate_distributions(args.dist.resolve(), version)
    if args.provenance is not None:
        write_provenance(root, args.provenance.resolve(), version, tag)
    if args.source_zip is not None:
        package_source_archive(
            root,
            args.source_zip.resolve(),
            allow_dirty=args.allow_dirty_source,
        )
    print(f"release contract OK: version={version} tag={tag or 'none'}")


if __name__ == "__main__":
    main()
