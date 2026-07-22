#!/usr/bin/env python3
"""Validate Calybris release versions and emit reproducible provenance metadata."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path

import tomllib

TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


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


def _command(root: Path, *command: str) -> str:
    return subprocess.check_output(command, cwd=root, text=True).strip()


def write_provenance(root: Path, output: Path, version: str, tag: str | None) -> None:
    dirty = bool(_command(root, "git", "status", "--porcelain", "--untracked-files=no"))
    if dirty:
        raise SystemExit("tracked source tree is dirty; refusing provenance generation")
    payload = {
        "schema_version": "calybris.release-provenance.v1",
        "version": version,
        "tag": tag,
        "git_commit": _command(root, "git", "rev-parse", "HEAD"),
        "tracked_tree_dirty": False,
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
    print(f"release contract OK: version={version} tag={tag or 'none'}")


if __name__ == "__main__":
    main()
