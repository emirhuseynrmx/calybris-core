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
    ".deepsource.toml",
    # Governs how the fuzz corpus is checked out: without it the binary seed is
    # line-ending translated on Windows and stops being the bytes it was.
    ".gitattributes",
    ".gitignore",
    "Cargo.lock",
    "Cargo.toml",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README-crates.md",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "build.rs",
    "deny.toml",
    "pyproject.toml",
}
SOURCE_ROOTS = {
    # `.cargo/audit.toml`: the one advisory cargo audit is told to ignore, and
    # why. Without it the security job fails on a source build.
    ".cargo",
    ".github",
    "assets",
    "benches",
    "bindings",
    # The C ABI crate is a workspace member. A source archive that names it in
    # Cargo.toml without shipping it does not build.
    "calybris-ffi",
    "docs",
    "examples",
    # Not a workspace member, but the seeds are part of the test corpus and the
    # targets are what a reviewer reruns.
    "fuzz",
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
    # One WAL seed, which is newline-delimited JSON.
    ".jsonl",
    ".lock",
    ".md",
    ".pdf",
    ".png",
    ".py",
    ".pyi",
    # Proptest writes its pinned counterexamples here. Dropping them loses the
    # inputs that once failed, which is the only reason the file exists.
    ".proptest-regressions",
    ".rs",
    ".toml",
    ".typ",
    ".txt",
    ".typed",
    ".yml",
}
# Files whose whole name is the allowlist, because they have no extension.
SOURCE_ALLOWED_NAMES = {
    ".gitignore",
}
# Suffixes allowed only under a particular prefix. A C source file belongs to
# the C ABI crate and a raw fuzz seed belongs to the corpus; allowing either
# anywhere would let a stray binary into `docs/`, which is what the rest of this
# allowlist exists to prevent.
SOURCE_SCOPED_SUFFIXES = {
    # The header is part of the frozen contract, and smoke.c is the only test
    # that checks the header against the library.
    ".c": ("calybris-ffi/",),
    ".h": ("calybris-ffi/",),
    # One seed, for the target that reads raw integers rather than JSON.
    ".bin": ("fuzz/seeds/",),
    # Checkpoints, OpenTimestamps proofs, RFC 3161 requests, responses and
    # certificates, a Bitcoin header: the byte-exact inputs the trust-layer
    # tests and fuzz targets are pinned to.
    ".body": ("tests/fixtures/",),
    ".checkpoint": ("tests/fixtures/", "fuzz/seeds/"),
    ".cnf": ("tests/fixtures/",),
    ".crt": ("tests/fixtures/",),
    ".hex": ("tests/fixtures/",),
    ".ots": ("tests/fixtures/", "fuzz/seeds/"),
    ".tsq": ("tests/fixtures/",),
    ".tsr": ("tests/fixtures/", "fuzz/seeds/"),
    # A checkpoint bundle as `calybris-verify` writes it: the log-signed note
    # and the public keys, checked by both the tool and scripts/verify_bundle.py.
    ".signed": ("tests/fixtures/",),
    ".vkey": ("tests/fixtures/",),
    # The Go program that generated the C2SP interop vectors, so they can be
    # regenerated rather than taken on trust.
    ".go": ("tests/interop/",),
    ".mod": ("tests/interop/",),
    ".sum": ("tests/interop/",),
}
SOURCE_REQUIRED_FILES = {
    "Cargo.toml",
    "build.rs",
    "src/lib.rs",
    "bindings/python/Cargo.toml",
    "bindings/python/build.rs",
    "bindings/python/src/lib.rs",
    "calybris-ffi/Cargo.toml",
    "calybris-ffi/src/lib.rs",
    "calybris-ffi/include/calybris.h",
    "calybris-ffi/tests/smoke.c",
    "python/calybris/__init__.py",
    "python/calybris/_core.pyi",
    "scripts/release_contract.py",
    ".github/workflows/release.yml",
    "proptest-regressions/budget.txt",
}
# Internal working notes and unpublished validation artifacts. The manifest walks
# the filesystem rather than the index, so ignore rules alone do not keep these
# out of a published archive.
SOURCE_INTERNAL_PREFIXES = (
    "docs/CALYRA_AUDIT_REPORT_",
    "docs/ENTERPRISE_GAUNTLET.md",
    "docs/audits/",
    "docs/calyra-audit-report-",
    "docs/superpowers/",
)
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
            members = [
                member
                for member in archive.getmembers()
                if member.name.endswith("/PKG-INFO")
            ]
            if len(members) != 1:
                raise SystemExit(f"sdist has {len(members)} PKG-INFO files: {path.name}")
            extracted = archive.extractfile(members[0])
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


# One flat chain of independent refusals. Splitting it would scatter the
# allowlist across helpers without making any single rule easier to read.
def _validate_source_name(name: str) -> PurePosixPath:  # skipcq: PY-R1000
    if "\\" in name:
        raise SystemExit(f"source archive path is not POSIX-normalized: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise SystemExit(f"unsafe source archive path: {name!r}")
    if any(part in SOURCE_DENIED_PARTS or part.endswith(".egg-info") for part in path.parts):
        raise SystemExit(f"generated artifact path in source archive: {name!r}")
    if path.suffix.lower() in SOURCE_DENIED_SUFFIXES:
        raise SystemExit(f"generated artifact in source archive: {name!r}")
    if name.startswith(SOURCE_INTERNAL_PREFIXES):
        raise SystemExit(f"internal document in source archive: {name!r}")
    if path.parts[0] in SOURCE_ROOT_FILES and len(path.parts) == 1:
        return path
    if path.parts[0] not in SOURCE_ROOTS:
        raise SystemExit(f"unexpected source archive path: {name!r}")
    if path.name in SOURCE_ALLOWED_NAMES:
        return path
    suffix = path.suffix.lower()
    scopes = SOURCE_SCOPED_SUFFIXES.get(suffix)
    if scopes is not None:
        if not name.startswith(scopes):
            # Keeps the generic phrase, because a caller matching on the class
            # of failure should not have to know about scoping, and adds the
            # reason, because a caller fixing it does.
            raise SystemExit(
                f'unexpected source archive path: {name!r} '
                f"({suffix} is only allowed under {' or '.join(scopes)})"
            )
        return path
    if suffix not in SOURCE_ALLOWED_SUFFIXES:
        raise SystemExit(f"unexpected source archive path: {name!r}")
    return path


def workspace_members(root: Path) -> list[str]:
    """Every path in `[workspace] members`, as written in the root Cargo.toml.

    Parsed rather than listed, so that adding a crate cannot silently leave it
    out of the source archive — which is exactly what happened to calybris-ffi.
    """
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    block = re.search(r"^\[workspace\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if block is None:
        raise SystemExit("the root Cargo.toml declares no [workspace]")
    members = re.search(r"members\s*=\s*\[(.*?)\]", block.group(1), re.S)
    if members is None:
        raise SystemExit("the [workspace] table declares no members")
    found = re.findall(r'"([^"]+)"', members.group(1))
    if not found:
        raise SystemExit("the [workspace] members list is empty")
    return found


def source_manifest_omissions(root: Path) -> list[tuple[str, str]]:
    """Tracked files the manifest would leave out, and why.

    `source_file_manifest` skips anything that fails validation without saying
    so, which is how thirty-one files went missing from a release archive at
    once. This reports them instead, so a test can refuse.

    Returns an empty list when git is unavailable; a machine without git cannot
    answer the question, and guessing would be worse than declining.
    """
    try:
        # `git` from PATH, as every other call in this file resolves it; the
        # release job runs on a runner whose PATH it controls.
        listed = subprocess.run(  # skipcq: BAN-B607
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    if listed.returncode != 0:
        return []

    shipped = {name for _, name in source_file_manifest(root)}
    omissions: list[tuple[str, str]] = []
    for name in sorted(listed.stdout.split()):
        if name in shipped:
            continue
        if name.startswith(SOURCE_INTERNAL_PREFIXES):
            continue  # deliberately withheld, and the prefix names it
        try:
            _validate_source_name(name)
        except SystemExit as reason:
            omissions.append((name, str(reason)))
        else:
            omissions.append((name, "not reached by any allowlisted root"))
    return omissions


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
