"""Compile calybris-ffi/tests/smoke.c against the static library and run it.

This is the only check that the header and the library agree. The Rust unit
tests in calybris-ffi exercise the same functions, but from Rust, using Rust's
idea of the struct layouts — so a header that declared a field in the wrong
order, or the wrong width, would pass every one of them. A C compiler reading
calybris.h would not.

Usage:

    python scripts/check_c_abi.py            # build, compile, run
    python scripts/check_c_abi.py --release  # against an optimised library

Exits 0 only when the C program runs and reports no failures.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FFI = REPO / "calybris-ffi"


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    print("  $", " ".join(str(part) for part in command))
    return subprocess.run(  # noqa: S603
        command, text=True, capture_output=True, check=False, **kwargs
    )


def cargo_build(profile: str) -> Path:
    """Builds the staticlib and returns its path."""
    command = ["cargo", "build", "-p", "calybris-ffi"]
    if profile == "release":
        command.append("--release")
    result = run(command, cwd=REPO)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit("cargo build failed")

    out = REPO / "target" / profile
    for name in ("calybris_ffi.lib", "libcalybris_ffi.a"):
        candidate = out / name
        if candidate.exists():
            return candidate
    raise SystemExit(f"no static library found in {out}")


def find_msvc() -> tuple[Path, Path] | None:
    """Returns (cl.exe, vcvars64.bat), or None when MSVC is not installed."""
    roots = [
        Path("C:/BuildTools"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/Community"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/Professional"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/Enterprise"),
        Path("C:/Program Files/Microsoft Visual Studio/2022/BuildTools"),
    ]
    for root in roots:
        vcvars = root / "VC/Auxiliary/Build/vcvars64.bat"
        if not vcvars.exists():
            continue
        candidates = sorted((root / "VC/Tools/MSVC").glob("*/bin/Hostx64/x64/cl.exe"))
        if candidates:
            return candidates[-1], vcvars
    return None


def compile_and_run_msvc(library: Path, out_dir: Path) -> int:
    found = find_msvc()
    if found is None:
        print("  MSVC not found; skipping the C check on this machine")
        return 0
    _, vcvars = found

    exe = out_dir / "smoke.exe"
    # What a Rust staticlib needs on Windows. `cargo rustc -- --print
    # native-static-libs` prints the current list; it changes rarely enough to
    # keep here, and a missing one shows up as an unresolved symbol.
    system_libs = [
        "advapi32.lib",
        "bcrypt.lib",
        "kernel32.lib",
        "ntdll.lib",
        "userenv.lib",
        "ws2_32.lib",
        "dbghelp.lib",
        "user32.lib",
        "cfgmgr32.lib",
        "synchronization.lib",
    ]

    # vcvars is a batch script that sets the environment for the rest of the
    # file, so the compile has to happen inside one. Quoting it through a single
    # `cmd /c` argument does not survive.
    script = out_dir / "build_smoke.bat"
    script.write_text(
        "@echo off\r\n"
        f'call "{vcvars}" >nul\r\n'
        "if errorlevel 1 exit /b 1\r\n"
        f'cl /nologo /W4 /WX /I "{FFI / "include"}" '
        f'"{FFI / "tests" / "smoke.c"}" '
        f'/Fo:"{out_dir}\\\\" /Fe:"{exe}" '
        f'/link "{library}" {" ".join(system_libs)}\r\n'
        "exit /b %errorlevel%\r\n",
        encoding="ascii",
    )

    result = run(["cmd", "/c", str(script)])
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit("compiling smoke.c failed")

    print("  compiled with cl.exe (/W4 /WX)")
    run_result = run([str(exe)])
    print(run_result.stdout, end="")
    if run_result.stderr:
        print(run_result.stderr, file=sys.stderr)
    return run_result.returncode


def compile_and_run_unix(library: Path, out_dir: Path) -> int:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        print("  no C compiler found; skipping the C check on this machine")
        return 0

    exe = out_dir / "smoke"
    command = [
        compiler,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(FFI / "include"),
        str(FFI / "tests" / "smoke.c"),
        str(library),
        "-o",
        str(exe),
        "-lpthread",
        "-ldl",
        "-lm",
    ]
    result = run(command)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit("compiling smoke.c failed")

    print(f"  compiled with {Path(compiler).name} (-Wall -Wextra -Werror)")
    run_result = run([str(exe)])
    print(run_result.stdout, end="")
    if run_result.stderr:
        print(run_result.stderr, file=sys.stderr)
    return run_result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="build optimised")
    args = parser.parse_args()
    profile = "release" if args.release else "debug"

    print(f"C ABI check ({platform.system()}, {profile})")
    library = cargo_build(profile)
    print(f"  library: {library.relative_to(REPO)}")

    out_dir = REPO / "target" / "c-abi"
    out_dir.mkdir(parents=True, exist_ok=True)

    if os.name == "nt":
        code = compile_and_run_msvc(library, out_dir)
    else:
        code = compile_and_run_unix(library, out_dir)

    if code != 0:
        print("C ABI check FAILED", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
