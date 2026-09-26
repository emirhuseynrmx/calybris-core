"""Compare Rust canonicalization to the independent official OTS implementation.

Requires pip install opentimestamps. No calendar/network access needed.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    cargo = shutil.which("cargo")
    if cargo is None:
        print("cargo is not on PATH", file=sys.stderr)
        return 2
    for fixture in sorted((root / "tests/fixtures/ots").glob("*.ots")):
        original = fixture.read_bytes()
        parsed = DetachedTimestampFile.deserialize(BytesDeserializationContext(original))
        context = BytesSerializationContext()
        parsed.serialize(context)
        official = context.getbytes()
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "canonical.ots"
            subprocess.run(  # nosec B603: fixed argument list, no shell
                [
                    cargo,
                    "run",
                    "--quiet",
                    "--example",
                    "ots_canonical",
                    "--features",
                    "preview",
                    "--",
                    str(fixture),
                    str(output),
                ],
                cwd=root,
                check=True,
            )
            actual = output.read_bytes()
        # Explicit checks rather than `assert`, which `python -O` removes.
        if actual != official:
            print(f"FAIL {fixture.name}: canonical bytes differ", file=sys.stderr)
            return 1
        reparsed = DetachedTimestampFile.deserialize(BytesDeserializationContext(actual))
        if reparsed.file_digest != parsed.file_digest:
            print(f"FAIL {fixture.name}: file digest changed", file=sys.stderr)
            return 1
        print(f"PASS {fixture.name}: official/Rust bytes and file digest agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
