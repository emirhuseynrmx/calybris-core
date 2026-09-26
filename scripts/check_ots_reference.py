"""Compare Rust canonicalization to the independent official OTS implementation.

Requires pip install opentimestamps. No calendar/network access needed.
"""
import pathlib
import subprocess
import tempfile
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile

root = pathlib.Path(__file__).resolve().parents[1]
for fixture in sorted((root / "tests/fixtures/ots").glob("*.ots")):
    original = fixture.read_bytes()
    parsed = DetachedTimestampFile.deserialize(BytesDeserializationContext(original))
    context = BytesSerializationContext()
    parsed.serialize(context)
    official = context.getbytes()
    with tempfile.TemporaryDirectory() as directory:
        output = pathlib.Path(directory) / "canonical.ots"
        subprocess.run(["cargo", "run", "--quiet", "--example", "ots_canonical",
                        "--features", "preview", "--", str(fixture), str(output)],
                       cwd=root, check=True)
        actual = output.read_bytes()
        assert actual == official, f"canonical bytes differ: {fixture.name}"
        reparsed = DetachedTimestampFile.deserialize(BytesDeserializationContext(actual))
        assert reparsed.file_digest == parsed.file_digest
    print(f"PASS {fixture.name}: official/Rust bytes and file digest agree")
