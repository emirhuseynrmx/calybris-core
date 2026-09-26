#!/usr/bin/env python3
"""Check a Calybris checkpoint bundle without Calybris.

Written from the public specifications, sharing no code with the Rust crate:
C2SP signed-note, tlog-checkpoint and tlog-cosignature for the signatures,
RFC 8032 for Ed25519, RFC 9162 for the Merkle tree, and the Calybris WAL rule
``entry_hash = SHA-256(previous_hash || data)`` (HMAC-SHA-256 with a key) for
the hash chain. Python's standard library is all it needs:

    python3 verify_bundle.py BUNDLE_DIR [--witness witness.vkey ...]

A bundle directory holds the files ``calybris-verify`` writes:

    000001.checkpoint          the signed note, with witness cosignatures
    000001.checkpoint.signed   the note with the log's signature only (stamped)
    000001.checkpoint.signed.ots, .tsr   timestamps over it, if any
    log.vkey, witness.vkey     the public keys
    decisions.wal.jsonl        the decision log the checkpoint commits to

Timestamps are checked with their own standard tools (``openssl ts -verify``,
``ots verify`` or opentimestamps.org); this prints the commands. It exits 0
when every check it made passed and 1 otherwise. It does not replay the
decisions: that needs the policies, and it is ``calybris-verify audit``'s job.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

# --- Ed25519 verification (RFC 8032, section 5.1.7) -------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = tuple[int, int, int, int]


def _add(a: Point, b: Point) -> Point:
    """Addition in extended coordinates (RFC 8032, section 5.1.4)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % _P
    pb = (y1 + x1) * (y2 + x2) % _P
    pc = 2 * t1 * t2 * _D % _P
    pd = 2 * z1 * z2 % _P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while s:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _same(a: Point, b: Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _decompress(s: bytes) -> Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BASE = _decompress((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid Ed25519 signature of ``message``."""
    if len(signature) != 64 or _BASE is None:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little")
    return _same(_mul(s, _BASE), _add(r, _mul(h % _L, a)))


# --- C2SP notes, keys and cosignatures ----------------------------------------


class Key:
    """A C2SP verifier key: ``name+hash+base64(algorithm || public key)``."""

    def __init__(self, text: str) -> None:
        name, key_hash, encoded = text.strip().split("+", 2)
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 33 or raw[0] not in (0x01, 0x04):
            raise ValueError("not an Ed25519 note key or cosignature/v1 key")
        if hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4].hex() != key_hash:
            raise ValueError("the key hash does not match the key")
        self.name, self.algorithm, self.public = name, raw[0], raw[1:]
        self.hash = bytes.fromhex(key_hash)


def parse_note(text: str) -> tuple[str, list[tuple[str, bytes, bytes, str]]]:
    """The note's text and its signature lines as (name, key hash, signature, line)."""
    split = text.rindex("\n\n")
    body, block = text[: split + 1], text[split + 2 :]
    if not block.endswith("\n"):
        raise ValueError("the note does not end in a newline")
    signatures = []
    for line in block[:-1].split("\n"):
        dash, name, encoded = line.split(" ", 2)
        if dash != "—":
            raise ValueError("a signature line does not start with an em dash")
        raw = base64.b64decode(encoded, validate=True)
        signatures.append((name, raw[:4], raw[4:], line))
    return body, signatures


def signature_by(signatures: list, key: Key) -> tuple[bytes, str] | None:
    for name, key_hash, sig, line in signatures:
        if name == key.name and key_hash == key.hash:
            return sig, line
    return None


def cosigned_at(body: str, sig: bytes, key: Key) -> int | None:
    """The time a cosignature/v1 states, if it verifies.

    A time of zero is refused (C2SP tlog-witness: a witness MUST NOT omit
    it), as is one above 2^63 - 1 (tlog-cosignature).
    """
    if len(sig) != 72:
        return None
    (when,) = struct.unpack(">Q", sig[:8])
    if when == 0 or when >= 2**63:
        return None
    message = f"cosignature/v1\ntime {when}\n".encode() + body.encode()
    return when if ed25519_verify(key.public, message, sig[8:]) else None


# --- RFC 9162 Merkle tree and the WAL chain -----------------------------------


def merkle_root(leaves: list[bytes]) -> bytes:
    """MTH of RFC 9162, section 2.1.1, iteratively over a stack of subtrees."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    stack: list[tuple[int, bytes]] = []
    for leaf in leaves:
        size, node = 1, leaf
        while stack and stack[-1][0] == size:
            _, left = stack.pop()
            size, node = size * 2, hashlib.sha256(b"\x01" + left + node).digest()
        stack.append((size, node))
    _, node = stack.pop()
    while stack:
        _, left = stack.pop()
        node = hashlib.sha256(b"\x01" + left + node).digest()
    return node


def wal_leaves(path: Path, hmac_key: bytes | None) -> tuple[list[bytes], str | None]:
    """The Merkle leaves of a WAL, or the first place its hash chain breaks."""
    previous = "genesis"
    leaves: list[bytes] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry = json.loads(line)
        # The chain hashes the data exactly as written, and "data" is the
        # last field of an entry: take its bytes from the line itself.
        data = line[line.index('"data":') + len('"data":') : -1]
        message = (previous + data).encode()
        expected = (
            hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
            if hmac_key
            else hashlib.sha256(message).hexdigest()
        )
        if entry["previous_hash"] != previous or entry["entry_hash"] != expected:
            return leaves, f"entry {number} breaks the hash chain"
        previous = entry["entry_hash"]
        leaves.append(hashlib.sha256(b"\x00" + bytes.fromhex(previous)).digest())
    return leaves, None


# --- The bundle ---------------------------------------------------------------

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


class Report:
    """Counts what passed and what failed, printing each as it is decided."""

    def __init__(self) -> None:
        self.passed = 0
        self.failures = 0

    def ok(self, what: str, detail: str) -> None:
        self.passed += 1
        print(f"  ok      {what}: {detail}")

    def fail(self, what: str, detail: str) -> None:
        self.failures += 1
        print(f"  FAILED  {what}: {detail}")


def check_log(r: Report, body: str, signatures: list, log: Key) -> tuple[bytes, str] | None:
    """The log's own signature line, if it verifies."""
    found = signature_by(signatures, log)
    if found and log.algorithm == 0x01 and ed25519_verify(log.public, body.encode(), found[0]):
        r.ok("log signature", f"{log.name} (the operator's own)")
        return found
    r.fail("log signature", f"no valid signature by {log.name}")
    return None


def check_witness(r: Report, body: str, signatures: list, w: Key) -> None:
    cosig = signature_by(signatures, w)
    when = cosigned_at(body, cosig[0], w) if cosig and w.algorithm == 0x04 else None
    if when is None:
        r.fail("witness", f"no valid cosignature by {w.name}")
    else:
        r.ok("witness", f"{w.name} cosigned at Unix time {when}")


def check_stamped(r: Report, signed_path: Path, expected: bytes) -> None:
    """The bytes that were timestamped, and the OpenTimestamps file over them."""
    signed = signed_path.read_bytes()
    if signed == expected:
        r.ok("stamped bytes", f"{signed_path.name} is the note with the log's signature")
    else:
        r.fail("stamped bytes", f"{signed_path.name} is not the log-signed note")
    ots = signed_path.with_name(f"{signed_path.name}.ots")
    if not ots.exists():
        return
    proof, digest = ots.read_bytes(), hashlib.sha256(signed).digest()
    start = len(OTS_MAGIC) + 2  # the major version and the SHA-256 tag
    if proof.startswith(OTS_MAGIC) and proof[start : start + 32] == digest:
        r.ok("OpenTimestamps file", f"is a proof of SHA-256 {digest.hex()}")
    else:
        r.fail("OpenTimestamps file", "is not a proof of the stamped bytes")


def check_wal(r: Report, wal_path: Path, hmac_key: bytes | None, size: int, root: bytes) -> None:
    leaves, broken = wal_leaves(wal_path, hmac_key)
    if broken:
        r.fail("WAL", broken)
    elif len(leaves) < size or merkle_root(leaves[:size]) != root:
        r.fail("Merkle root", "the WAL does not reproduce the checkpoint root")
    else:
        r.ok("WAL chain", f"{len(leaves)} entries, each hashing its predecessor")
        r.ok("Merkle root", f"the first {size} entries reproduce it (RFC 9162)")


def verify(
    bundle: Path,
    note_name: str = "000001.checkpoint",
    log_key: str = "log.vkey",
    witness_keys: tuple[str, ...] = ("witness.vkey",),
    wal: str = "decisions.wal.jsonl",
    hmac_key: bytes | None = None,
) -> int:
    r = Report()
    body, signatures = parse_note((bundle / note_name).read_text(encoding="utf-8"))
    lines = body.rstrip("\n").split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2], validate=True)
    print(f"checkpoint {origin}, {size} records, root {root.hex()}")

    found = check_log(r, body, signatures, Key((bundle / log_key).read_text(encoding="utf-8")))
    for path in witness_keys:
        check_witness(r, body, signatures, Key((bundle / path).read_text(encoding="utf-8")))
    signed_path = bundle / f"{note_name}.signed"
    if signed_path.exists() and found:
        check_stamped(r, signed_path, f"{body}\n{found[1]}\n".encode())
    if (bundle / wal).exists():
        check_wal(r, bundle / wal, hmac_key, size, root)

    print("\nTimestamps, with their own tools:")
    print(f"  openssl ts -verify -data {note_name}.signed -in {note_name}.signed.tsr \\")
    print("      -CAfile CA.pem")
    print(f"  ots verify {note_name}.signed.ots   (or both files on https://opentimestamps.org)")
    if r.failures:
        print(f"\nRESULT: FAILED ({r.failures} of {r.passed + r.failures} checks)")
        return 1
    print(f"\nRESULT: verified without Calybris ({r.passed} checks)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("bundle", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--note", default="000001.checkpoint")
    parser.add_argument("--log-key", default="log.vkey")
    parser.add_argument("--witness", action="append", help="witness .vkey (default witness.vkey)")
    parser.add_argument("--wal", default="decisions.wal.jsonl")
    parser.add_argument("--hmac-key-hex", help="for a WAL chained with HMAC-SHA-256")
    args = parser.parse_args(argv)
    key = bytes.fromhex(args.hmac_key_hex) if args.hmac_key_hex else None
    witnesses = tuple(args.witness) if args.witness else ("witness.vkey",)
    return verify(args.bundle, args.note, args.log_key, witnesses, args.wal, key)


if __name__ == "__main__":
    sys.exit(main())
