from __future__ import annotations

import base64
import hashlib
import importlib.util
import shutil
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "verify_bundle.py"
BUNDLE = Path(__file__).parents[2] / "tests" / "fixtures" / "bundle"
SPEC = importlib.util.spec_from_file_location("verify_bundle", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load the bundle verifier from {SCRIPT}")
verify_bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_bundle)

# RFC 8032, section 7.1, tests 1 and 2.
RFC8032 = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
        "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
        "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


@pytest.mark.parametrize(("public", "message", "signature"), RFC8032)
def test_ed25519_accepts_the_rfc_vectors_and_nothing_altered(
    public: str, message: str, signature: str
) -> None:
    pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert verify_bundle.ed25519_verify(pk, msg, sig)  # skipcq: BAN-B101
    for i in (0, 31, 32, 63):
        bad = bytearray(sig)
        bad[i] ^= 1
        assert not verify_bundle.ed25519_verify(pk, msg, bytes(bad))  # skipcq: BAN-B101
    assert not verify_bundle.ed25519_verify(pk, msg + b"x", sig)  # skipcq: BAN-B101
    assert not verify_bundle.ed25519_verify(pk[:31], msg, sig)  # skipcq: BAN-B101


def _mth(leaves: list[bytes]) -> bytes:
    """RFC 9162's recursive definition, to hold the iterative one against."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def test_the_merkle_root_matches_the_rfc_definition() -> None:
    leaves = [hashlib.sha256(bytes([i])).digest() for i in range(40)]
    for n in range(41):
        assert verify_bundle.merkle_root(leaves[:n]) == _mth(leaves[:n])  # skipcq: BAN-B101


def test_the_committed_bundle_verifies_without_calybris() -> None:
    assert verify_bundle.main([str(BUNDLE)]) == 0  # skipcq: BAN-B101


@pytest.mark.parametrize(
    ("name", "change", "says"),
    [
        ("decisions.wal.jsonl", ("100005", "999999"), "breaks the hash chain"),
        ("000001.checkpoint", ("\n12\n", "\n11\n"), "no valid signature"),
        ("000001.checkpoint.signed", ("fixture-log", "fixture-lag"), "not the log-signed note"),
    ],
)
def test_a_changed_bundle_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    change: tuple[str, str],
    says: str,
) -> None:
    bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, bundle)
    path = bundle / name
    text = path.read_text(encoding="utf-8")
    assert change[0] in text  # skipcq: BAN-B101
    path.write_text(text.replace(change[0], change[1], 1), encoding="utf-8", newline="")
    assert verify_bundle.main([str(bundle)]) == 1  # skipcq: BAN-B101
    assert says in capsys.readouterr().out  # skipcq: BAN-B101


def test_a_witness_it_was_not_signed_by_fails(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    shutil.copytree(BUNDLE, bundle)
    log_key = (bundle / "log.vkey").read_text(encoding="utf-8")
    (bundle / "other.vkey").write_text(log_key, encoding="utf-8")
    assert verify_bundle.main([str(bundle), "--witness", "other.vkey"]) == 1  # skipcq: BAN-B101


# The curve internals, for signing below.
P, L, BASE, MUL = (
    verify_bundle._P,  # skipcq: PYL-W0212
    verify_bundle._L,  # skipcq: PYL-W0212
    verify_bundle._BASE,  # skipcq: PYL-W0212
    verify_bundle._mul,  # skipcq: PYL-W0212
)


def _encode(point: tuple[int, int, int, int]) -> bytes:
    inv = pow(point[2], P - 2, P)
    x, y = point[0] * inv % P, point[1] * inv % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """RFC 8032 signing, only to make cosignatures the verifier must refuse."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    public = _encode(MUL(a, BASE))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    big_r = _encode(MUL(r, BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little")
    return public, big_r + ((r + k * a) % L).to_bytes(32, "little")


def test_the_test_signer_reproduces_rfc_8032() -> None:
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public, signature = _sign(seed, b"")
    assert (public.hex(), signature.hex()) == (RFC8032[0][0], RFC8032[0][2])  # skipcq: BAN-B101


@pytest.mark.parametrize(
    ("when", "accepted"), [(0, False), (1, True), (2**63 - 1, True), (2**63, False)]
)
def test_a_cosignature_time_of_zero_or_above_2_63_is_refused(when: int, accepted: bool) -> None:
    body = "fixture-log\n1\n" + "A" * 43 + "=\n"
    message = f"cosignature/v1\ntime {when}\n{body}".encode()
    public, signature = _sign(bytes(32), message)
    raw = b"\x04" + public
    key_hash = hashlib.sha256(b"w.example\n" + raw).digest()[:4].hex()
    key = verify_bundle.Key(f"w.example+{key_hash}+{base64.b64encode(raw).decode()}")
    sig = when.to_bytes(8, "big") + signature
    expected = when if accepted else None
    assert verify_bundle.cosigned_at(body, sig, key) == expected  # skipcq: BAN-B101
