# Audit scope: hybrid signatures and the trust layer

**Status: not independently audited.** This page is written for the auditor
who changes that. It names the code in scope, the claims to test, the evidence
already in the repository, and what is deliberately out of scope. The design
and the four questions it answers are in [TRUST.md](TRUST.md).

## In scope, in order of consequence

| # | Code | Feature | Why it matters |
|---|---|---|---|
| 1 | `src/hybrid.rs` | `preview-pq` | Signatures meant to stay valid for as long as decision records are kept, including after a quantum break of Ed25519 |
| 2 | RustCrypto `ml-dsa` 0.1.1, as called by `hybrid` | `preview-pq` | The FIPS 204 implementation itself; the reason `preview-pq` is labelled unaudited |
| 3 | `src/witness.rs` | `preview` | The rule that makes a split view detectable: a witness never cosigns two checkpoints that do not extend each other |
| 4 | `src/checkpoint.rs` | `preview` | Canonical checkpoint text, note signatures and cosignatures; interoperates with the C2SP ecosystem |
| 5 | `src/audit.rs` | `preview` | Quorum counting, split-view evidence, the revoked-key rule |
| 6 | `src/tsa.rs` | `preview-tsa` | RFC 3161 / CMS verification of untrusted DER |
| 7 | `src/ots.rs` | `preview` | OpenTimestamps parsing of untrusted bytes, Bitcoin header checks |
| 8 | `src/bin/calybris_verify/trust.rs` | `preview` | Key generation, calendar transport through `curl`, report and exit codes |

## Claims to test

Continuation scope also includes cached Merkle prefix/root/proof equivalence,
verified WAL construction, exact-propensity deserialization and finite OPE
results. The OTS fork-order regression is pinned as
`crash-065f6fa91bd55aef2965abcfebdcec4eb0715d5f.ots` and compared to
python-opentimestamps 0.4.5. A lost or unreadable witness state is refused
(fail closed); rollback to a valid old backup remains an explicit limitation,
not a promise of automatic key recovery. Windows power-loss
durability is not claimed; review storage assumptions separately.

**Hybrid signatures**

- A signature verifies only if both the Ed25519 and the ML-DSA-65 half verify
  over `"calyhyb1" ‖ digest`, the ML-DSA half with FIPS 204 context `calybris`.
- A batch item verifies only if its inclusion proof leads to the signed root
  and the one hybrid signature over `SHA-256("calyhbt1" ‖ size ‖ root)`
  verifies; no batch signature verifies as a plain signature over its root, or
  the reverse.
- Deterministic signing leaks nothing about the seed across many signatures,
  and `HybridSigner` never exposes key material (`Debug` included).
- Malformed keys and signatures of every length are refused without a panic.
- `ml-dsa`: FIPS 204 conformance beyond the ACVP vectors below, constant-time
  behaviour of signing with respect to secret data, and rejection of
  non-canonical encodings.

**Witness and audit**

- `Witness::add_checkpoint` never returns a cosignature for a checkpoint that
  does not extend the last one recorded for its origin, including across a
  crash between recording and signing, concurrent requests, and a
  `FileStore` shared by processes.
- A size-0 tree has exactly one acceptable root; no request can move a
  witness backwards.
- `FileStore` fails closed: a missing, truncated or unparsable state is an
  error, never an empty state, and `FileStore::create` never overwrites one.
  What it cannot see is a state restored from an older copy; the claim there
  is the one `tests/trust_operations.rs` makes, that the fork this allows
  misses a majority quorum and is caught by an auditor holding the real
  checkpoint.
- `WitnessPolicy` counts each trusted key at most once; `seen_by` and
  `fresh_as_of` are the *k*-th earliest and *k*-th latest cosignature times.
- `SplitView::verify` accepts only two log-signed checkpoints of one origin
  and size with different roots.
- `KeyStatus::accepts` never accepts on the signer's own clock, nor on
  evidence that covers only the content (`Covers::Content`), nor on a
  Bitcoin block's own time: an anchor counts only at or below the chain
  height recorded at the revocation. A timestamp over
  `SignedNote::signed_by` covers the log's signature.

**Checkpoints**

- `Checkpoint::parse` accepts exactly one text per checkpoint; `SignedNote`
  parsing and rendering are inverses; note signatures use `verify_strict`.
- Key hashes, note signatures and cosignature messages match C2SP for every
  input the Go reference accepts, and nothing this crate accepts is something
  the Go reference would read differently.

**RFC 3161**

- A token verifies only if the pinned certificate signed it, the signed
  attributes bind content type and message digest of the exact `TSTInfo`, the
  imprint is SHA-256 of the requested digest, the nonce matches when given,
  the certificate's extended key usage is the critical `timeStamping` one and
  nothing else (RFC 3161 §2.3), `genTime` lies in its validity, and an ESS
  `signingCertificate` (SHA-1) or `signingCertificateV2` attribute names the
  pinned certificate by hash, and by issuer and serial number when it gives
  them (RFC 3161 §2.4.1, RFC 5816).
- DER parsing of adversarial input neither panics nor accepts ambiguity; the
  re-encoding of signed attributes as a SET OF does not let a differently
  encoded attribute set verify.
- The `rsa` crate is used for public-key verification only (RUSTSEC-2023-0071
  concerns private-key operations; see `deny.toml`).

**OpenTimestamps**

- Parsing enforces the reference limits (message 4096 bytes, depth 256,
  payload 8192) and serialization is the reference client's canonical order.
  A parsed proof equals the proof its serialization parses back to, whatever
  order its branches arrived in (the property CI's fuzzer broke once; see the
  1.3.0 changelog).
- `verify_bitcoin` accepts only an attestation for the caller's height whose
  message equals the header's Merkle root, and a header whose target has at
  least 64 leading zero bits and whose hash meets it; nothing counts as
  evidence until `BitcoinHeader::confirm` matches a trusted block hash.
- `calybris-verify checkpoint verify` never reports more than was checked,
  and fails when a `--require`d level is missing.
- Calendar URLs outside the allowlist are never contacted by `upgrade`.

## Evidence already in the repository

| Test | What it pins |
|---|---|
| `tests/acvp_ml_dsa.rs` | NIST ACVP ML-DSA-65: 25 key generations, 8 deterministic signatures with context, 15 verifications (12 forgeries) |
| `tests/c2sp_interop.rs` | Byte-for-byte agreement with `golang.org/x/mod/sumdb/note` and `transparency-dev/formats/note` |
| `tests/split_view.rs` | Property test: forks shown to real witnesses in every order never both reach a majority quorum, and are always caught |
| `tests/rfc3161.rs` | Tokens from OpenSSL (RSA, P-256, P-384), FreeTSA and DigiCert; wrong key, wrong EKU, expiry, every single-byte change |
| `tests/opentimestamps.rs` | Reference-client files round-trip byte for byte; a 2015 proof verifies against Bitcoin block 358391; height binding |
| `tests/checkpoint_cli.rs` | The workflow through the binary: two witnesses, a forged history refused, a pending timestamp exits 3 |
| `tests/trust_operations.rs` | Witness state corrupted, lost and rolled back; concurrent witnesses on one state file; log key rotation and revocation |
| `tests/trust_edges.rs` | Refusals at the edges: origins, keys, signature limits, other origins, bare tokens |
| `scripts/verify_bundle.py` | A second verifier sharing no code with the crate (standard-library Python: RFC 8032, C2SP, RFC 9162), run on `tests/fixtures/bundle` |
| `fuzz/fuzz_targets/{note,ots,tsa}_decode.rs` | Parsers of untrusted input, run in CI; each also ran two minutes locally after the canonical-order fix without a finding |

## Out of scope

- The decision kernel, WAL and receipts, covered by
  [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) and
  [THREAT_MODEL.md](THREAT_MODEL.md).
- Key custody: generation inside an HSM, rotation, backups. The procedures
  are in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) §4–6, as guidance, not code.
- The transport between log, witnesses and auditors, and `curl` itself.
- The honesty of any particular witness operator or TSA.
