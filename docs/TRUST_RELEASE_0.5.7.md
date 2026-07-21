# Calybris 0.5.7 trust release

0.5.7 is a compatibility-preserving hardening release. It does not introduce
CALY-PROOF v2 or remove the v1 artifact surfaces; doing either in a patch release
would break stored proofs and downstream Rust APIs.

## Production path

- Construct new policies with `PolicySnapshot::try_new_trusted`. Python policy
  construction uses this path automatically. It canonicalizes catalog order,
  reserves model ID `0` for rejection, and rejects catalogs that cannot be
  represented by the public decision counters.
- Use decision receipts and `verify_receipt_full` at trust boundaries. This one
  call requires exact replay, canonical claims, a trusted signing key, and the
  expected state and WAL anchors.
- Use `checkpoint_coordinated` and recover with
  `load_coordinated_checkpoint`. The WAL is fsynced first, immutable snapshot and
  anchor generation files are written next, and the manifest is committed last.
- Use `replay_audited_wal_with_resolver` when a WAL spans more than one policy or
  catalog epoch. The verifier CLI accepts one `--policy` argument per historical
  policy and resolves the exact epoch, catalog epoch, and digest per record.

The application must place each logical ledger mutation and its corresponding
WAL append behind the same admission boundary used for coordinated checkpoints.
The core guarantees a linearizable ledger snapshot and an atomic generation
manifest; it cannot infer whether an application-side event was omitted from the
WAL.

## Compatibility surfaces

`DecisionCertificate`, `ProofEnvelope`, and the original single-policy replay
functions remain available for CALY-PROOF v1 replay compatibility. They are not
equivalent to full receipt verification. New integrations should not treat an
attachment envelope or a digest-only audit bundle as proof of signature, state,
and WAL anchoring.

## Digest compatibility

Ledger snapshots carrying `wal_high_watermark=Some(...)` now bind that exact
watermark into their digest. Snapshots with no WAL claim preserve the legacy v1
digest bytes. This fixes recovery-claim ambiguity without silently changing all
existing non-WAL artifacts.

## Release evidence

The release gate includes formatting, Clippy with warnings denied, the complete
Rust feature test suite, patch-semver comparison against 0.5.5, installed-wheel
Python tests, RustSec and dependency-policy checks, source SAST, package dry-runs,
and artifact checksum/provenance verification.
