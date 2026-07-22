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
- Use `checkpoint_coordinated`; inspect a committed generation with
  `load_coordinated_checkpoint`, and recover across a trust boundary with
  `load_and_verify_coordinated_checkpoint`. The latter additionally reads the
  actual WAL, verifies the checkpoint's committed prefix anchor, and permits a
  valid post-checkpoint suffix for deterministic replay. External latest-head
  anchors continue to require exact head equality.
- Verify whole state linkage with `verify_complete_trajectory_linkage`, supplying
  trusted genesis bytes and the independently expected terminal step. Linkage
  APIs detect missing/reordered state transitions but do not replay or
  authenticate embedded audit bundles; verify every bundle separately from its
  disclosed policy, input, and decision evidence. Compatibility names remain.
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

New recovery-aware snapshot versions encode and bind reservation allocator state;
ledger digests additionally bind the exact WAL high watermark when present.
Recovery rejects untagged legacy snapshots, preventing reservation-ID ABA after
restart without changing the public 0.5.x `BudgetSnapshot` field set.
Follow the fail-closed [0.5.5 → 0.5.7 migration runbook](MIGRATING_0.5.5_TO_0.5.7.md);
the allocator fence must come from durable history and migration is never in-place.

## Release evidence

The release gate includes formatting, Clippy with warnings denied, the complete
Rust feature test suite, patch-semver comparison against 0.5.5, installed-wheel
Python tests, RustSec and dependency-policy checks, source SAST, package dry-runs,
signed-tag and exact version parity checks, CycloneDX SBOMs, SHA-256 checksums,
build metadata, and GitHub artifact attestations. These gates run on the exact
tag commit before either publish job can start.
