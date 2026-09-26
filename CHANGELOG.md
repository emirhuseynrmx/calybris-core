# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-09-26

A trust layer that stops the operator from being the only party vouching for
which log is the log and when each record was written. Every addition is a
preview feature; no decision, digest or stable API changes. The design, and the
four questions it answers, are in `docs/TRUST.md`.

### Preview features

- **`checkpoint`** — tree heads as C2SP tlog-checkpoint text, signed as C2SP
  notes by the log and cosigned by witnesses (`cosignature/v1`). Keys use the Go
  `note` verifier-key format. Byte-for-byte agreement with the Go reference
  packages is pinned by `tests/c2sp_interop.rs`.
- **`witness`** — an independent witness speaking C2SP tlog-witness: it
  cosigns a checkpoint only with a consistency proof from the last one it
  cosigned, records its state through a compare-and-swap before signing, and
  maps each refusal to the protocol's HTTP status. `FileStore` keeps that
  state durably for a witness process.
- **`audit`** — witness quorums (`WitnessPolicy`), an auditor that follows one
  log and refuses forks, transferable split-view evidence, record inclusion
  against a witnessed checkpoint, time evidence from witnesses, RFC 3161 and
  Bitcoin, and `KeyStatus`, under which a revoked key counts only for what is
  proven to predate its revocation.
- **`ots`** — OpenTimestamps: the reference `.ots` format read and written in
  canonical order, calendar submission and upgrade, and verification against a
  Bitcoin block header at a verifier-supplied height, with an explicit Pending,
  Anchored or Verified status.
- **`tsa`** (new feature `preview-tsa`) — RFC 3161 requests and verification
  of responses against pinned TSA certificates: imprint, nonce, CMS signed
  attributes, RSA PKCS#1 v1.5 and ECDSA P-256/P-384 signatures, timeStamping key
  usage and validity at `genTime`.
- **`hybrid`** — `HybridSigner::sign_batch`, `verify_batch`: one hybrid
  signature over the Merkle root of many digests (tag `calyhbt1`), each with an
  inclusion proof.
- **`merkle`** — `all_inclusion_proofs`, every leaf's proof in `O(n log n)`.

### Command line

- `calybris-verify checkpoint keygen | create | request | stamp | upgrade |
  tsa-request | verify` and `calybris-verify witness cosign`, built with
  `preview`. `stamp` and `upgrade` reach OpenTimestamps calendars through the
  system `curl`; `verify` is offline and exits 3 while a timestamp is pending.

### Checks

- `tests/acvp_ml_dsa.rs`: NIST ACVP ML-DSA-65 vectors for key generation,
  deterministic signing with a context, and verification, through the calls
  `hybrid` makes. Conformance, not an audit; `docs/AUDIT_SCOPE.md` is the scope
  for one.
- `tests/split_view.rs`: property test of forks shown to real witnesses in
  every order.
- `tests/rfc3161.rs`, `tests/opentimestamps.rs`: tokens from OpenSSL, FreeTSA
  and DigiCert; reference-client proofs and Bitcoin block 358391.
- Fuzz targets `note_decode`, `ots_decode`, `tsa_decode`.

### Dependencies

- `preview` now also enables `provenance` and pulls in `base64`, `ripemd` and,
  for the binary's key generation and nonces, `getrandom` (not on wasm32).
- `preview-tsa` pulls in the RustCrypto `der`, `x509-cert`, `cms`, `x509-tsp`,
  `spki`, `rsa`, `p256` and `p384` crates. RUSTSEC-2023-0071 (`rsa`, private-key
  timing) is recorded as not applicable in `deny.toml` and `.cargo/audit.toml`:
  only public-key verification is used.

## [1.2.0] - 2026-09-25

1.2.0 answers the questions a decision raises after it is made — what would it
have taken to decide otherwise, is this decision really in the log, and would a
different policy have done better — without changing a single decision. The
kernel, the gate order, the utility, the tie-break and every existing digest
are exactly as in 1.0.0. There was no separate 1.1.0; what was planned for it
is here.

### Preview features

New capabilities ship behind the `preview` feature flag, which is **not** yet
covered by the 1.x stability promise (see `docs/PREVIEW.md` and
`docs/COMPATIBILITY.md`). Each will graduate to a stable flag in a later 1.x
release after review.

- **`counterfactual`** — `what_would_win` gives the smallest single-lever change
  (quality, latency, price, risk ceiling, enabled) after which a losing candidate
  is selected; `decision_margin` gives how far the winner's levers can move before
  it loses. Computed by running the real kernel and searching for the boundary,
  so it cannot disagree with `prescribe`. Exposed in Python as
  `PolicySnapshot.what_would_win` and `PolicySnapshot.decision_margin`.
- **`merkle`** — RFC 9162 inclusion and consistency proofs over log records,
  checked against the Certificate Transparency reference vectors. A tree head
  binds under the new tag `calymth1`.
- **`exploration`** — keyed, replayable exploration among near-best candidates,
  recording the exact probability of each choice and converting it into the
  `Selection` an `Outcome` already carries. New tag `calyexp1`.
- **`ope`** — off-policy estimates (IPS, self-normalised IPS, effective sample
  size) of what a different policy would have achieved, which count and report
  the records a deterministic log cannot speak for instead of hiding them.
- **`budget::Reservation`** — an owned reservation that can be settled once;
  double spends and use after delegation are compile errors.
- **`hybrid`** (feature `preview-pq`) — Ed25519 + ML-DSA-65 hybrid signatures over
  any artifact digest, valid only when both halves verify. The ML-DSA
  implementation used has not been independently audited, hence its own flag.
  New tag `calyhyb1`.

Each module cites the research it builds on; the list is in `docs/PREVIEW.md`.

### Documented

- `docs/DECISION_SEMANTICS.md` now states the two request-level refusals and
  their exact boundaries: risk **at** the hard limit is refused, confidence **at**
  the floor is accepted. This was always the behaviour; it was not written down,
  and a rule learned as "risk above *t*" maps to a hard limit of *t* + 1. Pinned by
  `request_level_refusals_hold_at_their_exact_boundaries`.

### Checks

- `src/kani_proofs.rs` and `.github/workflows/kani.yml`: bounded model checking of
  the Merkle split, the exploration probabilities and the counterfactual search,
  run in CI on Linux and kept out of the release gate while new.

## [1.0.0] - 2026-09-17

The release that makes the API and the formats stable. Everything in it is
something the crate had to settle before it could promise not to break it.

### Why 1.0.0 and not 0.8.0

The number is a commitment, not a boast. `0.x` means *expect breaking changes*,
and from here there are none to expect within 1.x: the public API is stable,
and anything that would break it waits for a major version. A `0.8.0` would have
said the opposite of what is true.

Calling it 1.0.0 also closes the window in which breaking changes are free, so
two things happened before the number moved.

`PolicySnapshot::new` is gone. It had been deprecated since 0.3.9 and had no
caller left in this repository; shipping it in 1.0.0 would have made it permanent.

Every public error enum is now `#[non_exhaustive]`, so a security fix that needs a
new way to refuse an input can ship in a 1.x release instead of forcing a major version.
The decision enums — `KernelAction`, `KernelReason`, `GateKind`,
`CandidateVerdict`, `Disposition`, `SelectionStrategy` — are deliberately left
exhaustive: a new variant there would change the decision contract, which is
exactly what this release promises not to do. Error paths flex; the semantics do
not.

`docs/COMPATIBILITY.md` states what a 1.x release may contain, what it never changes, and
what happens to a defect that would require changing a digest format: it gets
documented with a workaround rather than fixed, because a correction that
invalidates every artifact ever written against the format costs more than the
defect.

### The gate chain and the pricing each have one definition

Both were written twice — once in the prescribe loop, once in
`utility_for_model` — and an explanation surface would have made it three. An
ordered predicate chain that exists in two places agrees until one of them is
edited. `first_failed_gate` returns a field-less `GateKind`, so the hot loop pays
for a discriminant rather than for measured values, and `Pricing` holds the
loop-invariant half of the economic calculation. Behaviour is unchanged: the
golden and conformance vectors pin the decision digests and still pass.

### Per-candidate explanation

`PolicySnapshot::explain` reports a verdict for every candidate: the gate it
failed with the two numbers that gate compared, or the terms behind its utility.
Until now the trace held counts, so a caller could say "three candidates failed
on latency" but not "candidate A failed on latency at 900 ms against a 300 ms
cap" — which is the sentence anyone actually needs. It shares the gates and the
arithmetic with `prescribe`, and `tests/explain_agreement.rs` holds them to it,
including a property test that they never disagree on any request.

`prescribe_with_trace` is unchanged and remains allocation-free; `explain` is the
slow path and the only one that allocates.

### Outcomes, and how a choice was made

The kernel decided and forgot. `outcome::Outcome` gives the downstream half a
shape: whether a recommendation was applied, abandoned or still running, what it
actually cost, whether a person overrode it, and corrections as revisions that
supersede rather than overwrite.

It binds through `DecisionIdentity`, which carries the **policy digest, the input
digest, the decision digest and the request sequence** together. A decision
digest alone identifies a decision but not the world that produced it: a policy
whose risk limit moved, or a request whose latency cap moved, can both produce a
byte-identical decision, and a record bound to the decision alone would pass as
evidence about either one. `tests/outcome_contract.rs` demonstrates exactly that
— two tests that only mean anything while the two policies, and the two requests,
decide identically. `validate_against` checks all four and names the first that
disagrees.

**The kernel does not learn from these.** It stores no history and no decision
changes because of a record.

`Selection` carries the part that cannot be added later. A learner reading a
decision log only ever observes the action that was taken, and estimating the
others is honest only when the probability of each choice was written down at the
time — which is unrecoverable afterwards. So the propensity is an `Option`, and
which of the three states is legal depends on how the choice was made:

| Strategy | Propensity |
|---|---|
| `MaximiseUtility` | exactly 10,000 — it is deterministic |
| `Explore` | a stated probability in 1..=10,000 |
| `Human` | absent, because none exists |

Absent means *not causally evaluable*, and a record carrying it belongs outside
an off-policy estimate rather than defaulted into one. A person's reasons are not
a distribution, and a number there would make the record look usable when it is
not.

The disposition rules are the mirror of the same idea. `Applied` requires a
measurement, because asserting that something happened while recording nothing is
the shape a learner would later read as a silent success. `Abandoned` forbids one,
because nothing ran and a zero would read as a free success. `InFlight` cannot
record success or failure, because the work has not finished. And a rejection
admits only `Abandoned`: there was nothing to carry out. An outcome naming a model
the policy does not contain is refused too.

### What else 1.0.0 closes

Everything here exists because a stable release has to be checkable by someone
who was not here when it was written.

| | |
|---|---|
| **`docs/SPECIFICATION.md`** | All seven digest layouts field by field — widths, endianness, sort keys, presence bytes, enum discriminants, units, ceilings, and what is deliberately not hashed. `tests/specification.rs` transcribes that document back into code and compares it against the implementation, so the two cannot quietly part company. |
| **`docs/INVARIANTS.md`** | Every property the crate promises, with the test that fails when it stops being true, under stable `CAL-Innn` identifiers. `tests/invariants.rs` reads the file and refuses to pass if a row names a test that does not exist. |
| **Golden outcome vectors** | `tests/fixtures/calybris_outcome_v1.json` pins seven cases across the axes that carry format risk — including a human selection with no propensity, the only pinned value with an absent optional field. Asserted from Rust, from Python, and from C. |
| **`calybris-ffi`** | A stable C ABI over the decision path, for callers that are neither Rust nor Python. A C program compiled against the header reproduces the same pinned digests: one set of bytes, three callers. |
| **Torn-write and corruption tests** | `tests/crash_injection.rs` produces every truncation and every single-bit corruption of a real WAL and a real snapshot — about nine thousand damaged files — and checks that recovery never reports state that was not durably written. |
| **Fuzz harness** | Six coverage-guided targets over the decoders and the kernel, seeded from real documents, with a proptest mirror of the same properties that runs on every platform. |
| **Cross-architecture determinism** | The pinned vectors run under `cross` on aarch64, i686 and **s390x**. The layouts are declared little-endian, and a big-endian host is the only way to find out whether the code says so or merely inherits it. |
| **Release provenance** | On a clean checkout the stamped source digest **is** the git tree SHA, so anyone can recompute it with `git rev-parse HEAD^{tree}`. `cargo package` twice from the same commit must produce the same bytes. Both are CI gates. |

### The Python side gets both

`PolicySnapshot.explain` returns a list of `CandidateExplanation`, each carrying a
`status`, the gate that refused it with the two numbers that gate compared, and
the terms behind its utility. `Outcome`, `Observation` and the selection fields
are exposed with the same validation the Rust side applies, so a record written
from Python is a record the Rust side would have accepted.

This is not a convenience. The engine is Rust and anything that learns from these
records will be Python, and a record shape that exists on only one side of that
line is a record nobody writes.

The Python enums are strings — `eligible`, `rejected`, `over_budget`,
`non_positive_utility` for a verdict; `applied`, `abandoned`, `in_flight` for a
disposition; `maximise_utility`, `explore`, `human` for a strategy — because
filtering a list on a string reads better than matching on a tag, and an unknown
one is refused rather than coerced. Fields that do not apply are `None`, never
zero.

### Fixed before the freeze

`persistence` lost its `serde` feature gate while `outcome` was being added to
`lib.rs`, which broke `--no-default-features` — the command `SECURITY.md` tells
an external reviewer to run first. It is gated again, and all three feature
combinations build and test clean.

### Frozen semantics

`docs/DECISION_SEMANTICS.md` states the units, the ceilings, the gate order, the
tie-break, and the difference between the request's risk and the candidate's risk
ceiling — the last of which is the field most likely to be mislabelled as a
supplier's failure probability, which it is not. `tests/decision_semantics.rs`
pins every claim in it.

Two ceilings worth naming here: latency is `u32` milliseconds and so stops a
little under 49.7 days, and `provider_id` is capped at 63 by the `u64` mask,
refused at policy construction rather than silently at decision time.

### Maintenance

`SECURITY.md` states response targets one maintainer can actually hold. Within
1.x, a defect that would require a semantics or digest change cannot be fixed in
place, because correcting it would invalidate every artifact written against the
current format; it is documented with a workaround, and the fix waits for a major
version. Apache-2.0, unchanged.

### Versions

`calybris-core` and `calybris` are both 1.0.0. 0.6.1 was crates.io only and left
PyPI a release behind; this release ends that split.

## [0.6.1] - 2026-09-08

No code change, and **crates.io only**. `calybris-core` 0.6.1 behaves exactly as
0.6.0 does; there is no `calybris` 0.6.1 on PyPI, where 0.6.0 remains current.
`pip install calybris==0.6.1` will not resolve — ask for `calybris` and take
0.6.0, which is the same software.

The crates.io page for 0.6.0 shipped without the banner and the badges:
splitting `README-crates.md` off from the repository README dropped both without
anyone deciding to, and a published version's README cannot be replaced. A
release is the only way to correct that page, so this is one, and it was not
worth spending a PyPI version on.

## [0.6.0] - 2026-09-08

0.5.8 and 0.5.9 were never published. Everything they carried ships here, so
this section is the whole distance from 0.5.7.

### Added — decisions

- A typed, domain-neutral decision API on the existing kernel: `Candidate`,
  `DecisionRequest`, `DecisionEngine`, `DecisionResult` and `compare_policies`,
  exported from `calybris`. One already-priced job in, one selected candidate
  plus a replay-verified audit bundle out. No selection algorithm was added; the
  adapter maps a fixed quote onto the native cost rate as exactly one million
  input units and zero output units, so the native estimated cost is the quote.
  Suppliers, carriers, venues and models are the same call with a different
  catalog.
- `DecisionEngine.verify` recomputes the entire result from the caller's own
  catalog, policy and request rather than trusting a self-declared flag, and the
  catalog digest (`calybris.catalog.v1`) is kept distinct from the native policy,
  input and decision digests. It is a content identity, not a signature.
- `compare_policies` replays identical frozen requests through two policies and
  reports how many outcomes changed and how many became rejections, with bounded
  stored detail and totals that are never silently truncated. It names which
  configuration fields differ; it does not attribute a change to one of them, and
  it does not claim realized savings or a better real-world outcome.
- The comparison carries `before_policy` and `after_policy` — the native policy
  digest and both epochs for each side — and a `policy_changed` flag derived from
  them. These sit at the top level, so a comparison whose per-change detail was
  truncated still says which two policies produced it. `changed_fields` compares
  configured knobs only: two engines can share every field and still differ by
  epoch, and `policy_changed` is what answers that.
- `AgentBudget.lifecycle_report`, one atomic view of balance, unresolved work and
  its next action, corrections, denials and reservation accuracy, taken under a
  single lock so the parts cannot disagree. It is a presentation of facts the
  ledger already holds: no second ledger, no inferred reservation advice, and it
  is local accounting rather than an attestation of a provider's bill.

### Added — budget

- Python `AgentBudget` for shared in-process sync/async call admission backed by
  the Rust budget engine. Uncertain usage retains holds; explicit reconciliation,
  duplicate-attempt protection, bounded reports and fail-closed overruns are included.
- Credential-free example and reproducible threaded/async accounting stress harness.
- Regression tests for cancellation, timeout, concurrent admission/settlement,
  invalid usage, inherited-process rejection and unsupported response protocols.
- `AgentBudget` no longer spends its admitted-attempt limit on calls it refused.
  A denial leaves its identifier free to retry and is recorded in a bounded ring
  with a full count, so a long run is not ended by work it never did.
- Added `AgentBudget.correct`, which settles an overrun the budget could not
  absorb at a lower documented amount, keeps the originally observed cost and the
  stated reason, and refuses a second application or an amount that is not lower.
- Added `AgentBudget.reservation_accuracy`, which reports what the run's own history
  says about the reservations it was given: how much of each reserve was actually
  spent, how much was held and never used, and how many refusals happened while the
  budget could still have covered the most expensive call that completed. Nothing is
  suggested; a recommendation from a handful of calls would carry a confidence the
  history does not have.
- Added `AgentBudget.balance` for callers that need the ledger without a record of
  every attempt, and an explicit `__all__` for `calybris.agent`.

### Fixed

- `reservation_accuracy` counted an attempt as settled whenever it carried an
  observed cost, so an unabsorbed overrun and an attempt left uncertain by a failed
  operation both entered `settled_attempts` and skewed `median_ratio_ppm` and
  `held_unused_microcents`. The ledger was never wrong; the report was. Membership
  now follows the attempt's status, published as `SETTLED_STATUSES`. A corrected
  overrun does count, because the ledger took it.

### Changed

- The README leads with the decision API. Calybris is a decision engine that
  selects under explicit constraints and makes the decision verifiable afterwards;
  budget control is a component beside that decision, and model routing is one
  adapter among several rather than the subject.
- Python quickstart uses installed wheels. Core proof formats are unchanged, and
  the Rust decision and replay protocol is untouched by this release.

### Scope

- The decision adapter does not compute quantity discounts, exchange rates or
  schedules. Quotes, budget and business value are integers in one currency and
  scale chosen by the caller.
- The rejection trace counts the first failed gate per candidate. Global policy
  rejections happen before candidate gates, so an all-zero histogram does not mean
  every candidate was eligible.
- Lead time is milliseconds in a `u32`, which bounds it at roughly 49.7 days. A
  longer planning horizon needs a separately versioned adapter.
- No distributed or durable AgentBudget recovery, streaming adapter, automatic
  retries, provider price estimation, or guarantee over external provider billing.
- Existing snapshot-size and torn-WAL recovery limits remain unchanged.

## [0.5.7] - 2026-07-22

### Added
- Canonical trusted policy construction with stable catalog ordering, reserved
  rejection sentinel `model_id=0`, and a hard limit matching public decision counters.
- Full receipt verification that combines replay, claims integrity, trusted-key
  signature verification, state anchoring, and WAL anchoring in one fail-closed call.
- Recovery-aware ledger digests bind the exact WAL high watermark while preserving
  legacy digest identity for snapshots that carry no WAL claim.
- Recovery-aware snapshot versions encode the next reservation allocator
  position; restore rejects untagged legacy snapshots, preventing
  delayed-settlement ABA without changing the public 0.5.x snapshot shape.
- Explicit Rust and Python legacy-snapshot migration writes only to a distinct
  atomic output file, rejects normalized, case, symlink, and hard-link aliases
  of the source, and requires a caller-supplied durable allocator fence.
- Recovery-aware restore diagnostics distinguish legacy-format migration from
  ledger-value failures while preserving the original compatibility API.
- Linearizable budget snapshots during concurrent reserve, commit, release, top-up,
  and tenant mutations.
- Checkpoint commits reject active or otherwise unrestorable snapshots, and
  recovery rejects a snapshot watermark beyond the verified WAL head.
- Complete and anchored-fragment trajectory verifiers distinguish whole histories
  from valid but truncated fragments.
- Explicit `*_trajectory_linkage` APIs state that trajectory verification is
  structural and that per-bundle replay/authentication remains a separate step.
- Generation-based coordinated checkpoints: WAL fsync, immutable snapshot and anchor
  files, then an atomically committed manifest verified on recovery.
- Atomic JSON persistence uses collision-resistant, exclusively created temporary
  files and cleans up abandoned files on every error path, including concurrent writers.
- Policy-rotating audited WAL replay through a record-level `PolicyResolver`.
- `calybris-verify audit` accepts repeated `--policy` artifacts and resolves the
  exact policy epoch, catalog epoch, and digest for every WAL record.
- CLI `--json` verdicts use the JSON serializer so paths and OS errors containing
  control characters remain valid single-line JSON.
- CLI policy and anchor preflight failures honor `--json`, including `chain` and
  `audit` early-exit paths.
- Sync and async WAL verification hashes the original JSON `data` lexeme rather
  than a deserialized/re-serialized value, eliminating key-order, whitespace,
  and numeric-lexeme ambiguity.
- Async WAL writers reject oversized payloads before hashing or allocating the
  encoded entry, matching the synchronous writer's resource-exhaustion guard.
- Checked state-chain advancement that rejects step-counter exhaustion.
- Checked snapshot capture (`try_snapshot`) that rejects reservation-allocator
  exhaustion instead of re-emitting a saturated fence. `checkpoint`,
  `checkpoint_with_wal`, `checkpoint_coordinated` and the Python `snapshot`
  binding return that error; infallible `snapshot` panics as documented.
- Bounded JSON persistence reads and an additive coordinated-checkpoint loader
  that verifies the complete actual WAL against the committed checkpoint prefix
  while allowing valid later entries to proceed to deterministic replay.
- Canonical audit-bundle validation for schema, algorithm, proof version,
  producer, replay claim, and lowercase digest encoding before WAL replay.
- Strict Python schemas: unknown-field rejection, strict types, bounded Rust-width
  integers, literal schema versions, and lowercase SHA-256 digest validation.
- Scoped certificate verification binds trusted state/WAL anchors; compatibility
  certificate verification now also binds policy and catalog epochs.
- `PolicyBuilder::build_trusted` preserves precise trust-boundary errors without
  changing the legacy `BuildError` compatibility surface.

### Security
- Financial certificates recompute conservation from the frozen snapshot and no
  longer trust a caller-provided boolean claim.
- Python policy creation now uses the canonical trusted constructor.
- Rust `PolicyBuilder` now uses the same trusted constructor and rejects
  non-canonical enabled flags.
- Receipt, provenance, native Python anchor, and finance-model trust boundaries
  consistently require canonical lowercase digest encodings and bounded values.
- Commerce percentage-to-basis-point conversion uses decimal rounding instead of
  binary-float truncation.
- Added adversarial tests for catalog permutations, reserved sentinels, counter
  limits, receipt mutation, WAL watermark binding, checkpoint generations,
  concurrent snapshot isolation, policy rotation, and state-step overflow.
- Sync and async WAL diagnostics describe both duplicate and skipped record IDs as
  sequence continuity violations while retaining the v1 error variant for compatibility.
- Release tags are signed and version-matched before publish; security, SemVer,
  SBOM, checksum, provenance, and attestation gates run on the exact tag commit.

### Compatibility
- Existing CALY-PROOF v1 constructors and artifact surfaces remain available for
  replay compatibility. New integrations should use trusted policy construction,
  decision receipts, `verify_full`, and coordinated checkpoint APIs.
- The release is patch-semver compatible with 0.5.5; no existing public Rust item
  was removed or changed incompatibly.

## [0.5.5] - 2026-07-16

### Added
- **Decision receipts** (`receipt` module): canonical `calyrcp1\0` claims digest binds
  policy/input/decision digests to optional state and WAL evidence. The optional
  `calyrcs1\0` Ed25519 signature covers the complete receipt, not only the policy.
- **Anchored WAL verification**: `WalAnchor`, `WalWriter::anchor`,
  `verify_wal_against_anchor`, keyed and async equivalents, plus
  `calybris-verify --anchor`. A trusted external head detects clean suffix truncation.
- Cross-platform single-writer WAL lock shared by sync and async writers.
- File-identity writer locks cover canonical, symlink, and hardlink aliases
  without using a predictable shared temporary directory.
- Poisoned-writer fail-closed behavior after append/flush/sync I/O failures.
- Keyed WAL APIs reject HMAC keys shorter than 32 bytes.
- Anchored recovery planning rejects clean suffix truncation before restore.
- Fsync-backed atomic `save_wal_anchor` / `load_wal_anchor` persistence.
- Streaming verified WAL visitors keep CLI audit and recovery planning at
  constant memory with respect to log length.
- Sync and async WAL readers reject encoded entries larger than 16 MiB before
  JSON parsing, limiting single-line memory denial of service.
- Checked Rust decision APIs: `prescribe_checked`, `prescribe_with_trace_checked`,
  and `prescribe_batch_checked`.
- First-class Python production APIs for Ed25519-signed policy provenance,
  state trajectories, signed decision receipts, keyed audited WAL writes,
  trusted WAL anchors, anchored chain verification, and full WAL replay.
- Python adversarial coverage for untrusted keys, receipt mutation, duplicate
  writers, invalid metadata, weak HMAC keys, and clean suffix truncation.
- Release-only production torture benchmark covering a fully evaluated 64-model
  checked kernel, 25,000-step state trajectory, signed receipts, 25,000 keyed
  audited WAL records, trusted-anchor truncation rejection, contended budgets,
  and a 25,000-tenant ledger.

### Security
- Receipt issuance now returns `ReceiptError` for malformed or zero-position
  state/WAL anchors instead of panicking.
- Security artifact deserializers reject unknown JSON fields to prevent unsigned
  semantic-confusion claims beside verified data.
- Python artifact representations are UTF-8 and short-input safe for untrusted
  receipt, signed-policy, and WAL-anchor JSON.
- Python production APIs expose a stable `CalybrisError` hierarchy for receipt,
  provenance, WAL, persistence, state-trajectory, and artifact-validation failures.
- Receipt verification detects mutation of state step/digests, WAL sequence/hash,
  schema, signer identity, timestamp, key, or any decision-binding digest.
- Hex decoders reject malformed multi-byte UTF-8 without panicking.
- Updated `crossbeam-epoch` to 0.9.20, resolving RUSTSEC-2026-0204 in the benchmark
  dependency graph.
- Threat model now distinguishes internal hash-chain validation from externally
  anchored suffix-truncation detection.
- Semgrep Rust/Python/secrets/security-audit scanning is a blocking Security CI job.
- Bandit and pip-audit are blocking Python security CI jobs.
- Every third-party GitHub Action in CI, security, benchmark, and release
  workflows is pinned to an immutable 40-character commit SHA.
- Loom activation now uses the crate-scoped `CALYBRIS_LOOM` build switch plus
  the `loom-model` dependency feature instead of global `RUSTFLAGS`, preventing
  test-only cfg flags from leaking into third-party dependencies.

### Changed
- Version 0.5.5 for Rust and Python packages.
- Python package status moves from experimental/alpha to production-capable
  beta. Runtime integrity matches the Rust core; the public API remains pre-1.0.
- Release automation runs full preflight tests, validates distributions, emits
  SHA-256 checksums, creates GitHub build attestations, and publishes release assets.
- Python CI covers CPython 3.10 through 3.14.
- Production examples use checked input evaluation and decision receipts.
- Removed stale `finance_hft` and `hft_pretrade_guard` examples from the package.

## [0.5.0] - 2026-07-04

### Added
- **CALY-PROOF v1 specification** (`docs/CALY_PROOF.md`): byte-exact contract for every
  digest (policy/input/decision/ledger/state), the audit bundle binding, and the
  hash-chained WAL (unkeyed and HMAC-keyed) — so independent implementations can verify
  Calybris decision trails without running Calybris.
- **Golden vectors** (`tests/fixtures/caly_proof_v1.json` + `tests/golden_caly_proof.rs`):
  pinned byte-exact digests and WAL chain hashes. A vector mismatch is a breaking
  proof-format change requiring a new digest tag, never a silent re-pin.
- **`calybris-verify` auditor CLI** (`cargo install calybris-core --features wal`):
  `chain` (tamper/truncation detection), `audit` (per-entry digest checks; with
  `--policy` a full kernel replay of every decision), `policy` (canonical digest of a
  policy artifact). Exit codes 0/1/2; end-to-end tests cover tamper and wrong-policy
  rejection.
- **Stateful decision proofs** (`state` module): `StateChain` tracks a domain-state
  digest trajectory; `stateful_audit_bundle` (fail-closed) records
  `state_digest_before/after` per decision; `verify_trajectory` checks adjacency
  inside an unanchored fragment. Complete genesis/final-step verification was
  added in 0.5.7. New `calystt1\0` digest tag.
- **Signed policy provenance** (`provenance` feature, Ed25519): `sign_policy` /
  `verify_signed_policy` / `verify_signed_policy_with_key` bind a policy digest to an
  accountable signer and timestamp with domain separation (`calysig1\0`); signatures are
  non-transferable across policies, signers, and timestamps.
- WASM portability: the verification path compiles for `wasm32-unknown-unknown` with
  `--no-default-features`.
- **Python cross-language golden test** (`python/tests/test_golden_caly_proof.py`): the binding
  reads the *same* `tests/fixtures/caly_proof_v1.json` and reproduces the Rust reference's
  policy/input/decision digests byte for byte through the PyO3 surface — a runnable trust artifact
  that also catches field-marshalling bugs in the binding.
- **Conformance vector suite** (`tests/fixtures/caly_proof_conformance_v1.json`): one shared policy
  with inputs exercising every decision outcome (execute, substitute, and each rejection reason),
  pinned byte-exactly and asserted by both the Rust (`tests/conformance_caly_proof.rs`) and Python
  (`python/tests/test_conformance_caly_proof.py`) suites — the contract a third-party
  reimplementation (Go, TypeScript, browser) proves itself against.
- **Decision certificates** (`certificate` module): group an audit bundle + optional state
  trajectory + WAL position + policy-provenance signer into one canonically-serializable,
  fail-closed compatibility envelope. The signature covers policy provenance, not the
  full certificate. `issue_certificate` /
  `verify_certificate` (digests + replay, always available, incl. wasm) and
  `verify_certificate_signature` (feature `provenance`).
- **`calybris-verify --json`**: one-line machine-readable verdict on every verb for CI/compliance
  pipelines.
- **THREAT_MODEL.md**: documented what the proof system guarantees and — explicitly — what it does
  not (no confidentiality, does not prove the policy was good, cannot vouch for unseen inputs,
  caller key custody, caller-supplied timestamps), plus the certificate/signature-splicer attacker.

### Python packaging
- **abi3 wheels** (`abi3-py310`): the binding builds against the CPython stable ABI, so one
  wheel per platform covers Python 3.10+ — the release matrix drops from ~16 wheels to 5 and
  survives future CPython releases without a rebuild.
- **Type stubs** (`python/calybris/_core.pyi`): full signatures for the PyO3 classes
  (`KernelModel`, `KernelInput`, `KernelDecision`, `PolicySnapshot`, `BudgetEngine`) and module
  constants, so mypy and IDEs see the Rust-backed types. Writing the stubs surfaced and fixed two
  real type-precision gaps (`prescribe_with_trace` returns a tuple; `verify_status` returns a
  `Literal`).
- **Release workflow** (`.github/workflows/release.yml`): `maturin-action` builds the abi3 wheel
  matrix (Linux x86_64/aarch64, macOS x86_64/arm64, Windows) plus an sdist and publishes to PyPI
  via Trusted Publishing (OIDC, no token); a repository guard ensures only the canonical public
  repo can publish.
- Kernel-only crate artifact: `python/` and `pyproject.toml` are excluded from the crates.io
  package (78 → 59 files).

### Fixed
- CALY-PROOF §4 now shows the audit bundle `schema_version` exactly as the code emits it
  (`calybris.audit.v1`); the spec and implementation must not disagree on a proof contract.
- `SECURITY.md`, `.github/SECURITY.md`, and `docs/AUDIT_GUIDE.md` updated to the 0.5.x support line
  (was stale at 0.4.x / 0.4.5).
- Examples (`quickstart`, `llm_routing`, `pretrade_guard`, `replay_audit`) now use the fail-closed
  `verified_audit_bundle` / `append_verified_audited` path; the non-verifying `audit_bundle` is
  documented as the escape hatch, not the demonstrated default.
- Miri CI skips `async_wal::` (Tokio + filesystem tests are outside Miri's UB-detection scope).
- Added `docs/BENCHMARKS.md`: provenance and a reproduction recipe for the throughput figure,
  plus measured proof-surface costs (digests, certificates, Ed25519) via a new `proof_bench`.
- Added `docs/KEY_MANAGEMENT.md`: custody and rotation guidance for the HMAC WAL key and the
  Ed25519 policy signing key (the library holds neither).
- Golden-locked the two remaining proof tags: `tests/conformance_proof_surfaces.rs` pins the
  `calystt1` state digest and the `calysig1` Ed25519 signature — the signature vector doubles as a
  cross-platform determinism check.

### Changed
- `serde_json` now enables `float_roundtrip`: WAL chain verification re-serializes
  parsed payloads, and default f64 parsing can lose the final ulp on 17-significant-digit
  values, breaking byte-stable hashing for float-bearing payloads (CALY-PROOF §5.1).
- `full` feature now includes `provenance`.
- Version 0.5.0 (new public modules and binary).

## [0.4.5] - 2026-07-01

### Added
- Python bindings under `bindings/python`, built with PyO3 and maturin.
- Python API for `KernelModel`, `KernelInput`, `PolicySnapshot`, `KernelDecision`, batch prescription, replay verification, audit bundles, and policy fingerprints.
- `calybris_commerce` preview adapter for deterministic supplier / fulfillment routing.
- Typed commerce models: `SupplierSpec`, `OrderInput`, `RouteResult`, and `SupplierPolicy`.
- Batch commerce routing with optional audit bundles (`EcomEngine.route_batch`).
- `BatchRouteResult` wrapper for batch routing results with optional batch-level `rejection_histogram`.
- `trace_mode="summary"` for batch-level rejection reason counts (`trace_mode="compact"` is the default).
- Commerce property tests for determinism, budget safety, risk gates, SLA gates, and tamper detection.
- Workspace-level packaging metadata (`pyproject.toml`) so the binding can be built as a Python wheel without moving the Rust kernel.
- CI coverage for the Python binding crate.

### Changed
- `calybris_commerce.EcomEngine.route_batch` now returns `BatchRouteResult` instead of `list[RouteResult]`.
- Added `trace_mode="compact" | "summary"` for batch routing.
- Default compact mode keeps `rejection_histogram` empty and exposes only the primary rejection reason per rejected order.
- Renamed examples `hft_pretrade_guard` → `pretrade_guard`, `finance_hft` → `budget_guard` (no HFT positioning).
- README slimmed to quickstart + deep-dive links; adapter/Python detail moved to `docs/ADAPTERS.md` and `docs/PYTHON.md`.
- README reframed around the proof-carrying kernel; commerce/LLM/pre-trade documented as adapters.
- Security docs aligned (`0.4.x` supported); audit guide updated to 0.4.5.
- Core crate stays the default workspace member and keeps `#![forbid(unsafe_code)]`; PyO3 lives in a separate adapter crate.
- Version bump to 0.4.5.

## [0.4.0] - 2026-06-29

### Added
- `config` module: `EngineConfig` with builder pattern, validation, and safe defaults for latency penalty, risk limits, exposure caps, WAL sync, catalog size
- `builder` module: `InputBuilder`, `ModelBuilder`, `PolicyBuilder` — hard-to-misuse constructors with safe defaults
- `async_wal` module (feature `async`): Tokio-based non-blocking WAL with HMAC-SHA256, chain validation, configurable sync-on-append
- `persistence` module: atomic snapshot save/load (`checkpoint`, `restore`), crash `recovery_plan` with WAL entry counting
- `instrument` module (feature `observability`): structured `tracing` spans for `prescribe`, `verify`, budget ops, WAL; `EngineMetrics` struct for Prometheus/OTel export
- Feature flags: `async` (tokio WAL), `observability` (tracing), `full` (wal + async + observability)
- `production_gateway` example: full pipeline demo with 6 models, 3 tenants, config, builders, WAL, checkpoint, crash recovery
- Proptest coverage for config validation and builder→prescribe roundtrips
- 145+ tests passing (was 106)

### Changed
- Version bump to 0.4.0 (new public modules = minor version)
- README: feature flag table, builder ergonomics section, persistence/recovery docs, 136 test count, 91.6% coverage

## [0.3.12] - 2026-06-28

### Changed
- WAL and audit pipeline tests use `tempfile` crate instead of PID-based paths in `target/`
- Documented `latency_penalty_microunits_per_ms` dynamic overflow guard (i128 fallback via `all_latencies_fit`)
- Documented `reject()` intentionally empty `RejectionHistogram` on hard-limit rejections

### Added
- `tempfile` dev-dependency for proper test isolation

## [0.3.11] - 2026-06-28

### Added
- `KernelDecision::{is_executable,is_requested_execution,is_substitution,is_rejected}` helpers.
- `verify::VerifyError` compact error wrapper for fail-closed verification helpers.
- `verify::verified_audit_bundle`, which returns an audit bundle only after exact replay verification.
- `wal::WalWriter::append_verified_audited` and `wal::append_verified_audited`, fail-closed WAL append helpers for audited deployments.

### Changed
- README now includes a short "when to use it" section to make the crate boundary clearer on crates.io.
- GitHub Actions now use `actions/checkout@v7` and `actions/cache@v6`.
- Quickstart example header now uses ASCII punctuation for cleaner rustdoc rendering across terminals.

## [0.3.10] - 2026-06-27

### Fixed
- `top_up_tenant` holds `initial_microcents` lock through read → credit → write (fixes concurrent lost-update breaking I6)
- `conservation_status_for_snapshot` uses checked per-tenant sums (adversarial `BudgetSnapshot` no longer panics/wraps)
- `snapshot_totals` uses `i128` checked sums instead of `saturating_add` — overflow surfaces as `ConservationStatus::AggregateOverflow` / `aggregate_totals_representable: false` on certificates
- Rustdoc intra-doc links now build without broken-link warnings
- `WalWriter::append` advances sequence/hash state only after serialization and write succeed
- `ledger_digest` sorts tenants internally, so raw `BudgetSnapshot` order cannot change the canonical digest
- GitHub Actions use stable `actions/checkout@v4` and `actions/cache@v4`

### Changed
- Module docs: lock-order comment softened to scoped metadata locking + exclusive restore contract
- README separates local examples from dependency installation (`git clone` vs `cargo add`)
- Launch positioning avoids framework/exchange claims and keeps HFT language out of the top-level pitch

### Added
- Loom test `concurrent_two_topups_preserve_conservation_loom`
- `ConservationProof::aggregate_totals_representable`, `FinancialCertificate::aggregate_totals_representable`
- `BudgetEngine::try_total_committed_microcents`
- Regression tests for WAL append failure state, raw ledger ordering, and aggregate committed overflow

## [0.3.9] - 2026-06-26

### Changed
- `counterfactual_utility` delegates to `PolicySnapshot::utility_for_model` (true per-model evaluation)
- `docs/MIRI.md`: "Why some tests are skipped" — explicit Miri vs Loom vs proptest division

### Fixed
- `commit` holds `committed_microcents` lock from overflow check through final write (no panic under concurrent commits)
- `try_reserve` uses checked reserved-total increment; `BudgetReservation::Overflow` on `i64` saturation
- `rotate_certificate_baseline` monotonic — stale concurrent certs cannot regress baseline
- `restore_from_snapshot` rejects duplicate `tenant_id` in snapshot
- `top_up_tenant` / `commit` return `Overflow` on `i64` saturation (checked arithmetic)
- `THREAT_MODEL` / `SECURITY.md`: Loom/Miri residual risk wording aligned with CI reality
- `restore_from_snapshot` exclusive-recovery contract + rejects ghost reservations, negatives, unbalanced snapshots
- `certify_ledger` binds `committed_since_last_certificate` to frozen snapshot total via `rotate_certificate_baseline`
- `ensure_tenant` rejects negative budgets in release builds
- Conservation docs: holds after completed operations, not mid-flight snapshots (I6)
- `prove_conservation` / `certify_ledger` bind digest, conservation status, and version to one frozen snapshot
- Concurrent exposure cap enforced via per-tenant `AtomicI64` reserved totals (CAS)
- `lib.rs` / `Cargo.toml` positioning: pre-trade primitives, not exchange/HFT-gateway claims

### Added
- Miri CI job (nightly) — UB detection on lib tests + `audit_pipeline` ([docs/MIRI.md](docs/MIRI.md))
- Audit guide: policy `new_unchecked` escape hatch, caller `verify_decision` contract, external audit readiness checklist
- `BudgetSnapshot::version` — epoch embedded in snapshot and ledger digest
- `conservation_status_for_snapshot` — audit path without extra engine reads
- `PolicySnapshot::new_unchecked`, BPS range validation in `validate()` (`MAX_BPS`, `MAX_RISK_PENALTY_MULTIPLIER_BPS`)
- Loom sync primitives in budget core (`src/sync.rs` under `cfg(loom)`)
- Loom tests: exposure cap concurrent, snapshot restore after mutation
- README integration contract (`verify_decision` at audit boundaries)

### Changed
- `certify_snapshot` takes frozen snapshot only (version from `snapshot.version`)
- `ledger_digest` includes snapshot version
- `PolicySnapshot::new` deprecated — use `try_new` or `new_unchecked`
- `hft_pretrade_guard` separates exposure hold vs routing fee commit

## [0.3.8] - 2026-06-26

### Added
- `ConservationProof` — structured `prove_conservation` result with digest + totals + snapshot version
- `BudgetEngine::restore_from_snapshot`, `set_max_reserved_microcents`, exposure limit on `try_reserve`
- `certify_snapshot` — immutable financial certificate from frozen `BudgetSnapshot`
- Enriched `FinancialCertificate`: snapshot version, totals, `committed_since_last_certificate`
- Aggressive budget proptest (`aggressive_mixed_ops_maintain_conservation`)
- Loom concurrency tests (`tests/budget_loom.rs`) + CI job
- Expanded `budget_bench`: contention, top-up, snapshot/digest at scale

### Changed
- `prove_conservation` returns `Result<ConservationProof, ConservationStatus>` (was `Result<String, _>`)

## [0.3.7] - 2026-06-26

### Fixed
- Pin `criterion` to 0.5 (0.8 requires rustc 1.86; MSRV stays 1.85)
- Dependabot: ignore all `criterion` bumps until MSRV ≥ 1.86

### Changed
- GitHub Actions: `actions/checkout@v7`, `actions/cache@v6`

## [0.3.6] - 2026-06-26

### Changed
- `sha2` 0.11 + `hmac` 0.13 (must bump together — `digest` 0.11 API)
- `criterion` 0.8 (dev/bench only)
- Dependabot: group `sha2`/`hmac`/`subtle`; ignore criterion major auto-bumps

### Fixed
- `hmac::KeyInit` import for `new_from_slice` under hmac 0.13

## [0.3.5] - 2026-06-26

### Fixed
- `cargo-deny` CI: use `deny.toml` (not `cargo-deny.toml`) with SPDX allow list for MIT/Apache-2.0/Unlicense deps

### Added
- Adversarial tests: WAL chain attacks (duplicate sequence, hash mismatch, truncation, JSON reorder), budget conservation proptest, `PolicyError` coverage, `decode_hex32` fuzz, digest sensitivity
- Integration test `tests/audit_pipeline.rs` — end-to-end prescribe → WAL → replay → conservation
- Audit package: `docs/THREAT_MODEL.md`, `docs/SECURITY_INVARIANTS.md`, `docs/AUDIT_GUIDE.md`
- Security CI: `cargo audit`, `cargo deny`, Dependabot, weekly 10k-case proptest job

### Changed
- Expanded `SECURITY.md` with scope, supported versions, audit commands, known limitations

## [0.3.4] - 2026-06-26

### Changed
- MSRV raised to **1.85** (transitive deps such as `indexmap` 2.14 / `clap_lex` 1.1 use edition2024)
- CI split into two jobs: `MSRV (1.85.0)` and `Stable`

## [0.3.3] - 2026-06-26

### Fixed
- Pin `indexmap` to 2.13 in `Cargo.lock` (superseded by MSRV 1.85 in 0.3.4)
- CI uses `--locked` for reproducible builds

### Added
- `top_up_tenant()` — add funds without resetting lifetime `committed_microcents`
- `TopUpResult` enum
- Examples: `llm_routing`, `hft_pretrade_guard` (canonical use-case demos)
- CI: Rust 1.83.0 + stable matrix, `--no-default-features` test, `cargo doc`, all examples

### Changed
- README repositioned: proof-carrying decision core (LLM routing + pre-trade guard)
- Documented `committed_microcents` as lifetime cumulative spend
- Documented overrun fail-closed behavior and `ensure_tenant` vs `top_up_tenant`
- `WalWriter<T>` bound relaxed to `T: Serialize` (no unnecessary `Clone`)

## [0.3.2] - 2026-06-26

### Fixed
- Public `DigestDecodeError` replaces private `hex::FromHexError` on `AuditBundle` decode APIs
- `replay_audited_wal_keyed` returns `Err` on input or decision digest mismatch (fail-closed audit)
- `route_decision` example no longer swallows WAL append errors

### Changed
- WAL module docs: "crash-detecting" instead of "crash-recoverable"
- Feature split: `default = ["wal"]`, `wal = ["serde", "hmac", "subtle"]` — kernel-only via `--no-default-features`
- README Quick Start is fully runnable (`examples/quickstart.rs`)

## [0.3.1] - 2026-06-26

### Added
- `digest` module: versioned canonical SHA-256 digests for policy, input, decision, ledger
- `AuditBundle` with policy + input + decision digest binding and full replay flag
- `verify_decision` now checks complete `KernelDecision` equality and decision digest
- `counterfactual_utility()` for alternative model analysis
- `finance` module: `ledger_digest`, `FinancialCertificate`, `prove_conservation`
- `BudgetEngine::snapshot()`, `verify_conservation()`, `initial/committed/reserved_microcents`
- `TenantLedger`, `BudgetSnapshot`, `ConservationStatus` types
- `PolicySnapshot::validate()`, `try_new()`, `prescribe_batch()`, `prescribe_with_trace()`
- `RejectionHistogram`, `DecisionTrace`, `PolicyError`
- WAL `AuditedRecord`, `append_audited`, `replay_audited_wal` / `replay_audited_wal_keyed`
- Examples: `replay_audit`, `finance_hft`
- Benchmark: `budget_bench` (reserve / reserve+commit latency)

### Changed
- `CorrectnessCertificate` includes input and decision fingerprints
- `snapshot_fingerprint` now uses canonical sorted policy digest
- Budget engine tracks per-tenant initial and committed microcents for conservation proofs

## [0.3.0] - 2026-06-26

### Added
- `verify` module: `verify_decision`, `snapshot_fingerprint`, `certify_decision`
- `Display` for `KernelAction` and `KernelReason`
- Optional `serde` feature (default on); WAL behind `serde`
- `tenant_count()`, `active_reservations()`, `entry_count()`

## [0.2.1] - 2026-06-26

### Changed
- WAL `append()` serializes data once instead of twice (~2x faster)
- `compute_hash` returns `Result` instead of panicking on invalid HMAC key
- Comprehensive rustdoc on every public struct, enum, field, and function
- Budget `ReservationRecord` derives `Debug`
- `debug_assert` on negative initial budget in `ensure_tenant`

### Fixed
- `hash_entry` moved to `#[cfg(test)]` (was dead code in production)
- `write!` with trailing newline replaced by `writeln!`

## [0.2.0] - 2026-06-26

### Added
- HMAC-SHA256 keyed WAL mode (`open_keyed`, `verify_wal_keyed`, `read_verified_wal_keyed`)
- Constant-time hash comparison using `subtle` crate
- Criterion benchmarks: prescribe (22 models), model scaling (4-64), reject path
- `flush_and_sync()` method for batched WAL durability
- `MAX_PROVIDER_ID` constant (replaces magic number 64)
- `#[must_use]` on `WalWriter::append`
- `thiserror` derive for WAL error types
- Proptest fuzz: random data + random lengths WAL roundtrip
- Doc comments on kernel, WAL, and budget public APIs
- Banner image for README

### Changed
- WAL `append()` no longer calls `flush()` on every write (hot path optimization)
- Budget engine uses `HashMap<Arc<str>, _>` instead of `HashMap<String, _>`
- `prescribe_reference` now rejects `provider_id > MAX_PROVIDER_ID` unconditionally
- MSRV set to 1.83
- Release profile: LTO enabled, codegen-units=1
- Benchmarks migrated from manual timing to Criterion

### Fixed
- WAL chain validation: replaced fragile raw substring extraction with `serde_json` `preserve_order`
- `hash_entry` no longer uses `unwrap_or_default()` — errors propagate properly
- `prescribe_reference` provider_id >= 64 asymmetry with optimized `prescribe`

## [0.1.0] - 2026-06-24

### Added
- Integer-only prescriptive decision kernel (8.6M decisions/sec, 22 models)
- 11 constraint gates: risk, confidence, quality, budget, latency, capability, provider, region, cost, utility, optimality
- SHA-256 hash-chained write-ahead log (generic over any `Serialize + Deserialize` type)
- CAS atomic budget engine with conservation invariant
- Proptest property-based verification (kernel + cost + scaled terms)
- 30 tests including concurrency stress (100 threads)
- Two examples: `simple_kernel`, `verify_wal`
- Kernel benchmark (1M iterations)
- Apache-2.0 license
- `#![forbid(unsafe_code)]`
