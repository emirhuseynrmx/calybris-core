# Compatibility

What 1.x promises, and what would break it.

The version number is a commitment rather than a quality claim. `0.x` means
*expect breaking changes*; 1.0.0 means there are none to expect within 1.x. The
project keeps developing — new capabilities arrive in minor releases — but always
as additions, under the rules below.

## What is stable

Everything public in `calybris-core` and `calybris`: types, functions, constants,
feature flags, the JSON shapes of artifacts, and the digest formats. `calybris-ffi`
is covered too: `CALYBRIS_ABI_VERSION`, every `#[repr(C)]` layout, the status
codes and the function signatures. Its struct layouts are a separate stable
contract from the digest layouts, and a change to either waits for a major
version. The digest
formats are written out byte by byte in [SPECIFICATION.md](SPECIFICATION.md),
and `tests/specification.rs` runs that document against the implementation.

Also stable, and more important than the API: **the decisions**. The same catalog
and the same request produce the same decision, the same digest and the same
receipt as they did in 1.0.0, on any machine and in any build. That is the
property everything else exists to support, and it is the one that cannot be
traded for a fix.

## What a 1.x release may contain

- New capabilities, as additions: new functions, new types, new optional feature
  flags, new artifact formats under new digest tags. Code written against 1.0.0
  keeps compiling and keeps deciding the same way.
- A fix for a defect that lets a decision, receipt or WAL be forged, replayed
  incorrectly, or verified as valid when it is not
- A fix that makes an implementation match the semantics already documented in
  [DECISION_SEMANTICS.md](DECISION_SEMANTICS.md)
- A new variant in an error enum, which is why every error enum is
  `#[non_exhaustive]` — match on them with a `_` arm

There are two kinds of enum here and the difference is deliberate. An **error**
enum says what went wrong, and a security fix may need to say something new, so
every one of them is `#[non_exhaustive]`. A **semantics** enum — an action, a
reason, a gate, a disposition, a verification result — is part of the contract a
caller matches exhaustively on to be sure it has handled every case. Making
those `#[non_exhaustive]` would force a `_` arm that silently swallows a case
the caller has not thought about, which is the opposite of what they are for.
- Documentation, tests and build metadata

## What no 1.x release will change

- A change to the gate order, the tie-break, the utility formula, or any unit
- A new variant in `KernelAction`, `KernelReason`, `GateKind`, `CandidateVerdict`,
  `Disposition`, `SelectionStrategy`, `IdentityField`, `ConservationStatus` or
  `VerifyResult` — these are the decision and verification contract, and they are
  exhaustive on purpose, so adding one is a breaking change and waits for a
  major version
- A new field in `KernelInput`, `KernelModel` or `KernelDecision` — callers build
  these with struct literals, so a field is a breaking change, and they are
  hashed, so a field is a digest change
- A change to any digest layout or its tag

If a defect requires one of these, it is **documented here with a description
and a workaround** for as long as 1.x lasts, and the fix waits for a major
version. A correction that invalidates every artifact ever written against this
format costs more than the defect.

## Minimum supported Rust version

1.85, declared in `Cargo.toml`. Raising it is treated as a breaking change, so it
is not raised within 1.x.

## Feature flags

| Feature | Stable | Notes |
|---|---|---|
| `serde` | yes | pulls in persistence, certificate and receipt |
| `wal` | yes | default; implies `serde` |
| `async` | yes | implies `wal` |
| `observability` | yes | tracing spans |
| `provenance` | yes | Ed25519 signing |
| `full` | yes | all of the above |
| `loom-model` | **no** | test-only dependency switch, not part of the API |

`--no-default-features` is supported and tested. `SECURITY.md` asks a reviewer to
run it, so it has to work — which is why every example that needs `serde` or
`provenance` declares it in `required-features` rather than relying on a default.

## Artifacts written by older versions

Digest tags are versioned (`calypol1`, `calyinp1`, `calydcn1`, `calyldg1`,
`calyidn1`, `calysel1`, `calyout1`). An artifact written by an earlier release verifies under
the format it names. No 1.x release changes what an existing tag means. A new
format, when one is needed, arrives under a new tag, and the old tags keep
verifying alongside it.

This is not only a promise. `tests/fixtures/caly_proof_v1.json` and
`caly_proof_conformance_v1.json` were written during 0.5.5 and have never been
re-pinned since — `git log` on either file shows one commit. Today's code
reproduces them byte for byte (CAL-I025 through CAL-I028 in
[INVARIANTS.md](INVARIANTS.md)), which is the same thing as saying a 0.5-era
artifact still verifies here. If a release ever needs to edit one of those
files, that is the release that broke compatibility, and the fixture is the
evidence rather than the obstacle.

`calyidn1`, `calysel1` and `calyout1` are new in 1.0.0, so they have no history
to be compatible with. `calybris_outcome_v1.json` is where theirs starts.

## If you need something it does not do yet

Open an issue. An addition that fits the rules above can land in a 1.x minor
release; one that would break them is recorded for the next major version. The
decision semantics are documented, the digest layouts are written out byte by
byte in [SPECIFICATION.md](SPECIFICATION.md), and every property the crate
promises is listed in [INVARIANTS.md](INVARIANTS.md) against the test that guards
it — so a proposal can be checked against exactly what it would have to keep.
