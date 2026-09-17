# Compatibility

What 1.0.0 promises, and what would break it.

The version number is a commitment rather than a quality claim. `0.x` means
*expect breaking changes*; there are none left to expect, so calling a frozen
release `0.8.0` would have said the opposite of what is true.

## What is stable

Everything public in `calybris-core` and `calybris`: types, functions, constants,
feature flags, the JSON shapes of artifacts, and the digest formats. The digest
formats are written out byte by byte in [SPECIFICATION.md](SPECIFICATION.md),
and `tests/specification.rs` runs that document against the implementation.

Also stable, and more important than the API: **the decisions**. The same catalog
and the same request produce the same decision, the same digest and the same
receipt as they did in 1.0.0, on any machine and in any build. That is the
property everything else exists to support, and it is the one that cannot be
traded for a fix.

## What 1.0.x may contain

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

## What 1.0.x will never contain

- A change to the gate order, the tie-break, the utility formula, or any unit
- A new variant in `KernelAction`, `KernelReason`, `GateKind`, `CandidateVerdict`,
  `Disposition`, `SelectionStrategy`, `IdentityField`, `ConservationStatus` or
  `VerifyResult` — these are the decision and verification contract, and they are
  exhaustive on purpose, so adding one is a breaking change and this line does not
  make breaking changes
- A new field in `KernelInput`, `KernelModel` or `KernelDecision` — callers build
  these with struct literals, so a field is a breaking change, and they are
  hashed, so a field is a digest change
- A change to any digest layout or its tag

If a defect requires one of these, it will be **documented here with a
description and a workaround** rather than fixed. A correction that invalidates
every artifact ever written against this format costs more than the defect.

## Minimum supported Rust version

1.85, declared in `Cargo.toml`. Raising it would be a breaking change, so it will
not be raised. The crate will stop building on a future toolchain eventually; that
is what pinning `Cargo.lock` and publishing a source archive is for.

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
run it, so it has to work.

## Artifacts written by older versions

Digest tags are versioned (`calypol1`, `calyinp1`, `calydcn1`, `calyldg1`,
`calyidn1`, `calysel1`, `calyout1`). An artifact written by an earlier release verifies under
the format it names. Nothing in 1.0.x changes what an existing tag means, and
1.0.x introduces no new tag: a different format would be a different tag, and
that is not what this line is for.

## If you need something this will not do

Fork it. Apache-2.0 does not expire when maintenance does, and a fork is the
supported answer to a requirement this repository has decided not to meet. The
decision semantics are documented, the digest layouts are written out byte by byte
in [SPECIFICATION.md](SPECIFICATION.md), and every property the crate promises is
listed in [INVARIANTS.md](INVARIANTS.md) against the test that guards it. That is
roughly everything a fork needs and usually does not get.
