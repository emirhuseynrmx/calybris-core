# Security Policy

## Reporting a Vulnerability

Email: emirhuseyininci@gmail.com  
Subject: `[SECURITY] Calybris Core — <brief description>`

| Milestone | Target |
|-----------|--------|
| Acknowledgment | 7 days |
| Severity assessment | 30 days |
| Fix for a critical defect in 1.0.x | best effort, no committed date |

These are the targets of one person maintaining a project that has stopped taking
features. They are deliberately slower than the ones this file used to state,
which were 48 hours and 30 days: a frozen project cannot keep them, and a
security promise that is not kept is worse than one that was never made.

Please include: affected version, reproduction steps, impact on invariants I1–I10 (see `docs/SECURITY_INVARIANTS.md`), and suggested fix if any.

**Do not** open public GitHub issues for undisclosed vulnerabilities.

## Scope

| Component | In scope | Notes |
|-----------|----------|-------|
| `calybris-core` on crates.io | Yes | This repository |
| Examples / benches | Yes | Same repo |
| Your application integration | No | How you call `read_wal`, key storage, etc. |

## Supported Versions

1.0.0 is the last release that adds features. Development continues in a separate
product built on this core, not in this repository.

| Version | Supported |
|---------|-----------|
| 1.0.x   | Critical security and verification defects only |
| < 1.0   | No |

"Critical" means a defect that lets a decision, a receipt or a WAL be forged,
replayed incorrectly, or verified as valid when it is not. Anything that would
require changing the decision semantics or a digest format will not ship: those
are frozen, and correcting them would invalidate every artifact written against
them. Such a defect would be documented here with a description and a workaround
rather than silently fixed.

The licence does not expire when maintenance does. Apache-2.0 permits a fork, and
a fork is the supported answer to a need this repository will not meet.

## Security Properties (OSS)

- `#![forbid(unsafe_code)]` in project code
- Integer-only kernel hot path (no `f64` in prescribe)
- Version-tagged canonical SHA-256 digests
- Hash-chained WAL with optional HMAC-SHA256 (`subtle` constant-time compare)
- CAS budget engine with conservation invariant
- Fail-closed audited WAL replay on digest or prescribe mismatch

## Audit Package

External reviewers should start with:

1. [docs/AUDIT_GUIDE.md](docs/AUDIT_GUIDE.md) — commands and module map
2. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, trust boundaries, attackers
3. [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md) — invariants I1–I10 and test mapping

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo test --locked --test audit_pipeline
PROPTEST_CASES=10000 cargo test --locked --all-features
```

## Known Limitations

- **Unkeyed WAL:** Detects accidental corruption; a filesystem attacker can recompute plain SHA-256 chain hashes. Use **keyed WAL** in production.
- **`read_wal`:** Does not verify chain — use `read_verified_wal*` only on trusted paths.
- **Caller responsibility:** `verify_decision` must be enforced by your control plane; the library does not block application logic on failure.
- **Clean WAL suffix truncation:** A hash-chain prefix remains internally valid.
  Persist and verify a trusted external `WalAnchor` when log completeness matters.
- **Weak keyed-WAL configuration:** Keyed APIs reject HMAC keys shorter than
  32 bytes; load independent random key material from a secrets manager.
- **Oversized WAL records:** Readers and writers reject encoded entries above
  16 MiB before JSON parsing or persistence.
- **Unchecked Rust hot path:** Validate direct `KernelInput` values or use
  `prescribe_checked`; Python bindings validate automatically.
- **Artifact semantics:** Security artifacts reject unknown JSON fields. Do not
  attach unsigned application claims outside the signed receipt or WAL payload.
- **Formal concurrency proofs:** Loom/Miri in CI cover selected budget interleavings and UB paths; not exhaustive for all production schedules.

## Dependency Policy

- `Cargo.lock` committed; CI uses `--locked`
- Weekly `cargo audit` + `cargo deny` via `deny.toml` (see `.github/workflows/security.yml`)
- Dependabot for Cargo and GitHub Actions

## Deployment Security

Production deployments should add API-plane separation, deployment hardening (read-only containers, no-new-privileges), provider credential isolation, and additional adversarial tests around the service boundary.
