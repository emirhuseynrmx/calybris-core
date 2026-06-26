# Threat Model — Calybris Core (OSS)

**Scope:** `calybris-core` crate v0.3.x — deterministic decision kernel, digest binding, optional WAL, CAS budget engine.

**Out of scope:** Network transport, authentication, provider credentials, deployment hardening (see proprietary engine).

## Assets

| Asset | Why it matters |
|-------|----------------|
| **Decision correctness** | Wrong prescribe output routes capital or compute incorrectly |
| **Audit digests** | Bind decisions to policy + input; tampering must be detectable |
| **WAL chain integrity** | Historical decisions must not be silently rewritten |
| **Budget conservation** | `remaining + reserved + committed_lifetime == initial` after completed ops and at reconciliation |
| **HMAC key** (keyed WAL) | Secret that prevents hash recomputation by filesystem attacker |

## Trust boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Your application (trusted caller)                      │
│    prescribe / reserve / append_audited                 │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  calybris-core (this crate)                             │
│    kernel · verify · digest · budget · wal              │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│  Storage / OS (untrusted for WAL files on disk)         │
└─────────────────────────────────────────────────────────┘
```

- **Trusted:** Code that calls `prescribe`, `try_reserve`, `append_audited` with honest inputs.
- **Untrusted:** WAL files at rest (assume attacker can edit bytes unless HMAC key is secret).
- **Assumed honest:** Callers do not invoke `read_wal` on attacker-controlled files and treat output as verified.

## Attacker models

### A1 — WAL file tamperer
- **Capability:** Read/write WAL JSONL on disk; cannot derive HMAC key.
- **Goal:** Alter past decisions without detection.
- **Mitigation:** Hash chain + optional HMAC-SHA256; `read_verified_wal*` / `replay_audited_wal*` fail closed.
- **Residual risk:** Unkeyed chain detects accidental corruption; motivated attacker with write access can recompute unkeyed hashes. **Use keyed WAL in production.**

### A2 — Malicious API caller
- **Capability:** Submit arbitrary `KernelInput`, budget amounts, fake `KernelDecision`.
- **Goal:** Bypass policy or spend without reservation.
- **Mitigation:** Kernel is deterministic; `verify_decision` + digest binding detect substituted decisions; budget CAS prevents overspend.
- **Residual risk:** Caller can still *choose* to ignore `VerifyResult` — embed verification in your control plane.

### A3 — Concurrent tenant abuse
- **Capability:** Many threads racing on same tenant budget.
- **Goal:** Double-spend via TOCTOU.
- **Mitigation:** `debit_if_available` CAS loop; mutex ordering on metadata maps.
- **Residual risk:** Not formally verified with Loom/Miri in CI (roadmap item).

### A4 — Digest confusion
- **Capability:** Supply malformed hex in `AuditBundle`.
- **Goal:** Downstream systems accept invalid bindings.
- **Mitigation:** `DigestDecodeError` on decode; replay checks all three digests.

## Non-goals

- Side-channel resistance beyond HMAC compare (`subtle::ConstantTimeEq`)
- Byzantine consensus across replicas
- Cryptographic timestamps / TSA
- Post-quantum hash algorithms

## Recommended production controls

1. Enable `wal` feature with **HMAC key** from a secrets manager.
2. Always use `read_verified_wal_keyed` / `replay_audited_wal_keyed` — never `read_wal` on external paths.
3. Call `verify_decision` or `replay_audited_wal` before acting on historical entries.
4. Run `prove_conservation` on budget engine at reconciliation boundaries.
5. Pin crate version and verify `Cargo.lock` in CI (`--locked`).