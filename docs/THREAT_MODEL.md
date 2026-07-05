# Threat Model — Calybris Core (OSS)

**Scope:** `calybris-core` crate — deterministic decision kernel, digest binding, optional WAL, CAS budget engine, persistence, async WAL, proof envelope. Since 0.5.0 also covers the CALY-PROOF proof surfaces: certificates, signed policy provenance, stateful trajectories, and the `calybris-verify` auditor.

**Out of scope:** Network transport, authentication, provider credentials, and deployment hardening around the service boundary.

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
│    prescribe / reserve / append_verified_audited                 │
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

- **Trusted:** Code that calls `prescribe`, `try_reserve`, `append_verified_audited` with honest inputs.
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
- **Residual risk:** Loom/Miri cover selected concurrency and UB scenarios, but they are not formal proofs of all possible production interleavings.

### A4 — Digest confusion
- **Capability:** Supply malformed hex in `AuditBundle`.
- **Goal:** Downstream systems accept invalid bindings.
- **Mitigation:** `DigestDecodeError` on decode; replay checks all three digests.

## CALY-PROOF proof surfaces (0.5.0)

The single claim of the proof system is **integrity of a disclosed decision
trail**: given the policy, input, and decision, anyone can independently
confirm the decision is the exact deterministic output of that policy on that
input, and that a logged sequence was not altered, truncated, or reordered.
Sharp edges of that claim:

**Protects against** — silent tampering (canonical digests recomputed from
disclosed artifacts); log alteration/truncation/reorder/gaps (hash chain);
outsider forgery (keyed HMAC chain); "that's not the decision" (deterministic
replay); cross-version/platform drift (golden + conformance vectors);
repudiating the in-force policy (Ed25519-signed policy digest); splicing a
signature onto another policy/time/signer (domain separation `calysig1\0`);
inserting/dropping a state transition (state-digest chain).

**Does NOT protect against — read carefully:**

1. **No confidentiality.** Digests are integrity, not secrecy; WALs and
   certificates disclose inputs/decisions/values in the clear. Encrypt
   separately.
2. **Does not prove the policy was *good*.** It proves a decision followed *a*
   policy — not that the policy was wise, fair, or compliant. "Signed by the
   officer" is accountability, not correctness.
3. **Cannot vouch for inputs it never saw.** Wrong upstream data is faithfully,
   provably turned into the wrong decision. Input provenance is the caller's.
4. **Unkeyed chains detect accidents, not adversaries** (see A1).
5. **Key custody is entirely the caller's** — HMAC and Ed25519 keys are never
   managed here; a leaked key forges chains/signatures. Use HSM/KMS, rotate.
6. **Timestamps are caller-supplied.** The core is clock-free; `signed_at` is
   asserted, not proven — a signer can backdate. Use an external TSA if time
   non-repudiation matters.
7. **The verifier trusts its own build.** `calybris-verify` re-derives digests
   with the same code that made them; the fixed golden/conformance vectors
   exist so a *second, independent* implementation is the real cross-check.
8. **No liveness/durability guarantee.** It proves properties of records that
   exist, not that a decision was logged or reached disk. Pair with
   `append_verified_audited` + fsync.
9. **Fixed-point, not float.** Kernel types are integer-only; float payloads
   need exact round-tripping (CALY_PROOF §5.1) or the guarantee weakens.

### A5 — Certificate/signature splicer
- **Capability:** Reuse a valid signature or certificate on a different policy,
  time, or signer.
- **Goal:** Make an unauthorized decision look authorized.
- **Mitigation:** Domain-separated signing message binds policy digest +
  timestamp + signer id; `verify_certificate` recomputes all digests and
  replays; `verify_signed_policy_with_key` pins the trust anchor.
- **Residual risk:** A leaked signing key defeats this — custody is the caller's.

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
