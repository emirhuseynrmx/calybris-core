# Key Management

Calybris uses two independent keys, both **entirely in the caller's custody** —
the library never generates, stores, or rotates them (see the custody line in
[THREAT_MODEL.md](THREAT_MODEL.md)). This guide is the operational counterpart:
what each key is for, and how to hold and rotate it without breaking a proof
trail.

| Key | Algorithm | Protects | Feature |
|-----|-----------|----------|---------|
| **WAL chain key** | HMAC-SHA256 | Tamper-*evidence* of a decision log against an insider who can rewrite the file | `wal` (keyed mode) |
| **Policy signing key** | Ed25519 | Attribution — *which* accountable party approved a policy | `provenance` |

They are unrelated: you can use either, both, or neither. Neither key is ever
needed to *replay* a decision (that only needs the disclosed policy/input);
they add tamper-evidence and attribution on top.

## 1. WAL chain key (HMAC-SHA256)

Without a key the hash chain detects accidents (truncation, bit-rot). **With**
a key it detects a motivated insider who can rewrite the file, because they
cannot recompute a valid chain without the secret.

```rust
use calybris_core::wal::{WalWriter, read_verified_wal_keyed, verify_wal_keyed};

// 32 bytes from your secrets manager — never a literal in source.
let key: Vec<u8> = load_from_kms("calybris/wal-hmac");

let mut wal = WalWriter::open_keyed(std::path::Path::new("decisions.jsonl"), &key)?;
// … append_verified_audited(&policy, input, decision, meta)? …

// Auditor side (same key):
let (entries, last_hash) = verify_wal_keyed(std::path::Path::new("decisions.jsonl"), &key)?;
```

**Custody**
- 32 bytes of CSPRNG output. Store in a secrets manager / KMS / HSM, never in
  source, env files committed to git, or container images.
- The auditor who verifies the chain needs the same key. If verification is
  performed by a third party you do not want to hand the key to, verify in a
  boundary you control and hand them the *result* (or use signatures instead —
  they are asymmetric, see §2).
- Comparison is constant-time (`subtle`), so a leaked HMAC does not leak via
  timing — but a leaked *key* forges chains. Treat it as a top-tier secret.

**Rotation** — the chain binds each entry to the previous hash under one key,
so a key change is a **segment boundary**, not an in-place re-key:
1. Finalize the current WAL file (stop appending) and record its `last_hash`
   and key id in your metadata store.
2. Start a **new** WAL file under the new key. Genesis of the new file may
   record the previous file's `last_hash` in its first entry's metadata so the
   two segments are provably ordered.
3. Keep the old key long enough to verify archived segments; retire it only
   after those segments are re-sealed or no longer under audit.

Never re-key a file in place — recomputing the chain with a new key destroys
the very tamper-evidence the key exists to provide.

## 2. Policy signing key (Ed25519)

Answers "who approved this policy," not "was the log altered." Asymmetric: the
**private** signing key stays with the approver; the **public** verifying key
is distributed freely to anyone who audits.

```rust
use calybris_core::provenance::{sign_policy, verify_signed_policy_with_key};
use ed25519_dalek::{SigningKey, VerifyingKey};

// Signing key lives in an HSM/KMS; here shown loaded as raw bytes.
let signing = SigningKey::from_bytes(&load_from_kms("calybris/policy-officer"));
let signed = sign_policy(&policy, &signing, "risk-officer:ayse", now_epoch_ms());

// Verifier pins the trust anchor (the officer's known public key):
let trusted: VerifyingKey = load_public_key("risk-officer:ayse");
verify_signed_policy_with_key(&policy, &signed, &trusted)?;
```

**Custody**
- The **signing** key is the sensitive one: whoever holds it can approve any
  policy in that officer's name. Keep it in an HSM/KMS; sign via the KMS API
  rather than exporting raw bytes where possible.
- The **verifying** (public) key is not secret — publish it. Verifiers MUST
  pin it (`verify_signed_policy_with_key`) rather than trusting the key
  embedded in the artifact, or an attacker can sign with their own key and
  attach their own public key.
- The signed message is domain-separated (`calysig1\0` + policy digest +
  timestamp + signer id), so a signature is non-transferable across policies,
  signers, and timestamps.

**Rotation**
1. Generate the new keypair in the HSM; publish the new public key alongside
   the old one with validity dates (a small signer registry / JWKS-style file).
2. Sign new policies with the new key; keep the old public key available to
   verify historically signed policies.
3. Revoke by removing the retired public key from the trust set once no
   in-audit policy relies on it. Because the timestamp is signed, verifiers can
   also reject signatures dated after a key's revocation.

## 3. Caveats the keys do not remove

- Timestamps are **caller-asserted** — a holder of the signing key can backdate
  `signed_at_epoch_ms`. For non-repudiation of *time*, co-sign with an external
  timestamping authority (RFC 3161).
- Keys protect integrity/attribution, **not confidentiality** — payloads are in
  the clear. Encrypt at rest/in transit separately.
- A leaked key defeats its guarantee entirely. Rotation cadence and HSM custody
  are your controls; the library gives you the primitives, not the policy.

## 4. Operational checklist

- [ ] Keys generated from a CSPRNG, inside an HSM/KMS where possible.
- [ ] No key material in source, committed env files, or container images.
- [ ] HMAC WAL key and Ed25519 signing key are distinct secrets with separate
      custody and rotation schedules.
- [ ] Verifying (public) keys published with validity dates; verifiers pin the
      trust anchor rather than trusting the embedded key.
- [ ] WAL re-key is a new-file segment boundary, never an in-place recompute.
- [ ] Retired keys retained only as long as archived segments/policies remain
      under audit, then removed from the trust set.
- [ ] External RFC 3161 timestamping added if non-repudiation of *time* matters.
- [ ] Payload confidentiality handled separately (keys are integrity, not secrecy).

See also: [CALY_PROOF.md](CALY_PROOF.md) §5 (WAL) and §7 (signatures),
[THREAT_MODEL.md](THREAT_MODEL.md) (A1 file tamperer, A5 signature splicer).
