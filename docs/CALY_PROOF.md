# CALY-PROOF v1 — Canonical Proof Format

This document specifies the byte-exact format of every digest and hash chain
Calybris produces, so that **an independent implementation can verify a
Calybris decision trail without running Calybris**. The Rust crate is the
reference implementation; this spec is the contract.

Scope: policy / input / decision / ledger digests, the audit bundle binding,
and the hash-chained WAL (unkeyed and HMAC-keyed).

## 0. Conventions

- `SHA256(x)` — FIPS 180-4 SHA-256 over byte string `x`.
- `HMAC-SHA256(k, x)` — RFC 2104 with SHA-256.
- `LE(v)` — little-endian encoding of integer `v` at its declared width.
- `hex(x)` — lowercase hexadecimal, two digits per byte, no prefix.
- `||` — byte concatenation.
- All digests are 32 bytes, rendered as 64 lowercase hex characters.

Every digest is **domain-separated** by a 9-byte version tag (8 ASCII bytes +
one NUL). Bumping a layout bumps the tag (`…1` → `…2`); old proofs stay
verifiable under their original tag.

| Digest | Tag bytes |
|---|---|
| Policy | `calypol1\0` |
| Input | `calyinp1\0` |
| Decision | `calydcn1\0` |
| Budget ledger | `calyldg1\0` |
| State transition | `calystt1\0` |

## 1. Policy digest

```
policy_digest = SHA256(
    "calypol1\0"
 || LE(policy_epoch: u64)
 || LE(catalog_epoch: u64)
 || LE(hard_risk_limit_bps: u16)
 || LE(minimum_confidence_bps: u16)
 || LE(risk_penalty_multiplier_bps: u16)
 || LE(latency_penalty_microunits_per_ms: u64)
 || model_bytes*                      # ascending model_id order
)
```

Each model contributes, in order:

```
LE(model_id: u32) || LE(provider_id: u16) || LE(quality_bps: u16)
 || LE(risk_ceiling_bps: u16) || LE(enabled: u8) || LE(p95_latency_ms: u32)
 || LE(capabilities: u64) || LE(region_mask: u64)
 || LE(input_cost_microunits_per_million_tokens: u64)
 || LE(output_cost_microunits_per_million_tokens: u64)
```

Models are sorted by ascending `model_id` before hashing, so catalog insert
order never changes the digest.

## 2. Input digest

```
input_digest = SHA256(
    "calyinp1\0"
 || LE(request_sequence: u64) || LE(requested_model_id: u32)
 || LE(input_tokens: u32) || LE(output_tokens: u32)
 || LE(business_value_microunits: i64) || LE(budget_limit_microunits: u64)
 || LE(risk_bps: u16) || LE(confidence_bps: u16)
 || LE(minimum_quality_bps: u16) || LE(max_p95_latency_ms: u32)
 || LE(required_capabilities: u64) || LE(allowed_provider_mask: u64)
 || LE(required_region_mask: u64)
)
```

Signed integers use two's-complement little-endian at their declared width.

## 3. Decision digest

```
decision_digest = SHA256(
    "calydcn1\0"
 || LE(request_sequence: u64)
 || action: u8                        # ExecuteRequested=1, Substitute=2, Reject=3
 || LE(reason: u16)                   # discriminant values, see kernel::KernelReason
 || LE(selected_model_id: u32) || LE(selected_model_index: u16)
 || LE(estimated_cost_microunits: u64) || LE(expected_utility_microunits: i64)
 || LE(counterfactual_model_id: u32) || LE(counterfactual_utility_microunits: i64)
 || LE(evaluated_models: u16) || LE(eligible_models: u16)
 || LE(policy_epoch: u64) || LE(catalog_epoch: u64)
)
```

## 4. Audit bundle

An audit bundle binds one decision to its policy and input:

```json
{
  "schema_version": "calybris.audit.v1",
  "digest_algorithm": "sha256",
  "proof_version": 1,
  "policy_epoch": ..., "catalog_epoch": ...,
  "created_by": "calybris",
  "policy_digest_hex": hex(policy_digest),
  "input_digest_hex": hex(input_digest),
  "decision_digest_hex": hex(decision_digest),
  "replay_valid": true
}
```

A verifier accepts a bundle iff it can recompute all three digests from the
disclosed policy/input/decision and — when the policy is disclosed —
re-derive the decision via the kernel and match it field-for-field
(`replay_valid`). Fail-closed producers (`verified_audit_bundle`,
`append_verified_audited`) never emit a bundle whose replay failed.

## 5. Hash-chained WAL

One JSON object per line (JSONL). Entry layout:

```json
{"sequence":N,"previous_hash":"...","entry_hash":"...","data":<payload JSON>}
```

- `sequence` starts at 1 and increments by exactly 1; gaps and duplicates are
  chain violations.
- `previous_hash` of entry 1 is the literal string `genesis`.
- Unkeyed chain:  `entry_hash = hex(SHA256(previous_hash_utf8 || data_json_utf8))`
- Keyed chain:    `entry_hash = hex(HMAC-SHA256(key, previous_hash_utf8 || data_json_utf8))`
- `data_json_utf8` is the exact serialized bytes of the `data` field as
  written. Verifiers that re-serialize a parsed payload MUST reproduce those
  bytes exactly; comparisons of keyed chains MUST be constant-time.

### 5.1 Payload float rule

The chain binds the *serialized bytes* of the payload. JSON floating-point
round-tripping is only byte-stable when the parser is exact — a default
parser that loses the final ulp on 17-significant-digit values will compute
a different hash for a record it just read. Therefore:

1. Payloads SHOULD be float-free (Calybris kernel types are integer-only).
2. Implementations that permit floats MUST parse them exactly
   (`serde_json` `float_roundtrip` feature in the reference implementation)
   and MUST serialize with shortest-roundtrip formatting (Ryu).

### 5.2 Audited records

`append_verified_audited` writes `data` as:

```json
{"audit": <audit bundle>, "input": <KernelInput>, "decision": <KernelDecision>, "metadata": ...}
```

An auditor verifies, per entry: chain linkage (§5), then
`input_digest(input) == audit.input_digest_hex`,
`decision_digest(decision) == audit.decision_digest_hex`, and — given the
policy artifact — `policy_digest(policy) == audit.policy_digest_hex` plus a
full kernel replay of `decision`.

## 6. State transition digest (stateful decisions)

A stateful decision extends the bundle with the state trajectory:

```
state_digest = SHA256("calystt1\0" || LE(step: u64) || state_bytes)
```

where `state_bytes` is the caller-defined canonical encoding of the domain
state (same integer-only guidance as §5.1). A stateful proof records
`state_digest_before` and `state_digest_after`; a sequence of proofs is valid
iff each entry's `before` equals the previous entry's `after` (with step 0 /
`genesis` rules identical to §5) and each decision replays.

## 7. Signed policy provenance (feature `provenance`)

A policy may be bound to an accountable signer with Ed25519 (RFC 8032):

```
message   = "calysig1\0" || policy_digest (32 raw bytes)
         || LE(signed_at_epoch_ms: u64) || signer_id_utf8
signature = Ed25519(signing_key, message)
```

The signed artifact discloses `policy_digest_hex`, `signer_id`,
`signed_at_epoch_ms`, `public_key_hex` (32 bytes) and `signature_hex`
(64 bytes). Verifiers MUST recompute the policy digest from the disclosed
policy (§1), rebuild the message, and verify the signature; deployments with
a registered signer key MUST additionally pin `public_key_hex` to that trust
anchor. Domain separation makes a signature non-transferable across
policies, signers, and timestamps.

## 8. Portability

The verification path (kernel, digests, state chain, replay) compiles for
`wasm32-unknown-unknown` with `--no-default-features`; proofs can be checked
in browsers and edge runtimes. The WAL writer requires a filesystem.

## 9. Golden vectors

`tests/fixtures/caly_proof_v1.json` pins byte-exact expected digests for a
fixed policy/input/decision triple and a fixed WAL chain. Any implementation
(and any future version of this crate, on any platform) MUST reproduce them
exactly. A vector mismatch is a breaking change and requires a new digest
tag, never a silent re-pin.
