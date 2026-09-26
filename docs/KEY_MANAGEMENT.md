# Key Management

Calybris uses independent keys, all **entirely in the caller's custody** —
the library never generates, stores, or rotates them (`calybris-verify
checkpoint keygen` can generate checkpoint and witness keys, and stops there;
see the custody line in
[THREAT_MODEL.md](THREAT_MODEL.md)). This guide is the operational counterpart:
what each key is for, and how to hold and rotate it without breaking a proof
trail.

| Key | Algorithm | Protects | Feature |
|-----|-----------|----------|---------|
| **WAL chain key** | HMAC-SHA256 | Tamper-*evidence* of a decision log against an insider who can rewrite the file | `wal` (keyed mode) |
| **Policy signing key** | Ed25519 | Attribution — *which* accountable party approved a policy | `provenance` |
| **Receipt signing key** | Ed25519 | Authenticity of a complete decision receipt, including state/WAL evidence | `receipt` + `provenance` |
| **Checkpoint log key** | Ed25519 (C2SP note) | That a checkpoint of the decision log is the log's own | `preview` |
| **Witness key** and its state file | Ed25519 (`cosignature/v1`) | That an independent party saw the checkpoint, and that it extends everything the witness saw before | `preview` |
| **Pinned TSA certificate** (someone else's key) | RSA or ECDSA | That an RFC 3161 token dates the signed checkpoint | `preview-tsa` |

They are unrelated: you can use either, both, or neither. Neither key is ever
needed to *replay* a decision (that only needs the disclosed policy/input);
they add tamper-evidence and attribution on top.

## 1. WAL chain key (HMAC-SHA256)

Without a key the hash chain detects accidents (malformed writes, bit-rot). **With**
a key it detects a motivated insider who can rewrite the file, because they
cannot recompute a valid chain without the secret.

Neither mode detects a cleanly removed suffix without a trusted external
`WalAnchor`; store each finalized head outside the WAL file.

WAL writer locks are keyed by the operating system file identity, so symlink
and hardlink aliases share one lock. By default the lock files live in the
current user's secure runtime/cache directory. Services running under multiple
OS users against the same WAL must set `CALYBRIS_WAL_LOCK_DIR` to one shared,
access-controlled directory.

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
- Keyed WAL APIs reject keys shorter than 32 bytes, including empty keys. This
  prevents a deployment from accidentally labeling a publicly forgeable chain
  as HMAC-protected.
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
   verify historically signed policies. Do not remove archival public keys
   merely because the private key has been retired.
3. Publish a revocation time in the verifier's trusted registry. A signed
   caller timestamp alone cannot establish that a signature predates compromise.
   Accept revoked-key history only with independently verified evidence
   covering the signature (`audit::Covers::Signature`) before revocation;
   content-only evidence is insufficient.

## 3. Receipt signing key (Ed25519)

Receipt signatures answer a different question from policy signatures:
"which service attested to this complete decision receipt?" The signed message
includes the canonical receipt claims digest, so changing the decision, state
transition, or WAL anchor invalidates the signature.

Use a distinct KMS/HSM key and identity for receipt signing when policy approval
and runtime attestation belong to different trust domains. Pin the verifying
key with `verify_receipt_signature(..., Some(&trusted_key))`; never trust only
the public key embedded in an untrusted receipt.

## 4. Checkpoint log key (preview)

The key that signs checkpoints ([TRUST.md](TRUST.md)). Its name is the log's
origin, for example `decisions.example.com/log`. Monitoring, storage and
incident evidence around these procedures are in
[TRUST_OPERATIONS.md](TRUST_OPERATIONS.md).

**Generate** it with `calybris-verify checkpoint keygen --kind log`, which
draws 32 bytes from the operating system's CSPRNG, or derive it from a seed
your KMS releases (`LogSigner::from_seed`). `keygen` creates the `.skey`
readable by its owner only (mode `0600` on Unix, set as the file is created;
on Windows one access entry for the owner, set with `icacls` before the
secret is written), refuses to replace an existing `.skey` or `.vkey`, and
if either cannot be written removes whatever it had created, so a failed
run leaves neither file. The library signs with the key in
memory; it has no HSM interface, so a key that must never leave an HSM needs a
signer outside Calybris that produces the same C2SP signature line.

**Store** the `.skey` with the same care as the WAL key, and never beside the
log it signs: whoever holds both can sign a rewritten history. Publish the
`.vkey` where auditors will find it, with the date it took effect.

**Rotate** through one checkpoint that both keys sign:

1. Generate the new key and publish its `.vkey` with its start date, over
   the same channel as the first key.
2. Sign the next checkpoint with the old key, then add the new key's line to
   the same note (`SignedNote::add_signature`). Verifiers holding either key
   accept that checkpoint.
3. Have the witnesses cosign it, then switch each witness to the new key
   (`Witness::add_log`). A witness keeps its memory of the log across the
   change, because the memory is per origin, not per key.
4. Sign every later checkpoint with the new key only. Auditors hand over at
   the transition checkpoint: their old-key view ends there and their new-key
   view starts there.
5. Mark the old key revoked from a time after the transition was witnessed,
   and keep its `.vkey` for as long as the checkpoints it signed are audited.

`tests/trust_operations.rs` runs this sequence, including a checkpoint the
old key signs after the rotation, which every witness refuses.

**If the key is compromised:**

1. Stop signing with it, and fix the time of the compromise with evidence
   that is not your own word: an RFC 3161 token over a statement of it, or a
   witnessed checkpoint of an incident log.
2. Tell every witness to drop the key now. From then on they refuse any
   checkpoint it signs, so the thief cannot get a new history cosigned.
3. Authenticate the replacement key out of band. The compromised key cannot
   vouch for it, which is the difference from a planned rotation.
4. The first checkpoint under the new key must extend the last checkpoint
   the witnesses cosigned; they enforce that with a consistency proof, so the
   history is carried over by the witnesses, not by the old key.
5. Auditors verify old checkpoints with `KeyStatus::Revoked { at,
   bitcoin_height }`: a signature counts only if a witness quorum or an
   RFC 3161 token over the signed note dates it before `at`, or an
   OpenTimestamps proof over it sits in a Bitcoin block at or below
   `bitcoin_height`. Record that height, the tip of your own node, when you
   revoke; a Bitcoin block's own time is set by its miner and is never
   compared with `at`. Evidence that dates only the body does not count.
6. Compare every checkpoint the old key signed after `at` that you can find
   with your auditors' views (`Auditor::compare`): a second history signed
   with the stolen key comes out as split-view proof.

## 5. Witness key and state (preview)

A witness is a key and a state file together. The state is the latest tree
head it cosigned for each log; it is what makes the witness refuse a
rewritten history, so losing it is as serious as losing the key.

- **Start** a witness with `calybris-verify witness init --state FILE`
  (`FileStore::create`). It refuses to overwrite an existing file, so it can
  never reset a witness.
- **A missing or unreadable state is refused**, never taken as a new witness
  (`FileStore::open`). The witness stops cosigning until the file is back.
- **Back up** the state after every cosignature, or keep it on storage that
  is itself replicated synchronously. **Restoring an older copy is a
  rollback**: the witness will cosign a fork that extends the head in that
  copy. `tests/trust_operations.rs` shows it, and shows what still catches it:
  the other witnesses refuse the fork, so it misses the quorum, and any
  auditor holding the real checkpoint turns the fork into proof. So never
  restore the witnesses of different parties from backups at the same time,
  and if one witness's state is lost for good, retire it:
- **Retiring a witness** (state lost, key lost or key exposed): generate a
  new witness key under a new name, `witness init` its state, publish the new
  `.vkey`, and have verifiers replace the old key in their `WitnessPolicy`.
  Cosignatures the old key made stay checkable with its `.vkey`. Never give a
  new state to an old key.

## 6. Pinned TSA certificates (preview-tsa)

An RFC 3161 token is checked against a TSA certificate you pin
(`tsa::PinnedTsa`); the verifier builds no chain and checks no revocation
list. So the pin set is the policy, and it is yours to keep current:

- Pin each TSA's signing certificate from the TSA's own publication, and
  record its validity period. A token verifies only if its `genTime` falls
  inside that period.
- When a TSA rotates its certificate, add the new one to the pin set and keep
  the old one for the tokens it signed.
- If a TSA reports its key compromised, remove that certificate from the pin
  set for new verifications, and treat its tokens from after the compromise
  as no evidence. Tokens from before it still date what they dated only if a
  second source agrees; so stamp with two TSAs, or a TSA and OpenTimestamps.
- An unreachable TSA or a response that does not verify costs the timestamp,
  not the checkpoint: publish the checkpoint, have it witnessed, and request
  the token again. `checkpoint verify` reports a missing or failed token as
  what it is, and `--require timestamped` turns it into a failure where a
  timestamp is mandatory.

## 7. Caveats the keys do not remove

- Timestamps are **caller-asserted** — a holder of the signing key can backdate
  `signed_at_epoch_ms`. For non-repudiation of *time*, date checkpoints with
  witnesses, an RFC 3161 authority or OpenTimestamps, and treat a revoked key
  as valid only for what that evidence places before its revocation
  (`audit::KeyStatus`, [TRUST.md](TRUST.md)).
- Keys protect integrity/attribution, **not confidentiality** — payloads are in
  the clear. Encrypt at rest/in transit separately.
- A leaked key defeats its guarantee entirely. Rotation cadence and HSM custody
  are your controls; the library gives you the primitives, not the policy.

## 8. Operational checklist

- [ ] Keys generated from a CSPRNG, inside an HSM/KMS where possible.
- [ ] No key material in source, committed env files, or container images.
- [ ] HMAC WAL, policy-signing, and receipt-signing keys are distinct secrets with separate
      custody and rotation schedules.
- [ ] Verifying (public) keys published with validity dates; verifiers pin the
      trust anchor rather than trusting the embedded key.
- [ ] WAL re-key is a new-file segment boundary, never an in-place recompute.
- [ ] Retired keys retained only as long as archived segments/policies remain
      under audit, then removed from the trust set.
- [ ] External RFC 3161 timestamping added if non-repudiation of *time* matters.
- [ ] Checkpoint log key stored apart from the log; rotation goes through a
      checkpoint both keys sign (§4).
- [ ] Each witness state backed up with its key, never restored together with
      another party's witness, and a witness with lost state retired, not reset (§5).
- [ ] TSA pin set kept current, with two independent time sources (§6).
- [ ] Payload confidentiality handled separately (keys are integrity, not secrecy).

See also: [CALY_PROOF.md](CALY_PROOF.md) §5 (WAL), §7 (policy signatures),
and §8 (decision receipts),
[THREAT_MODEL.md](THREAT_MODEL.md) (A1 file tamperer, A5 signature splicer).
