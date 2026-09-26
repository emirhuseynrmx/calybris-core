# Trust-layer operations, 1.3 preview

The automated tests establish protocol behavior. They are not an external
cryptographic audit, and a maintainer-operated witness is not independent.
The key procedures step by step are in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)
§4–6; this page is the operating runbook around them.

## Log key custody and rotation

Generate distinct log and witness seeds with `checkpoint keygen`; never put
`.skey` files in the published bundle. Restrict secret-directory access to the
service identity and back it up encrypted. Use an HSM-backed signing adapter
for deployments that require non-exportable keys; the CLI uses seed files.

Keep the checkpoint origin fixed. Publish the new public key through an
authenticated operator channel, with key id, activation date, old key id and
the last externally anchored checkpoint. Verifiers pin the new key explicitly;
an arbitrary key embedded in a document is not a trust anchor. Witnesses update
their log-key pin while retaining the same stored tree head, then demand a
consistency proof extending that head. Keep old public keys for historical
verification. Old signatures are not magically verified by a new public key.

During a compromise: stop the signer, preserve the WAL and externally held
checkpoints, revoke the key with a trusted time, establish the last checkpoint
whose *signature* existed before that time, distribute a new pin and extend
the retained witness heads. Do not regenerate a history to make it look clean.
Content-only timestamps and the operator's own timestamp cannot establish
when a compromised key signed. Use `KeyStatus` with `Covers::Signature` evidence.

## Witness state and key recovery

Use a local filesystem with tested locking and rename semantics. Do not share
a `FileStore` over a filesystem whose advisory locks or atomic replacement are
not guaranteed. Test storage durability for the actual operating system.
Unix synchronizes parent directories; Windows currently has no corresponding
power-loss guarantee. Run one deployment owner per canonical state-file path;
do not alias the path through alternate links.

Back up the witness key and state together. Record heads in a separate,
authenticated append-only store. A corrupt or missing state file fails closed: `witness cosign` refuses it,
and `witness init` never overwrites a state. An old but valid backup cannot be
distinguished locally from the latest state: freeze that identity. Recover to heads agreed with external pinned
checkpoints, or retire the key and enroll a new witness identity. Never reuse
the old key with an empty state. Published witness policies must explicitly
activate the new public key; changing keys does not automatically migrate trust.

Do not count two keys from one organisation as two independent operators.
Monitor failed requests, divergent roots, stale checkpoints, last successful
cosignature and witness key changes. Alert on missing quorum rather than
silently reducing the threshold.

## TSA and Bitcoin lifecycle

Pin the TSA signing certificate through an authenticated channel. Retain the
certificate alongside historical tokens. Certificate validity is checked at
token time; the verifier does not implement online certificate revocation or
general PKIX chain construction. A new certificate requires an explicit pin
update and operational revocation review. Test the new pin before activation.

On timeout, invalid DER, wrong imprint, wrong nonce, expired certificate or
invalid signature, keep the checkpoint but report incomplete/failed time
evidence. Retry with bounded backoff; never substitute the local clock for
an external timestamp. OTS Pending is not Bitcoin evidence. Upgrade only via
allowlisted calendars. Verify the proof against the block header, then confirm
the hash at that height with your own fully validated Bitcoin node. Independent
explorers can be an explicitly stated alternative, not a claim of own-node
verification. Keep the raw token/proof, block header and provenance of its pin.

## Release and incident evidence

Keep exact source commit, public-key registry, signed checkpoint, token/proof,
test results and benchmark environment. Preview APIs remain preview. A signed
release tag requires the maintainer's signing identity; a machine-generated
throwaway key does not substitute for that identity. Verify distribution
attestations against the actual published artifact digest, not a rebuilt file.
