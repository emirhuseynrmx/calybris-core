# Trust beyond the operator

Everything else in Calybris proves that a decision followed its policy, and
that the log of decisions has not been edited since its head was anchored. All
of it assumes one party is honest about which log is *the* log, and when each
record was written: the operator. This page is about removing that assumption.

It covers the `preview` modules `checkpoint`, `witness`, `audit` and `ots`, the
`preview-tsa` module `tsa`, and batch signing in `hybrid` (`preview-pq`). None
of them changes a decision or an existing digest. Like every preview feature,
their API may change in a minor release ([PREVIEW.md](PREVIEW.md)).

```text
 WAL entries ──► Merkle tree ──► checkpoint ──► log signature
                  (RFC 9162)     (C2SP text)          │
                                                      ▼
                                  witnesses cosign it only if it extends
                                  everything they cosigned before
                                                      │
                   ┌──────────────────────────────────┼─────────────────────┐
                   ▼                                  ▼                     ▼
          RFC 3161 token (TSA)           OpenTimestamps → Bitcoin      auditors compare
                   └──────────────► time evidence ◄───┘                  their views
```

One checkpoint covers every record before it, so one witness round and one
timestamp per checkpoint date millions of decisions. Nothing here runs on the
decision path.

## The four questions

### Where this stands today

The mechanisms are implemented and tested; the independent parties are not yet
in place. **No witness run by anyone other than the maintainer cosigns a
Calybris log today.** A policy of witnesses run by one party is a policy of one
witness, and `calybris-verify` reports what was checked, not what was hoped for.
The RFC 3161 authorities and Bitcoin are independent now; witnesses become
independent when other organisations run them, which the C2SP formats make
possible without any Calybris-specific software.

### 1. How does an independent witness notice it is being shown a false history?

By remembering. A witness keeps, for each log, the last tree head it cosigned,
and cosigns a new checkpoint only with a consistency proof (RFC 9162 §2.1.4)
that the new tree extends that head. It never cosigns a smaller tree, or a
different root at the same size. A log that rewrote a record, or that shows one
history to some parties and another to others, cannot produce the proof, and
the witness refuses (`witness::Witness::add_checkpoint`, HTTP 422).

One witness only knows what it was shown. Two things close the rest:

- **Quorum.** A verifier requires *k* of *n* witnesses it trusts
  (`audit::WitnessPolicy`). With *k* greater than *n*/2, two histories that do
  not extend each other cannot both reach the quorum unless the witnesses that
  signed both are dishonest, because an honest witness signs one history.
  `tests/split_view.rs` checks this against real witness state machines, with
  forks presented in every order.
- **Comparing notes.** An auditor holding one checkpoint checks any other it
  is shown (`audit::Auditor::compare`). Two checkpoints of the same size with
  different roots, both signed by the log, are proof anyone can verify
  (`audit::SplitView`). For different sizes, the log must supply a consistency
  proof, and a forked history cannot.

The witness writes its state before it returns a cosignature, through an atomic
compare-and-swap (`witness::FileStore` for a process on disk), so a crash or a
race cannot make it sign two inconsistent checkpoints while state is retained.
A missing or unreadable state is refused rather than taken for a new witness
(`FileStore::open`; `witness init` never overwrites a state). A valid old
backup put back is different: the file alone cannot show it is old, so an
external pinned head is required to detect that rollback, and the same witness
key is never restarted with empty or old state. `tests/trust_operations.rs`
demonstrates both.

Persistence synchronizes the temporary file before atomic replacement. Unix
also synchronizes the parent directory, subject to the filesystem's durability
contract. Windows does not synchronize that directory: process restart is
tested, but sudden power loss is not covered by a durable-write guarantee.
Production operators must validate their storage or use a durable transactional
`WitnessStore`; atomic replacement alone is not power-loss durability.

The formats are C2SP [tlog-checkpoint](https://c2sp.org/tlog-checkpoint),
[signed-note](https://c2sp.org/signed-note),
[tlog-cosignature](https://c2sp.org/tlog-cosignature) and
[tlog-witness](https://c2sp.org/tlog-witness), so the witnesses already running
for Go's checksum database and Sigsum can witness a Calybris log, and this
witness can serve their logs. `tests/c2sp_interop.rs` pins vectors made by the Go
reference packages: this crate verifies what Go signs, and reproduces Go's
output byte for byte.

### 2. Who confirms that a decision was recorded when it says it was?

Not the operator: every timestamp the operator writes is an assertion. Three
independent sources, each covering a whole checkpoint:

| Source | What it proves | Who you trust |
|---|---|---|
| Witness cosignatures | At least *k* witnesses had seen the checkpoint by the *k*-th earliest cosignature time (`audit::Witnessed::seen_by`) | The quorum |
| RFC 3161 token | A timestamping authority signed the digest at `genTime` (`tsa::verify_response`) | The TSA certificate you pinned |
| OpenTimestamps | The digest is committed in a Bitcoin block on the main chain; the block's time bounds when it existed (`ots::DetachedTimestamp::verify_bitcoin`, then `BitcoinHeader::confirm`) | Bitcoin's proof of work, and the source that tells you which block is at that height |

`audit::existed_by` takes the earliest. What is timestamped is the
**log-signed note** (`SignedNote::signed_by`: the body plus the log's signature
line), not the body alone, so the timestamp dates the signature as well as
every record in the tree. A stamp over the body alone (`Checkpoint::digest`) is
still accepted, as evidence of the content only; see question 3 for why the
difference matters.

The RFC 3161 check pins the TSA's signing certificate, requires its critical
`timeStamping` key usage and a `genTime` inside its validity, and verifies the
CMS signature over signed attributes that bind the token's content (RSA
PKCS#1 v1.5, ECDSA P-256 and P-384). It does not build a chain to a root or
check revocation: you name the certificate you trust. `tests/rfc3161.rs` uses
tokens from a local OpenSSL TSA of each key type and from FreeTSA and DigiCert,
each accepted by `openssl ts -verify` before it was pinned.

An OpenTimestamps proof is **Pending** until a calendar commits it to a Bitcoin
transaction, a few hours after submission:

| State | Meaning | Dates the checkpoint? |
|---|---|---|
| Pending | Calendars accepted the digest and promised to commit it | No |
| Anchored | The proof reaches a Bitcoin block attestation, not yet checked | No |
| Header checked | The path ends in the Merkle root of a header at the stated height whose work meets its own target and a floor of 2^64 | No |
| Confirmed | A source you trust names that header's hash for that height: `bitcoin-cli getblockhash` on your own node, or several independent explorers that agree | Yes: the block's time |

A header is 80 bytes anyone can write. One with an easy target and the right
Merkle root passes every check a header can have on its own; before the floor
(`ots::MIN_TARGET_ZERO_BITS`) it cost nothing to make, now it costs about 2^64
hashes, and only the chain check makes it worthless. So a proof dates nothing
until `BitcoinHeader::confirm` matches the hash, and `calybris-verify` asks for
`--block-hash`. The height is an input for the same reason: nothing in a proof
authenticates the height it claims.

### 3. What if an administrator also gets the signing keys?

Then they can sign anything as the log. What they cannot do:

- **Rewrite what witnesses saw.** Honest witnesses already cosigned the real
  history and refuse anything that does not extend it, so a rewritten past
  never reaches the quorum.
- **Show different histories to different people unnoticed.** See question 1.
- **Backdate.** A record appended now is in a checkpoint that witnesses,
  a TSA and Bitcoin date to now.
- **Freeze the log by going quiet** without it showing:
  `audit::Auditor::with_max_age` refuses a checkpoint whose quorum's newest
  cosignatures are too old.

What is left is signing new, correctly dated records. `audit::KeyStatus`
handles the key itself: once a key is marked revoked at time *t*, something it
signed counts only if independent evidence shows its **signature** existed
before *t*. The signer's own timestamp is not an input, and neither is
evidence that dates only the content: a checkpoint body stamped at 10:00 does
not show who signed it when, and a thief holding the key at 12:00 can sign that
old body. Evidence counts when it covers the signature (`audit::Covers`): a
stamp over the log-signed note, or a witness cosignature, since a witness
checks the log's signature before it cosigns. Keeping keys in an HSM, rotating them,
and choosing witnesses run by other organisations remain operational decisions
([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)); a witness run by the same
administrator adds nothing.

### 4. Has the hybrid signature implementation been independently audited?

**No.** Writing code cannot change that answer; an independent auditor can.
What has been done:

- A hybrid signature is valid only if **both** Ed25519 and ML-DSA-65 verify, so
  a flaw in the ML-DSA implementation does not weaken what Ed25519 gives today.
- `tests/acvp_ml_dsa.rs` runs NIST's ACVP vectors for ML-DSA-65 through the
  exact calls `hybrid` makes: all 25 key generations from a seed, 8
  deterministic signatures with a context, and 15 verifications, 12 of them
  forgeries that must be rejected. This shows conformance to FIPS 204 on those
  paths. It does not show resistance to side channels.
- Batches (`hybrid::HybridSigner::sign_batch`) sign one Merkle root for many
  digests, so there is less ML-DSA signing to go wrong, and one 3,309-byte
  signature instead of thousands.
- `preview-pq` stays a separate feature, labelled unaudited.

[AUDIT_SCOPE.md](AUDIT_SCOPE.md) is written for an auditor: the code in scope,
the claims to test, and what is out of scope.

## Running it

`calybris-verify` built with `preview` (and `preview-tsa` for tokens) runs the
whole flow. The operator:

```sh
calybris-verify checkpoint keygen --name decisions.example.com/log --kind log --out log
calybris-verify checkpoint create decisions.wal.jsonl --origin decisions.example.com/log \
    --key log.skey --prev checkpoints/000001.checkpoint --out checkpoints/000002.checkpoint
calybris-verify checkpoint request decisions.wal.jsonl --note checkpoints/000002.checkpoint --old 1000 > req.txt
```

Each witness, holding its own key and state:

```sh
calybris-verify witness init --state w1.state.json      # once, when the witness starts
calybris-verify witness cosign req.txt --key w1.skey --log decisions.example.com/log=log.vkey \
    --state w1.state.json --append-to checkpoints/000002.checkpoint
```

The state file is the witness's memory and fails closed: `cosign` refuses
when it is missing or unreadable, and `init` never overwrites one. The witness
refuses to cosign with a clock reading zero (C2SP tlog-witness forbids a
cosignature without a time), and `verify` does not count such a
cosignature. `--append-to` is checked before anything is signed: the note
must be the checkpoint in the request and carry no signature from this
witness yet. The note is then replaced in one rename, and left alone if it
changed while the witness was signing; the cosignature is on standard output
either way. A witness
restored from an older backup would cosign a fork of what it forgot; see
[KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) §5 for backups, and for retiring a
witness whose state is lost.

`req.txt` is a C2SP tlog-witness request body, so it can equally be sent to a
witness that speaks the protocol over HTTP.

Timestamps:

```sh
calybris-verify checkpoint stamp checkpoints/000002.checkpoint --log-key log.vkey   # OpenTimestamps, Pending
calybris-verify checkpoint upgrade checkpoints/000002.checkpoint.signed.ots        # hours later: Anchored
calybris-verify checkpoint tsa-request checkpoints/000002.checkpoint --log-key log.vkey  # prints the nonce
curl -H "Content-Type: application/timestamp-query" --data-binary @checkpoints/000002.checkpoint.signed.tsq \
    -o checkpoints/000002.checkpoint.signed.tsr https://freetsa.org/tsr
```

Both stamp `000002.checkpoint.signed`, the note with the log's signature only,
which they write next to it. `upgrade --allow-calendar URL` admits a calendar
that `stamp --calendar` used but the default list does not name.

An auditor, with only public material:

```sh
calybris-verify checkpoint verify checkpoints/000002.checkpoint --log-key log.vkey \
    --witness w1.vkey --witness w2.vkey --witness w3.vkey --threshold 2 \
    --wal decisions.wal.jsonl --prev checkpoints/000001.checkpoint \
    --ots checkpoints/000002.checkpoint.signed.ots \
    --block-height H --block-header HEX --block-hash HASH \
    --tsr checkpoints/000002.checkpoint.signed.tsr --tsa-cert freetsa.crt --nonce N \
    --require full
```

Or without Calybris at all: `scripts/verify_bundle.py` checks the log
signature, the cosignatures, the stamped bytes, the WAL chain and the Merkle
root with nothing but Python's standard library, written from the
specifications. `tests/fixtures/bundle` is a bundle both programs check.

```sh
python3 scripts/verify_bundle.py checkpoints/ --note 000002.checkpoint --witness w1.vkey
```

The last line of `checkpoint verify` names what was established, and nothing more:

| Result | Meaning |
|---|---|
| `SIGNATURE VERIFIED ONLY` | The operator's own signature. Nothing independent was checked. |
| `INDEPENDENTLY WITNESSED` | A quorum of the witnesses you named cosigned; no independent timestamp. |
| `TIMESTAMP VERIFIED` | An RFC 3161 token or a confirmed Bitcoin block dates it; no witnesses. |
| `FULL VERIFICATION COMPLETE` | The pinned log signature, configured witness quorum and at least one external timestamp. |

`--require witnessed|timestamped|bitcoin|full` makes a missing level a failure.

### What `FULL VERIFICATION COMPLETE` covers

Every one of these, and only these:

1. The note is signed by the log key you gave with `--log-key`.
2. At least `--threshold` of the witness keys you gave cosigned it. Each of
   them had, before cosigning, checked that it extends every checkpoint of
   this log it cosigned before.
3. An independent timestamp verified: an RFC 3161 token checked against a
   TSA certificate you pinned, or an OpenTimestamps proof in a Bitcoin block
   whose hash you confirmed with `--block-hash`. The output says whether it
   covers the log's signature or only the body.
4. Each optional check you asked for passed: `--wal` (the WAL's first entries
   reproduce the checkpoint root and their hash chain holds), `--prev` (the
   checkpoint names its predecessor), `--revoked-at` (the signature is dated
   before the revocation).

It does **not** establish:

- That the decisions in the log were computed correctly. That is replay:
  each WAL entry's decision recomputed under its policy
  (`wal::replay_audited_wal`, `examples/verify_wal.rs`) or each receipt
  verified. A witnessed, timestamped log of wrong decisions is still wrong.
- That the policy was the approved one; that is policy provenance
  (`provenance`, [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) §2).
- That the witnesses are run by different parties, or that the keys you
  passed are the right ones. Which keys to trust is your input; the verifier
  cannot infer organisational independence from a public key.
- That a pinned TSA certificate has not been revoked since: revocation is not
  checked online ([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) §6).
- That the input data behind the decisions was honest.
- Anything about records after the checkpoint's size.

Exit codes: 0 no check failed and every requirement was met; 1 a check failed
or a requirement was not; 2 usage; 3 nothing failed but a timestamp is still
pending, or its block is not confirmed.

What to keep, per checkpoint:

```text
checkpoints/
  000001.checkpoint              signed note; cosignature lines are appended to it
  000001.checkpoint.signed       the note with the log's signature only: what is stamped
  000001.checkpoint.signed.ots   OpenTimestamps proof of it
  000001.checkpoint.signed.tsq   RFC 3161 request (holds the nonce)
  000001.checkpoint.signed.tsr   RFC 3161 response
```

A checkpoint may name the previous one in an extension line
`prev <SHA-256 of its body>`; `verify --prev` checks it. The consistency proof a
witness checks is the stronger link, since it covers every record rather than
one digest.

`stamp` and `upgrade` reach the calendars through the system `curl`; the
library has no HTTP stack. They write the reference client's `.ots` format in
its canonical order, so `ots` reads these files and `calybris-verify` reads
its. On Windows the reference client currently fails at start-up
(python-bitcoinlib cannot load OpenSSL), which `calybris-verify` avoids.

## What this does not claim

- That records are true. It proves which records were written and when, not
  that their inputs were right ([THREAT_MODEL.md](THREAT_MODEL.md)).
- That witnesses are independent. A policy of witnesses run by one party is a
  policy of one witness, and today every Calybris witness is run by the
  maintainer.
- That a TSA is honest beyond its certificate, or that a Bitcoin block is on
  the main chain beyond what the source you gave `--block-hash` says.
- An audited post-quantum implementation (question 4).
