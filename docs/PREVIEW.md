# Preview features

Released in 1.2.0 and 1.3.0, behind the `preview`, `preview-pq` and
`preview-tsa` feature flags, and **not yet covered by the 1.x stability
promise**. Modules marked *1.3.0* arrived in that release. Their APIs may change in a
minor release. Each one graduates to a stable feature in a later 1.x release
after review; graduating is an addition, so code that did not turn a preview
flag on is unaffected either way.

Nothing on this page changes a decision. The kernel, the gate order, the
utility, the tie-break and every existing digest are exactly as in 1.0.0; the
features below read decisions, or add new artifacts under new digest tags.

```toml
calybris-core = { version = "1.3", features = ["preview"] }      # everything below except hybrid signatures
calybris-core = { version = "1.3", features = ["preview-pq"] }   # adds Ed25519 + ML-DSA-65 hybrid signatures
calybris-core = { version = "1.3", features = ["preview-tsa"] }  # adds RFC 3161 token verification (1.3.0)
```

| Module | Question it answers | New digest tag |
|---|---|---|
| `counterfactual` | What would this candidate need to win? How far can the winner move before it loses? | — |
| `merkle` | Is this one decision in the log? Is today's log an extension of yesterday's? | `calymth1` |
| `exploration` | Take a small, keyed, replayable share of near-best alternatives, and record exactly how likely each choice was | `calyexp1` |
| `ope` | What would a *different* policy have achieved, estimated from outcomes that were observed? | — |
| `budget::Reservation` | A reservation that can be settled once, by the code that owns it | — |
| `hybrid` (`preview-pq`) | A signature that stays convincing if either Ed25519 or ML-DSA is broken; one signature for a whole batch (1.3.0) | `calyhyb1`, `calyhbt1` |
| `checkpoint` (1.3.0) | The log's state as C2SP checkpoint text, signed by the log and cosigned by witnesses | — |
| `witness` (1.3.0) | Will an independent party cosign this checkpoint? Only if it extends everything it cosigned before | — |
| `audit` (1.3.0) | Did enough witnesses see it? Was I shown the same log as everyone else? Did this signature predate its key's revocation? | — |
| `ots` (1.3.0) | Is this checkpoint committed in a Bitcoin block, and which one? | — |
| `tsa` (`preview-tsa`, 1.3.0) | Did a timestamping authority sign this checkpoint's digest, and when? | — |

The trust layer (`checkpoint`, `witness`, `audit`, `ots`, `tsa`) is described
end to end, with the questions it answers and a command-line walkthrough, in
[TRUST.md](TRUST.md).

## `counterfactual`

`what_would_win(policy, input, model_id)` returns, for a candidate that was not
selected, the smallest change to **one** of its levers — quality, p95 latency,
price, risk ceiling, or being switched on — after which the kernel selects it.
`decision_margin(policy, input)` returns, for the winner, how far each lever can
move before it stops winning.

Both run the real kernel on a copy of the policy with one field changed and
search for the boundary, so there is no second formula to drift from
`prescribe`. The tests check that every boundary is exact: at the boundary the
candidate wins, one step short it does not.

What it does not claim: a single-lever answer. A candidate that could win only by
moving two levers together has no answer here, and the lever is left out rather
than guessed. The answer is about this request and this catalog; it says
nothing about what the candidate *should* change.

Python: `PolicySnapshot.what_would_win(input, model_id)` and
`PolicySnapshot.decision_margin(input)`.

Research: counterfactual explanations as recourse — Wachter, Mittelstadt and
Russell, [arXiv:1711.00399](https://arxiv.org/abs/1711.00399); exact recourse for
linear, integer-scored decisions — Ustun, Spangher and Liu,
[arXiv:1809.06514](https://arxiv.org/abs/1809.06514).

## `merkle`

RFC 9162 (Certificate Transparency 2.0) Merkle trees over log records:
`inclusion_proof` / `verify_inclusion` for one record, `consistency_proof` /
`verify_consistency` for "the tree of size *m* is a prefix of the tree of size
*n*". A log rewritten after its head was published cannot produce a consistency
proof. `leaf_from_entry_hash` turns a WAL `entry_hash` into leaf data, so the
tree commits to what the hash chain already commits to.

The tree is the standard one, checked against the Certificate Transparency
reference vectors, so any RFC 9162 verifier can check these proofs without this
crate. The free functions recompute every subtree a proof needs, so a proof
costs time linear in the log. `MerkleTree` (1.3.0) keeps each complete
subtree's hash as records arrive: a root or proof for any size then takes
`O(log² n)`, about two microseconds at ten million records, for 64 bytes of
memory per record ([BENCHMARKS.md](BENCHMARKS.md)). `TreeHead::digest` (`calymth1`) is the 32 bytes a signer or an
independent witness signs.

What it does not claim: publication or witnessing. It produces and checks the
proofs; getting a head co-signed by witnesses the operator does not control is
a deployment decision.

Research: witness co-signing — Syta et al.,
[arXiv:1503.08768](https://arxiv.org/abs/1503.08768).

## `exploration`

A deterministic kernel can never learn what its second choice would have done.
`explore(policy, input, config, key)` lets the kernel decide as usual, then,
among eligible candidates within `window_microunits` of the winner's utility,
takes an alternative on `rate_bps` of requests. The draw is
`HMAC-SHA256(key, "calyexp1" ‖ policy digest ‖ input digest)`: fixed by the
policy, the request and the key, unpredictable without the key, and replayed
exactly by `verify`. The record carries the exact probability of the choice as
a fraction (`ExplorationRecord::propensity`), and
`ExplorationRecord::selection()` turns it into the `Selection` an `Outcome`
already records, in whole basis points. Keep the fraction: below a basis point
the rounding is not small (see `ope`).

What it does not claim: public verifiability. Only a holder of the key can
replay the draw. A draw anyone can check needs a verifiable random function
(RFC 9381), which is not here.

Research: why a system that learns only from its own approvals fools itself —
Scarone et al., [arXiv:2606.18479](https://arxiv.org/abs/2606.18479); logged
propensities — Li et al., [arXiv:1003.0146](https://arxiv.org/abs/1003.0146).

## `ope`

`evaluate(target, logs, reward, clip)` estimates a target policy's mean reward
from `(request, Outcome)` pairs, using the propensity each outcome recorded:
IPS with an approximate 95% interval, self-normalised IPS, and the effective
sample size. Outcomes that do not validate, carry no propensity (a person
chose) or are paired with the wrong request are excluded and counted; a clip
that is not a positive, finite weight is refused (`OpeError::InvalidClip`).

**Exact propensities (1.3.0).** An `Outcome` records its propensity in whole
basis points, rounded and never below one. At an exploration rate of 1 bp over
22 near-best candidates an alternative's true probability is 0.045 bp, so the
rounded weight is 22 times too small. `evaluate_exact` takes the exact
`ope::Propensity` from each `ExplorationRecord` and excludes a record whose
fraction does not round to what its outcome recorded. `tests/preview.rs`
checks, on a population drawn exactly as the mechanism draws, that the exact
estimate equals the true value and the rounded one does not;
`tests/ope_reference.rs` holds the estimators against a reference written from
their definitions. `Estimate::warnings` names the conditions under which an
estimate or its interval should not be taken at face value: few records, a
low effective sample size, no matches, unsupported choices, clipping.

In 1.3.0 this module's API changed, as preview APIs may: `LoggedChoice` holds
a `Propensity` in place of `propensity_bps`, and `estimate` and `evaluate`
return `Result<Estimate, OpeError>` in place of `Option<Estimate>`.

What it does not claim, stated in the result: a log written only by the kernel's
own ranking cannot speak for choices it never made. Those records are counted in
`Estimate::unsupported`; when that is not zero, the estimate describes only the
requests on which the two policies agree. The remedy is `exploration`, and the
integration test shows the pair recovering a target policy's success rate from
logs of a policy that never ran it.

Research: doubly robust estimation — Dudík, Langford and Li,
[arXiv:1103.4601](https://arxiv.org/abs/1103.4601); offline evaluation from
logged propensities — Li et al.,
[arXiv:1003.5956](https://arxiv.org/abs/1003.5956); deterministic logging
policies — Narita et al., [arXiv:2212.01925](https://arxiv.org/abs/2212.01925).

## `budget::Reservation`

`BudgetEngine::reserve_owned` returns a `Reservation` that is neither `Clone`
nor `Copy`; `commit` and `release` take it by value. Double spending, settling
after release, and using a reservation after handing it to another task are
compile errors (checked by `compile_fail` doctests). An overrun the tenant
cannot cover hands the reservation back instead of losing it. Dropping one
without settling it keeps the hold, as a cancelled call does in the Python
budget: returning money for work that may have started would be an accidental
refund.

Research: a catalog of 63 production budget overruns in LLM-agent frameworks —
Khan, [arXiv:2606.04056](https://arxiv.org/abs/2606.04056).

## `hybrid` (feature `preview-pq`)

`HybridSigner::sign` signs `"calyhyb1" ‖ digest` with Ed25519 and with ML-DSA-65
(FIPS 204, context `calybris`); `hybrid::verify` accepts only when **both**
halves verify. Signing is deterministic and keys come from caller-held seeds.

*1.3.0:* `HybridSigner::sign_batch` signs many digests with one hybrid
signature over the RFC 9162 root of a tree of them (tag `calyhbt1`), and gives
each an inclusion proof; `verify_batch` checks the signature once and
`VerifiedBatch::verify_item` each item in `log₂ n` hashes.
`tests/acvp_ml_dsa.rs` runs NIST's ACVP ML-DSA-65 vectors through the calls
this module makes.

What it does not claim: an audited post-quantum implementation. The ML-DSA
implementation used (RustCrypto `ml-dsa`) has **not been independently
audited**, which is why this has its own flag. Passing the ACVP vectors shows
conformance on those paths, not the absence of side channels.
[AUDIT_SCOPE.md](AUDIT_SCOPE.md) is the scope for an audit.

Research: post-quantum audit evidence — Kao,
[arXiv:2512.00110](https://arxiv.org/abs/2512.00110).

## `checkpoint`, `witness`, `audit` (1.3.0)

`checkpoint` writes a tree head as a C2SP checkpoint, signs it as a C2SP note,
and adds witness cosignatures (`cosignature/v1`), byte-compatible with the Go
reference implementation. `witness` is a witness: it cosigns a checkpoint only
with a consistency proof from the last one it cosigned for that log, and speaks
C2SP tlog-witness. `audit` counts a quorum of trusted witnesses, follows one
log through time, turns two conflicting checkpoints into transferable proof of a
split view, proves a record's inclusion, and decides whether a signature by a
revoked key predates its revocation.

A witness's state fails closed: `FileStore::create` (`calybris-verify witness
init`) starts one and never overwrites an existing state, and
`FileStore::open` refuses a missing or unreadable one rather than start from
nothing. `tests/trust_operations.rs` covers corrupted, lost and rolled-back
state, witnesses running at once, and a log key rotated through a checkpoint
both keys sign.

What it does not claim: that witnesses are independent of each other or of the
operator; choosing them is the deployment's decision.

Research: witness cosigning — Syta et al.,
[arXiv:1503.08768](https://arxiv.org/abs/1503.08768).

## `ots` (1.3.0)

OpenTimestamps proofs in the reference client's `.ots` format: parse, write,
submit a checkpoint digest to public calendars, fold in their upgrades, and
verify a proof against a Bitcoin block header. A proof is Pending, Anchored or
confirmed: a header the verifier supplies, with the height it was fetched
at and a work floor, is checked first, and the block counts only once
`BitcoinHeader::confirm` matches its hash against a source the verifier
trusts. Stamp `SignedNote::signed_by`, the log-signed note, so the timestamp
dates the signature too.

What it does not claim: that a header is on the main chain. Compare the block
hash with a node you trust.

## `tsa` (feature `preview-tsa`, 1.3.0)

Builds an RFC 3161 request for a checkpoint digest and verifies the response:
the imprint, the nonce, the CMS signed attributes and signature (RSA PKCS#1
v1.5, ECDSA P-256/P-384), and a pinned signing certificate with the
`timeStamping` key usage, valid at `genTime`.

What it does not claim: chain building or revocation checking. The caller pins
the TSA certificates it trusts.

## Formal checks

`src/kani_proofs.rs` holds bounded model-checking harnesses for properties the
preview features rest on: the Merkle split, the exploration probabilities
summing to one, and the counterfactual boundary search. They run in CI on Linux
(`.github/workflows/kani.yml`), separately from the release gate while they are
new. Kani: Delmas et al., [arXiv:2607.01504](https://arxiv.org/abs/2607.01504).
