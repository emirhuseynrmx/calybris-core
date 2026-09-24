# Decision semantics

What the kernel promises, in the units it promises it in.

This is the decision contract, stable across every 1.x release. Everything here is pinned by
`tests/decision_semantics.rs`, because a contract that only exists in prose drifts
without failing anything.

## Units

| Quantity | Type | Unit | Ceiling |
|---|---|---|---|
| Cost, value, budget, utility | `u64` / `i64` | microunits | — |
| Quality, risk, confidence | `u16` | basis points | 10,000 = 100% |
| Latency | `u32` | milliseconds | ~49.7 days |
| Catalog cost | `u64` | microunits per **million** tokens | — |

A microunit is 1/1,000,000 of the caller's unit. The kernel does not know whether
that unit is a lira, a dollar or a credit, and it performs **no currency
conversion**. A catalog priced in two currencies is a catalog with a bug the
kernel cannot see; convert before you build the snapshot, and record the rate and
its date alongside the decision.

Latency is milliseconds in a `u32`, so the representable range stops a little
under 49.7 days. Anything that measures in days — a delivery date, a lead time —
has to convert, and the conversion belongs to the caller who can also record it.
Do not reinterpret the field as days: the penalty term is
`latency_penalty_microunits_per_ms × p95_latency_ms`, and it will be wrong by six
orders of magnitude without saying so.

## Ceilings

| Limit | Value | Why |
|---|---|---|
| `MAX_PROVIDER_ID` | 63 | one bit per provider in a `u64` mask |
| `MAX_CATALOG_MODELS` | 65,535 | candidate indices are `u16` |
| `MAX_BPS` | 10,000 | basis points are a fraction of one |

`provider_id` is a **grouping** concept and is optional. It exists so a request
can say "only these groups", which is a routing idea: many models, few providers.
In a domain where the candidate *is* the party — a supplier, a carrier — the two
collapse and the mask has little to do.

`provider_id > 63` is refused by `PolicySnapshot::validate`, so the ceiling
surfaces when the policy is built rather than silently at decision time. If a
single policy needs more than 63 groups, that policy is usually two policies: a
request rarely has every group as a real candidate, and narrower catalogs make
`compare_policies` mean something.

## Before any candidate: the request-level refusals

Two checks run on the request alone, before a single candidate is looked at.
A request that fails either is refused with no candidate evaluated, and
`explain` returns an empty candidate list for it.

1. `risk_bps >= hard_risk_limit_bps` → `RiskHardLimit`
2. `confidence_bps < minimum_confidence_bps` → `ConfidenceHardLimit`

Risk is checked first. Note the two comparisons point different ways, and both
boundaries are part of the contract: a request whose risk is **exactly at** the
hard limit is refused, and a request whose confidence is **exactly at** the floor
is accepted. A rule written elsewhere as "refuse when risk is above `t`" therefore
corresponds to `hard_risk_limit_bps = t + 1`, not `t`.

The per-candidate `risk_ceiling_bps` gate below is the other way round again: a
candidate accepts a request whose risk is equal to its ceiling and refuses one
above it.

## The gates, in order

A candidate is checked in this order and reported against the **first** gate it
fails. A candidate failing three gates is counted once, under the first.

1. `enabled == 0`
2. quality below `minimum_quality_bps`
3. p95 latency above `max_p95_latency_ms` (0 means no limit)
4. missing a required capability bit
5. `provider_id` unrepresentable in the mask
6. provider not in `allowed_provider_mask`
7. no shared bit with `required_region_mask`
8. request risk above the candidate's `risk_ceiling_bps`
9. cost above `budget_limit_microunits`
10. utility not above zero

The order is part of the contract because the reported reason depends on it.
`PolicySnapshot::explain` reports the same gate the counters do, from the same
code.

## Risk

Two fields, and they are not the same quantity:

- `KernelInput::risk_bps` — how much risk **this request** carries. It drives the
  risk penalty in the utility.
- `KernelModel::risk_ceiling_bps` — how much risk **this candidate accepts**. It
  is an eligibility gate.

`risk_ceiling_bps` is **not** the probability that a candidate fails. A product
that labels it "supplier failure rate" is selling something the kernel does not
compute. Per-candidate expected loss is a separate estimate that belongs to
whatever produces the catalog.

## Utility

```
utility = quality_adjusted − risk_penalty − cost − latency_penalty
```

Computed in `i128` and clamped into `i64` rather than wrapped, so an extreme
catalog cannot turn a large positive into a negative and reverse a ranking.
A candidate whose utility is not strictly above zero is not eligible.

## Ties

Ranking is a total order, so the same catalog and the same request always name
the same winner, on any machine and in any build:

1. higher utility
2. then lower cost
3. then higher quality
4. then lower `model_id`

Catalog order never decides. The last rule exists so that two candidates
identical on everything measurable still resolve without a coin flip.

## Missing information

The kernel has no concept of "unknown". Every field is present and every value is
used as given. A candidate with no history and a candidate measured as poor are
indistinguishable to it, because the difference is not in the input.

That difference matters, and it belongs above: decide what an absent estimate
means — exclude the candidate, substitute an assumption, ask for the data, send it
to a person — and record which you chose. Passing a default through as a
measurement is the one failure this crate cannot catch for you.

## Time

The kernel reads no clock. `request_sequence` orders requests, and any timestamp
is supplied by the caller. A decision that depends on when it is replayed is not
replayable, which is the property the whole crate exists to hold.

## What is frozen

The items above, the digest formats, and the replay behaviour. No 1.x release
changes them; a change would wait for a major version. New capabilities can still
arrive in 1.x as additions — see `COMPATIBILITY.md` for the rules.
