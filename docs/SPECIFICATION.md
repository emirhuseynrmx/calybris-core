# Calybris digest specification

Every digest in this crate is a SHA-256 over a fixed byte layout, not over JSON.
This document is that layout, field by field, so that a second implementation can
produce the same 32 bytes without reading the Rust.

The layouts are frozen. [COMPATIBILITY.md](COMPATIBILITY.md) says what that
means for 1.0.x; the short version is that a change here would invalidate every
artifact ever written, so a defect in one of these is documented rather than
fixed.

## Conventions

These hold everywhere below unless a section says otherwise.

| | |
|---|---|
| Hash | SHA-256, one pass, no length prefix over the whole message |
| Integers | **little-endian**, two's complement for signed |
| Widths | the Rust type's width exactly: `u8`=1, `u16`=2, `u32`=4, `u64`/`i64`=8 |
| Enums | hashed as their `repr` discriminant, not their name |
| Booleans | one byte, `0` or `1` |
| Options | one **presence byte** (`0` absent, `1` present), and the value only when present |
| Strings | `u32` byte length, then the UTF-8 bytes; no terminator |
| Order | fields in the order listed; collections sorted by the key each section names |

Every layout starts with a nine-byte tag: eight ASCII characters and a `\0`. The
trailing digit is the format version. A reader that does not recognise a tag must
refuse the artifact rather than guess.

| Tag | Covers |
|---|---|
| `calypol1\0` | policy snapshot |
| `calyinp1\0` | decision input |
| `calydcn1\0` | decision output |
| `calyldg1\0` | budget ledger |
| `calyidn1\0` | decision identity |
| `calysel1\0` | selection |
| `calyout1\0` | outcome |

### Why a presence byte

An absent measurement and a zero measurement are different claims. Writing
`Option::None` as eight zero bytes would make "we never measured the cost" and
"it cost nothing" produce the same digest, and a later reader would have no way
to tell them apart. Every optional field below is written as a presence byte
first, which costs one byte and makes the two cases distinct.

## Units

| Quantity | Unit | Type |
|---|---|---|
| Money in the kernel | microunits | `u64` / `i64` |
| Money in the ledger | microcents | `i64` |
| Cost rates | microunits per million tokens | `u64` |
| Proportions | basis points, 10,000 = 100% | `u16` |
| Latency | milliseconds | `u32` |
| Time in outcomes | microseconds since the Unix epoch | `u64` |

Basis points are never a float. A proportion above 10,000 is refused at
validation rather than clamped, because a policy that says 150% is a policy
somebody mistyped.

## Policy snapshot — `calypol1\0`

```
tag                                   9 bytes
policy_epoch                          u64
catalog_epoch                         u64
hard_risk_limit_bps                   u16
minimum_confidence_bps                u16
risk_penalty_multiplier_bps           u16
latency_penalty_microunits_per_ms     u64
  then, for each model, in ascending model_id order:
    model_id                          u32
    provider_id                       u16
    quality_bps                       u16
    risk_ceiling_bps                  u16
    enabled                           u8
    p95_latency_ms                    u32
    capabilities                      u64
    region_mask                       u64
    input_cost_microunits_per_million_tokens    u64
    output_cost_microunits_per_million_tokens   u64
```

The catalog is sorted by `model_id` before hashing, so two snapshots that hold
the same models in a different order produce the same digest. Nothing else about
the catalog is hashed — not its length, not its capacity — because the models
themselves determine it.

The derived fields a snapshot caches (`max_quality_bps`, `max_input_cost`,
`max_output_cost`) are **not** hashed. They are functions of the models already
in the digest, and hashing them would let a bug in their computation change an
identity that should not have moved.

## Decision input — `calyinp1\0`

```
tag                          9 bytes
request_sequence             u64
requested_model_id           u32
input_tokens                 u32
output_tokens                u32
business_value_microunits    i64
budget_limit_microunits      u64
risk_bps                     u16
confidence_bps               u16
minimum_quality_bps          u16
max_p95_latency_ms           u32
required_capabilities        u64
allowed_provider_mask        u64
required_region_mask         u64
```

Note the order: `business_value` before `budget_limit`, and `risk`/`confidence`
before `minimum_quality`. It does not match the field order of the struct, and it
is the order that is normative.

## Decision output — `calydcn1\0`

```
tag                                   9 bytes
request_sequence                      u64
action                                u8    (see below)
reason                                u16   (see below)
selected_model_id                     u32
selected_model_index                  u16
estimated_cost_microunits             u64
expected_utility_microunits           i64
counterfactual_model_id               u32
counterfactual_utility_microunits     i64
evaluated_models                      u16
eligible_models                       u16
policy_epoch                          u64
catalog_epoch                         u64
```

`action` is one byte and `reason` is two, even though both are small enums. That
asymmetry is in the format and cannot be tidied.

| `action` | |
|---|---|
| 1 | the requested model was selected |
| 2 | a different model was selected |
| 3 | nothing was selected |

| `reason` | |
|---|---|
| 1 | the requested model maximised utility |
| 2 | an alternative maximised utility |
| 100 | risk above the policy's hard limit |
| 101 | confidence below the policy's hard limit |
| 102 | no enabled model |
| 103 | quality constraint |
| 104 | latency constraint |
| 105 | capability constraint |
| 106 | provider constraint |
| 107 | region constraint |
| 108 | budget constraint |
| 109 | no candidate had positive utility |
| 110 | risk above a candidate's ceiling |

The gap between 2 and 100 is deliberate: below 100 the kernel selected
something, at or above 100 it did not.

## Budget ledger — `calyldg1\0`

```
tag                          9 bytes
version                      u64
tenant count                 u64
active_reservations          u64
  then, for each tenant, in ascending tenant_id byte order:
    tenant_id length         u32
    tenant_id                that many UTF-8 bytes
    initial_microcents       i64
    remaining_microcents     i64
    reserved_microcents      i64
    committed_microcents     i64
  then, only if a WAL high watermark is present:
    b"calybris.ledger.wal-watermark.v1\0"    33 bytes
    wal_high_watermark                       u64
```

Tenants are sorted by `tenant_id` as **bytes**, not by any locale collation.

The watermark suffix is the one place a presence byte is not used: a snapshot
without WAL evidence hashes exactly as it did before the watermark existed, so
ledger digests written by earlier releases still verify. A reader implementing
this layout must therefore append nothing at all when there is no watermark,
rather than appending a zero.

## Decision identity — `calyidn1\0`

```
tag                   9 bytes
policy_digest         32 bytes
input_digest          32 bytes
decision_digest       32 bytes
request_sequence      u64
```

The three digests are the raw 32 bytes, not hex.

## Selection — `calysel1\0`

```
tag                   9 bytes
strategy              u8    0 maximise utility, 1 explore, 2 human
acted_model_id        u32
propensity presence   u8
propensity_bps        u16   only when present
```

The propensity is absent exactly when the strategy is `human`, and present
otherwise. A reader must not substitute 10,000 for an absent one: absent means
the record cannot be used in an off-policy estimate at all.

## Outcome — `calyout1\0`

```
tag                          9 bytes
identity digest              32 bytes    (calyidn1 over the identity)
observed_at_micros           u64
revision                     u32
selection digest             32 bytes    (calysel1 over the selection)
disposition                  u8    0 applied, 1 abandoned, 2 in flight
realized_cost presence       u8
realized_cost_microunits     u64   only when present
realized_latency presence    u8
realized_latency_ms          u32   only when present
succeeded presence           u8
succeeded                    u8    only when present, 0 or 1
```

The identity and the selection are folded in as digests rather than inlined, so
that a reader can compare either part of an outcome without recomputing the
whole record.

`observed_at_micros` is supplied by the caller. The kernel reads no clock
anywhere in this crate: a record whose digest depends on when it is replayed is
not replayable.

## Overflow

The utility calculation accumulates in `i128` and **clamps** to the `i64` range
rather than wrapping. A clamped utility is a decision the kernel still makes,
deterministically, and the same inputs clamp the same way on every platform.

Ledger totals are the exception: when a total does not fit in `i64`, the
certificate reports `aggregate_totals_representable: false` and zeroes the
totals, rather than reporting a wrapped number as if it were a balance.

## Ceilings

These are refused at validation, not clamped, because a caller that exceeds one
has a bug the kernel should not paper over.

| | |
|---|---|
| `provider_id` | 63 — the allowed-provider mask is 64 bits |
| catalog size | 65,535 models — `selected_model_index` is a `u16` |
| any `_bps` field | 10,000 |
| `p95_latency_ms` | `u32::MAX`, about 49.7 days |

## What is not in a digest

- Wall-clock time, except the `observed_at_micros` a caller supplies
- Any host detail: hostname, process id, architecture, endianness of the machine
- Floating point, anywhere, in any layout
- Iteration order of any hash map — every collection here is sorted first

This is the whole reason the layouts are byte-level rather than JSON: there is no
field ordering, no number formatting and no unicode normalisation left for two
implementations to disagree about.

## Conformance

`tests/decision_semantics.rs` pins the semantics, and the golden and conformance
vector tests pin the digests themselves. A second implementation that reproduces
the layouts above will reproduce those vectors; if it does not, this document is
wrong and the vectors are right.
