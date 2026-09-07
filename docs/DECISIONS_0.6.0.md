# Calybris 0.6.0: deterministic decision engine

Calybris selects eligible candidates under explicit constraints and records a
replay-verifiable decision. It does not guarantee the best real-world business
outcome. Supplier, carrier and model selection are adapters over one kernel.

## Supported business API

`Candidate`, `DecisionRequest`, `DecisionEngine` and `compare_policies` are
exported from `calybris`. Run `python examples/supplier_decision.py` for an
offline fixed-quote supplier example. No supplier order is sent.

`DecisionEngine(candidates, config=EngineConfig(...))` freezes and validates
the candidate catalog, sorts by numeric candidate ID, and builds a native
PolicySnapshot. Duplicate IDs and invalid catalogs fail native validation.
Candidate count is capped at 65,535; provider IDs are 0..63. Labels/customer
records belong in the application, outside the mathematical decision input.

`decide(request)` returns `calybris.decision.v1`: selected/rejected, nullable
selected_candidate_id, catalog SHA256, the full native decision and reason code,
native aggregate rejection trace, and a replay-verified audit bundle. The
trace counts the first failed gate per candidate, not every possible violation.
Global policy rejections can happen before candidate gates; zero histogram
counts do not mean all candidates were eligible.

`verify(request, result)` recomputes the entire result against this engine.
Trust comes from the caller's expected catalog/policy/request, not from a
self-declared replay_valid field. Persist these inputs along with the result.
Catalog digest (`calybris.catalog.v1`, sorted UTF-8 JSON, SHA256) is distinct
from native policy/input/decision digests. It is not a digital signature.

## Units and mapping

One request describes one already-priced job. Each candidate's fixed quote is
mapped to its native input-cost rate, with exactly 1,000,000 native input units
and zero output units. This yields the quoted cost without a second pricing
algorithm. This adapter does not compute quantity discounts or exchange rates.
All quote/budget/value quantities use integer microunits in the same currency
and scale chosen by the caller. Native bounds and overflow handling still apply.

Lead time is milliseconds, backed by u32 (about 49.7 days maximum). Convert days
explicitly; a larger planning horizon needs a separately versioned adapter.
Set `latency_penalty_microunits_per_ms=0` if lead time is only a hard eligibility
constraint. The existing EngineConfig default penalty is 2 per millisecond.
Quality/confidence/risk use 0..10,000 basis points. Required capability bits
must all match; region mask follows the native any-overlap semantics. A zero
maximum lead time means no lead-time ceiling. No eligible positive-utility
candidate yields rejected; selected ID is None, not a fictitious zero candidate.

## Policy comparison

`compare_policies(before, after, requests, max_requests=10000, max_changes=100)`
requires identical canonical candidate catalogs. Each frozen request is passed
to both immutable engines. It reports total, changed, newly_rejected, bounded
before/after proof details, and changed configuration fields. A changed outcome
means action/reason/selected ID/estimated cost/utility changed; epoch-only or
trace-only changes do not increment it. Input overflow raises, never returns a
silently partial total. Stored detail truncation is explicit.

Changed fields identify configuration differences, not individual causal
attribution. Replays do not demonstrate realized savings or supplier performance.

`before_policy` and `after_policy` sit at the top level and each carry the native
policy digest, the policy epoch and the catalog epoch. They are recorded whether
or not per-change detail was truncated, so a comparison summarizing ten thousand
requests in a hundred stored changes still names the two policies that produced
it. `policy_changed` compares those identities.

Read `policy_changed` rather than `changed_fields` when the question is whether
the policy differs at all. `changed_fields` compares the configured scoring knobs
only, so two engines built from the same `EngineConfig` at different
`policy_epoch` values report no changed fields and are nonetheless different
policies. `DecisionEngine` exposes `policy_digest`, `policy_epoch` and
`catalog_epoch` for the same purpose outside a comparison.

## Existing budget component

`AgentBudget.lifecycle_report()` returns detached JSON-ready
`calybris.budget-lifecycle.v1` under one reentrant lock. It includes current
ledger conservation, immutable attempts, unresolved operations and next actions,
original and corrected costs/reasons, bounded denied history with total and
truncation flag, and measured reservation accuracy. No amount is recommended.

The budget API names its unit microcents (100,000,000 per USD); convert other
application units explicitly at the boundary. Reports reflect caller-supplied
costs, not independently verified provider billing. Correction reasons may
contain sensitive information; they are not automatically redacted.

## Compatibility and operating contract

Existing PolicyBuilder/InputBuilder/CalybrisEngine APIs and Rust decision ABI
remain available. 0.6.0 adds the fixed-quote surface; existing model routing need
not migrate. The no-candidate native trace now preserves rejection counts that
were previously discarded; selection and native decision digests are unchanged.

AgentBudget retains the development branch's behavior: denied IDs remain
reusable; accepted IDs cannot be reused. `correct` is documented, one-time and
preserves original observed cost. Pin 0.6.x when migrating from 0.5.x.

DecisionEngine uses immutable native policy inputs for concurrent independent
calls. AgentBudget is thread-safe and process-local, cannot be pickled or shared
after fork, and is not made restart-durable by lifecycle_report. The preexisting
WAL/checkpoint APIs have their own explicit guarantees; this release adds no
distributed ownership, automatic failover or power-loss guarantee.

Python errors remain InputValidationError/PolicyValidationError/VerificationError
at their existing boundaries (Pydantic ValidationError for typed model fields).
Native numeric action/reason codes in the full decision remain authoritative;
human strings are explanations, not exception-matching protocols.
