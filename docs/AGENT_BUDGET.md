# AgentBudget (0.5.8)

Use one shared `AgentBudget` to reserve spending capacity before starting a paid
call. The operation may be an LLM request or another priced tool. The Rust
`BudgetEngine` owns integer accounting; the Python adapter owns call lifecycle.

```python
from calybris import AgentBudget

run = AgentBudget(100_000_000)  # 1 USD = 100 cents * 1,000,000 microcents

# `perform_one_call` is your existing synchronous, non-streaming operation.
# `complete_cost` must return its complete observed cost in integer microcents.
# result = run.call("attempt-1", upper_bound_microcents, perform_one_call, complete_cost)
```

For an immediately runnable example without credentials:

```console
pip install calybris==0.5.8
python examples/agent_budget.py
```

During release-candidate evaluation, install the built local wheel instead of
expecting the candidate to exist on PyPI.

## Integrating your existing provider call

```python
from calybris import AgentBudget, BudgetDeniedError

async def execute_step(shared_run, attempt_id, upper_bound, provider_call, cost_of):
    try:
        return await shared_run.acall(attempt_id, upper_bound, provider_call, cost_of)
    except BudgetDeniedError:
        # provider_call was not invoked; pause or stop the agent here.
        raise

# Create shared_run once for the task, not once per request.
# provider_call: zero-argument callable returning an awaitable completed response.
# cost_of: synchronous callable returning the complete integer microcent cost.
# Capture your provider arguments in a closure or functools.partial.
```

Admission needs an explicit upper bound, not an optimistic average. Derive it
from the applicable price schedule, input bound and enforced output/usage limits.
Reject unknown pricing in your adapter. Disable hidden SDK retries, or include
all possible attempts in the bound and complete cost. AgentBudget never retries.
It does not estimate tokens, fetch prices, enforce a provider's output limit,
or control its invoice. A correct ledger is not proof of correct provider usage.

`call` accepts a synchronous operation; `acall` awaits its operation. Both return
the original response after successful settlement. The cost callback must be
synchronous, short and return a plain non-negative `int` <= 2**63-1. Reserve
amounts are strictly positive integers in the same range. No implicit float or
currency conversion occurs. Attempt IDs are 1–256 UTF-8 bytes; avoid secrets in IDs.

## Lifecycle and errors

| Event | Attempt state | Accounting / next action |
|---|---|---|
| Insufficient capacity | `denied` | No operation call, no hold; `BudgetDeniedError`. The identifier stays free and the admitted-attempt limit is untouched |
| Admitted and not finished | `running` | Hold remains unavailable to others |
| Complete valid cost <= reservation | `committed` | Commit cost, return unused reservation |
| Operation/cost exception, cancellation or invalid usage | `uncertain` | Retain hold, propagate the original exception |
| Caller verifies no charge and releases | `released` | Return entire hold |
| Actual cost > reservation, affordable | `overrun_settled` | Commit observed cost and close run |
| Actual cost > reservation, unaffordable | `overrun_unsettled` | Preserve original hold and observed cost; close run |
| Documented correction settles a lower true debt | `corrected` | Commit the corrected amount; keep the observed cost and the stated reason |

Both overrun states raise `BudgetOverrunError`; it carries `attempt_id`,
`actual_microcents`, and `settled`. Even an affordable overrun closes admission.
Already running calls may finish; closing cannot undo external calls.

For unresolved usage, obtain external evidence first:

```python
run.reconcile("attempt-1", actual_microcents=42)
# Or, only after confirming the provider did not bill:
run.release("attempt-1", confirmed_no_charge=True)
```

Only unresolved, non-running attempts may be reconciled. A duplicate settlement
raises `AttemptStateError`. Previously observed costs cannot be replaced by a
different value or silently released. An unaffordable overrun has no automatic
repair or top-up in this API: the discrepancy stays visible, with the run closed,
for external accounting/recovery. Reconciliation does not reopen a closed run.

IDs are unique among admitted attempts. A duplicate raises
`DuplicateAttemptError`, rather than returning a cached response or repeating
the operation. Retry a failed attempt with a new ID and reserve again; a denied
one keeps its ID, because nothing was admitted under it. `max_attempts`
(default 10,000) bounds the registry of admitted attempts, and denials are held
separately in their own bounded ring.
At the limit `AttemptLimitError` is raised before dispatch. Invalid parameters
are rejected without occupying an ID. Do not create a fresh budget to bypass
the registry limit and then assume earlier spend remains accounted for.

## Corrections and denials

A denial is not an event: nothing ran, nothing was held, and no money moved. Its
identifier stays available, so the same logical step can be attempted again once
capacity exists, and it does not spend the run's admitted-attempt limit. Denials are
still recorded, in a bounded ring; `denied_total` counts every one, so a history that
has been truncated says so rather than quietly shrinking.

An overrun the budget cannot absorb keeps its hold and closes the run, and neither
`release` nor `reconcile` will move it - a debt you observed is not erased by asking
twice. `correct` exists for the case where the true amount is lower and you can say
why: a provider credit, a corrected invoice line. It settles that amount, keeps the
originally observed cost beside it with the stated reason, refuses an amount at or
above what was observed, and cannot be applied twice. It does not reopen the run, and
it is not a way to unlock a hold while the debt still stands.

```python
run.correct(attempt_id, corrected_microcents, reason="provider credit CR-1")
```

`balance()` returns the ledger alone for callers that only need the remaining amount;
`report()` remains the full record.

## Reports and concurrency

`run.report()` returns a frozen `RunReport`, containing frozen `AttemptReport`
snapshots and integer ledger totals. `dataclasses.asdict(report)` produces a JSON
compatible dictionary. Reports do not retain responses, prompts, exception text
or credentials. IDs and costs are still application data that you control.

Reports and state transitions are serialized with one short Python lock. User
callbacks and awaits run outside it. Reports cost O(number of attempts), bounded
by `max_attempts`; avoid polling full reports at high frequency on large runs.
There is no fairness or latency SLA. Large user-selected limits still use memory.
The conservation flag covers the internal ledger; `overrun_unsettled` can coexist
with a balanced ledger because it is observed external cost not yet committed.
Check attempt states as well as ledger totals. The report is not signed evidence
of provider billing and is not a durable checkpoint.

## Explicit support boundary

- Same process, same instance shared by threads/tasks. Fork-inherited use is
  rejected before acquiring its inherited lock; pickling is rejected.
- No cross-worker/server budget coordination or durable restart recovery. A new
  instance is a new budget. Never reconstruct admission from report JSON alone.
- No streaming: iterator, async iterator and awaitable results are rejected as
  uncertain. A custom stream wrapper may not implement these protocols; callers
  must supply fully consumed responses and complete usage.
- Async cancellation/timeout retains the hold, even when a task may have stopped
  before the upstream call began. This conservatism prevents accidental refunds.
- `close()` blocks new calls but neither cancels running calls nor releases holds.
- Terminating the process, fatal interpreter/native failure, or forcibly injecting
  exceptions into threads is outside the lifecycle guarantee.
- This feature does not fix the core snapshot-size or torn-WAL recovery limits.

## Reproducible load tests

```console
pip install pytest hypothesis psutil
python -m pytest python/tests/test_agent_budget.py
python scripts/stress_agent_budget.py --workers 64 --steps 16000
```

The full stress command drives 1,024,000 mixed terminal attempts, 128-thread
admission contention, 10,000 async tasks with response loss/cancellation, and
6,400 racing settlements. It compares actual accounting to independently summed
callback outcomes. It uses synthetic operations and the real installed native
engine. It does not validate a live provider integration or constitute an isolated
performance comparison. Use an external timeout when running stress in CI.
