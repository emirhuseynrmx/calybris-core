"""Run with an installed wheel: python examples/agent_budget.py. No API key needed."""

import asyncio
import json
from dataclasses import asdict

from calybris import AgentBudget, BudgetDeniedError


async def main():
    budget = AgentBudget(100, max_attempts=10)

    async def completed_call():
        # Replace with one non-streaming provider/tool call, with retries disabled.
        await asyncio.sleep(0)
        return {"answer": "done", "cost_microcents": 30}

    result = await budget.acall(
        "lookup-1", 60, completed_call, lambda response: response["cost_microcents"]
    )
    if result["answer"] != "done":
        raise SystemExit("the paid call did not return its response")

    async def response_lost():
        raise TimeoutError("The provider may already have charged this call")

    try:
        await budget.acall("lookup-2", 60, response_lost, lambda response: 0)
    except TimeoutError:
        pass

    # The uncertain 60 remains reserved; only 10 is available.
    try:
        await budget.acall("lookup-3", 20, completed_call, lambda r: r["cost_microcents"])
    except BudgetDeniedError:
        print("Third call was never dispatched: insufficient unreserved budget.")

    # Substitute verified usage from your provider, not an assumed refund.
    budget.reconcile("lookup-2", 25)
    budget.close()
    report = budget.report()
    # The ledger is the point of this example, so it is checked, not asserted:
    # an assert disappears under `python -O` and CI runs this file.
    if (report.remaining_microcents, report.committed_microcents, report.reserved_microcents) != (
        45,
        55,
        0,
    ):
        raise SystemExit(f"unexpected ledger: {report}")
    print(json.dumps(asdict(report), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
