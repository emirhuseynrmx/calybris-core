"""Real AgentBudget + Rust engine load tests; no provider calls or mocked ledger.

Run from an installed wheel: python scripts/stress_agent_budget.py --steps 16000
Requires psutil for process memory measurement. Output is JSON Lines.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version

import psutil
from calybris import (
    AgentBudget,
    AttemptLimitError,
    AttemptStateError,
    BudgetDeniedError,
    BudgetOverrunError,
    CorrectionError,
    DuplicateAttemptError,
)


def check(condition, detail):
    """Fails the harness loudly, and keeps doing so under `python -O`.

    `assert` would say this more briefly and would also be removed by the
    optimiser, leaving a stress harness that prints PASS without having verified
    anything. Checking is the entire job of this script, so it is never optional.
    """
    if not condition:
        raise AssertionError(detail)


def emit(name, started, **fields):
    print(
        json.dumps(dict(test=name, status="PASS", seconds=time.perf_counter() - started, **fields)),
        flush=True,
    )


def ledger(report, initial, committed, reserved=0):
    check(report.initial_microcents == initial, "report.initial_microcents == initial")
    check(report.committed_microcents == committed, "report.committed_microcents == committed")
    check(report.reserved_microcents == reserved, "report.reserved_microcents == reserved")
    check(
        report.remaining_microcents == initial - committed - reserved,
        "report.remaining_microcents == initial - committed - reserved",
    )
    check(report.conservation_balanced, "report.conservation_balanced")


def threaded_soak(workers, steps):
    start = time.perf_counter()
    count = workers * steps
    run = AgentBudget(count * 100, max_attempts=count)
    barrier = threading.Barrier(workers)
    stop = threading.Event()
    failures = []
    peak = [0]

    def observe():
        process = psutil.Process()
        while not stop.wait(0.25):
            peak[0] = max(peak[0], process.memory_info().rss)
            if peak[0] > 1536 * 1024 * 1024:
                failures.append("RSS exceeded 1.5 GiB")
                run.close()
                return

    monitor = threading.Thread(target=observe, daemon=True)
    monitor.start()

    def worker(worker_id):
        barrier.wait(timeout=30)
        expected = 0
        for i in range(steps):
            attempt = f"{worker_id}:{i}"
            actual = (worker_id * 17 + i * 13) % 81
            if i % 17 == 0:

                def uncertain():
                    raise TimeoutError("synthetic response loss")

                try:
                    run.call(attempt, 100, uncertain, lambda r: 0)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError("timeout swallowed")
                if i % 34 == 0:
                    run.release(attempt, confirmed_no_charge=True)
                else:
                    run.reconcile(attempt, actual)
                    expected += actual
            else:
                check(
                    run.call(attempt, 100, lambda: actual, lambda r: r) == actual,
                    "run.call(attempt, 100, lambda: actual, lambda r: r) == actual",
                )
                expected += actual
            if i % 1000 == 0:
                try:
                    run.call(
                        attempt,
                        1,
                        lambda: (_ for _ in ()).throw(AssertionError("duplicate dispatched")),
                        lambda r: 0,
                    )
                except DuplicateAttemptError:
                    pass
                else:
                    raise AssertionError("duplicate admitted")
        return expected

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            expected = sum(pool.map(worker, range(workers)))
        report = run.report()
        ledger(report, count * 100, expected)
        check(len(report.attempts) == count, "len(report.attempts) == count")
        check(
            all(a.status in ("committed", "released") for a in report.attempts),
            'all(a.status in ("committed", "released") for a in report.attempts)',
        )
        try:
            run.call("beyond-limit", 1, lambda: None, lambda r: 0)
        except AttemptLimitError:
            pass
        else:
            raise AssertionError("attempt registry grew beyond bound")
        check(not failures, failures)
        peak[0] = max(peak[0], psutil.Process().memory_info().rss)
        emit(
            "threaded_mixed_accounting_soak",
            start,
            workers=workers,
            terminal_attempts=count,
            committed_microcents=expected,
            peak_rss_bytes=peak[0],
            max_attempts=count,
        )
    finally:
        stop.set()
        monitor.join(timeout=5)


def contention():
    start = time.perf_counter()
    run = AgentBudget(1700, max_attempts=128)
    begin = threading.Barrier(128)
    admitted = threading.Barrier(128)

    def worker(i):
        begin.wait(timeout=30)

        def operation():
            admitted.wait(timeout=30)
            return 100

        try:
            run.call(str(i), 100, operation, lambda r: r)
            return 1
        except BudgetDeniedError:
            admitted.wait(timeout=30)
            return 0

    with ThreadPoolExecutor(max_workers=128) as pool:
        accepted = sum(pool.map(worker, range(128)))
    check(accepted == 17, "accepted == 17")
    ledger(run.report(), 1700, 1700)
    emit("128_thread_inflight_admission", start, accepted=17, denied=111)


async def async_storm():
    start = time.perf_counter()
    run = AgentBudget(1000 * 100, max_attempts=10_000)
    admitted = asyncio.Event()
    ready = 0

    async def worker(i):
        nonlocal ready

        async def operation():
            nonlocal ready
            ready += 1
            if ready == 10_000:
                admitted.set()
            await admitted.wait()
            if i % 5 == 0:
                raise asyncio.CancelledError()
            if i % 7 == 0:
                raise TimeoutError()
            return 37

        try:
            await run.acall(str(i), 100, operation, lambda r: r)
            return "committed"
        except BudgetDeniedError:
            ready += 1
            if ready == 10_000:
                admitted.set()
            return "denied"
        except asyncio.CancelledError:
            return "cancelled"
        except TimeoutError:
            return "uncertain"

    result = await asyncio.wait_for(asyncio.gather(*(worker(i) for i in range(10_000))), 120)
    check(result.count("denied") == 9000, 'result.count("denied") == 9000')
    committed = result.count("committed") * 37
    unresolved = result.count("cancelled") + result.count("uncertain")
    report = run.report()
    ledger(report, 100_000, committed, unresolved * 100)
    # Denials are history rather than capacity, so the registry holds the admitted 1000
    # while the count of refusals still accounts for every one of the 10,000 tasks.
    check(len(report.attempts) == 1000, "len(report.attempts) == 1000")
    check(report.denied_total == 9000, "report.denied_total == 9000")
    check(
        len(report.attempts) + report.denied_total == 10_000,
        "len(report.attempts) + report.denied_total == 10_000",
    )
    # Reconcile each actually admitted uncertain call from the independent outcomes.
    for i, state in enumerate(result):
        if state in ("cancelled", "uncertain"):
            run.reconcile(str(i), 19)
    ledger(run.report(), 100_000, committed + unresolved * 19)
    emit(
        "10000_async_admission_and_cancellation",
        start,
        outcomes={s: result.count(s) for s in set(result)},
        reconciled=unresolved,
    )


def settlement_races(rounds=200):
    start = time.perf_counter()
    run = AgentBudget(rounds * 100, max_attempts=rounds)
    expected = 0
    with ThreadPoolExecutor(max_workers=32) as pool:
        for r in range(rounds):
            attempt = str(r)
            try:
                run.call(attempt, 100, lambda: 1 / 0, lambda x: 0)
            except ZeroDivisionError:
                pass
            barrier = threading.Barrier(32)

            def settle(i):
                barrier.wait(timeout=20)
                try:
                    if i % 2:
                        run.reconcile(attempt, 31)
                        return 31
                    run.release(attempt, confirmed_no_charge=True)
                    return 0
                except AttemptStateError:
                    return None

            results = list(pool.map(settle, range(32)))
            winners = [x for x in results if x is not None]
            check(len(winners) == 1, "len(winners) == 1")
            expected += winners[0]
    ledger(run.report(), rounds * 100, expected)
    emit("settlement_races", start, attempts=rounds, settlement_calls=rounds * 32)


def denial_pressure(workers=64, steps=4000):
    """A run kept at the edge of its budget must never be ended by calls it refused."""
    start = time.perf_counter()
    # The budget must be what runs out, not the registry: with both set to the same
    # number the capacity check fires first and no denial is ever produced, which is
    # how the first version of this scenario passed while measuring nothing.
    affordable = 500
    admitted_cap = 4 * affordable
    run = AgentBudget(affordable * 10, max_attempts=admitted_cap, max_denied_records=64)
    barrier = threading.Barrier(workers)
    counts = {"admitted": 0, "denied": 0, "limit": 0}
    lock = threading.Lock()

    def worker(worker_id):
        barrier.wait(timeout=30)
        local = {"admitted": 0, "denied": 0, "limit": 0}
        for i in range(steps):
            try:
                run.call(f"{worker_id}:{i}", 10, lambda: "ok", lambda r: 10)
                local["admitted"] += 1
            except BudgetDeniedError:
                local["denied"] += 1
            except AttemptLimitError:
                local["limit"] += 1
        with lock:
            for key, value in local.items():
                counts[key] += value

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(worker, range(workers)))

    report = run.report()
    # Capacity is spent by admitted work alone, and every refusal is still counted.
    check(counts["admitted"] == affordable, counts)
    check(counts["denied"] == workers * steps - affordable, counts)
    check(counts["limit"] == 0, "the registry ended a run the budget had not")
    check(len(report.attempts) == counts["admitted"], 'len(report.attempts) == counts["admitted"]')
    check(report.denied_total == counts["denied"], 'report.denied_total == counts["denied"]')
    check(
        len(report.denied) == min(64, counts["denied"]),
        'len(report.denied) == min(64, counts["denied"])',
    )
    ledger(report, affordable * 10, counts["admitted"] * 10)
    emit(
        "denial_pressure",
        start,
        calls=workers * steps,
        admitted=counts["admitted"],
        denied=counts["denied"],
        limit_errors=counts["limit"],
        denied_records_kept=len(report.denied),
    )


def correction_races(rounds=200, racers=32):
    """Every stuck overrun must accept exactly one documented correction."""
    start = time.perf_counter()
    settled = 0
    with ThreadPoolExecutor(max_workers=racers) as pool:
        for round_index in range(rounds):
            run = AgentBudget(50)
            try:
                run.call("x", 40, lambda: "ok", lambda _response: 60)
            except BudgetOverrunError:
                pass
            check(
                run.report().attempts[0].status == "overrun_unsettled",
                "the overrun did not stay unsettled",
            )
            barrier = threading.Barrier(racers)

            # `run` and `barrier` are rebound every round, so they are bound here
            # rather than captured: a closure that reads them late would race the
            # next round's objects.
            def correct(i, run=run, barrier=barrier):
                barrier.wait(timeout=20)
                amount = 10 + i
                try:
                    run.correct("x", amount, reason=f"credit-{i}")
                    return amount
                except CorrectionError:
                    return None

            results = list(pool.map(correct, range(racers)))
            winners = [x for x in results if x is not None]
            check(len(winners) == 1, f"round {round_index}: {len(winners)} winners")
            report = run.report()
            attempt = report.attempts[0]
            check(attempt.status == "corrected", 'attempt.status == "corrected"')
            check(attempt.actual_microcents == 60, "observed cost was lost")
            check(
                attempt.corrected_microcents == winners[0],
                "attempt.corrected_microcents == winners[0]",
            )
            check(attempt.correction_reason is not None, "attempt.correction_reason is not None")
            ledger(report, 50, winners[0])
            settled += winners[0]
    emit(
        "correction_races",
        start,
        overruns=rounds,
        correction_calls=rounds * racers,
        settled_microcents=settled,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=16000)
    parser.add_argument("--workers", type=int, default=64)
    args = parser.parse_args()
    print(
        json.dumps(dict(calybris=version("calybris"), steps=args.steps, workers=args.workers)),
        flush=True,
    )
    contention()
    asyncio.run(async_storm())
    settlement_races()
    denial_pressure()
    correction_races()
    threaded_soak(args.workers, args.steps)


if __name__ == "__main__":
    main()
