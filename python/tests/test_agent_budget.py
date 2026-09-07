import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier, Event

import pytest
from calybris.agent import (
    AgentBudget,
    AttemptLimitError,
    AttemptStateError,
    BudgetDeniedError,
    BudgetOverrunError,
    CorrectionError,
    DuplicateAttemptError,
    RunClosedError,
)
from calybris.errors import InputValidationError


def test_success_refunds_only_unused_reservation_and_report_is_detached():
    run = AgentBudget(100)
    assert run.call("a", 80, lambda: "response", lambda r: 30) == "response"
    report = run.report()
    assert (
        report.remaining_microcents,
        report.reserved_microcents,
        report.committed_microcents,
    ) == (70, 0, 30)
    assert report.conservation_balanced
    with pytest.raises(FrozenInstanceError):
        report.attempts[0].status = "uncertain"
    run.call("b", 10, lambda: None, lambda r: 0)
    assert len(report.attempts) == 1


def test_denial_never_executes_the_callback_and_leaves_its_id_free():
    run = AgentBudget(10)
    called = []
    with pytest.raises(BudgetDeniedError):
        run.call("a", 11, lambda: called.append(1), lambda r: 0)
    assert called == []
    report = run.report()
    assert report.attempts == ()
    assert report.denied[0].status == "denied" and report.denied_total == 1

    # Nothing ran and nothing was held, so the same step may be attempted again.
    assert run.call("a", 1, lambda: "ok", lambda r: 1) == "ok"
    assert run.report().attempts[0].status == "committed"


def test_an_admitted_id_cannot_be_reused():
    run = AgentBudget(10)
    run.call("a", 1, lambda: "ok", lambda r: 1)
    with pytest.raises(DuplicateAttemptError):
        run.call("a", 1, lambda: pytest.fail("called"), lambda r: 0)


@pytest.mark.parametrize("bad", [-1, True, 1.5, 2**63, "10", None])
def test_invalid_reservation_does_not_consume_id(bad):
    run = AgentBudget(10)
    with pytest.raises(InputValidationError):
        run.call("a", bad, lambda: pytest.fail("called"), lambda r: 0)
    assert run.report().attempts == ()


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, 2**63])
def test_invalid_max_attempts_rejected(bad):
    with pytest.raises(InputValidationError):
        AgentBudget(10, max_attempts=bad)


@pytest.mark.parametrize("bad", ["", "x" * 257, None, 10, "\ud800"])
def test_invalid_id_is_rejected_before_dispatch(bad):
    with pytest.raises(InputValidationError):
        AgentBudget(10).call(bad, 1, lambda: pytest.fail("called"), lambda r: 0)


def test_exception_keeps_hold_until_explicit_reconciliation():
    run = AgentBudget(100)

    def fail():
        raise TimeoutError("provider may have billed")

    with pytest.raises(TimeoutError):
        run.call("a", 80, fail, lambda r: 0)
    with pytest.raises(BudgetDeniedError):
        run.call("b", 21, lambda: pytest.fail("called"), lambda r: 0)
    assert run.report().reserved_microcents == 80
    run.reconcile("a", 50)
    assert (run.report().remaining_microcents, run.report().committed_microcents) == (50, 50)
    with pytest.raises(AttemptStateError):
        run.reconcile("a", 50)


@pytest.mark.parametrize("bad", [-1, True, 2**63, 3.5, None])
def test_bad_usage_keeps_hold_and_does_not_commit(bad):
    run = AgentBudget(100)
    with pytest.raises(InputValidationError):
        run.call("a", 80, lambda: "ok", lambda r: bad)
    report = run.report()
    assert report.attempts[0].status == "uncertain"
    assert (
        report.remaining_microcents,
        report.reserved_microcents,
        report.committed_microcents,
    ) == (20, 80, 0)


def test_cost_callback_exception_keeps_hold():
    run = AgentBudget(10)

    def bad_usage(response):
        raise LookupError("missing usage")

    with pytest.raises(LookupError):
        run.call("a", 10, lambda: object(), bad_usage)
    assert run.report().reserved_microcents == 10


def test_release_needs_explicit_no_charge_confirmation():
    run = AgentBudget(10)
    with pytest.raises(ZeroDivisionError):
        run.call("a", 10, lambda: 1 / 0, lambda r: 0)
    with pytest.raises(InputValidationError):
        run.release("a", confirmed_no_charge=False)
    assert run.report().reserved_microcents == 10
    run.release("a", confirmed_no_charge=True)
    assert run.report().remaining_microcents == 10
    with pytest.raises(AttemptStateError):
        run.release("a", confirmed_no_charge=True)


@pytest.mark.parametrize("budget, committed, reserved", [(100, 60, 0), (50, 0, 40)])
def test_overrun_is_visible_and_stops_new_work_even_when_affordable(budget, committed, reserved):
    run = AgentBudget(budget)
    with pytest.raises(BudgetOverrunError):
        run.call("a", 40, lambda: "ok", lambda r: 60)
    report = run.report()
    assert report.closed and report.attempts[0].actual_microcents == 60
    assert report.committed_microcents == committed
    assert report.reserved_microcents == reserved
    assert report.conservation_balanced
    with pytest.raises(RunClosedError):
        run.call("b", 1, lambda: pytest.fail("called"), lambda r: 0)
    with pytest.raises(AttemptStateError):
        run.release("a", confirmed_no_charge=True)
    with pytest.raises(AttemptStateError):
        run.reconcile("a", 1)


def test_denials_do_not_consume_the_admitted_attempt_limit():
    run = AgentBudget(10, max_attempts=2)
    run.call("a", 1, lambda: None, lambda r: 0)
    for i in range(5):
        with pytest.raises(BudgetDeniedError):
            run.call(f"d{i}", 11, lambda: pytest.fail("called"), lambda r: 0)
    # One slot is still free despite five refusals in between.
    run.call("b", 1, lambda: None, lambda r: 0)
    with pytest.raises(AttemptLimitError):
        run.call("c", 1, lambda: pytest.fail("called"), lambda r: 0)
    report = run.report()
    assert len(report.attempts) == 2
    assert report.denied_total == 5


def test_denial_history_is_bounded_but_its_loss_is_visible():
    run = AgentBudget(1, max_denied_records=3)
    for i in range(10):
        with pytest.raises(BudgetDeniedError):
            run.call(f"d{i}", 5, lambda: pytest.fail("called"), lambda r: 0)
    report = run.report()
    assert len(report.denied) == 3
    assert report.denied_total == 10
    assert [record.attempt_id for record in report.denied] == ["d7", "d8", "d9"]


def test_100_simultaneous_calls_cannot_spend_inflight_reservations():
    run = AgentBudget(70)
    start = Barrier(100)
    finished_admission = Barrier(100)

    def worker(i):
        start.wait(timeout=15)

        def operation():
            finished_admission.wait(timeout=15)
            return 10

        try:
            run.call(str(i), 10, operation, lambda r: r)
            return "accepted"
        except BudgetDeniedError:
            finished_admission.wait(timeout=15)
            return "denied"

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(worker, range(100)))
    assert results.count("accepted") == 7
    assert results.count("denied") == 93
    assert run.report().committed_microcents == 70
    assert run.report().reserved_microcents == 0


def test_duplicate_and_manual_settlement_cannot_interfere_with_active_call():
    run = AgentBudget(100)
    entered, finish = Event(), Event()

    def operation():
        entered.set()
        assert finish.wait(10)
        return 20

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run.call, "a", 50, operation, lambda r: r)
        try:
            assert entered.wait(10)
            with pytest.raises(DuplicateAttemptError):
                run.call("a", 50, lambda: pytest.fail("called"), lambda r: 0)
            with pytest.raises(AttemptStateError):
                run.reconcile("a", 0)
            with pytest.raises(AttemptStateError):
                run.release("a", confirmed_no_charge=True)
            run.close()
        finally:
            finish.set()
        assert future.result() == 20
    assert run.report().committed_microcents == 20


def test_reconcile_release_race_has_one_winner():
    run = AgentBudget(100)
    with pytest.raises(ZeroDivisionError):
        run.call("a", 80, lambda: 1 / 0, lambda r: 0)
    barrier = Barrier(32)

    def worker(i):
        barrier.wait(timeout=10)
        try:
            if i % 2:
                run.reconcile("a", 30)
                return "committed"
            run.release("a", confirmed_no_charge=True)
            return "released"
        except AttemptStateError:
            return "lost"

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(worker, range(32)))
    assert results.count("lost") == 31
    expected = 30 if "committed" in results else 0
    assert run.report().committed_microcents == expected
    assert run.report().remaining_microcents == 100 - expected


def test_async_cancel_keeps_hold_but_success_settles():
    async def scenario():
        run = AgentBudget(100)
        started = asyncio.Event()

        async def hang():
            started.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(run.acall("a", 80, hang, lambda r: 0))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert run.report().reserved_microcents == 80
        run.reconcile("a", 20)

        async def good():
            return 5

        assert await run.acall("b", 10, good, lambda r: r) == 5
        assert run.report().remaining_microcents == 75

    asyncio.run(scenario())


def test_sync_rejects_coroutine_before_dispatch():
    async def operation():
        pytest.fail("must not run")

    run = AgentBudget(100)
    with pytest.raises(InputValidationError):
        run.call("a", 10, operation, lambda r: 0)
    assert run.report().attempts == ()


def test_iterator_response_is_not_mistaken_for_completed_usage():
    run = AgentBudget(100)
    with pytest.raises(InputValidationError):
        run.call("a", 10, lambda: iter([1, 2]), lambda r: 0)
    assert run.report().reserved_microcents == 10
    assert run.report().attempts[0].status == "uncertain"


@pytest.mark.parametrize("asynchronous", [False, True])
def test_async_cost_callback_is_rejected_before_any_billable_operation(asynchronous):
    run = AgentBudget(100)
    calls = []

    async def bad_cost(result):
        return 0

    def sync_op():
        calls.append(1)
        return "ok"

    async def async_op():
        return sync_op()

    with pytest.raises(InputValidationError):
        if asynchronous:
            asyncio.run(run.acall("a", 10, async_op, bad_cost))
        else:
            run.call("a", 10, sync_op, bad_cost)
    assert calls == []
    assert run.report().attempts == ()


def test_zero_budget_and_zero_reservation_cannot_dispatch():
    run = AgentBudget(0)
    with pytest.raises(InputValidationError):
        run.call("a", 0, lambda: pytest.fail("called"), lambda r: 0)
    with pytest.raises(BudgetDeniedError):
        run.call("b", 1, lambda: pytest.fail("called"), lambda r: 0)
    assert run.report().remaining_microcents == 0


def test_run_cannot_be_pickled_as_if_it_were_durable_state():
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(AgentBudget(100))


def test_inherited_process_cannot_access_budget_even_when_mutex_is_locked(monkeypatch):
    import calybris.agent as module
    from calybris import AgentBudgetError

    run = AgentBudget(100)
    original_pid = module.os.getpid()
    # Simulates the post-fork PID boundary without forking a threaded test runner.
    monkeypatch.setattr(module.os, "getpid", lambda: original_pid + 1)
    with run._lock:
        with pytest.raises(AgentBudgetError):
            run.report()
        with pytest.raises(AgentBudgetError):
            run.call("a", 10, lambda: pytest.fail("called"), lambda r: 0)


def _stuck_overrun():
    """A run whose observed cost the budget could not absorb."""
    run = AgentBudget(50)
    with pytest.raises(BudgetOverrunError):
        run.call("x", 40, lambda: "ok", lambda r: 60)
    assert run.report().attempts[0].status == "overrun_unsettled"
    return run


def test_a_documented_correction_settles_a_stuck_overrun():
    run = _stuck_overrun()
    assert run.balance().reserved_microcents == 40

    run.correct("x", 30, reason="provider credit CR-1")

    report = run.report()
    attempt = report.attempts[0]
    assert attempt.status == "corrected"
    assert attempt.actual_microcents == 60, "the observed cost must survive the correction"
    assert attempt.corrected_microcents == 30
    assert attempt.correction_reason == "provider credit CR-1"
    assert report.committed_microcents == 30
    assert report.reserved_microcents == 0
    assert report.conservation_balanced
    # A correction settles a debt; it does not reopen a run that closed.
    assert report.closed
    with pytest.raises(RunClosedError):
        run.call("y", 1, lambda: pytest.fail("called"), lambda r: 0)


def test_a_correction_cannot_be_applied_twice():
    run = _stuck_overrun()
    run.correct("x", 30, reason="provider credit CR-1")
    with pytest.raises(CorrectionError):
        run.correct("x", 10, reason="second bite")
    assert run.report().committed_microcents == 30


def test_a_correction_cannot_raise_the_settled_amount():
    run = _stuck_overrun()
    for amount in (60, 61):
        with pytest.raises(CorrectionError):
            run.correct("x", amount, reason="not a correction")
    assert run.report().attempts[0].status == "overrun_unsettled"
    assert run.balance().reserved_microcents == 40


def test_a_correction_needs_a_stated_reason():
    run = _stuck_overrun()
    for reason in ("", "   ", None, 5, "x" * 257):
        with pytest.raises(InputValidationError):
            run.correct("x", 10, reason=reason)
    assert run.report().attempts[0].status == "overrun_unsettled"


@pytest.mark.parametrize("prepare", ["missing", "committed", "uncertain"])
def test_only_an_unsettled_overrun_can_be_corrected(prepare):
    run = AgentBudget(100)
    if prepare == "committed":
        run.call("x", 10, lambda: "ok", lambda r: 5)
    elif prepare == "uncertain":
        with pytest.raises(RuntimeError):
            run.call("x", 10, lambda: (_ for _ in ()).throw(RuntimeError("boom")), lambda r: 0)
        assert run.report().attempts[0].status == "uncertain"
    with pytest.raises(CorrectionError):
        run.correct("x", 1, reason="documented")


def test_only_one_thread_wins_a_concurrent_correction():
    run = _stuck_overrun()
    start = Barrier(8)
    outcomes = []

    def attempt(index):
        start.wait()
        try:
            run.correct("x", 20 + index, reason=f"credit-{index}")
            return "won"
        except CorrectionError:
            return "refused"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(8)))

    assert outcomes.count("won") == 1
    report = run.report()
    assert report.attempts[0].status == "corrected"
    assert report.reserved_microcents == 0
    assert report.conservation_balanced


def test_balance_agrees_with_the_full_report():
    run = AgentBudget(100)
    run.call("a", 30, lambda: "ok", lambda r: 12)
    balance, report = run.balance(), run.report()
    assert balance.initial_microcents == report.initial_microcents
    assert balance.remaining_microcents == report.remaining_microcents
    assert balance.reserved_microcents == report.reserved_microcents
    assert balance.committed_microcents == report.committed_microcents
    assert balance.closed == report.closed and balance.close_reason == report.close_reason


def test_balance_is_immutable_and_process_bound():
    run = AgentBudget(10)
    with pytest.raises(FrozenInstanceError):
        run.balance().remaining_microcents = 0


def test_accuracy_names_the_reservation_as_the_reason_for_refusals():
    """Refused while the budget could still cover the largest completed call."""
    run = AgentBudget(100)
    for i in range(4):
        run.call(f"a{i}", 20, lambda: "ok", lambda r: 10)
    # 60 remains, so a refusal needs a reservation larger than that - which is exactly
    # the situation the accuracy report exists to name.
    for i in range(5):
        with pytest.raises(BudgetDeniedError):
            run.call(f"d{i}", 70, lambda: pytest.fail("called"), lambda r: 0)

    accuracy = run.reservation_accuracy()
    assert accuracy.settled_attempts == 4
    assert accuracy.median_ratio_ppm == 500_000, "10 of 20 reserved is half"
    assert accuracy.held_unused_microcents == 40
    assert accuracy.largest_settled_microcents == 10
    assert accuracy.denials_total == 5
    assert accuracy.denials_with_headroom == 5, "60 remained; the largest call cost 10"


def test_accuracy_does_not_blame_the_reservation_when_the_budget_is_truly_gone():
    run = AgentBudget(30)
    for i in range(3):
        run.call(f"a{i}", 10, lambda: "ok", lambda r: 10)
    with pytest.raises(BudgetDeniedError):
        run.call("d", 10, lambda: pytest.fail("called"), lambda r: 0)
    accuracy = run.reservation_accuracy()
    assert accuracy.median_ratio_ppm == 1_000_000, "the reserve was exactly right"
    assert accuracy.held_unused_microcents == 0
    assert accuracy.denials_with_headroom == 0, "nothing was left; the reserve is not at fault"


def test_accuracy_reports_nothing_before_anything_settles():
    run = AgentBudget(10)
    accuracy = run.reservation_accuracy()
    assert accuracy.settled_attempts == 0
    assert accuracy.median_ratio_ppm is None
    assert accuracy.denials_with_headroom == 0
