import json

import pytest
from calybris.agent import AgentBudget, BudgetDeniedError, BudgetOverrunError


def test_lifecycle_retains_correction_and_reports_pruned_denials():
    run = AgentBudget(50, max_denied_records=1)
    for _ in range(3):
        with pytest.raises(BudgetDeniedError):
            run.call("denied", 100, lambda: None, lambda r: 0)
    with pytest.raises(BudgetOverrunError):
        run.call("overrun", 40, lambda: None, lambda r: 60)
    report = run.lifecycle_report()
    assert report["unresolved"][0]["next_action"] == "documented_correction"
    assert report["denied_history_truncated"]
    assert report["denied_total"] == 3
    run.correct("overrun", 30, reason="provider credit CR-1")
    settled = run.lifecycle_report()
    assert settled["unresolved"] == []
    assert settled["corrections"][0]["actual_microcents"] == 60
    assert settled["corrections"][0]["corrected_microcents"] == 30
    assert settled["balance"]["remaining_microcents"] == 20
    assert settled["conservation_balanced"]
    assert json.loads(json.dumps(settled))["schema_version"] == "calybris.budget-lifecycle.v1"
    assert report["balance"]["reserved_microcents"] == 40


def test_uncertain_operation_is_not_reported_as_free():
    run = AgentBudget(100)

    def fail():
        raise RuntimeError("private exception")

    with pytest.raises(RuntimeError):
        run.call("pending", 40, fail, lambda r: 0)
    report = run.lifecycle_report()
    assert report["unresolved"][0]["next_action"] == "reconcile_or_confirm_no_charge"
    assert report["balance"]["reserved_microcents"] == 40
    assert "private exception" not in json.dumps(report)


def test_an_unsettled_overrun_is_not_counted_as_a_settled_attempt():
    """An observed cost is not a settled one.

    The overrun below has an amount and a reservation, but the ledger never took it:
    the run is closed awaiting a documented correction. Counting it would report an
    accuracy figure for work the budget did not complete, and would contradict
    ``largest_settled_microcents`` in the same object.
    """
    run = AgentBudget(50)
    with pytest.raises(BudgetOverrunError):
        run.call("overrun", 40, lambda: None, lambda r: 60)

    accuracy = run.reservation_accuracy()

    assert run.lifecycle_report()["attempts"][0]["status"] == "overrun_unsettled"
    assert accuracy.settled_attempts == 0
    assert accuracy.median_ratio_ppm is None
    assert accuracy.largest_settled_microcents == 0


def test_a_correction_settles_the_attempt_and_then_it_counts():
    run = AgentBudget(50)
    with pytest.raises(BudgetOverrunError):
        run.call("overrun", 40, lambda: None, lambda r: 60)
    run.correct("overrun", 30, reason="provider credit CR-1")

    accuracy = run.reservation_accuracy()

    assert run.lifecycle_report()["attempts"][0]["status"] == "corrected"
    assert accuracy.settled_attempts == 1
    # Accuracy asks what the call cost against what was reserved, so it keeps the
    # originally observed 60 against 40 rather than the negotiated settlement.
    assert accuracy.median_ratio_ppm == 1_500_000


def test_an_uncertain_attempt_is_not_counted_either():
    run = AgentBudget(100)

    def fail():
        raise RuntimeError("private exception")

    with pytest.raises(RuntimeError):
        run.call("pending", 40, fail, lambda r: 0)

    assert run.reservation_accuracy().settled_attempts == 0
