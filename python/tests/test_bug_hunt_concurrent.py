"""Concurrent BudgetGuard stress — CSV 'Budget Concurrency' probe."""

from __future__ import annotations

import random
import threading

from calybris import MICROCENTS_PER_CENT, BudgetGuard

USD = MICROCENTS_PER_CENT


def test_concurrent_reserve_never_exceeds_exposure_cap():
    guard = BudgetGuard().ensure_tenant("desk", 500 * USD, max_reserved_microcents=100 * USD)
    errors: list[str] = []

    def worker(seed: int):
        rng = random.Random(seed)
        for _ in range(40):
            amt = rng.randint(1, 40) * USD
            hold = guard.reserve("desk", amt)
            if hold.is_reserved and hold.reservation_id is not None:
                if rng.random() < 0.5:
                    guard.commit(hold.reservation_id, rng.randint(1, 10_000))
                else:
                    guard.release(hold.reservation_id)
            if guard.reserved_microcents("desk") > 100 * USD:
                errors.append(f"cap exceeded: {guard.reserved_microcents('desk')}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert guard.verify_conservation().is_balanced


def test_concurrent_top_up_reserve_commit_release_mixed():
    """CSV probe: mixed top_up + reserve + commit + release under exposure cap."""
    guard = BudgetGuard().ensure_tenant("desk", 1_000 * USD, max_reserved_microcents=200 * USD)
    errors: list[str] = []

    def worker(seed: int):
        rng = random.Random(seed)
        for step in range(50):
            match step % 5:
                case 0:
                    guard.top_up("desk", rng.randint(1, 20) * USD)
                case 1:
                    hold = guard.reserve("desk", rng.randint(1, 30) * USD)
                    if hold.is_reserved and hold.reservation_id is not None:
                        if rng.random() < 0.4:
                            guard.commit(hold.reservation_id, rng.randint(1, 5_000))
                        else:
                            guard.release(hold.reservation_id)
                case 2:
                    guard.set_max_reserved_microcents("desk", rng.randint(50, 300) * USD)
                case _:
                    pass
            # Cap may be raised up to 300*USD during the run; reserved must never exceed that.
            if guard.reserved_microcents("desk") > 300 * USD:
                errors.append("cap exceeded after mixed ops")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert guard.verify_conservation().is_balanced
