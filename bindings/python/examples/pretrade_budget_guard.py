"""Exposure-layer pre-trade guard (companion to ``pretrade_guard`` Rust example).

The Rust example runs the full pipeline: venue policy gate -> exposure hold ->
fee commit. This script isolates layer 2 so you can wire ``BudgetGuard`` into an
existing OMS without adopting the routing kernel yet.

Run:
    maturin build --release --out dist
    pip install dist/calybris-*.whl --force-reinstall
    python bindings/python/examples/pretrade_budget_guard.py
"""
from __future__ import annotations

from calybris import BudgetGuard, MICROCENTS_PER_CENT

USD = 100 * MICROCENTS_PER_CENT

# desk-alpha: same limits as the Rust VWAP scenario
guard = BudgetGuard().ensure_tenant(
    "desk-alpha",
    2_000_000 * USD,
    max_reserved_microcents=500_000 * USD,
)

# Child orders already cleared the policy gate; exposure layer sees notional only.
child_orders = [
    ("CL-10041", "AAPL", "buy", 85_000 * USD, 12_200),
    ("CL-10042", "TSLA", "sell", 210_000 * USD, 18_600),
    ("CL-10045", "MSFT", "buy", 55_000 * USD, 9_800),
    ("CL-10044", "SPY", "buy", 620_000 * USD, 21_400),  # exceeds open exposure cap
]

print("Calybris BudgetGuard — desk-alpha exposure layer")
print("================================================")
print("budget 2,000,000 USD | open exposure cap 500,000 USD\n")

admitted = 0
for client_id, symbol, side, notional, fee in child_orders:
    hold = guard.reserve("desk-alpha", notional)
    if not hold.is_reserved or hold.reservation_id is None:
        print(
            f"{client_id} {symbol:<4} {side:<4} "
            f"{notional // USD:>7,} USD  BLOCKED  exposure={hold.status}"
        )
        continue

    settlement = guard.commit(hold.reservation_id, fee)
    admitted += 1
    print(
        f"{client_id} {symbol:<4} {side:<4} "
        f"{notional // USD:>7,} USD  ADMITTED  fee={fee}  settlement={settlement.status}"
    )

proof = guard.prove_conservation()
certificate = guard.certificate()

print()
print(f"admitted:        {admitted}/{len(child_orders)}")
print(f"open reserved:   {guard.reserved_microcents('desk-alpha') // USD:,} USD")
print(f"remaining:       {guard.remaining_microcents('desk-alpha') // USD:,} USD")
print(f"conservation:    {guard.verify_conservation().status}")
print(f"ledger digest:   {proof.ledger_digest_hex[:16]}...")
print(f"certificate ok:  {certificate.conservation_balanced}")