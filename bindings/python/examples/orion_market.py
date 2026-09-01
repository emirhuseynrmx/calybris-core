"""Orion Market-scale supplier routing — 10 000 orders, 8 couriers, audit trail.

Simulates the kind of fulfillment routing a large e-commerce platform runs
per minute: thousands of parallel orders across multiple courier networks,
each with distinct SLAs, regional coverage, and risk tolerances.

Run with:
    maturin develop --release
    python examples/orion_market.py
"""
from __future__ import annotations

import random
import time

from calybris_commerce import (
    CAP_FRAGILE,
    CAP_HEAVY,
    CAP_SAME_DAY,
    CAP_STANDARD,
    REGION_TR_ALL,
    REGION_TR_ANKARA,
    REGION_TR_IST,
    REGION_TR_IZMIR,
    OrderInput,
    SupplierPolicy,
    SupplierSpec,
)

policy = (
    SupplierPolicy(policy_epoch=12, catalog_epoch=88)
    .return_risk_limit(max_pct=35.0)
    .confidence_floor(min_pct=55.0)
    .risk_sensitivity(multiplier_bps=4_000)
    .latency_cost(microunits_per_hour=5_000)
    .add_supplier(SupplierSpec(
        supplier_id=1, name="ExpressLine — Istanbul",
        reliability_pct=99.4, risk_tolerance_pct=40.0,
        sla_hours=4, shipping_cost_microunits=12_000_000,
        handling_cost_microunits=2_000_000,
        capabilities=CAP_SAME_DAY | CAP_FRAGILE,
        region_mask=REGION_TR_IST,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=2, name="ExpressLine — Ankara",
        reliability_pct=99.1, risk_tolerance_pct=40.0,
        sla_hours=4, shipping_cost_microunits=11_500_000,
        capabilities=CAP_SAME_DAY,
        region_mask=REGION_TR_ANKARA,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=3, name="ExpressLine — Aegean",
        reliability_pct=98.8, risk_tolerance_pct=40.0,
        sla_hours=6, shipping_cost_microunits=11_000_000,
        capabilities=CAP_SAME_DAY | CAP_FRAGILE,
        region_mask=REGION_TR_IZMIR,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=4, name="NextDay Cargo — Nationwide",
        reliability_pct=97.5, risk_tolerance_pct=50.0,
        sla_hours=24, shipping_cost_microunits=5_500_000,
        capabilities=CAP_HEAVY | CAP_FRAGILE,
        region_mask=REGION_TR_ALL,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=5, name="Standard Carrier A — Nationwide",
        reliability_pct=96.2, risk_tolerance_pct=60.0,
        sla_hours=48, shipping_cost_microunits=3_200_000,
        capabilities=CAP_HEAVY,
        region_mask=REGION_TR_ALL,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=6, name="Standard Carrier B — Nationwide",
        reliability_pct=95.8, risk_tolerance_pct=60.0,
        sla_hours=48, shipping_cost_microunits=3_000_000,
        region_mask=REGION_TR_ALL,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=7, name="Economy Carrier — Nationwide",
        reliability_pct=93.0, risk_tolerance_pct=70.0,
        sla_hours=72, shipping_cost_microunits=1_800_000,
        region_mask=REGION_TR_ALL,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=8, name="HeavyHaul — Nationwide",
        reliability_pct=95.0, risk_tolerance_pct=55.0,
        sla_hours=96, shipping_cost_microunits=8_000_000,
        handling_cost_microunits=5_000_000,
        capabilities=CAP_HEAVY,
        region_mask=REGION_TR_ALL,
    ))
    .build_engine()
)

print(policy)
print(f"Policy fingerprint: {policy.fingerprint}\n")

rng = random.Random(42)
regions = [REGION_TR_IST, REGION_TR_ANKARA, REGION_TR_IZMIR, REGION_TR_ALL]
region_weights = [0.35, 0.20, 0.15, 0.30]

orders = [
    OrderInput(
        order_id=f"OM-{i:06d}",
        order_sequence=i,
        order_value_microunits=rng.randint(15_000_000, 500_000_000),
        budget_limit_microunits=rng.randint(3_000_000, 15_000_000),
        return_risk_pct=rng.betavariate(1.5, 20.0) * 100,
        confidence_pct=rng.uniform(60.0, 100.0),
        required_capabilities=(
            CAP_FRAGILE if rng.random() < 0.15
            else CAP_HEAVY if rng.random() < 0.10
            else CAP_STANDARD
        ),
        required_regions=rng.choices(regions, weights=region_weights)[0],
        max_delivery_hours=rng.choice([4, 6, 24, 48, 72, 0]),
    )
    for i in range(1, 10_001)
]

t0 = time.perf_counter()
batch = policy.route_batch(orders, audit=False, trace_mode="summary")
results = batch.results
elapsed = time.perf_counter() - t0

accepted    = sum(1 for r in results if r.status == "accepted")
substituted = sum(1 for r in results if r.status == "substituted")
rejected    = sum(1 for r in results if r.status == "rejected")
total_cost  = sum(r.estimated_cost_microunits for r in results if r.is_fulfilled)
avg_cost    = total_cost / max(accepted + substituted, 1)

by_supplier: dict[int, int] = {}
for r in results:
    if r.is_fulfilled:
        by_supplier[r.chosen_supplier_id] = by_supplier.get(r.chosen_supplier_id, 0) + 1

print(f"Routed {len(orders):,} orders in {elapsed * 1000:.1f} ms "
      f"({len(orders) / elapsed:,.0f} orders/sec)\n")
print(f"  Accepted    : {accepted:,} ({accepted/len(orders)*100:.1f}%)")
print(f"  Substituted : {substituted:,} ({substituted/len(orders)*100:.1f}%)")
print(f"  Rejected    : {rejected:,} ({rejected/len(orders)*100:.1f}%)")
if batch.rejection_histogram:
    print(f"  Rejections  : {batch.rejection_histogram}")
print(f"  Avg cost    : {avg_cost/1_000_000:.2f} TL")
print("\nSupplier share:")
for sid, count in sorted(by_supplier.items()):
    pct = count / (accepted + substituted) * 100
    print(f"  Supplier {sid:2d}: {count:5,} orders ({pct:.1f}%)")

print("\nAudit spot-check (first 5 fulfilled orders):")
fulfilled = [(o, r) for o, r in zip(orders, results) if r.is_fulfilled][:5]
for order, result in fulfilled:
    dec_raw = policy.prescribe_raw(order)
    bundle = policy.verified_audit_bundle(order, dec_raw)
    status = "VALID" if bundle.replay_valid else "FAIL"
    print(f"  {order.order_id}  supplier={result.chosen_supplier_id}  {status}")
