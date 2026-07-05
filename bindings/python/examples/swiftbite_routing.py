"""SwiftBite-scale courier routing — food delivery with tight SLA gates.

Food delivery has stricter latency constraints than parcel shipping:
- Cold chain / refrigeration capability requirements
- Sub-2-hour delivery windows
- High-volume, low-value orders with different risk profiles

This example models a city-level food delivery dispatcher using Calybris.
"""
from __future__ import annotations

import random
import time

from calybris_commerce import (
    CAP_REFRIGERATED,
    CAP_SAME_DAY,
    CAP_STANDARD,
    REGION_TR_ANKARA,
    REGION_TR_IST,
    REGION_TR_IZMIR,
    OrderInput,
    SupplierPolicy,
    SupplierSpec,
)

REGION_TR_IST_EUROPEAN  = 1 << 10
REGION_TR_IST_ANATOLIAN = 1 << 11
REGION_TR_ANK_CENTRAL   = 1 << 12
REGION_TR_ANK_NORTH     = 1 << 13

policy = (
    SupplierPolicy(policy_epoch=5, catalog_epoch=310)
    .return_risk_limit(max_pct=25.0)
    .confidence_floor(min_pct=70.0)
    .risk_sensitivity(multiplier_bps=5_000)
    .latency_cost(microunits_per_hour=50_000)
    .add_supplier(SupplierSpec(
        supplier_id=10, name="RiderFleet — IST European",
        reliability_pct=98.5, risk_tolerance_pct=30.0,
        sla_hours=1, shipping_cost_microunits=8_000_000,
        capabilities=CAP_SAME_DAY | CAP_REFRIGERATED,
        region_mask=REGION_TR_IST_EUROPEAN,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=11, name="RiderFleet — IST Anatolian",
        reliability_pct=98.2, risk_tolerance_pct=30.0,
        sla_hours=1, shipping_cost_microunits=8_200_000,
        capabilities=CAP_SAME_DAY | CAP_REFRIGERATED,
        region_mask=REGION_TR_IST_ANATOLIAN,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=12, name="RiderFleet — Ankara Central",
        reliability_pct=97.9, risk_tolerance_pct=30.0,
        sla_hours=1, shipping_cost_microunits=7_500_000,
        capabilities=CAP_SAME_DAY | CAP_REFRIGERATED,
        region_mask=REGION_TR_ANK_CENTRAL,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=13, name="RiderFleet — Ankara North",
        reliability_pct=97.3, risk_tolerance_pct=35.0,
        sla_hours=1, shipping_cost_microunits=7_800_000,
        capabilities=CAP_SAME_DAY,
        region_mask=REGION_TR_ANK_NORTH,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=20, name="PlatformRider — Istanbul",
        reliability_pct=95.0, risk_tolerance_pct=40.0,
        sla_hours=2, shipping_cost_microunits=5_000_000,
        capabilities=CAP_SAME_DAY,
        region_mask=REGION_TR_IST,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=21, name="PlatformRider — Ankara",
        reliability_pct=94.5, risk_tolerance_pct=40.0,
        sla_hours=2, shipping_cost_microunits=4_800_000,
        capabilities=CAP_SAME_DAY,
        region_mask=REGION_TR_ANKARA,
    ))
    .add_supplier(SupplierSpec(
        supplier_id=22, name="PlatformRider — Izmir",
        reliability_pct=94.8, risk_tolerance_pct=40.0,
        sla_hours=2, shipping_cost_microunits=5_200_000,
        capabilities=CAP_SAME_DAY,
        region_mask=REGION_TR_IZMIR,
    ))
    .build_engine()
)

print(policy)
print(f"Policy fingerprint: {policy.fingerprint}\n")

rng = random.Random(7)
regions_city = [
    REGION_TR_IST_EUROPEAN,
    REGION_TR_IST_ANATOLIAN,
    REGION_TR_ANK_CENTRAL,
    REGION_TR_ANK_NORTH,
    REGION_TR_IST,
    REGION_TR_ANKARA,
]
weights = [0.25, 0.20, 0.18, 0.12, 0.15, 0.10]

orders = [
    OrderInput(
        order_id=f"SB-{i:06d}",
        order_sequence=i,
        order_value_microunits=rng.randint(30_000_000, 250_000_000),
        budget_limit_microunits=rng.randint(6_000_000, 10_000_000),
        return_risk_pct=rng.betavariate(1.0, 30.0) * 100,
        confidence_pct=rng.uniform(70.0, 100.0),
        required_capabilities=(
            CAP_REFRIGERATED if rng.random() < 0.30 else CAP_STANDARD
        ),
        required_regions=rng.choices(regions_city, weights=weights)[0],
        max_delivery_hours=rng.choice([1, 1, 2, 2, 2]),
    )
    for i in range(1, 5_001)
]

t0 = time.perf_counter()
batch = policy.route_batch(orders, audit=False, trace_mode="summary")
results = batch.results
elapsed = time.perf_counter() - t0

fulfilled   = [r for r in results if r.is_fulfilled]
rejected    = [r for r in results if r.is_rejected]
substituted = [r for r in results if r.status == "substituted"]

print(f"Dispatched {len(orders):,} orders in {elapsed*1000:.1f} ms "
      f"({len(orders)/elapsed:,.0f}/sec)\n")
print(f"  Fulfilled   : {len(fulfilled):,} ({len(fulfilled)/len(orders)*100:.1f}%)")
print(f"  Substituted : {len(substituted):,}")
print(f"  Rejected    : {len(rejected):,} ({len(rejected)/len(orders)*100:.1f}%)")
if batch.rejection_histogram:
    print(f"  Rejections  : {batch.rejection_histogram}")

by_courier: dict[int, int] = {}
for r in fulfilled:
    by_courier[r.chosen_supplier_id] = by_courier.get(r.chosen_supplier_id, 0) + 1

print("\nCourier dispatch share:")
for cid, count in sorted(by_courier.items()):
    print(f"  Courier {cid:2d}: {count:4,} orders")

print("\n-- Single order with full audit ----------------------------------")
sample = orders[0]
result = policy.route_order(sample, audit=True)
print(f"Order   : {result.order_id}")
print(f"Status  : {result.status}")
print(f"Courier : {result.chosen_supplier_id}")
print(f"Cost    : {result.estimated_cost_microunits / 1_000_000:.2f} TL")
print(f"Reason  : {result.reasoning}")
assert result.audit_bundle is not None
print(f"Policy  : {result.audit_bundle.policy_digest_hex[:16]}...")
print(f"Replay  : {result.audit_bundle.replay_valid}")
