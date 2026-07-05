"""NovaMart comprehensive commerce-routing benchmark.

Scenario:
    NovaMart is a fictional marketplace evaluating Calybris for courier and
    supplier routing. The benchmark generates 50,000 deterministic orders,
    routes them through three policy snapshots, and reports production-style
    metrics: throughput, fulfillment, substitution, rejection reasons, budget
    safety, determinism, audit replay, tamper detection, and peak memory.

Run:
    maturin build --release --out dist
    pip install dist/calybris-*.whl --force-reinstall
    python bindings/python/examples/novamart_benchmark.py
    python bindings/python/examples/novamart_benchmark.py --csv-out novamart.csv --json-out novamart.json
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import gc
import json
from pathlib import Path
import random
import statistics
import time
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - optional benchmark dependency
    psutil = None  # type: ignore[assignment]

from calybris import VerificationError
from calybris_commerce import (
    CAP_FRAGILE,
    CAP_HEAVY,
    CAP_REFRIGERATED,
    CAP_SAME_DAY,
    CAP_STANDARD,
    EcomEngine,
    OrderInput,
    REGION_TR_AEGEAN,
    REGION_TR_ANKARA,
    REGION_TR_BURSA,
    REGION_TR_CENTRAL,
    REGION_TR_EASTERN,
    REGION_TR_IST,
    REGION_TR_IZMIR,
    REGION_TR_ALL,
    SupplierPolicy,
    SupplierSpec,
)


ORDER_COUNT = 50_000
DETERMINISM_SAMPLE = 250
AUDIT_SAMPLE = 100
LATENCY_SAMPLE = 1_000

REASON_LABELS = {
    "budget_constraint": "Budget",
    "latency_constraint": "Latency",
    "non_positive_utility": "Utility",
    "confidence_hard_limit": "Confidence",
    "capability_constraint": "Capability",
    "region_constraint": "Region",
    "risk_hard_limit": "Risk",
    "risk_ceiling_constraint": "Risk ceiling",
    "quality_constraint": "Quality",
    "provider_constraint": "Provider",
    "no_enabled_model": "No enabled supplier",
}


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    max_return_risk_pct: float
    min_confidence_pct: float
    risk_multiplier_bps: int
    latency_cost_per_hour: int
    budget_scale: float


PROFILES = [
    PolicyProfile(
        name="strict",
        max_return_risk_pct=24.0,
        min_confidence_pct=72.0,
        risk_multiplier_bps=5_500,
        latency_cost_per_hour=10_800_000,
        budget_scale=0.88,
    ),
    PolicyProfile(
        name="medium",
        max_return_risk_pct=32.0,
        min_confidence_pct=62.0,
        risk_multiplier_bps=4_200,
        latency_cost_per_hour=3_600_000,
        budget_scale=1.00,
    ),
    PolicyProfile(
        name="relaxed",
        max_return_risk_pct=42.0,
        min_confidence_pct=55.0,
        risk_multiplier_bps=3_000,
        latency_cost_per_hour=3_600_000,
        budget_scale=1.18,
    ),
]


def supplier_catalog() -> list[SupplierSpec]:
    return [
        SupplierSpec(
            supplier_id=101,
            name="Istanbul Same-Day Fragile",
            reliability_pct=99.3,
            risk_tolerance_pct=38.0,
            sla_hours=4,
            shipping_cost_microunits=14_000_000,
            handling_cost_microunits=2_000_000,
            capabilities=CAP_SAME_DAY | CAP_FRAGILE,
            region_mask=REGION_TR_IST,
        ),
        SupplierSpec(
            supplier_id=102,
            name="Ankara Same-Day",
            reliability_pct=98.9,
            risk_tolerance_pct=40.0,
            sla_hours=5,
            shipping_cost_microunits=13_000_000,
            capabilities=CAP_SAME_DAY,
            region_mask=REGION_TR_ANKARA,
        ),
        SupplierSpec(
            supplier_id=103,
            name="Izmir Same-Day Fragile",
            reliability_pct=98.6,
            risk_tolerance_pct=39.0,
            sla_hours=6,
            shipping_cost_microunits=12_200_000,
            capabilities=CAP_SAME_DAY | CAP_FRAGILE,
            region_mask=REGION_TR_IZMIR | REGION_TR_AEGEAN,
        ),
        SupplierSpec(
            supplier_id=104,
            name="Bursa Same-Day",
            reliability_pct=98.4,
            risk_tolerance_pct=39.0,
            sla_hours=6,
            shipping_cost_microunits=11_800_000,
            capabilities=CAP_SAME_DAY,
            region_mask=REGION_TR_BURSA,
        ),
        SupplierSpec(
            supplier_id=201,
            name="NextDay Nationwide",
            reliability_pct=97.8,
            risk_tolerance_pct=50.0,
            sla_hours=24,
            shipping_cost_microunits=6_200_000,
            capabilities=CAP_FRAGILE | CAP_HEAVY,
            region_mask=REGION_TR_ALL,
        ),
        SupplierSpec(
            supplier_id=202,
            name="Economy Nationwide",
            reliability_pct=95.9,
            risk_tolerance_pct=64.0,
            sla_hours=72,
            shipping_cost_microunits=2_400_000,
            capabilities=CAP_HEAVY,
            region_mask=REGION_TR_ALL,
        ),
        SupplierSpec(
            supplier_id=203,
            name="Budget Nationwide",
            reliability_pct=94.7,
            risk_tolerance_pct=70.0,
            sla_hours=96,
            shipping_cost_microunits=1_800_000,
            region_mask=REGION_TR_ALL,
        ),
        SupplierSpec(
            supplier_id=301,
            name="ColdChain Metro",
            reliability_pct=98.2,
            risk_tolerance_pct=42.0,
            sla_hours=24,
            shipping_cost_microunits=10_800_000,
            capabilities=CAP_REFRIGERATED | CAP_FRAGILE,
            region_mask=REGION_TR_IST | REGION_TR_ANKARA | REGION_TR_IZMIR | REGION_TR_BURSA,
        ),
        SupplierSpec(
            supplier_id=302,
            name="ColdChain Economy",
            reliability_pct=96.5,
            risk_tolerance_pct=48.0,
            sla_hours=48,
            shipping_cost_microunits=7_400_000,
            capabilities=CAP_REFRIGERATED,
            region_mask=REGION_TR_ALL,
        ),
        SupplierSpec(
            supplier_id=401,
            name="Heavy Cargo",
            reliability_pct=96.4,
            risk_tolerance_pct=58.0,
            sla_hours=48,
            shipping_cost_microunits=8_500_000,
            handling_cost_microunits=4_000_000,
            capabilities=CAP_HEAVY | CAP_FRAGILE,
            region_mask=REGION_TR_ALL,
        ),
        SupplierSpec(
            supplier_id=501,
            name="Central Anatolia Regional",
            reliability_pct=96.8,
            risk_tolerance_pct=55.0,
            sla_hours=36,
            shipping_cost_microunits=4_800_000,
            region_mask=REGION_TR_CENTRAL | REGION_TR_ANKARA,
        ),
        SupplierSpec(
            supplier_id=502,
            name="Eastern Regional",
            reliability_pct=95.7,
            risk_tolerance_pct=62.0,
            sla_hours=60,
            shipping_cost_microunits=5_100_000,
            region_mask=REGION_TR_EASTERN,
        ),
    ]


def build_engine(profile: PolicyProfile) -> EcomEngine:
    builder = (
        SupplierPolicy(policy_epoch=20260701, catalog_epoch=17)
        .return_risk_limit(max_pct=profile.max_return_risk_pct)
        .confidence_floor(min_pct=profile.min_confidence_pct)
        .risk_sensitivity(multiplier_bps=profile.risk_multiplier_bps)
        .latency_cost(microunits_per_hour=profile.latency_cost_per_hour)
    )
    for supplier in supplier_catalog():
        builder.add_supplier(supplier)
    return EcomEngine(builder.build())


def capability_for_order(rng: random.Random, max_delivery_hours: int) -> int:
    roll = rng.random()
    if roll < 0.07:
        return CAP_REFRIGERATED
    if roll < 0.20:
        return CAP_FRAGILE
    if roll < 0.31:
        return CAP_HEAVY
    if max_delivery_hours <= 6 and roll < 0.55:
        return CAP_SAME_DAY
    return CAP_STANDARD


def generate_orders(profile: PolicyProfile, order_count: int) -> list[OrderInput]:
    rng = random.Random(20260701)
    regions = [
        REGION_TR_IST,
        REGION_TR_ANKARA,
        REGION_TR_IZMIR,
        REGION_TR_BURSA,
        REGION_TR_CENTRAL,
        REGION_TR_AEGEAN,
        REGION_TR_EASTERN,
        REGION_TR_ALL,
    ]
    weights = [0.32, 0.18, 0.14, 0.08, 0.09, 0.07, 0.05, 0.07]
    preferred_suppliers = [0, 0, 0, 101, 102, 201, 202, 301, 401]

    orders: list[OrderInput] = []
    for sequence in range(1, order_count + 1):
        same_day = rng.random() < 0.22
        max_delivery_hours = (
            rng.choice([4, 6, 24])
            if same_day
            else rng.choice([24, 48, 72, 0])
        )
        high_value = rng.random() < 0.20
        budget = int(rng.randint(3_000_000, 18_000_000) * profile.budget_scale)
        orders.append(
            OrderInput(
                order_id=f"NM-{sequence:07d}",
                order_sequence=sequence,
                requested_supplier_id=rng.choice(preferred_suppliers),
                order_value_microunits=rng.randint(
                    55_000_000,
                    1_400_000_000 if high_value else 340_000_000,
                ),
                budget_limit_microunits=budget,
                return_risk_pct=rng.betavariate(1.2, 18.0) * 100,
                confidence_pct=rng.uniform(58.0, 100.0),
                required_capabilities=capability_for_order(rng, max_delivery_hours),
                required_regions=rng.choices(regions, weights=weights)[0],
                minimum_reliability_pct=94.0,
                max_delivery_hours=max_delivery_hours,
            )
        )
    return orders


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * p))
    return ordered[index]


def rss_mb(process: Any | None = None) -> float | None:
    if psutil is None:
        return None
    process = process or psutil.Process()
    return process.memory_info().rss / (1024 * 1024)


def display_reason(reason: object) -> str:
    raw = str(reason)
    return REASON_LABELS.get(raw, raw.replace("_", " "))


def run_policy(profile: PolicyProfile, order_count: int) -> dict[str, object]:
    engine = build_engine(profile)
    orders = generate_orders(profile, order_count)

    engine.route_batch(orders[:100], audit=False)

    gc.collect()
    process = None if psutil is None else psutil.Process()
    mem_before = rss_mb(process)
    batch_started = time.perf_counter()
    batch = engine.route_batch(orders, audit=False)
    batch_results = batch.results
    batch_elapsed = time.perf_counter() - batch_started
    mem_after = rss_mb(process)
    rss_delta_mb = (
        None
        if mem_before is None or mem_after is None
        else max(0.0, mem_after - mem_before)
    )

    single_started = time.perf_counter()
    single_results = [engine.route_order(order, audit=False) for order in orders]
    single_elapsed = time.perf_counter() - single_started

    rng = random.Random(90210)
    sample_size = min(DETERMINISM_SAMPLE, len(orders))
    sample_indices = rng.sample(range(len(orders)), sample_size)
    deterministic = all(
        batch_results[index].status == single_results[index].status
        and batch_results[index].chosen_supplier_id == single_results[index].chosen_supplier_id
        and batch_results[index].estimated_cost_microunits
        == single_results[index].estimated_cost_microunits
        for index in sample_indices
    )

    latency_sample = orders[: min(LATENCY_SAMPLE, len(orders))]
    single_latency_us: list[float] = []
    for order in latency_sample:
        started_ns = time.perf_counter_ns()
        engine.route_order(order, audit=False)
        single_latency_us.append((time.perf_counter_ns() - started_ns) / 1_000)

    status_counts = Counter(result.status for result in batch_results)
    supplier_counts = Counter(
        result.chosen_supplier_id for result in batch_results if result.is_fulfilled
    )
    rejection_reasons = Counter(
        result.decision.reason for result in batch_results if result.is_rejected
    )
    substitution_pairs = Counter(
        (order.requested_supplier_id, result.chosen_supplier_id)
        for order, result in zip(orders, batch_results)
        if result.status == "substituted"
    )
    fulfilled_pairs = [
        (order, result)
        for order, result in zip(orders, batch_results)
        if result.is_fulfilled
    ]
    fulfilled_costs = [
        result.estimated_cost_microunits / 1_000_000 for _, result in fulfilled_pairs
    ]
    over_budget_count = sum(
        1
        for order, result in fulfilled_pairs
        if result.estimated_cost_microunits > order.budget_limit_microunits
    )

    audit_success = 0
    for order, _ in fulfilled_pairs[:AUDIT_SAMPLE]:
        audited = engine.route_order(order, audit=True)
        if audited.audit_bundle is not None and audited.audit_bundle.replay_valid:
            audit_success += 1

    tamper_detected = True
    if len(fulfilled_pairs) >= 2:
        first_order, _ = fulfilled_pairs[0]
        wrong_order, _ = fulfilled_pairs[1]
        original_decision = engine.prescribe_raw(first_order)
        try:
            engine.verified_audit_bundle_for_order(wrong_order, original_decision)
            tamper_detected = False
        except (VerificationError, Exception):
            tamper_detected = True

    return {
        "profile": profile.name,
        "fingerprint": engine.fingerprint,
        "orders": len(orders),
        "batch_ms": batch_elapsed * 1000,
        "batch_ops": len(orders) / batch_elapsed,
        "single_ms": single_elapsed * 1000,
        "single_ops": len(orders) / single_elapsed,
        "rss_delta_mb": rss_delta_mb,
        "accepted": status_counts["accepted"],
        "substituted": status_counts["substituted"],
        "rejected": status_counts["rejected"],
        "fulfillment_rate": (status_counts["accepted"] + status_counts["substituted"]) / len(orders),
        "substitution_rate": status_counts["substituted"] / len(orders),
        "avg_cost": statistics.mean(fulfilled_costs) if fulfilled_costs else 0.0,
        "p50_cost": percentile(fulfilled_costs, 0.50),
        "p95_cost": percentile(fulfilled_costs, 0.95),
        "single_p50_us": percentile(single_latency_us, 0.50),
        "single_p95_us": percentile(single_latency_us, 0.95),
        "over_budget": over_budget_count,
        "deterministic": deterministic,
        "determinism_sample": sample_size,
        "audit_success": audit_success,
        "audit_attempts": min(AUDIT_SAMPLE, len(fulfilled_pairs)),
        "tamper_detected": tamper_detected,
        "supplier_counts": supplier_counts,
        "rejection_reasons": rejection_reasons,
        "substitution_pairs": substitution_pairs,
    }


def format_optional_mb(value: object) -> str:
    if value is None:
        return "     n/a"
    return f"{float(value):>8.2f}"


def print_summary(rows: list[dict[str, object]], order_count: int) -> None:
    print("NovaMart Comprehensive Benchmark")
    print(f"Orders per profile: {order_count:,}")
    print(f"Supplier profiles: {len(supplier_catalog())}")
    print()
    print(
        "profile   batch_ops/s  single_ops/s  rss_mb  fulfill%  subst%  "
        "avg_TL  p95_TL  p50_us  p95_us  over_budget  audit  tamper"
    )
    for row in rows:
        print(
            f"{row['profile']:<8} "
            f"{row['batch_ops']:>11,.0f} "
            f"{row['single_ops']:>12,.0f} "
            f"{format_optional_mb(row['rss_delta_mb'])} "
            f"{row['fulfillment_rate'] * 100:>8.1f} "
            f"{row['substitution_rate'] * 100:>7.1f} "
            f"{row['avg_cost']:>7.2f} "
            f"{row['p95_cost']:>7.2f} "
            f"{row['single_p50_us']:>7.1f} "
            f"{row['single_p95_us']:>7.1f} "
            f"{row['over_budget']:>11} "
            f"{row['audit_success']:>3}/{row['audit_attempts']:<3} "
            f"{str(row['tamper_detected']):>6}"
        )
    print()


def print_details(rows: list[dict[str, object]]) -> None:
    for row in rows:
        print(f"Policy: {row['profile']} ({str(row['fingerprint'])[:12]}...)")
        print(
            f"  decisions: accepted={row['accepted']:,}, "
            f"substituted={row['substituted']:,}, rejected={row['rejected']:,}"
        )
        print("  top suppliers:")
        for supplier_id, count in row["supplier_counts"].most_common(5):
            print(f"    {supplier_id}: {count:,}")
        print("  top rejection reasons:")
        for reason, count in row["rejection_reasons"].most_common(5):
            print(f"    {display_reason(reason)}: {count:,}")
        print("  top substitutions:")
        for (requested, chosen), count in row["substitution_pairs"].most_common(5):
            print(f"    requested {requested} -> chosen {chosen}: {count:,}")
        print()


def compact_row(row: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"supplier_counts", "rejection_reasons", "substitution_pairs"}
    }


def json_ready(row: dict[str, object]) -> dict[str, Any]:
    output = compact_row(row)
    output["supplier_counts"] = dict(row["supplier_counts"].most_common())
    output["rejection_reasons"] = {
        display_reason(reason): count
        for reason, count in row["rejection_reasons"].most_common()
    }
    output["substitution_pairs"] = [
        {"requested": requested, "chosen": chosen, "count": count}
        for (requested, chosen), count in row["substitution_pairs"].most_common()
    ]
    return output


def write_json(path: str, rows: list[dict[str, object]], order_count: int) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "benchmark": "novamart",
        "orders_per_profile": order_count,
        "supplier_profiles": len(supplier_catalog()),
        "profiles": [json_ready(row) for row in rows],
    }
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def write_csv(path: str, rows: list[dict[str, object]]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(compact_row(rows[0]).keys())
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(compact_row(row))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--orders", type=int, default=ORDER_COUNT)
    parser.add_argument("--json-out", default="")
    parser.add_argument("--csv-out", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = [run_policy(profile, args.orders) for profile in PROFILES]
    print_summary(rows, args.orders)
    print_details(rows)
    if args.json_out:
        write_json(args.json_out, rows, args.orders)
        print(f"Wrote JSON: {args.json_out}")
    if args.csv_out:
        write_csv(args.csv_out, rows)
        print(f"Wrote CSV: {args.csv_out}")


if __name__ == "__main__":
    main()
