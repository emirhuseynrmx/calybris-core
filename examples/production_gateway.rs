//! Production-like LLM gateway simulation
//!
//! This example is intentionally boring: every boundary verifies before writing.
//!
//! Demonstrates the safe path:
//! config → builder → prescribe → verify → budget → verified WAL → checkpoint_with_wal → recovery
//!
//! ```bash
//! cargo run --example production_gateway --features wal
//! ```

use calybris_core::budget::BudgetEngine;
use calybris_core::builder::{InputBuilder, ModelBuilder, PolicyBuilder};
use calybris_core::config::EngineConfig;
use calybris_core::finance::{certify_ledger, prove_conservation};
use calybris_core::persistence::{checkpoint_with_wal, recovery_plan, restore};
use calybris_core::verify::{verify_decision, VerifyResult};
use calybris_core::wal::WalWriter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Calybris — Production Gateway Simulation");
    println!("=========================================\n");

    // ── 1. Config ──
    let config = EngineConfig::new()
        .latency_penalty(3)
        .hard_risk_limit(9_500)
        .minimum_confidence(6_000)
        .default_exposure_cap(10_000_000);
    config.validate()?;
    println!(
        "[config] latency_penalty={}µ/ms, risk_limit={}bps, exposure_cap={}µ",
        config.latency_penalty_microunits_per_ms,
        config.hard_risk_limit_bps,
        config.default_exposure_cap_microcents
    );

    // ── 2. Build catalog with builders ──
    let snapshot = PolicyBuilder::new(config.clone())
        .epochs(1, 1)
        .model(
            ModelBuilder::new(1, 0)
                .quality(9500)
                .latency(450)
                .cost(250, 1000)
                .build(),
        )
        .model(
            ModelBuilder::new(2, 0)
                .quality(7500)
                .latency(120)
                .cost(15, 60)
                .build(),
        )
        .model(
            ModelBuilder::new(3, 1)
                .quality(9200)
                .latency(380)
                .cost(300, 1500)
                .build(),
        )
        .model(
            ModelBuilder::new(4, 1)
                .quality(7000)
                .latency(90)
                .cost(25, 125)
                .build(),
        )
        .model(
            ModelBuilder::new(5, 2)
                .quality(8800)
                .latency(320)
                .cost(125, 500)
                .build(),
        )
        .model(
            ModelBuilder::new(6, 2)
                .quality(7200)
                .latency(80)
                .cost(8, 30)
                .build(),
        )
        .build()?;

    let model_names = [
        "gpt-4o",
        "gpt-4o-mini",
        "claude-sonnet",
        "claude-haiku",
        "gemini-pro",
        "gemini-flash",
    ];
    println!("[catalog] {} models loaded\n", snapshot.models().len());

    // ── 3. Budget engine with config-driven tenant init ──
    let budget = BudgetEngine::new();
    config.ensure_tenant(&budget, "team-platform", 100_000_000);
    config.ensure_tenant(&budget, "team-support", 50_000_000);
    config.ensure_tenant(&budget, "team-compliance", 200_000_000);
    println!("[budget] 3 tenants initialized (exposure cap from config)\n");

    // ── 4. WAL ──
    let wal_path = std::path::PathBuf::from("production_gateway_demo.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal = WalWriter::open(&wal_path)?;

    // ── 5. Process requests ──
    let requests = vec![
        (
            "team-platform",
            "compliance review",
            1u64,
            1u32,
            4000u32,
            2000u32,
            500_000i64,
            2000u16,
            9000u16,
            9000u16,
        ),
        (
            "team-support",
            "ticket response",
            2,
            1,
            500,
            200,
            10_000,
            500,
            9000,
            6000,
        ),
        (
            "team-platform",
            "code generation",
            3,
            3,
            2000,
            1000,
            200_000,
            1000,
            8500,
            8000,
        ),
        (
            "team-compliance",
            "audit summary",
            4,
            1,
            8000,
            4000,
            800_000,
            1500,
            9500,
            9200,
        ),
        (
            "team-support",
            "faq answer",
            5,
            6,
            200,
            100,
            5_000,
            300,
            9000,
            5000,
        ),
    ];

    for (tenant, scenario, seq, model_id, inp_tok, out_tok, value, risk, conf, min_q) in &requests {
        let input = InputBuilder::new(*seq, *model_id)
            .tokens(*inp_tok, *out_tok)
            .business_value(*value)
            .budget_limit(50_000_000)
            .risk(*risk, *conf)
            .minimum_quality(*min_q)
            .max_latency(1000)
            .build();

        let (decision, trace) = snapshot.prescribe_with_trace(input);

        // Verify before anything else
        assert_eq!(
            verify_decision(&snapshot, input, &decision),
            VerifyResult::Valid
        );

        // Budget reservation
        let cost = decision.estimated_cost_microunits as i64;
        if decision.is_executable() && cost > 0 {
            let (_res, id) = budget.try_reserve(tenant, cost);
            if let Some(id) = id {
                budget.commit(id, cost);
            }
        }

        let selected_name = if decision.selected_model_id > 0 && decision.selected_model_id <= 6 {
            model_names[(decision.selected_model_id - 1) as usize]
        } else {
            "none"
        };

        println!("  [{tenant}] {scenario}");
        println!(
            "    action={}, selected={}, reason={}",
            decision.action, selected_name, decision.reason
        );
        println!(
            "    cost={}µ, utility={}µ, eligible={}/{}",
            decision.estimated_cost_microunits,
            decision.expected_utility_microunits,
            decision.eligible_models,
            decision.evaluated_models
        );
        if trace.rejections.quality > 0 || trace.rejections.budget > 0 {
            println!(
                "    rejections: quality={} budget={} latency={}",
                trace.rejections.quality, trace.rejections.budget, trace.rejections.latency
            );
        }
        println!();

        // Fail-closed WAL append — invalid decisions never enter the log
        wal.append_verified_audited(&snapshot, input, decision, scenario.to_string())?;
    }
    wal.flush_and_sync()?;
    println!("[wal] {} entries written\n", wal.sequence());

    // ── 6. Financial proof ──
    let _proof = prove_conservation(&budget)?;
    let cert = certify_ledger(&budget);
    println!("[finance] conservation: balanced");
    println!(
        "[finance] committed: {} microcents",
        cert.total_committed_microcents
    );
    println!("[finance] digest: {}…\n", &cert.ledger_digest_hex[..16]);

    // ── 7. Checkpoint with WAL high-watermark ──
    let snap_path = std::path::PathBuf::from("production_gateway_snapshot.json");
    let snap = checkpoint_with_wal(&budget, &snap_path, wal.sequence())?;
    println!(
        "[checkpoint] saved {} tenants, wal_watermark={} to {}",
        snap.tenants.len(),
        snap.wal_high_watermark.unwrap_or(0),
        snap_path.display()
    );

    // ── 8. Simulate crash recovery ──
    let plan = recovery_plan(&snap_path, &wal_path)?;
    println!(
        "[recovery] plan: {} total WAL entries, {} to replay (watermark={})",
        plan.total_wal_entries, plan.entries_to_replay, plan.wal_high_watermark
    );

    let fresh_budget = BudgetEngine::new();
    let restored = restore(&fresh_budget, &snap_path)?;
    println!(
        "[recovery] restored {} tenants from checkpoint",
        restored.tenants.len()
    );
    for t in &restored.tenants {
        println!(
            "  {} -> remaining={}, committed={}",
            t.tenant_id, t.remaining_microcents, t.committed_microcents
        );
    }

    // Cleanup
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&snap_path);

    println!("\nFull pipeline: config -> build -> prescribe -> verify -> budget -> verified WAL -> checkpoint_with_wal -> recovery");
    Ok(())
}
