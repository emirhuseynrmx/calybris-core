//! Production-like LLM gateway simulation
//!
//! Demonstrates: config → builder → prescribe → verify → budget → WAL → checkpoint
//! in a realistic multi-tenant scenario with 6 models and 3 tenants.
//!
//! ```bash
//! cargo run --example production_gateway --features wal
//! ```

use calybris_core::budget::BudgetEngine;
use calybris_core::builder::{InputBuilder, ModelBuilder, PolicyBuilder};
use calybris_core::config::EngineConfig;
use calybris_core::finance::{certify_ledger, prove_conservation};
use calybris_core::persistence::{checkpoint, restore};
use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
use calybris_core::wal::WalWriter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Calybris — Production Gateway Simulation");
    println!("=========================================\n");

    // ── 1. Config ──
    let config = EngineConfig::new()
        .latency_penalty(3)
        .hard_risk_limit(9_500)
        .minimum_confidence(6_000)
        .default_exposure_cap(500_000_000);
    config.validate()?;
    println!(
        "[config] latency_penalty={}µ/ms, risk_limit={}bps",
        config.latency_penalty_microunits_per_ms, config.hard_risk_limit_bps
    );

    // ── 2. Build catalog with builders ──
    let snapshot = PolicyBuilder::new(config)
        .epochs(1, 1)
        .model(
            ModelBuilder::new(1, 0)
                .quality(9500)
                .latency(450)
                .cost(250, 1000)
                .build(),
        ) // gpt-4o
        .model(
            ModelBuilder::new(2, 0)
                .quality(7500)
                .latency(120)
                .cost(15, 60)
                .build(),
        ) // gpt-4o-mini
        .model(
            ModelBuilder::new(3, 1)
                .quality(9200)
                .latency(380)
                .cost(300, 1500)
                .build(),
        ) // claude-sonnet
        .model(
            ModelBuilder::new(4, 1)
                .quality(7000)
                .latency(90)
                .cost(25, 125)
                .build(),
        ) // claude-haiku
        .model(
            ModelBuilder::new(5, 2)
                .quality(8800)
                .latency(320)
                .cost(125, 500)
                .build(),
        ) // gemini-pro
        .model(
            ModelBuilder::new(6, 2)
                .quality(7200)
                .latency(80)
                .cost(8, 30)
                .build(),
        ) // gemini-flash
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

    // ── 3. Budget engine with 3 tenants ──
    let budget = BudgetEngine::new();
    budget.ensure_tenant("team-platform", 100_000_000);
    budget.ensure_tenant("team-support", 50_000_000);
    budget.ensure_tenant("team-compliance", 200_000_000);
    budget.set_max_reserved_microcents("team-support", 10_000_000);
    println!("[budget] 3 tenants initialized\n");

    // ── 4. WAL ──
    let wal_path = std::path::PathBuf::from("production_gateway_demo.jsonl");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal = WalWriter::open(&wal_path)?;

    // ── 5. Process requests ──
    let requests = vec![
        (
            "team-platform",
            "compliance review",
            1,
            1,
            4000,
            2000,
            500_000,
            2000,
            9000,
            9000,
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
        assert_eq!(
            verify_decision(&snapshot, input, &decision),
            VerifyResult::Valid
        );

        let bundle = audit_bundle(&snapshot, input, &decision);
        assert!(bundle.replay_valid);

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

        wal.append_audited(&snapshot, input, decision, scenario.to_string())?;
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

    // ── 7. Checkpoint ──
    let snap_path = std::path::PathBuf::from("production_gateway_snapshot.json");
    let snap = checkpoint(&budget, &snap_path)?;
    println!(
        "[checkpoint] saved {} tenants to {}",
        snap.tenants.len(),
        snap_path.display()
    );

    // ── 8. Simulate crash recovery ──
    let fresh_budget = BudgetEngine::new();
    let restored = restore(&fresh_budget, &snap_path)?;
    println!(
        "[recovery] restored {} tenants from checkpoint",
        restored.tenants.len()
    );
    for t in &restored.tenants {
        println!(
            "  {} → remaining={}, committed={}",
            t.tenant_id, t.remaining_microcents, t.committed_microcents
        );
    }

    // Cleanup
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&snap_path);

    println!("\n✓ Full pipeline: config → build → prescribe → verify → budget → WAL → checkpoint → recovery");
    Ok(())
}
