//! Production LLM gateway reference
//!
//! This example is intentionally boring: every boundary verifies before writing.
//!
//! Demonstrates the safe path:
//! config → builder → prescribe → verify → budget → verified WAL → checkpoint_with_wal → recovery
//!
//! ```bash
//! # Both values are 64 hex characters loaded from your KMS in production.
//! CALYBRIS_WAL_HMAC_KEY_HEX=... \
//! CALYBRIS_RECEIPT_SIGNING_KEY_HEX=... \
//! cargo run --example production_gateway --features full
//! ```

use calybris_core::budget::BudgetEngine;
use calybris_core::builder::{InputBuilder, ModelBuilder, PolicyBuilder};
use calybris_core::config::EngineConfig;
use calybris_core::digest::bytes_to_hex;
use calybris_core::finance::{certify_ledger, ledger_digest, prove_conservation};
use calybris_core::persistence::{
    checkpoint_with_wal, recovery_plan_keyed_against_anchor, restore, save_wal_anchor,
};
use calybris_core::receipt::{
    issue_receipt, sign_receipt, verify_receipt, verify_receipt_signature, verify_receipt_state,
    verify_receipt_wal, ReceiptAnchors, ReceiptState, ReceiptWal,
};
use calybris_core::state::StateChain;
use calybris_core::verify::{verify_decision, VerifyResult};
use calybris_core::wal::WalWriter;

fn load_hex_env<const N: usize>(name: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let value = std::env::var(name)?;
    if value.len() != N * 2 {
        return Err(format!("{name} must contain exactly {} hex characters", N * 2).into());
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = nibble(pair[0])
            .ok_or_else(|| format!("{name} contains invalid hex at offset {}", index * 2))?;
        let low = nibble(pair[1])
            .ok_or_else(|| format!("{name} contains invalid hex at offset {}", index * 2 + 1))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn now_epoch_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Calybris — Production Gateway Simulation");
    println!("=========================================\n");

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

    let budget = BudgetEngine::new();
    config.ensure_tenant(&budget, "team-platform", 100_000_000);
    config.ensure_tenant(&budget, "team-support", 50_000_000);
    config.ensure_tenant(&budget, "team-compliance", 200_000_000);
    println!("[budget] 3 tenants initialized (exposure cap from config)\n");

    let wal_key = load_hex_env::<32>("CALYBRIS_WAL_HMAC_KEY_HEX")?;
    let receipt_key_bytes = load_hex_env::<32>("CALYBRIS_RECEIPT_SIGNING_KEY_HEX")?;
    let receipt_signing_key = ed25519_dalek::SigningKey::from_bytes(&receipt_key_bytes);

    let wal_path = std::path::PathBuf::from("production_gateway_demo.jsonl");
    let anchor_path = std::path::PathBuf::from("production_gateway_anchor.json");
    let _ = std::fs::remove_file(&wal_path);
    let mut wal = WalWriter::open_keyed(&wal_path, &wal_key)?;
    let mut state_chain = StateChain::genesis(&ledger_digest(&budget.snapshot()));

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

        let (decision, trace) = snapshot.prescribe_with_trace_checked(input)?;

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
        let transition = state_chain.advance(&ledger_digest(&budget.snapshot()));

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
        let entry =
            wal.append_verified_audited(&snapshot, input, decision, scenario.to_string())?;
        let mut receipt = issue_receipt(
            &snapshot,
            input,
            &decision,
            ReceiptAnchors {
                state: Some(ReceiptState {
                    step: transition.step,
                    state_digest_before_hex: bytes_to_hex(&transition.digest_before),
                    state_digest_after_hex: bytes_to_hex(&transition.digest_after),
                }),
                wal: Some(ReceiptWal {
                    sequence: entry.sequence,
                    entry_hash: entry.entry_hash.clone(),
                }),
            },
        )?;
        sign_receipt(
            &mut receipt,
            &receipt_signing_key,
            "production-gateway",
            now_epoch_ms()?,
        )?;
        verify_receipt(&receipt, &snapshot, input, &decision)?;
        verify_receipt_signature(&receipt, Some(&receipt_signing_key.verifying_key()))?;
        verify_receipt_state(
            &receipt,
            transition.step,
            &bytes_to_hex(&transition.digest_before),
            &bytes_to_hex(&transition.digest_after),
        )?;
        verify_receipt_wal(&receipt, entry.sequence, &entry.entry_hash)?;
    }
    wal.flush_and_sync()?;
    let wal_anchor = wal.anchor();
    save_wal_anchor(&wal_anchor, &anchor_path)?;
    println!("[wal] {} entries written\n", wal.sequence());

    let _proof = prove_conservation(&budget)?;
    let cert = certify_ledger(&budget);
    println!("[finance] conservation: balanced");
    println!(
        "[finance] committed: {} microcents",
        cert.total_committed_microcents
    );
    println!("[finance] digest: {}…\n", &cert.ledger_digest_hex[..16]);

    let snap_path = std::path::PathBuf::from("production_gateway_snapshot.json");
    let snap = checkpoint_with_wal(&budget, &snap_path, wal.sequence())?;
    println!(
        "[checkpoint] saved {} tenants, wal_watermark={} to {}",
        snap.tenants.len(),
        snap.wal_high_watermark.unwrap_or(0),
        snap_path.display()
    );

    let plan = recovery_plan_keyed_against_anchor(&snap_path, &wal_path, &wal_key, &wal_anchor)?;
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

    // Cleanup demo artifacts after releasing the single-writer lock.
    drop(wal);
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&snap_path);
    let _ = std::fs::remove_file(&anchor_path);

    println!("\nFull pipeline: config -> checked prescribe -> verify -> budget/state -> keyed WAL -> signed receipt -> external anchor -> anchored recovery");
    Ok(())
}
