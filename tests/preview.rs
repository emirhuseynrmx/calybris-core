//! The preview features working together, and the owned budget reservation.
//!
//! The loop the preview features exist for: a policy decides, a keyed draw
//! occasionally takes a near-best alternative and records how likely that was,
//! the outcome comes back as an ordinary `Outcome`, and an off-policy estimate
//! then says what a *different* policy would have earned — without ever
//! running it.

#![cfg(feature = "preview")]

use calybris_core::budget::{BudgetEngine, BudgetSettlement};
use calybris_core::exploration::{explore, verify, ExplorationConfig};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, verify_consistency, verify_inclusion, TreeHead,
};
use calybris_core::ope::{estimate, evaluate, evaluate_exact, LoggedChoice, OpeError, Propensity};
use calybris_core::outcome::{Observation, Outcome};

const KEY: [u8; 32] = [42; 32];

#[cfg(feature = "wal")]
#[test]
fn a_cached_wal_tree_proves_prefixes_and_refuses_corruption_or_wrong_key() {
    use calybris_core::merkle::{leaf_from_entry_hash, MerkleTree};
    use calybris_core::wal::WalWriter;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("decisions.jsonl");
    let mut writer = WalWriter::<u64>::open_keyed(&path, &KEY).unwrap();
    let mut leaves = Vec::new();
    for n in 0..129 {
        let entry = writer.append(n).unwrap();
        leaves.push(leaf_hash(&leaf_from_entry_hash(&entry.entry_hash).unwrap()));
    }
    writer.flush_and_sync().unwrap();
    drop(writer);
    let tree = MerkleTree::from_verified_wal(&path, Some(&KEY)).unwrap();
    assert_eq!(tree.len(), 129);
    for size in [1, 17, 64, 128, 129] {
        let head = tree.head(size).unwrap();
        let proof = tree.inclusion_proof(size - 1, size).unwrap();
        verify_inclusion(&head, size - 1, &leaves[size as usize - 1], &proof).unwrap();
        if size > 1 {
            verify_consistency(
                &tree.head(1).unwrap(),
                &head,
                &tree.consistency_proof(1, size).unwrap(),
            )
            .unwrap();
        }
    }
    assert!(MerkleTree::from_verified_wal(&path, Some(&[99; 32])).is_err());
    let changed = std::fs::read_to_string(&path)
        .unwrap()
        .replacen("\"data\":64", "\"data\":65", 1);
    std::fs::write(&path, changed).unwrap();
    assert!(MerkleTree::from_verified_wal(&path, Some(&KEY)).is_err());
}

fn model(id: u32, quality: u16) -> KernelModel {
    KernelModel {
        model_id: id,
        provider_id: 0,
        quality_bps: quality,
        risk_ceiling_bps: 10_000,
        enabled: 1,
        p95_latency_ms: 10,
        capabilities: 0,
        region_mask: ALL_REGIONS,
        input_cost_microunits_per_million_tokens: 1_000,
        output_cost_microunits_per_million_tokens: 1_000,
    }
}

fn input(seq: u64) -> KernelInput {
    KernelInput {
        request_sequence: seq,
        requested_model_id: 1,
        input_tokens: 100,
        output_tokens: 100,
        business_value_microunits: 10_000_000,
        budget_limit_microunits: 1_000_000_000,
        risk_bps: 0,
        confidence_bps: 10_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        required_capabilities: 0,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

/// Model 1 ranks first but, in this made-up world, succeeds 60% of the time;
/// model 2 ranks a close second and succeeds 90% of the time. The logging
/// policy explores 30% of requests between them. A target policy that ranks
/// model 2 first should be estimated near 0.9, the logger's own ranking near 0.6.
#[test]
fn exploration_logs_let_an_estimate_score_a_policy_that_never_ran() {
    let logger =
        PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000), model(2, 8_990)])
            .unwrap();
    let target =
        PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 8_990), model(2, 9_000)])
            .unwrap();
    let cfg = ExplorationConfig {
        rate_bps: 3_000,
        window_microunits: 1_000_000,
    };

    let mut logs = Vec::new();
    for seq in 0..40_000_u64 {
        let x = input(seq);
        let record = explore(&logger, x, cfg, &KEY).unwrap();
        verify(&logger, x, &KEY, &record).unwrap();
        // Deterministic "world": success decided by a hash of the sequence.
        let u = (seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 11) % 1_000;
        let succeeded = match record.acted_model_id {
            1 => u < 600,
            _ => u < 900,
        };
        let mut outcome = Outcome::applied(
            &logger,
            &x,
            &record.decision,
            seq,
            Observation {
                succeeded: Some(succeeded),
                ..Observation::default()
            },
        );
        outcome.selection = record.selection().unwrap();
        outcome.validate().unwrap();
        logs.push((x, outcome));
    }
    let reward = |o: &Outcome| o.observation.succeeded.map(|s| if s { 1.0 } else { 0.0 });

    let for_target = evaluate(&target, &logs, reward, None).unwrap();
    assert_eq!(for_target.unsupported, 0);
    assert!((for_target.ips - 0.9).abs() < 0.03, "target {for_target:?}");
    assert!(for_target.ips_ci95.0 < 0.9 && 0.9 < for_target.ips_ci95.1 + 0.01);

    let for_logger = evaluate(&logger, &logs, reward, None).unwrap();
    assert!((for_logger.ips - 0.6).abs() < 0.03, "logger {for_logger:?}");
}

#[test]
fn without_exploration_the_estimate_says_it_cannot_answer() {
    let logger =
        PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000), model(2, 8_990)])
            .unwrap();
    let target =
        PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 8_990), model(2, 9_000)])
            .unwrap();
    let logs: Vec<_> = (0..100)
        .map(|seq| {
            let x = input(seq);
            let d = logger.prescribe(x);
            (
                x,
                Outcome::applied(
                    &logger,
                    &x,
                    &d,
                    seq,
                    Observation {
                        succeeded: Some(true),
                        ..Observation::default()
                    },
                ),
            )
        })
        .collect();
    let e = evaluate(
        &target,
        &logs,
        |o| o.observation.succeeded.map(|s| if s { 1.0 } else { 0.0 }),
        None,
    )
    .unwrap();
    assert_eq!(
        e.unsupported, 100,
        "every record is a choice the log could never have made"
    );
}

#[test]
fn an_outcome_paired_with_the_wrong_request_is_excluded() {
    let p = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000)]).unwrap();
    let x = input(1);
    let d = p.prescribe(x);
    let o = Outcome::applied(
        &p,
        &x,
        &d,
        1,
        Observation {
            succeeded: Some(true),
            ..Observation::default()
        },
    );
    let e = evaluate(&p, &[(input(2), o), (x, o)], |_| Some(1.0), None).unwrap();
    assert_eq!(e.used, 1);
    assert_eq!(e.excluded, 1);
}

#[test]
fn a_decision_log_proves_one_record_and_its_own_history() {
    // Leaves are record hashes; any 32 bytes stand in for a WAL entry hash here.
    let records: Vec<[u8; 32]> = (0..25_u8).map(|i| [i; 32]).collect();
    let hashed: Vec<_> = records.iter().map(|r| leaf_hash(r)).collect();
    let yesterday = TreeHead::of(&records[..17]);
    let today = TreeHead::of(&records);
    let proof = inclusion_proof(&hashed, 9).unwrap();
    verify_inclusion(&today, 9, &hashed[9], &proof).unwrap();
    let proof = consistency_proof(&hashed, 17).unwrap();
    verify_consistency(&yesterday, &today, &proof).unwrap();
}

#[test]
fn an_owned_reservation_settles_once_and_conserves() {
    let engine = BudgetEngine::new();
    engine.ensure_tenant("t", 1_000);
    let r = engine.reserve_owned("t", 300).unwrap();
    assert_eq!(r.amount_microcents(), 300);
    assert!(matches!(
        r.commit(200),
        Ok(BudgetSettlement::Committed { .. })
    ));
    assert_eq!(engine.active_reservations(), 0);
    assert_eq!(engine.remaining_microcents("t"), Some(800));
    assert!(engine.verify_conservation() == calybris_core::budget::ConservationStatus::Balanced);

    let r = engine.reserve_owned("t", 100).unwrap();
    assert!(matches!(r.release(), BudgetSettlement::Released { .. }));
    assert_eq!(engine.remaining_microcents("t"), Some(800));
}

#[test]
fn a_dropped_reservation_keeps_its_hold_rather_than_refunding() {
    let engine = BudgetEngine::new();
    engine.ensure_tenant("t", 1_000);
    {
        let _r = engine.reserve_owned("t", 400).unwrap();
    }
    assert_eq!(engine.active_reservations(), 1);
    assert_eq!(engine.remaining_microcents("t"), Some(600));
    assert!(engine.verify_conservation() == calybris_core::budget::ConservationStatus::Balanced);
}

#[test]
fn an_overrun_hands_the_reservation_back_instead_of_losing_it() {
    let engine = BudgetEngine::new();
    engine.ensure_tenant("t", 500);
    let r = engine.reserve_owned("t", 400).unwrap();
    let (settlement, r) = r.commit(10_000).unwrap_err();
    assert!(matches!(settlement, BudgetSettlement::Overrun { .. }));
    assert!(matches!(r.release(), BudgetSettlement::Released { .. }));
    assert_eq!(engine.active_reservations(), 0);
    assert_eq!(engine.remaining_microcents("t"), Some(500));
}

#[test]
fn a_refused_reservation_is_an_error_carrying_the_reason() {
    let engine = BudgetEngine::new();
    engine.ensure_tenant("t", 50);
    assert!(engine.reserve_owned("t", 100).is_err());
    assert!(engine.reserve_owned("missing", 1).is_err());
}

#[test]
fn a_persons_choice_and_a_missing_reward_are_excluded_not_defaulted() {
    use calybris_core::outcome::Selection;
    let p = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000)]).unwrap();
    let x = input(1);
    let d = p.prescribe(x);
    let observed = Observation {
        succeeded: Some(true),
        ..Observation::default()
    };
    let mut human = Outcome::applied(&p, &x, &d, 1, observed);
    human.selection = Selection::human(1);
    let silent = Outcome::applied(
        &p,
        &x,
        &d,
        2,
        Observation {
            realized_latency_ms: Some(5),
            ..Observation::default()
        },
    );
    let counted = Outcome::applied(&p, &x, &d, 3, observed);
    let reward = |o: &Outcome| o.observation.succeeded.map(|s| if s { 1.0 } else { 0.0 });
    let e = evaluate(&p, &[(x, human), (x, silent), (x, counted)], reward, None).unwrap();
    assert_eq!((e.used, e.excluded), (1, 2));
}

#[test]
fn a_reservation_reports_itself_and_can_be_handed_over_by_id() {
    let engine = BudgetEngine::new();
    engine.ensure_tenant("t", 1_000);
    let r = engine.reserve_owned("t", 250).unwrap();
    let id = r.id();
    let shown = format!("{r:?}");
    assert!(
        shown.contains("Reservation") && shown.contains("250"),
        "{shown}"
    );
    assert_eq!(r.into_id(), id);
    assert_eq!(
        engine.active_reservations(),
        1,
        "handing over the id keeps the hold"
    );
    assert!(matches!(
        engine.release(id),
        BudgetSettlement::Released { .. }
    ));
    assert_eq!(engine.active_reservations(), 0);
}

#[test]
fn a_target_that_refuses_the_request_earns_nothing_for_it() {
    // The target's hard risk limit sits below the request's risk, so it would
    // select nothing; that record is used, valued at zero, and not unsupported.
    let logger = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000)]).unwrap();
    let target = PolicySnapshot::try_new(1, 1, 100, 0, 0, 0, vec![model(1, 9_000)]).unwrap();
    let x = KernelInput {
        risk_bps: 500,
        ..input(1)
    };
    let d = logger.prescribe(x);
    let o = Outcome::applied(
        &logger,
        &x,
        &d,
        1,
        Observation {
            succeeded: Some(true),
            ..Observation::default()
        },
    );
    let e = evaluate(&target, &[(x, o)], |_| Some(1.0), None).unwrap();
    assert_eq!((e.used, e.matched, e.unsupported), (1, 0, 0));
    assert_eq!(e.ips, 0.0);
}

/// The review finding: `Selection` holds a propensity in whole basis points,
/// never below one. At a 1 bp exploration rate over 22 near-best candidates
/// an alternative's real probability is a small fraction of a basis point, so
/// the rounded weight undercounts it by a factor of about twenty. Only the
/// exact fraction, carried from the exploration record, weighs it correctly.
#[test]
fn at_one_basis_point_over_22_candidates_only_the_exact_propensity_weighs_correctly() {
    let models: Vec<_> = (1..=22_u16)
        .map(|id| model(u32::from(id), 9_000 - id))
        .collect();
    let logger = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, models.clone()).unwrap();
    let cfg = ExplorationConfig {
        rate_bps: 1,
        window_microunits: 1_000_000_000,
    };
    let (x, record) = (0..5_000_000_u64)
        .map(|seq| {
            let x = input(seq);
            (x, explore(&logger, x, cfg, &KEY).unwrap())
        })
        .find(|(_, r)| r.explored)
        .expect("a 1 bp draw comes up within a few tens of thousands of requests");
    assert_eq!(record.window_size, 22);
    let exact = record.propensity().unwrap();
    let selection = record.selection().unwrap();
    assert_eq!(
        selection.propensity_bps,
        Some(1),
        "recorded as one basis point"
    );
    assert!(exact.weight() > 20.0 * 10_000.0, "{exact:?}");

    // A target policy that always takes the candidate the log explored.
    let target_models: Vec<_> = models
        .iter()
        .map(|m| {
            let mut m = *m;
            if m.model_id == record.acted_model_id {
                m.quality_bps = 9_500;
            }
            m
        })
        .collect();
    let target = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, target_models).unwrap();
    let mut outcome = Outcome::applied(
        &logger,
        &x,
        &record.decision,
        1,
        Observation {
            succeeded: Some(true),
            ..Observation::default()
        },
    );
    outcome.selection = selection;
    outcome.validate().unwrap();

    let rounded = evaluate(&target, &[(x, outcome)], |_| Some(1.0), None).unwrap();
    let precise = evaluate_exact(&target, &[(x, outcome, exact)], |_| Some(1.0), None).unwrap();
    assert_eq!(rounded.max_weight, 10_000.0);
    assert!((precise.max_weight - exact.weight()).abs() < 1e-6);
    assert!(precise.max_weight / rounded.max_weight > 20.0);

    // An exact propensity that is not the one the outcome recorded is refused.
    assert_eq!(
        evaluate_exact(
            &target,
            &[(x, outcome, Propensity::ONE)],
            |_| Some(1.0),
            None
        ),
        Err(OpeError::NoUsableRecords)
    );
}

/// 22 near-best candidates of falling quality, all inside any window.
fn twenty_two() -> Vec<KernelModel> {
    (1..=22_u16)
        .map(|id| model(u32::from(id), 9_000 - id))
        .collect()
}

fn wide(rate_bps: u16) -> ExplorationConfig {
    ExplorationConfig {
        rate_bps,
        window_microunits: 1_000_000_000,
    }
}

/// The recorded propensity is what the draw actually does: over many
/// requests each candidate is acted on at the rate its record claims, every
/// record states the formula's fraction exactly, and the fractions of the 22
/// candidates add up to one.
#[test]
fn recorded_propensities_are_the_frequencies_the_draw_produces() {
    let logger = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, twenty_two()).unwrap();
    let rate = 2_000_u64;
    let (k, den) = (22_u64, 10_000 * 22);
    let winner_num = (10_000 - rate) * k + rate;
    assert_eq!(winner_num + (k - 1) * rate, den, "the fractions sum to one");

    let n = 60_000_u64;
    let mut counts = [0_u64; 23];
    for seq in 0..n {
        let r = explore(&logger, input(seq), wide(rate as u16), &KEY).unwrap();
        let p = r.propensity().unwrap();
        let expected = if r.acted_model_id == 1 {
            winner_num
        } else {
            rate
        };
        assert_eq!(
            (p.numerator(), p.denominator()),
            (expected, den),
            "seq {seq}"
        );
        assert_eq!(r.selection().unwrap().propensity_bps, Some(p.to_bps()));
        counts[r.acted_model_id as usize] += 1;
    }
    for (id, &count) in counts.iter().enumerate().skip(1) {
        let p = if id == 1 { winner_num } else { rate } as f64 / den as f64;
        let mean = n as f64 * p;
        let sd = (n as f64 * p * (1.0 - p)).sqrt();
        assert!(
            (count as f64 - mean).abs() < 5.0 * sd,
            "candidate {id}: {count} draws, {mean:.0} ± {sd:.0} expected"
        );
    }
}

/// The acceptance test for the exact propensity. A population in which each
/// candidate appears exactly as often as its logged probability says, so an
/// unbiased estimator must return the true value exactly, with no sampling
/// noise to hide behind. At a 10 bp rate over 22 candidates an alternative's
/// true probability is 0.45 bp; the basis points round it to 1 bp.
#[test]
fn at_a_low_rate_only_exact_propensities_value_an_exact_population_exactly() {
    let logger = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, twenty_two()).unwrap();
    let records: Vec<_> = (0..50_000_u64)
        .map(|seq| explore(&logger, input(seq), wide(10), &KEY).unwrap())
        .collect();
    let kept = records.iter().find(|r| !r.explored).unwrap();
    let explored = records.iter().find(|r| r.explored).unwrap();
    let (p_win, p_alt) = (kept.propensity().unwrap(), explored.propensity().unwrap());
    assert_eq!(p_alt.denominator(), 220_000);
    assert_eq!((p_alt.numerator(), p_alt.to_bps()), (10, 1));

    // Candidate i pays i/100 every time; the population is one denominator's
    // worth of requests.
    let reward = |id: u32| f64::from(id) / 100.0;
    let population = |target: u32, exact: bool| -> Vec<LoggedChoice> {
        let mut out = Vec::new();
        for id in 1..=22_u32 {
            let p = if id == 1 { p_win } else { p_alt };
            let logged = if exact {
                p
            } else {
                Propensity::from_bps(p.to_bps()).unwrap()
            };
            for _ in 0..p.numerator() {
                out.push(LoggedChoice {
                    acted_model_id: id,
                    propensity: logged,
                    reward: reward(id),
                    target_model_id: target,
                });
            }
        }
        assert_eq!(out.len() as u64, p_win.denominator());
        out
    };
    for target in [1_u32, 5, 22] {
        let exact = estimate(&population(target, true), None).unwrap();
        let rounded = estimate(&population(target, false), None).unwrap();
        let truth = reward(target);
        assert!(
            (exact.ips - truth).abs() < 1e-12,
            "target {target}: exact {} vs {truth}",
            exact.ips
        );
        if target != 1 {
            // 1 bp in place of 0.4545 bp: a weight of 10,000 in place of 22,000.
            let ratio = rounded.ips / truth;
            assert!((ratio - 10_000.0 / 22_000.0).abs() < 1e-9, "{ratio}");
        }
    }
}

/// An outcome that does not validate is excluded rather than estimated from.
#[test]
fn an_outcome_that_does_not_validate_is_excluded() {
    use calybris_core::outcome::Selection;
    let p = PolicySnapshot::try_new(1, 1, 9_000, 0, 0, 0, vec![model(1, 9_000)]).unwrap();
    let x = input(1);
    let d = p.prescribe(x);
    let good = Outcome::applied(
        &p,
        &x,
        &d,
        1,
        Observation {
            succeeded: Some(true),
            ..Observation::default()
        },
    );
    // The kernel's own choice claimed at less than certainty: not a record
    // the kernel could have written.
    let mut claimed = good;
    claimed.selection = Selection {
        propensity_bps: Some(5_000),
        ..Selection::followed(&d)
    };
    assert!(claimed.validate().is_err());
    let e = evaluate(&p, &[(x, claimed), (x, good)], |_| Some(1.0), None).unwrap();
    assert_eq!((e.used, e.excluded), (1, 1));
    let e = evaluate_exact(
        &p,
        &[
            (x, claimed, Propensity::from_bps(5_000).unwrap()),
            (x, good, Propensity::ONE),
        ],
        |_| Some(1.0),
        None,
    )
    .unwrap();
    assert_eq!((e.used, e.excluded), (1, 1));
}
