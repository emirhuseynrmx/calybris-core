//! The fuzz targets' properties, as tests that run on every machine.
//!
//! `fuzz/` holds coverage-guided targets for the same decoders. Those need
//! nightly and libFuzzer, which does not link on Windows MSVC, so on a developer
//! machine they may only be compiled. These are the same properties driven by
//! proptest instead: weaker input generation, but they run in the ordinary suite
//! on every platform, which is what makes them evidence rather than intent.
//!
//! ## Why the inputs are built from the types
//!
//! The first version of this file generated JSON-ish text from fragments. It
//! passed, and it was worthless: of five thousand generated strings, ninety-one
//! were valid JSON and **none** decoded as a snapshot or an outcome, so three of
//! the properties below were never once evaluated. A test that cannot reach the
//! code it names is worse than no test, because it reads as coverage.
//!
//! So the documents here are serialised from generated values — which guarantees
//! the decoder is entered — and then also mutated textually, which probes the
//! decoder itself while keeping the entry rate high. `entry_rate` at the bottom
//! asserts that both still arrive, so this file cannot rot back into the version
//! that checked nothing.

#![cfg(feature = "serde")]

use std::sync::atomic::{AtomicUsize, Ordering};

use calybris_core::budget::{conservation_status_for_snapshot, BudgetSnapshot, ConservationStatus};
use calybris_core::digest::{decision_digest, digest_to_hex, policy_digest};
use calybris_core::kernel::{
    KernelAction, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS,
};
use calybris_core::outcome::{
    outcome_digest, DecisionIdentity, Disposition, Observation, Outcome, Selection,
    SelectionStrategy, FULL_PROBABILITY_BPS,
};
use proptest::prelude::*;

/// Counts how often each decoder was actually entered, so that
/// [`entry_rate_is_not_zero`] can refuse the vacuous version of this file.
static SNAPSHOTS_DECODED: AtomicUsize = AtomicUsize::new(0);
static OUTCOMES_DECODED: AtomicUsize = AtomicUsize::new(0);

// --- generators over the real shapes --------------------------------------

fn any_observation() -> impl Strategy<Value = Observation> {
    (
        proptest::option::of(any::<u64>()),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<bool>()),
    )
        .prop_map(
            |(realized_cost_microunits, realized_latency_ms, succeeded)| Observation {
                realized_cost_microunits,
                realized_latency_ms,
                succeeded,
            },
        )
}

fn any_selection() -> impl Strategy<Value = Selection> {
    (
        prop_oneof![
            Just(SelectionStrategy::MaximiseUtility),
            Just(SelectionStrategy::Explore),
            Just(SelectionStrategy::Human),
        ],
        any::<u32>(),
        // Deliberately includes the values validation must refuse: absent where
        // it is required, present where it is forbidden, zero, and over 10,000.
        proptest::option::of(prop_oneof![
            Just(0u16),
            Just(1u16),
            Just(FULL_PROBABILITY_BPS),
            Just(FULL_PROBABILITY_BPS + 1),
            any::<u16>(),
        ]),
    )
        .prop_map(|(strategy, acted_model_id, propensity_bps)| Selection {
            strategy,
            acted_model_id,
            propensity_bps,
        })
}

fn any_outcome() -> impl Strategy<Value = Outcome> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
        any_selection(),
        prop_oneof![
            Just(Disposition::Applied),
            Just(Disposition::Abandoned),
            Just(Disposition::InFlight),
        ],
        any_observation(),
    )
        .prop_map(
            |(
                policy_digest,
                input_digest,
                decision_digest,
                request_sequence,
                observed_at_micros,
                revision,
                selection,
                disposition,
                observation,
            )| Outcome {
                identity: DecisionIdentity {
                    policy_digest,
                    input_digest,
                    decision_digest,
                    request_sequence,
                },
                observed_at_micros,
                revision,
                selection,
                disposition,
                observation,
            },
        )
}

fn any_snapshot() -> impl Strategy<Value = BudgetSnapshot> {
    use calybris_core::budget::TenantLedger;
    (
        any::<u64>(),
        proptest::collection::vec(
            (
                "[a-z]{1,6}",
                // A mix of values that balance and values that cannot, so both
                // branches of the conservation check are reached.
                prop_oneof![Just(1_000_000i64), Just(0i64), any::<i64>()],
                prop_oneof![Just(300_000i64), Just(0i64), any::<i64>()],
                prop_oneof![Just(0i64), any::<i64>()],
                prop_oneof![Just(700_000i64), Just(0i64), any::<i64>()],
            )
                .prop_map(
                    |(
                        tenant_id,
                        initial_microcents,
                        remaining_microcents,
                        reserved_microcents,
                        committed_microcents,
                    )| TenantLedger {
                        tenant_id,
                        initial_microcents,
                        remaining_microcents,
                        reserved_microcents,
                        committed_microcents,
                    },
                ),
            0..4,
        ),
        0usize..4,
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(version, tenants, active_reservations, wal_high_watermark)| BudgetSnapshot {
                version,
                tenants,
                active_reservations,
                wal_high_watermark,
            },
        )
}

/// One small textual edit to a valid document: the decoder's own robustness,
/// rather than the type's.
fn mutate(text: &str, seed: usize) -> String {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return String::new();
    }
    let at = seed % bytes.len();
    match seed % 5 {
        0 => text[..at].to_string(), // truncated
        1 => format!("{}{}", &text[..at], text[at..].to_uppercase()), // case
        2 => text.replacen('0', "99999999999999999999", 1), // overflow
        3 => text.replacen("null", "0", 1), // absent -> zero
        _ => text.replacen('"', "", 1), // broken quoting
    }
}

// --- the properties -------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 600, ..ProptestConfig::default() })]

    /// A snapshot that decodes and reports balanced must actually balance. This
    /// is the one place a decoder defect could become a silently wrong ledger.
    #[test]
    fn a_snapshot_reported_balanced_actually_balances(
        snapshot in any_snapshot(),
        seed in any::<usize>(),
    ) {
        let text = serde_json::to_string(&snapshot).expect("encode");

        for candidate in [text.clone(), mutate(&text, seed)] {
            let Ok(decoded) = serde_json::from_str::<BudgetSnapshot>(&candidate) else {
                continue;
            };
            SNAPSHOTS_DECODED.fetch_add(1, Ordering::Relaxed);

            let _ = calybris_core::finance::ledger_digest(&decoded);
            if conservation_status_for_snapshot(&decoded) == ConservationStatus::Balanced {
                for tenant in &decoded.tenants {
                    let parts = tenant
                        .remaining_microcents
                        .checked_add(tenant.reserved_microcents)
                        .and_then(|sum| sum.checked_add(tenant.committed_microcents));
                    prop_assert_eq!(
                        parts,
                        Some(tenant.initial_microcents),
                        "a balanced snapshot does not balance for {}",
                        tenant.tenant_id,
                    );
                }
            }
        }
    }

    /// An outcome that validation accepts must satisfy every rule the format
    /// promises. Downstream this record supports a causal claim, so an accepted
    /// record that breaks a rule is worse than a rejected one.
    #[test]
    fn an_accepted_outcome_satisfies_every_documented_rule(
        outcome in any_outcome(),
        seed in any::<usize>(),
    ) {
        let text = serde_json::to_string(&outcome).expect("encode");

        for candidate in [text.clone(), mutate(&text, seed)] {
            let Ok(decoded) = serde_json::from_str::<Outcome>(&candidate) else {
                continue;
            };
            OUTCOMES_DECODED.fetch_add(1, Ordering::Relaxed);

            // Digesting arbitrary field values must not panic or overflow.
            let _ = outcome_digest(&decoded);

            if decoded.validate().is_err() {
                continue;
            }

            match decoded.selection.strategy {
                SelectionStrategy::MaximiseUtility => {
                    prop_assert_eq!(
                        decoded.selection.propensity_bps,
                        Some(FULL_PROBABILITY_BPS),
                    );
                }
                SelectionStrategy::Explore => {
                    let bps = decoded.selection.propensity_bps;
                    prop_assert!(matches!(bps, Some(b) if (1..=FULL_PROBABILITY_BPS).contains(&b)));
                }
                SelectionStrategy::Human => {
                    prop_assert_eq!(decoded.selection.propensity_bps, None);
                }
            }

            match decoded.disposition {
                Disposition::Applied => prop_assert!(!decoded.observation.is_empty()),
                Disposition::Abandoned => prop_assert!(decoded.observation.is_empty()),
                Disposition::InFlight => {
                    prop_assert!(decoded.observation.succeeded.is_none());
                }
            }
        }
    }

    /// Anything that decodes must survive re-encoding, or two readers of the
    /// same artifact could disagree about what it says.
    #[test]
    fn a_decoded_outcome_survives_re_encoding(outcome in any_outcome()) {
        let encoded = serde_json::to_string(&outcome).expect("encode");
        let again: Outcome = serde_json::from_str(&encoded)
            .expect("what we encoded must decode");

        prop_assert_eq!(outcome, again);
        prop_assert_eq!(outcome_digest(&outcome), outcome_digest(&again));
    }
}

/// A forged signature must never verify. Nothing here holds a signing key, so
/// nothing it can build should pass.
#[cfg(feature = "provenance")]
mod provenance {
    use super::*;
    use calybris_core::provenance::{verify_signed_policy, SignedPolicy};

    fn fixed_snapshot() -> PolicySnapshot {
        PolicySnapshot::try_new(
            1,
            1,
            9_000,
            1_000,
            2_000,
            5,
            vec![KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0b1,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 3_000_000,
                output_cost_microunits_per_million_tokens: 15_000_000,
            }],
        )
        .expect("snapshot")
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

        #[test]
        fn an_invented_signature_never_verifies(
            signer in "[ -~]{0,24}",
            signed_at in any::<u64>(),
            key_hex in "[0-9a-f]{0,80}",
            signature_hex in "[0-9a-f]{0,160}",
            use_real_digest in any::<bool>(),
        ) {
            let snapshot = fixed_snapshot();
            let policy_digest_hex = if use_real_digest {
                // Naming the right policy must not be enough on its own.
                digest_to_hex(&policy_digest(&snapshot))
            } else {
                "00".repeat(32)
            };

            let signed = SignedPolicy {
                policy_digest_hex,
                signer_id: signer,
                signed_at_epoch_ms: signed_at,
                public_key_hex: key_hex,
                signature_hex,
            };

            prop_assert!(
                verify_signed_policy(&snapshot, &signed).is_err(),
                "an unsigned artifact verified against a real policy",
            );
        }
    }
}

// The kernel on inputs no caller would write on purpose. `debug_assertions` are
// on in a test build, so an arithmetic mistake is a panic here rather than a
// quietly wrong decision.
proptest! {
    #![proptest_config(ProptestConfig { cases: 600, ..ProptestConfig::default() })]

    #[test]
    fn the_kernel_decides_identically_twice_on_any_input_it_accepts(
        model_ids in proptest::collection::vec(any::<u32>(), 1..6),
        quality in proptest::collection::vec(0u16..=10_000, 1..6),
        in_cost in proptest::collection::vec(any::<u64>(), 1..6),
        out_cost in proptest::collection::vec(any::<u64>(), 1..6),
        latency in proptest::collection::vec(any::<u32>(), 1..6),
        latency_penalty in any::<u64>(),
        value in any::<i64>(),
        budget in any::<u64>(),
        tokens in any::<u32>(),
    ) {
        let count = model_ids
            .len()
            .min(quality.len())
            .min(in_cost.len())
            .min(out_cost.len())
            .min(latency.len());
        let models: Vec<KernelModel> = (0..count)
            .map(|i| KernelModel {
                model_id: model_ids[i],
                provider_id: (i % 64) as u16,
                quality_bps: quality[i],
                risk_ceiling_bps: 10_000,
                enabled: 1,
                p95_latency_ms: latency[i],
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: in_cost[i],
                output_cost_microunits_per_million_tokens: out_cost[i],
            })
            .collect();

        let Ok(snapshot) = PolicySnapshot::try_new(1, 1, 10_000, 0, 2_000, latency_penalty, models)
        else {
            return Ok(());
        };

        let input = KernelInput {
            request_sequence: 1,
            requested_model_id: model_ids[0],
            input_tokens: tokens,
            output_tokens: tokens,
            business_value_microunits: value,
            budget_limit_microunits: budget,
            risk_bps: 0,
            confidence_bps: 10_000,
            minimum_quality_bps: 0,
            max_p95_latency_ms: 0,
            required_capabilities: 0,
            allowed_provider_mask: ALL_PROVIDERS,
            required_region_mask: 0,
        };
        if input.validate().is_err() {
            return Ok(());
        }

        let first = snapshot.prescribe(input);
        let second = snapshot.prescribe(input);
        prop_assert_eq!(decision_digest(&first), decision_digest(&second));

        // Explaining must not disagree with deciding, on any input at all.
        let explanation = snapshot.explain(input);
        if first.action != KernelAction::Reject {
            prop_assert!(
                explanation
                    .candidates
                    .iter()
                    .any(|candidate| candidate.model_id == first.selected_model_id),
            );
        }
    }
}

/// The guard against the version of this file that tested nothing.
///
/// Rust runs tests in one process, so by the time this runs the property tests
/// above have recorded how often each decoder was actually entered. If either
/// count is zero, the corresponding property was never evaluated, and it should
/// fail rather than report success.
///
/// It is named to sort last; `cargo test` does not guarantee order, so it also
/// generates its own inputs rather than relying purely on the counters.
#[test]
fn zz_entry_rate_is_not_zero() {
    let mut snapshots = 0_usize;
    let mut outcomes = 0_usize;

    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let snapshot_strategy = any_snapshot();
    let outcome_strategy = any_outcome();

    for _ in 0..200 {
        let snapshot = snapshot_strategy
            .new_tree(&mut runner)
            .expect("generate")
            .current();
        let text = serde_json::to_string(&snapshot).expect("encode");
        if serde_json::from_str::<BudgetSnapshot>(&text).is_ok() {
            snapshots += 1;
        }

        let outcome = outcome_strategy
            .new_tree(&mut runner)
            .expect("generate")
            .current();
        let text = serde_json::to_string(&outcome).expect("encode");
        if serde_json::from_str::<Outcome>(&text).is_ok() {
            outcomes += 1;
        }
    }

    assert_eq!(
        snapshots, 200,
        "a serialised snapshot must always decode; the generator has drifted",
    );
    assert_eq!(
        outcomes, 200,
        "a serialised outcome must always decode; the generator has drifted",
    );

    // And the properties above must have reached them too.
    assert!(
        SNAPSHOTS_DECODED.load(Ordering::Relaxed) > 0,
        "no snapshot reached the conservation property",
    );
    assert!(
        OUTCOMES_DECODED.load(Ordering::Relaxed) > 0,
        "no outcome reached the validation property",
    );
}
