# Invariant registry

Every property this crate promises, with the test that fails when it stops being
true. The identifiers are stable: `CAL-I012` means the same thing in a bug report
next year as it does today. That is why they are not renumbered when a row is
inserted, and why the sequence has gaps wherever an invariant was retired.

`tests/invariants.rs` reads this file and refuses to pass if a row names a test
that does not exist, so the right-hand column cannot quietly go stale. Adding an
invariant means adding a row *and* a test; there is no way to have one without
the other.

## Decisions

| ID | Invariant | Guarded by |
|---|---|---|
| CAL-I001 | The same policy and the same input decide identically, on any machine and in any build | `decision_semantics::the_same_input_decides_identically` |
| CAL-I002 | Every gate reports the number it compared against the limit it compared it to | `explain_agreement::every_gate_reports_the_numbers_it_compared` |
| CAL-I003 | Ties break by utility, then cost, then quality, then model identifier — never by catalog position | `decision_semantics::ties_break_by_cost_then_quality_then_identifier` |
| CAL-I004 | The order of the catalog does not decide the winner | `decision_semantics::catalog_order_does_not_decide_the_winner` |
| CAL-I005 | When every candidate is rejected the result is a rejection, not a fallback guess | `decision_semantics::every_candidate_rejected_is_a_rejection_and_not_a_guess` |
| CAL-I006 | The budget is a wall: a candidate over it is refused, not scaled down to fit | `decision_semantics::the_budget_is_a_wall_and_not_a_target` |
| CAL-I007 | Extreme inputs saturate rather than wrapping — utility accumulates in `i128` and clamps | `decision_semantics::extreme_inputs_saturate_instead_of_wrapping` |
| CAL-I008 | The ceilings in the documentation are the ceilings in the code | `decision_semantics::the_documented_ceilings_are_the_actual_ceilings` |
| CAL-I009 | `p95_latency_ms` reaches about 49.7 days, and the type is the reason | `decision_semantics::the_latency_ceiling_is_a_little_under_fifty_days` |
| CAL-I010 | `explain` cannot disagree with `prescribe`: the chosen candidate is reported eligible, with the highest utility | `explain_agreement::the_chosen_candidate_is_reported_eligible` |
| CAL-I011 | A request refused at the hard limits invents no per-candidate reasons, because the catalog was never walked | `explain_agreement::a_request_refused_at_the_hard_limits_invents_no_candidate_reasons` |

## Digests

Each layout is written out in [SPECIFICATION.md](SPECIFICATION.md). The tests
below rebuild it from that prose and compare, so a row failing means the document
and the code have parted company — and the document is not automatically the one
that is wrong.

| ID | Invariant | Guarded by |
|---|---|---|
| CAL-I012 | The policy layout is what the specification says | `specification::the_policy_layout_is_what_the_document_says` |
| CAL-I013 | The input layout is what the specification says | `specification::the_input_layout_is_what_the_document_says` |
| CAL-I014 | The decision layout is what the specification says | `specification::the_decision_layout_is_what_the_document_says` |
| CAL-I015 | A rejection hashes by the same layout as a selection | `specification::a_rejection_hashes_by_the_same_layout` |
| CAL-I016 | The ledger layout is what the specification says | `specification::the_ledger_layout_is_what_the_document_says` |
| CAL-I017 | The identity layout is what the specification says | `specification::the_identity_layout_is_what_the_document_says` |
| CAL-I018 | The selection layout is what the specification says | `specification::the_selection_layout_is_what_the_document_says` |
| CAL-I019 | The outcome layout is what the specification says | `specification::the_outcome_layout_is_what_the_document_says` |
| CAL-I020 | A catalog in a different order reaches the same policy digest | `specification::a_catalog_in_a_different_order_hashes_the_same` |
| CAL-I021 | Tenants sort by raw bytes, not by any locale collation | `specification::tenants_sort_by_bytes_and_not_by_locale` |
| CAL-I022 | An absent measurement and a zero measurement are different bytes | `specification::absent_and_zero_are_different_bytes` |
| CAL-I023 | A snapshot with no WAL watermark appends nothing at all, rather than a zero | `specification::a_missing_watermark_appends_nothing_at_all` |
| CAL-I024 | Every format tag is nine bytes, `caly`-prefixed, and distinct from the others | `specification::every_tag_is_distinct_and_well_formed` |
| CAL-I025 | The pinned golden digests are reproduced byte for byte | `golden_caly_proof::golden_digests_are_reproduced_byte_for_byte` |
| CAL-I026 | The pinned golden decision semantics are stable | `golden_caly_proof::golden_decision_semantics_are_stable` |
| CAL-I027 | The pinned WAL chain hashes are reproduced | `golden_caly_proof::golden_wal_chain_hashes_are_reproduced` |
| CAL-I028 | Every conformance case reproduces its pinned digests | `conformance_caly_proof::every_conformance_case_reproduces_its_pinned_digests` |
| CAL-I049 | The pinned policy is the one the outcome vectors were generated from | `golden_outcome::the_pinned_policy_is_the_policy_these_vectors_were_made_from` |
| CAL-I050 | A followed, fully measured outcome is reproduced byte for byte | `golden_outcome::a_followed_and_fully_measured_outcome_is_reproduced_byte_for_byte` |
| CAL-I051 | An abandoned outcome is reproduced byte for byte | `golden_outcome::an_abandoned_outcome_is_reproduced_byte_for_byte` |
| CAL-I052 | A partially measured in-flight outcome is reproduced byte for byte | `golden_outcome::a_partial_in_flight_outcome_is_reproduced_byte_for_byte` |
| CAL-I053 | An exploration at one basis point is reproduced byte for byte | `golden_outcome::an_exploration_at_one_basis_point_is_reproduced_byte_for_byte` |
| CAL-I054 | A human choice carrying no propensity is reproduced byte for byte — the vector that would catch a dropped presence byte | `golden_outcome::a_human_choice_with_no_propensity_is_reproduced_byte_for_byte` |
| CAL-I055 | Zero measurements at a non-zero revision are reproduced byte for byte | `golden_outcome::zero_measurements_at_revision_seven_are_reproduced_byte_for_byte` |
| CAL-I056 | An abandoned rejection is reproduced byte for byte | `golden_outcome::an_abandoned_rejection_is_reproduced_byte_for_byte` |
| CAL-I057 | No two pinned outcomes collide, so no field has stopped reaching the hash | `golden_outcome::the_pinned_outcomes_are_all_different_from_each_other` |
| CAL-I058 | Every pinned identity is rebuildable from its policy, input and decision | `golden_outcome::every_pinned_identity_is_rebuildable_from_its_three_parts` |

## Outcomes

| ID | Invariant | Guarded by |
|---|---|---|
| CAL-I029 | An outcome binds to the policy, the input and the decision together | `outcome_contract::an_outcome_binds_to_the_policy_the_input_and_the_decision` |
| CAL-I030 | A policy change breaks the binding even when the decision is byte-identical | `outcome_contract::the_same_decision_under_a_different_policy_is_not_the_same_outcome` |
| CAL-I031 | A different request breaks the binding even when it decides identically | `outcome_contract::a_different_request_that_decides_the_same_way_is_not_the_same_outcome` |
| CAL-I032 | `Applied` requires a measurement — it cannot assert that something happened while recording nothing | `outcome_contract::applied_without_a_measurement_is_refused` |
| CAL-I033 | `Abandoned` forbids one — nothing ran, so a zero here cannot later read as a free success | `outcome_contract::abandoned_with_a_measurement_is_refused` |
| CAL-I034 | `InFlight` cannot record success or failure, because the work has not finished | `outcome_contract::in_flight_cannot_claim_it_already_finished` |
| CAL-I035 | A rejection admits only `Abandoned` — there was nothing to carry out | `outcome_contract::a_rejection_cannot_have_been_carried_out` |
| CAL-I036 | Following the ranking means acting on what it ranked | `outcome_contract::following_the_ranking_means_acting_on_what_it_ranked` |
| CAL-I037 | A deterministic strategy records certainty and nothing else | `outcome_contract::maximise_utility_must_record_certainty` |
| CAL-I038 | Exploration records the probability that cannot be recovered afterwards | `outcome_contract::exploration_must_record_the_probability_it_cannot_recover_later` |
| CAL-I039 | A human choice records no probability, because none exists to record | `outcome_contract::a_human_choice_records_no_probability` |
| CAL-I040 | An observed event cannot have had no chance of happening | `outcome_contract::an_observed_event_cannot_have_had_no_chance_of_happening` |
| CAL-I041 | An outcome cannot name a model the policy does not contain | `outcome_contract::an_outcome_for_a_model_outside_the_catalog_is_refused` |
| CAL-I042 | The identity is computed the same way wherever it is built | `outcome_contract::the_identity_is_computed_the_same_way_wherever_it_is_built` |

## Pipelines

| ID | Invariant | Guarded by |
|---|---|---|
| CAL-I043 | The audit pipeline binds the decision, the budget and the keyed WAL into one verifiable whole | `audit_pipeline::full_audit_pipeline_with_budget_and_keyed_wal` |
| CAL-I044 | A receipt binds replay, state, WAL anchor and signature together | `receipt_pipeline::receipt_pipeline_binds_replay_state_wal_anchor_and_signature` |

## The API itself

| ID | Invariant | Guarded by |
|---|---|---|
| CAL-I045 | Every semantics enum stays exhaustively matchable, so a caller that handles every case keeps doing so | `invariants::semantics_enums_stay_exhaustively_matchable` |
| CAL-I046 | Every error enum stays `#[non_exhaustive]`, so a security fix can add a variant | `invariants::error_enums_stay_extendable` |
| CAL-I047 | Every row in this file names a test that exists | `invariants::every_invariant_names_a_test_that_exists` |
| CAL-I048 | Every identifier in this file is unique and well formed | `invariants::the_identifiers_are_unique_and_well_formed` |

## What is deliberately not here

Performance. There is no invariant in this registry about how fast anything is,
because a number measured on one machine is not a property of the crate, and a
promise the test suite cannot keep does not belong in a file whose whole purpose
is that every row is checked.
