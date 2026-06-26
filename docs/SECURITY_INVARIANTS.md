# Security Invariants

Formal properties the OSS crate is designed to uphold. Each maps to tests auditors should re-run.

## I1 — Deterministic kernel

**Invariant:** For fixed `PolicySnapshot` and `KernelInput`, `prescribe` always returns the same `KernelDecision`.

**Code:** `src/kernel.rs` — integer-only arithmetic, no `unsafe`.

**Tests:** `optimized_kernel_matches_reference_decision` (proptest), `prescribe_batch_matches_individual`.

## I2 — Fail-closed verification

**Invariant:** If any structural or digest field of a recorded decision does not match replay, verification returns non-`Valid`.

**Code:** `src/verify.rs` — `verify_decision`, `audit_bundle`.

**Tests:** `tampered_counterfactual_detected`, `verify_decision_wrong_policy_epoch`, `decode_hex32_rejects_*`.

## I3 — Canonical digests

**Invariant:** Digests use version-tagged byte layouts (not JSON); policy models sorted by `model_id`; single-bit input change alters digest.

**Code:** `src/digest.rs` — `POLICY_DIGEST_TAG`, `INPUT_DIGEST_TAG`, `DECISION_DIGEST_TAG`, `LEDGER_DIGEST_TAG`.

**Tests:** `policy_digest_order_independent`, `input_digest_sensitive_to_single_field_change`, `digests_stable_under_repeat` (proptest).

## I4 — WAL chain integrity

**Invariant:** Entry *n* hashes `previous_hash || data_json` (HMAC if keyed). Validation rejects duplicate sequence, broken `previous_hash`, tampered payload, truncated/malformed lines.

**Code:** `src/wal.rs` — `validate_chain_inner`, `compute_hash`.

**Tests:** `duplicate_sequence_rejected`, `previous_hash_mismatch_rejected`, `hmac_tamper_detected`, `keyed_wal_roundtrip` (proptest).

## I5 — Audited replay binding

**Invariant:** `replay_audited_wal*` returns `Err` if replay invalid or any of policy/input/decision digest hex does not match canonical recomputation.

**Code:** `src/wal.rs` — `replay_audited_wal_keyed`.

**Tests:** `audited_replay_fails_on_{input,policy,decision}_digest_mismatch`.

## I6 — Budget conservation

**Invariant:** After each **completed** budget operation and at reconciliation boundaries, per tenant: `remaining + reserved + committed_lifetime == initial`.

Mid-operation snapshots are not linearizable — multi-step reserve/commit/release may show transient imbalance between CAS and map updates.

**Code:** `src/budget.rs` — `conservation_status_for_snapshot`, `verify_conservation`, `debit_if_available` CAS.

**Tests:** `conservation_invariant`, `aggressive_mixed_ops_maintain_conservation` (proptest), `random_ops_maintain_conservation`, `concurrent_reserve_never_overspends`, `failed_overrun_does_not_create_budget`, `restore_from_snapshot_roundtrip`, `restore_rejects_ghost_reserved`, `restore_rejects_unbalanced_snapshot`, `ensure_tenant_rejects_negative_budget`, `exposure_limit_blocks_reserve`, `exposure_limit_holds_under_concurrent_reserve`, Loom (`tests/budget_loom.rs`, 6 scenarios).

## I7 — No unsafe in project code

**Invariant:** `#![forbid(unsafe_code)]` on crate root.

**Code:** `src/lib.rs`.

**Tests:** Miri UB pass on `--lib` + `audit_pipeline` (CI `security.yml`); Loom for concurrent budget paths.

## I8 — Ledger digest stability

**Invariant:** `ledger_digest` is independent of tenant insertion order; includes `BudgetSnapshot::version`; `prove_conservation` / `certify_ledger` bind digest + status + version + `committed_since_last_certificate` to one frozen snapshot.

**Code:** `src/finance.rs` — `conservation_status_for_snapshot`, `certify_snapshot`, `BudgetEngine::rotate_certificate_baseline`.

**Tests:** `ledger_digest_tenant_order_independent`, `prove_conservation_ok_after_mixed_ops`, `certify_snapshot_is_immutable_binding`, `certify_ledger_binds_committed_delta_to_snapshot`, `prove_and_certify_are_internally_consistent`.