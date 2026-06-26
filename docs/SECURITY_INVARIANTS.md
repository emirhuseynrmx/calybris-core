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

**Invariant:** At all times per tenant: `remaining + reserved + committed_lifetime == initial`.

**Code:** `src/budget.rs` — `verify_conservation`, `debit_if_available` CAS.

**Tests:** `conservation_invariant`, `random_ops_maintain_conservation` (proptest), `concurrent_reserve_never_overspends`, `failed_overrun_does_not_create_budget`.

## I7 — No unsafe in project code

**Invariant:** `#![forbid(unsafe_code)]` on crate root.

**Code:** `src/lib.rs`.

## I8 — Ledger digest stability

**Invariant:** `ledger_digest` is independent of tenant insertion order; `prove_conservation` returns `Ok` iff I6 holds.

**Code:** `src/finance.rs`.

**Tests:** `ledger_digest_tenant_order_independent`, `prove_conservation_ok_after_mixed_ops`.