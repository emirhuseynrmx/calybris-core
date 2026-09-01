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

**Invariant:** Entry *n* hashes `previous_hash || data_json` (HMAC if keyed). Validation rejects non-contiguous sequence numbers, broken `previous_hash`, tampered payload, and truncated/malformed records. Blank whitespace-only lines are separators and are not semantic records; integrity is defined over the parsed record chain, not every byte of the container file.

**Code:** `src/wal.rs` — `validate_chain_inner`, `compute_hash`.

**Tests:** `duplicate_sequence_rejected`, `previous_hash_mismatch_rejected`, `hmac_tamper_detected`, `keyed_wal_roundtrip` (proptest).

## I5 — Audited replay binding

**Invariant:** `replay_audited_wal*` returns `Err` if audit metadata is non-canonical, the stored replay claim is false, replay fails, or any policy/input/decision digest does not match canonical lowercase recomputation.

**Code:** `src/wal.rs` — `replay_audited_wal_keyed`.

**Tests:** `audited_replay_fails_on_{input,policy,decision}_digest_mismatch`.

## I6 — Budget conservation

**Invariant:** After each **completed** budget operation and at reconciliation boundaries, per tenant: `remaining + reserved + committed_lifetime == initial`.

Snapshots take the checkpoint gate exclusively and are linearizable against reserve, commit, release, top-up, tenant creation, restore, and exposure-cap updates.

**Code:** `src/budget.rs` — `conservation_status_for_snapshot`, `verify_conservation`, `debit_if_available` CAS.

**Tests:** `conservation_invariant`, `aggressive_mixed_ops_maintain_conservation` (proptest), `random_ops_maintain_conservation`, `concurrent_reserve_never_overspends`, `failed_overrun_does_not_create_budget`, `restore_from_snapshot_roundtrip`, `restore_rejects_ghost_reserved`, `restore_rejects_unbalanced_snapshot`, `ensure_tenant_rejects_negative_budget`, `exposure_limit_blocks_reserve`, `exposure_limit_holds_under_concurrent_reserve`, Loom (`tests/budget_loom.rs`, 8 scenarios).

## I7 — No unsafe in project code

**Invariant:** `#![forbid(unsafe_code)]` on crate root.

**Code:** `src/lib.rs`.

**Tests:** Miri UB pass on `--lib` + `audit_pipeline` (CI `security.yml`); Loom for concurrent budget paths.

## I8 — Ledger digest stability

**Invariant:** `ledger_digest` is independent of tenant insertion order and binds the recovery-aware `BudgetSnapshot::version` (which encodes allocator position) plus any WAL high watermark. Recovery restores allocator and certificate baseline state, clears process-local exposure configuration, and rejects untagged legacy snapshots.

**Code:** `src/finance.rs` — `conservation_status_for_snapshot`, `certify_snapshot`, `BudgetEngine::rotate_certificate_baseline`.

**Tests:** `ledger_digest_tenant_order_independent`, `ledger_digest_binds_reservation_allocator_state`, `restore_preserves_reservation_id_monotonicity`, `restore_replaces_all_recovery_sensitive_runtime_state`, `certify_snapshot_is_immutable_binding`, and `prove_and_certify_are_internally_consistent`.

## I9 — Receipt claim binding

**Invariant:** A `DecisionReceipt` is issued only after exact replay succeeds. Malformed or zero-position state/WAL anchors return an error and never panic. Its canonical digest binds the length-prefixed schema identifier, policy/input/decision digests, policy epochs, replay status, and optional state and WAL anchors. With `provenance`, the signature also binds signer identity and signing time. Serialized security artifacts reject unknown fields.

**Code:** `src/receipt.rs` — `issue_receipt`, `receipt_claims_digest`, `verify_receipt`, `sign_receipt`.

**Tests:** `receipt_verifies_and_binds_all_anchors`, `malformed_anchors_are_rejected_during_issuance_without_panicking`, `receipt_json_rejects_unknown_fields`, `tampered_state_or_wal_claim_fails`, `signed_receipt_rejects_claim_and_signer_tampering`, `golden_signed_receipt_is_reproduced_byte_for_byte`, `receipt_pipeline`, and the Python golden receipt test.

## I10 — Anchored, single-writer WAL

**Invariant:** Only one active writer may own a WAL file identity. A trusted `WalAnchor` stored outside the WAL binds the expected sequence and head hash, detecting clean suffix truncation that internal chain validation alone cannot detect. Keyed APIs reject HMAC keys shorter than 32 bytes. Encoded entries above 16 MiB are rejected before JSON parsing. After an append, flush, or sync I/O error, the writer is poisoned and refuses further writes.

**Code:** `src/wal.rs`, `src/async_wal.rs` — writer lock acquisition, `anchor`, `verify_wal_against_anchor*`, poisoned writer checks.

**Tests:** `second_writer_is_rejected`, `clean_suffix_truncation_requires_anchor`, `short_hmac_keys_are_rejected_even_for_empty_wals`, `anchored_recovery_rejects_clean_suffix_truncation`, async equivalents, and `verify_cli` anchored truncation coverage.

## I11 — Complete trajectory and coordinated recovery anchoring

**Invariant:** A complete state trajectory is accepted only when it starts from a caller-trusted genesis digest and reaches an independently expected final step. A coordinated checkpoint is recovery-ready only after the complete actual WAL chain verifies and contains the checkpoint's committed prefix anchor; valid later entries remain available for deterministic replay.

**Code:** `src/state.rs` — `verify_complete_trajectory`, `verify_trajectory_fragment`; `src/persistence.rs` — `load_and_verify_coordinated_checkpoint`.

**Tests:** `complete_trajectory_rejects_empty_or_truncated_evidence`, `coordinated_checkpoint_full_verification_rejects_a_truncated_wal`, `coordinated_checkpoint_accepts_a_valid_wal_suffix_for_replay`, and prefix/suffix tamper coverage.
