//! Stable C ABI for the Calybris decision kernel.
//!
//! This crate exists so that a caller which is not Rust and not Python can make
//! the same decision and recompute the same digest. It adds no behaviour: every
//! function here converts C structs into the kernel's own types, calls into
//! `calybris-core`, and converts back.
//!
//! ## What is stable here
//!
//! [`CALYBRIS_ABI_VERSION`] and the layout of every `#[repr(C)]` struct below.
//! The struct layouts are **not** the digest layouts — those are documented in
//! `docs/SPECIFICATION.md` and are a separate, also-frozen thing. A caller must
//! not hash these structs; it must ask for a digest.
//!
//! ## Panics
//!
//! Unwinding across an `extern "C"` boundary is undefined behaviour, so every
//! entry point catches it and returns [`CALYBRIS_ERR_PANIC`]. The kernel is not
//! expected to panic; this is the boundary refusing to make a bug worse.
//!
//! ## Ownership
//!
//! A `calybris_policy*` comes from [`calybris_policy_new`] and is released by
//! [`calybris_policy_free`], exactly once. Everything else is written into
//! caller-provided memory; this crate allocates nothing the caller must free
//! except that handle.

use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use calybris_core::digest::{decision_digest, digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{
    KernelAction, KernelDecision, KernelInput, KernelModel, PolicySnapshot, TrustPolicyError,
};
use calybris_core::verify::{verify_decision, VerifyResult};

/// The ABI this build speaks. A caller compiled against a different major
/// number must refuse to load the library rather than guess.
pub const CALYBRIS_ABI_VERSION: u32 = 1;

/// Length of a hex digest, without the terminating NUL.
pub const CALYBRIS_DIGEST_HEX_LEN: usize = 64;

// --- status codes ----------------------------------------------------------

/// Success.
pub const CALYBRIS_OK: c_int = 0;
/// A required pointer was null.
pub const CALYBRIS_ERR_NULL: c_int = -1;
/// The catalog or its limits were refused by the kernel.
pub const CALYBRIS_ERR_INVALID_POLICY: c_int = -2;
/// The request was refused by the kernel's own validation.
pub const CALYBRIS_ERR_INVALID_INPUT: c_int = -3;
/// The output buffer was too small; nothing was written.
pub const CALYBRIS_ERR_BUFFER_TOO_SMALL: c_int = -4;
/// A field did not correspond to any known variant.
pub const CALYBRIS_ERR_UNKNOWN_VARIANT: c_int = -5;
/// A panic was caught at the boundary. This is a defect; please report it.
pub const CALYBRIS_ERR_PANIC: c_int = -6;
/// The catalog held more candidates than a `u16` index can address.
pub const CALYBRIS_ERR_CATALOG_TOO_LARGE: c_int = -7;
/// A candidate used model id 0, which is reserved.
pub const CALYBRIS_ERR_RESERVED_MODEL_ID: c_int = -8;
/// A candidate's `enabled` was neither 0 nor 1.
pub const CALYBRIS_ERR_INVALID_ENABLED_FLAG: c_int = -9;

// --- C-visible structures --------------------------------------------------

/// One candidate in the catalog. Mirrors `KernelModel`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CalybrisModel {
    pub model_id: u32,
    pub provider_id: u16,
    pub quality_bps: u16,
    pub risk_ceiling_bps: u16,
    /// Non-zero for enabled.
    pub enabled: u8,
    pub p95_latency_ms: u32,
    pub capabilities: u64,
    pub region_mask: u64,
    pub input_cost_microunits_per_million_tokens: u64,
    pub output_cost_microunits_per_million_tokens: u64,
}

/// The policy's own limits, separate from the catalog.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CalybrisPolicyConfig {
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
    pub hard_risk_limit_bps: u16,
    pub minimum_confidence_bps: u16,
    pub risk_penalty_multiplier_bps: u16,
    pub latency_penalty_microunits_per_ms: u64,
}

/// One request. Mirrors `KernelInput`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CalybrisInput {
    pub request_sequence: u64,
    pub requested_model_id: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub business_value_microunits: i64,
    pub budget_limit_microunits: u64,
    pub risk_bps: u16,
    pub confidence_bps: u16,
    pub minimum_quality_bps: u16,
    pub max_p95_latency_ms: u32,
    pub required_capabilities: u64,
    pub allowed_provider_mask: u64,
    pub required_region_mask: u64,
}

/// One decision. Mirrors `KernelDecision`.
///
/// `action` is 1 execute-requested, 2 substitute, 3 reject. `reason` is the
/// discriminant documented in `docs/SPECIFICATION.md`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CalybrisDecision {
    pub request_sequence: u64,
    pub action: u8,
    pub reason: u16,
    pub selected_model_id: u32,
    pub selected_model_index: u16,
    pub estimated_cost_microunits: u64,
    pub expected_utility_microunits: i64,
    pub counterfactual_model_id: u32,
    pub counterfactual_utility_microunits: i64,
    pub evaluated_models: u16,
    pub eligible_models: u16,
    pub policy_epoch: u64,
    pub catalog_epoch: u64,
}

/// An opaque policy snapshot. Create with [`calybris_policy_new`], release with
/// [`calybris_policy_free`].
pub struct CalybrisPolicy {
    inner: PolicySnapshot,
}

// --- conversions -----------------------------------------------------------

impl From<CalybrisModel> for KernelModel {
    fn from(model: CalybrisModel) -> Self {
        Self {
            model_id: model.model_id,
            provider_id: model.provider_id,
            quality_bps: model.quality_bps,
            risk_ceiling_bps: model.risk_ceiling_bps,
            // Verbatim, not coerced. `try_new_trusted` refuses anything
            // outside 0..=1, and coercing here would make the C path accept a
            // catalog Python refuses.
            enabled: model.enabled,
            p95_latency_ms: model.p95_latency_ms,
            capabilities: model.capabilities,
            region_mask: model.region_mask,
            input_cost_microunits_per_million_tokens: model
                .input_cost_microunits_per_million_tokens,
            output_cost_microunits_per_million_tokens: model
                .output_cost_microunits_per_million_tokens,
        }
    }
}

impl From<CalybrisInput> for KernelInput {
    fn from(input: CalybrisInput) -> Self {
        Self {
            request_sequence: input.request_sequence,
            requested_model_id: input.requested_model_id,
            input_tokens: input.input_tokens,
            output_tokens: input.output_tokens,
            business_value_microunits: input.business_value_microunits,
            budget_limit_microunits: input.budget_limit_microunits,
            risk_bps: input.risk_bps,
            confidence_bps: input.confidence_bps,
            minimum_quality_bps: input.minimum_quality_bps,
            max_p95_latency_ms: input.max_p95_latency_ms,
            required_capabilities: input.required_capabilities,
            allowed_provider_mask: input.allowed_provider_mask,
            required_region_mask: input.required_region_mask,
        }
    }
}

impl From<KernelDecision> for CalybrisDecision {
    fn from(decision: KernelDecision) -> Self {
        Self {
            request_sequence: decision.request_sequence,
            action: decision.action as u8,
            reason: decision.reason as u16,
            selected_model_id: decision.selected_model_id,
            selected_model_index: decision.selected_model_index,
            estimated_cost_microunits: decision.estimated_cost_microunits,
            expected_utility_microunits: decision.expected_utility_microunits,
            counterfactual_model_id: decision.counterfactual_model_id,
            counterfactual_utility_microunits: decision.counterfactual_utility_microunits,
            evaluated_models: decision.evaluated_models,
            eligible_models: decision.eligible_models,
            policy_epoch: decision.policy_epoch,
            catalog_epoch: decision.catalog_epoch,
        }
    }
}

/// Rebuilds a kernel decision from its C form.
///
/// A digest has to be computable from what the caller holds, which means the C
/// struct must convert back. `action` and `reason` are checked rather than
/// transmuted: a caller that invents a discriminant gets an error, not a value
/// the kernel never produces.
fn decision_from_c(decision: &CalybrisDecision) -> Option<KernelDecision> {
    use calybris_core::kernel::KernelReason as R;

    let action = match decision.action {
        1 => KernelAction::ExecuteRequested,
        2 => KernelAction::Substitute,
        3 => KernelAction::Reject,
        _ => return None,
    };
    let reason = match decision.reason {
        1 => R::RequestedModelMaximizesUtility,
        2 => R::AlternativeMaximizesUtility,
        100 => R::RiskHardLimit,
        101 => R::ConfidenceHardLimit,
        102 => R::NoEnabledModel,
        103 => R::QualityConstraint,
        104 => R::LatencyConstraint,
        105 => R::CapabilityConstraint,
        106 => R::ProviderConstraint,
        107 => R::RegionConstraint,
        108 => R::BudgetConstraint,
        109 => R::NonPositiveUtility,
        110 => R::RiskCeilingConstraint,
        _ => return None,
    };

    Some(KernelDecision {
        request_sequence: decision.request_sequence,
        action,
        reason,
        selected_model_id: decision.selected_model_id,
        selected_model_index: decision.selected_model_index,
        estimated_cost_microunits: decision.estimated_cost_microunits,
        expected_utility_microunits: decision.expected_utility_microunits,
        counterfactual_model_id: decision.counterfactual_model_id,
        counterfactual_utility_microunits: decision.counterfactual_utility_microunits,
        evaluated_models: decision.evaluated_models,
        eligible_models: decision.eligible_models,
        policy_epoch: decision.policy_epoch,
        catalog_epoch: decision.catalog_epoch,
    })
}

/// Writes `text` plus a NUL into `out`, or reports the buffer is too small.
///
/// Nothing is written when it does not fit, so a caller that ignores the status
/// still does not read a truncated digest as a whole one.
unsafe fn write_cstr(text: &str, out: *mut c_char, capacity: usize) -> c_int {
    if out.is_null() {
        return CALYBRIS_ERR_NULL;
    }
    if capacity < text.len() + 1 {
        return CALYBRIS_ERR_BUFFER_TOO_SMALL;
    }
    ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), out, text.len());
    *out.add(text.len()) = 0;
    CALYBRIS_OK
}

/// Runs `body`, turning a panic into a status code rather than undefined
/// behaviour.
fn guard<F: FnOnce() -> c_int>(body: F) -> c_int {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(CALYBRIS_ERR_PANIC)
}

// --- entry points ----------------------------------------------------------

/// The ABI version this library speaks.
#[no_mangle]
pub extern "C" fn calybris_abi_version() -> u32 {
    CALYBRIS_ABI_VERSION
}

/// The crate version, as a static NUL-terminated string. Do not free it.
#[no_mangle]
pub extern "C" fn calybris_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Builds a policy snapshot.
///
/// On success `*out` holds a handle the caller must release with
/// [`calybris_policy_free`]. On failure `*out` is set to null.
///
/// # Safety
///
/// `config` and `out` must be valid pointers. `models` must point to
/// `model_count` initialised [`CalybrisModel`] values, and may be null only when
/// `model_count` is zero.
#[no_mangle]
pub unsafe extern "C" fn calybris_policy_new(
    config: *const CalybrisPolicyConfig,
    models: *const CalybrisModel,
    model_count: usize,
    out: *mut *mut CalybrisPolicy,
) -> c_int {
    guard(|| {
        // Cleared before any other check. A caller passing a variable that
        // already holds a pointer must not be left holding it after a failure,
        // and that is exactly what happens if the config check comes first.
        if out.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        *out = ptr::null_mut();

        if config.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        if models.is_null() && model_count != 0 {
            return CALYBRIS_ERR_NULL;
        }

        let config = *config;
        let catalog: Vec<KernelModel> = if model_count == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(models, model_count)
                .iter()
                .map(|model| KernelModel::from(*model))
                .collect()
        };

        // The trusted constructor, the same one the Python binding uses. It
        // sorts the catalog by model_id and refuses a reserved id or an
        // out-of-range enabled flag — so a C caller and a Python caller handed
        // the same candidates in a different order get the same policy digest
        // and the same selected_model_index. The legacy `try_new` does none of
        // that, and using it here would have made the ABI agree with nothing.
        match PolicySnapshot::try_new_trusted(
            config.policy_epoch,
            config.catalog_epoch,
            config.hard_risk_limit_bps,
            config.minimum_confidence_bps,
            config.risk_penalty_multiplier_bps,
            config.latency_penalty_microunits_per_ms,
            catalog,
        ) {
            Ok(inner) => {
                *out = Box::into_raw(Box::new(CalybrisPolicy { inner }));
                CALYBRIS_OK
            }
            Err(TrustPolicyError::CatalogTooLarge { .. }) => CALYBRIS_ERR_CATALOG_TOO_LARGE,
            Err(TrustPolicyError::ReservedModelId) => CALYBRIS_ERR_RESERVED_MODEL_ID,
            Err(TrustPolicyError::InvalidEnabledFlag { .. }) => CALYBRIS_ERR_INVALID_ENABLED_FLAG,
            Err(_) => CALYBRIS_ERR_INVALID_POLICY,
        }
    })
}

/// Releases a policy handle. Passing null is allowed and does nothing.
///
/// # Safety
///
/// `policy` must have come from [`calybris_policy_new`] and must not have been
/// freed already.
#[no_mangle]
pub unsafe extern "C" fn calybris_policy_free(policy: *mut CalybrisPolicy) {
    if policy.is_null() {
        return;
    }
    let _ = guard(|| {
        drop(Box::from_raw(policy));
        CALYBRIS_OK
    });
}

/// How many candidates the policy holds.
///
/// # Safety
///
/// `policy` must be a live handle; `out` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn calybris_policy_model_count(
    policy: *const CalybrisPolicy,
    out: *mut usize,
) -> c_int {
    guard(|| {
        if policy.is_null() || out.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        *out = (*policy).inner.models().len();
        CALYBRIS_OK
    })
}

/// Decides one request.
///
/// # Safety
///
/// All three pointers must be valid, and `policy` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn calybris_decide(
    policy: *const CalybrisPolicy,
    input: *const CalybrisInput,
    out: *mut CalybrisDecision,
) -> c_int {
    guard(|| {
        if policy.is_null() || input.is_null() || out.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        let request = KernelInput::from(*input);
        if request.validate().is_err() {
            return CALYBRIS_ERR_INVALID_INPUT;
        }
        *out = CalybrisDecision::from((*policy).inner.prescribe(request));
        CALYBRIS_OK
    })
}

/// Replays a decision and reports whether it is the one this policy makes.
///
/// `*valid` is set to non-zero only when the replay matches exactly.
///
/// # Safety
///
/// All four pointers must be valid, and `policy` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn calybris_verify(
    policy: *const CalybrisPolicy,
    input: *const CalybrisInput,
    decision: *const CalybrisDecision,
    valid: *mut u8,
) -> c_int {
    guard(|| {
        // Same rule as `calybris_policy_new`: the out-parameter is cleared
        // before anything can fail, so a caller who ignores the status code
        // cannot read a stale 1 left over from an earlier call.
        if valid.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        *valid = 0;

        if policy.is_null() || input.is_null() || decision.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        let Some(rebuilt) = decision_from_c(&*decision) else {
            return CALYBRIS_ERR_UNKNOWN_VARIANT;
        };
        let request = KernelInput::from(*input);
        if request.validate().is_err() {
            return CALYBRIS_ERR_INVALID_INPUT;
        }
        *valid =
            u8::from(verify_decision(&(*policy).inner, request, &rebuilt) == VerifyResult::Valid);
        CALYBRIS_OK
    })
}

/// Writes the policy digest as 64 hex characters plus a NUL.
///
/// # Safety
///
/// `policy` must be a live handle. `out` must point to `capacity` writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn calybris_policy_digest_hex(
    policy: *const CalybrisPolicy,
    out: *mut c_char,
    capacity: usize,
) -> c_int {
    guard(|| {
        if policy.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        write_cstr(
            &digest_to_hex(&policy_digest(&(*policy).inner)),
            out,
            capacity,
        )
    })
}

/// Writes the input digest as 64 hex characters plus a NUL.
///
/// # Safety
///
/// `input` must be valid. `out` must point to `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn calybris_input_digest_hex(
    input: *const CalybrisInput,
    out: *mut c_char,
    capacity: usize,
) -> c_int {
    guard(|| {
        if input.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        let request = KernelInput::from(*input);
        write_cstr(&digest_to_hex(&input_digest(&request)), out, capacity)
    })
}

/// Writes the decision digest as 64 hex characters plus a NUL.
///
/// # Safety
///
/// `decision` must be valid. `out` must point to `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn calybris_decision_digest_hex(
    decision: *const CalybrisDecision,
    out: *mut c_char,
    capacity: usize,
) -> c_int {
    guard(|| {
        if decision.is_null() {
            return CALYBRIS_ERR_NULL;
        }
        let Some(rebuilt) = decision_from_c(&*decision) else {
            return CALYBRIS_ERR_UNKNOWN_VARIANT;
        };
        write_cstr(&digest_to_hex(&decision_digest(&rebuilt)), out, capacity)
    })
}

#[cfg(test)]
// Every test here calls an `extern "C"` entry point, which Rust only allows
// inside `unsafe`. Semgrep's unsafe-usage rule flags each block; they are
// marked individually rather than excluded wholesale, so a new `unsafe` in the
// library itself is still reported.
mod tests {
    use super::*;

    fn config() -> CalybrisPolicyConfig {
        CalybrisPolicyConfig {
            policy_epoch: 1,
            catalog_epoch: 1,
            hard_risk_limit_bps: 9_000,
            minimum_confidence_bps: 1_000,
            risk_penalty_multiplier_bps: 2_000,
            latency_penalty_microunits_per_ms: 5,
        }
    }

    fn models() -> Vec<CalybrisModel> {
        vec![
            CalybrisModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0b1,
                region_mask: u64::MAX,
                input_cost_microunits_per_million_tokens: 3_000_000,
                output_cost_microunits_per_million_tokens: 15_000_000,
            },
            CalybrisModel {
                model_id: 2,
                provider_id: 1,
                quality_bps: 8_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 100,
                capabilities: 0b1,
                region_mask: u64::MAX,
                input_cost_microunits_per_million_tokens: 1_000_000,
                output_cost_microunits_per_million_tokens: 5_000_000,
            },
        ]
    }

    fn input() -> CalybrisInput {
        CalybrisInput {
            request_sequence: 42,
            requested_model_id: 1,
            input_tokens: 1_000,
            output_tokens: 500,
            business_value_microunits: 5_000_000,
            budget_limit_microunits: 50_000_000,
            risk_bps: 1_000,
            confidence_bps: 9_000,
            minimum_quality_bps: 0,
            max_p95_latency_ms: 0,
            required_capabilities: 0b1,
            allowed_provider_mask: u64::MAX,
            required_region_mask: 0,
        }
    }

    unsafe fn policy() -> *mut CalybrisPolicy {
        let catalog = models();
        let mut handle = ptr::null_mut();
        assert_eq!(
            calybris_policy_new(&config(), catalog.as_ptr(), catalog.len(), &mut handle),
            CALYBRIS_OK,
        );
        assert!(!handle.is_null());
        handle
    }

    #[test]
    fn a_decision_across_the_boundary_matches_the_kernel() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let request = input();

            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );

            // The same decision, made without going through the ABI.
            let native = (*handle).inner.prescribe(KernelInput::from(request));
            assert_eq!(decision.selected_model_id, native.selected_model_id);
            assert_eq!(decision.action, native.action as u8);
            assert_eq!(decision.reason, native.reason as u16);
            assert_eq!(
                decision.expected_utility_microunits,
                native.expected_utility_microunits,
            );

            calybris_policy_free(handle);
        }
    }

    /// The point of the C struct round trip: a digest computed from what the C
    /// caller holds must equal the one the kernel computes.
    #[test]
    fn a_digest_computed_from_the_c_struct_matches_the_kernel() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );

            let mut buffer = [0_i8; CALYBRIS_DIGEST_HEX_LEN + 1];
            assert_eq!(
                calybris_decision_digest_hex(&decision, buffer.as_mut_ptr(), buffer.len()),
                CALYBRIS_OK,
            );
            let hex: String = buffer[..CALYBRIS_DIGEST_HEX_LEN]
                .iter()
                .map(|byte| *byte as u8 as char)
                .collect();

            let native = (*handle).inner.prescribe(KernelInput::from(request));
            assert_eq!(hex, digest_to_hex(&decision_digest(&native)));

            calybris_policy_free(handle);
        }
    }

    #[test]
    fn a_buffer_one_byte_short_writes_nothing() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let mut buffer = [0x7f_i8; CALYBRIS_DIGEST_HEX_LEN];
            assert_eq!(
                calybris_policy_digest_hex(handle, buffer.as_mut_ptr(), buffer.len()),
                CALYBRIS_ERR_BUFFER_TOO_SMALL,
            );
            assert!(
                buffer.iter().all(|byte| *byte == 0x7f),
                "a refused write must leave the buffer untouched",
            );
            calybris_policy_free(handle);
        }
    }

    #[test]
    fn an_invented_action_is_refused_rather_than_transmuted() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );

            decision.action = 99;
            let mut buffer = [0_i8; CALYBRIS_DIGEST_HEX_LEN + 1];
            assert_eq!(
                calybris_decision_digest_hex(&decision, buffer.as_mut_ptr(), buffer.len()),
                CALYBRIS_ERR_UNKNOWN_VARIANT,
            );

            let mut valid = 1_u8;
            assert_eq!(
                calybris_verify(handle, &request, &decision, &mut valid),
                CALYBRIS_ERR_UNKNOWN_VARIANT,
            );
            assert_eq!(valid, 0, "a refused verification must not leave valid set");

            calybris_policy_free(handle);
        }
    }

    #[test]
    fn a_tampered_decision_fails_verification() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );

            let mut valid = 0_u8;
            assert_eq!(
                calybris_verify(handle, &request, &decision, &mut valid),
                CALYBRIS_OK,
            );
            assert_eq!(valid, 1, "the decision we just made must verify");

            decision.estimated_cost_microunits += 1;
            assert_eq!(
                calybris_verify(handle, &request, &decision, &mut valid),
                CALYBRIS_OK,
            );
            assert_eq!(valid, 0, "an edited decision must not verify");

            calybris_policy_free(handle);
        }
    }

    #[test]
    fn every_null_is_refused_rather_than_dereferenced() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            let mut handle = ptr::null_mut();

            assert_eq!(
                calybris_policy_new(ptr::null(), ptr::null(), 0, &mut handle),
                CALYBRIS_ERR_NULL,
            );
            assert_eq!(
                calybris_decide(ptr::null(), &request, &mut decision),
                CALYBRIS_ERR_NULL,
            );
            assert_eq!(
                calybris_input_digest_hex(ptr::null(), ptr::null_mut(), 0),
                CALYBRIS_ERR_NULL,
            );
            // Freeing null is defined as doing nothing.
            calybris_policy_free(ptr::null_mut());
        }
    }

    #[test]
    fn an_empty_catalog_builds_and_rejects_everything() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut handle = ptr::null_mut();
            let status = calybris_policy_new(&config(), ptr::null(), 0, &mut handle);
            if status != CALYBRIS_OK {
                // A kernel that refuses an empty catalog is also a valid answer;
                // what must not happen is a handle alongside an error.
                assert!(handle.is_null());
                return;
            }

            let mut count = 99;
            assert_eq!(calybris_policy_model_count(handle, &mut count), CALYBRIS_OK);
            assert_eq!(count, 0);

            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );
            assert_eq!(decision.action, KernelAction::Reject as u8);

            calybris_policy_free(handle);
        }
    }

    /// The out-parameter must be cleared before anything can fail.
    ///
    /// A caller holding `int valid = 1` from an earlier call and ignoring the
    /// status code would otherwise read the stale 1 as a successful
    /// verification. The header promises `*valid` is 0 on every failing path,
    /// and for a while it was not.
    #[test]
    fn a_failed_verification_clears_valid_before_it_fails() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let request = input();
            let mut decision = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(
                calybris_decide(handle, &request, &mut decision),
                CALYBRIS_OK
            );

            // Each failing argument in turn, from a caller-set 1.
            let mut valid = 1_u8;
            assert_eq!(
                calybris_verify(ptr::null(), &request, &decision, &mut valid),
                CALYBRIS_ERR_NULL,
            );
            assert_eq!(valid, 0, "a null policy left valid set");

            valid = 1;
            assert_eq!(
                calybris_verify(handle, ptr::null(), &decision, &mut valid),
                CALYBRIS_ERR_NULL,
            );
            assert_eq!(valid, 0, "a null input left valid set");

            valid = 1;
            assert_eq!(
                calybris_verify(handle, &request, ptr::null(), &mut valid),
                CALYBRIS_ERR_NULL,
            );
            assert_eq!(valid, 0, "a null decision left valid set");

            valid = 1;
            let mut refused = input();
            refused.risk_bps = 60_000;
            assert_eq!(
                calybris_verify(handle, &refused, &decision, &mut valid),
                CALYBRIS_ERR_INVALID_INPUT,
            );
            assert_eq!(valid, 0, "a refused request left valid set");

            calybris_policy_free(handle);
        }
    }

    /// The same rule for the policy handle: a failure must not leave a caller
    /// holding whatever pointer their variable had before the call.
    #[test]
    fn a_failed_construction_clears_the_handle_before_it_fails() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = policy();
            let catalog = models();

            // A stale but real pointer, which is the dangerous case: a caller
            // who ignores the status and frees it would free it twice.
            let mut out = handle;
            assert_eq!(
                calybris_policy_new(ptr::null(), catalog.as_ptr(), catalog.len(), &mut out),
                CALYBRIS_ERR_NULL,
            );
            assert!(out.is_null(), "a null config left a stale handle");

            let mut out = handle;
            assert_eq!(
                calybris_policy_new(&config(), ptr::null(), 2, &mut out),
                CALYBRIS_ERR_NULL,
            );
            assert!(out.is_null(), "a null catalog left a stale handle");

            // And a refused policy, not only a null argument.
            let mut reserved = models();
            reserved[0].model_id = 0;
            let mut out = handle;
            assert_eq!(
                calybris_policy_new(&config(), reserved.as_ptr(), reserved.len(), &mut out),
                CALYBRIS_ERR_RESERVED_MODEL_ID,
            );
            assert!(out.is_null(), "a refused policy left a stale handle");

            calybris_policy_free(handle);
        }
    }

    /// The reason the trusted constructor matters: the catalog is canonicalised,
    /// so the order a caller happens to pass candidates in cannot change the
    /// policy digest or the selected index.
    ///
    /// Without it a C caller and a Python caller handed the same candidates in a
    /// different order would disagree, which would make the ABI agree with
    /// nothing.
    #[test]
    fn catalog_order_does_not_change_the_policy() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let sorted = models();
            let mut reversed = models();
            reversed.reverse();

            let mut a = ptr::null_mut();
            let mut b = ptr::null_mut();
            assert_eq!(
                calybris_policy_new(&config(), sorted.as_ptr(), sorted.len(), &mut a),
                CALYBRIS_OK,
            );
            assert_eq!(
                calybris_policy_new(&config(), reversed.as_ptr(), reversed.len(), &mut b),
                CALYBRIS_OK,
            );

            let mut first = [0_i8; CALYBRIS_DIGEST_HEX_LEN + 1];
            let mut second = [0_i8; CALYBRIS_DIGEST_HEX_LEN + 1];
            assert_eq!(
                calybris_policy_digest_hex(a, first.as_mut_ptr(), first.len()),
                CALYBRIS_OK,
            );
            assert_eq!(
                calybris_policy_digest_hex(b, second.as_mut_ptr(), second.len()),
                CALYBRIS_OK,
            );
            assert_eq!(first, second, "catalog order changed the policy digest");

            // And the decision, including the index into the canonical catalog.
            let request = input();
            let mut one = std::mem::zeroed::<CalybrisDecision>();
            let mut two = std::mem::zeroed::<CalybrisDecision>();
            assert_eq!(calybris_decide(a, &request, &mut one), CALYBRIS_OK);
            assert_eq!(calybris_decide(b, &request, &mut two), CALYBRIS_OK);
            assert_eq!(one.selected_model_id, two.selected_model_id);
            assert_eq!(one.selected_model_index, two.selected_model_index);

            calybris_policy_free(a);
            calybris_policy_free(b);
        }
    }

    /// An enabled flag of 2 is refused rather than coerced to 1.
    ///
    /// The conversion used to normalise it with `!= 0`, which made the C path
    /// accept a catalog the Python binding refuses. Two callers of the same
    /// contract must not disagree about what a valid catalog is.
    #[test]
    fn an_enabled_flag_outside_zero_and_one_is_refused() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut catalog = models();
            catalog[1].enabled = 2;

            let mut out = ptr::null_mut();
            assert_eq!(
                calybris_policy_new(&config(), catalog.as_ptr(), catalog.len(), &mut out),
                CALYBRIS_ERR_INVALID_ENABLED_FLAG,
            );
            assert!(out.is_null());
        }
    }

    /// Model id 0 is reserved, and the C path must say so specifically rather
    /// than reporting a generic invalid policy.
    #[test]
    fn the_reserved_model_id_is_refused_by_name() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut catalog = models();
            catalog[0].model_id = 0;

            let mut out = ptr::null_mut();
            assert_eq!(
                calybris_policy_new(&config(), catalog.as_ptr(), catalog.len(), &mut out),
                CALYBRIS_ERR_RESERVED_MODEL_ID,
            );
            assert!(out.is_null());
        }
    }

    #[test]
    fn the_abi_version_and_crate_version_are_reported() {
        assert_eq!(calybris_abi_version(), CALYBRIS_ABI_VERSION);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let version = std::ffi::CStr::from_ptr(calybris_version());
            assert_eq!(version.to_str().expect("utf-8"), env!("CARGO_PKG_VERSION"));
        }
    }
}
