/* Calybris 1.0 — stable C ABI for the deterministic decision kernel.
 *
 * This header and CALYBRIS_ABI_VERSION are the contract. The struct layouts
 * below are frozen; so are the status codes and the function signatures.
 *
 * The struct layouts are NOT the digest layouts. Digests are defined
 * byte-for-byte in docs/SPECIFICATION.md and are a separate frozen thing: never
 * hash these structs, always ask for a digest.
 *
 * Every function returns a status. CALYBRIS_OK is zero and every error is
 * negative, so `if (status != CALYBRIS_OK)` is the check. No function unwinds:
 * a panic inside the library is caught and returned as CALYBRIS_ERR_PANIC.
 *
 * Licensed under Apache-2.0.
 */

#ifndef CALYBRIS_H
#define CALYBRIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A caller compiled against a different ABI version must refuse to load the
 * library rather than guess at the struct layouts. */
#define CALYBRIS_ABI_VERSION 1u

/* Hex digest length, not counting the terminating NUL. Buffers need 65. */
#define CALYBRIS_DIGEST_HEX_LEN 64

/* --- status codes ------------------------------------------------------- */

#define CALYBRIS_OK 0
#define CALYBRIS_ERR_NULL (-1)
#define CALYBRIS_ERR_INVALID_POLICY (-2)
#define CALYBRIS_ERR_INVALID_INPUT (-3)
#define CALYBRIS_ERR_BUFFER_TOO_SMALL (-4)
#define CALYBRIS_ERR_UNKNOWN_VARIANT (-5)
#define CALYBRIS_ERR_PANIC (-6)
#define CALYBRIS_ERR_CATALOG_TOO_LARGE (-7)
#define CALYBRIS_ERR_RESERVED_MODEL_ID (-8)
#define CALYBRIS_ERR_INVALID_ENABLED_FLAG (-9)

/* --- actions and reasons ------------------------------------------------ */

#define CALYBRIS_ACTION_EXECUTE_REQUESTED 1
#define CALYBRIS_ACTION_SUBSTITUTE 2
#define CALYBRIS_ACTION_REJECT 3

/* Below 100 the kernel selected something; at or above 100 it did not. */
#define CALYBRIS_REASON_REQUESTED_MAXIMIZES_UTILITY 1
#define CALYBRIS_REASON_ALTERNATIVE_MAXIMIZES_UTILITY 2
#define CALYBRIS_REASON_RISK_HARD_LIMIT 100
#define CALYBRIS_REASON_CONFIDENCE_HARD_LIMIT 101
#define CALYBRIS_REASON_NO_ENABLED_MODEL 102
#define CALYBRIS_REASON_QUALITY_CONSTRAINT 103
#define CALYBRIS_REASON_LATENCY_CONSTRAINT 104
#define CALYBRIS_REASON_CAPABILITY_CONSTRAINT 105
#define CALYBRIS_REASON_PROVIDER_CONSTRAINT 106
#define CALYBRIS_REASON_REGION_CONSTRAINT 107
#define CALYBRIS_REASON_BUDGET_CONSTRAINT 108
#define CALYBRIS_REASON_NON_POSITIVE_UTILITY 109
#define CALYBRIS_REASON_RISK_CEILING_CONSTRAINT 110

/* --- structures -------------------------------------------------------- */

/* One candidate. Costs are microunits per million tokens; proportions are
 * basis points, where 10000 is 100%.
 *
 * `enabled` must be exactly 0 or 1. Anything else is CALYBRIS_ERR_INVALID_ENABLED_FLAG,
 * not coerced to 1 — the same catalog must be valid or invalid whichever
 * language presents it.
 *
 * `model_id` 0 is reserved: CALYBRIS_ERR_RESERVED_MODEL_ID.
 *
 * The catalog is canonicalised on construction: candidates are sorted by
 * model_id, so the order they are passed in does not affect the policy digest
 * or selected_model_index. Two callers handing over the same candidates get the
 * same policy. */
typedef struct {
  uint32_t model_id;
  uint16_t provider_id;
  uint16_t quality_bps;
  uint16_t risk_ceiling_bps;
  uint8_t enabled;
  uint32_t p95_latency_ms;
  uint64_t capabilities;
  uint64_t region_mask;
  uint64_t input_cost_microunits_per_million_tokens;
  uint64_t output_cost_microunits_per_million_tokens;
} calybris_model;

/* The policy's limits, separate from the catalog. */
typedef struct {
  uint64_t policy_epoch;
  uint64_t catalog_epoch;
  uint16_t hard_risk_limit_bps;
  uint16_t minimum_confidence_bps;
  uint16_t risk_penalty_multiplier_bps;
  uint64_t latency_penalty_microunits_per_ms;
} calybris_policy_config;

/* One request. A zero limit means "no limit" for max_p95_latency_ms and
 * minimum_quality_bps; required_region_mask of zero means "any region". */
typedef struct {
  uint64_t request_sequence;
  uint32_t requested_model_id;
  uint32_t input_tokens;
  uint32_t output_tokens;
  int64_t business_value_microunits;
  uint64_t budget_limit_microunits;
  uint16_t risk_bps;
  uint16_t confidence_bps;
  uint16_t minimum_quality_bps;
  uint32_t max_p95_latency_ms;
  uint64_t required_capabilities;
  uint64_t allowed_provider_mask;
  uint64_t required_region_mask;
} calybris_input;

/* One decision. */
typedef struct {
  uint64_t request_sequence;
  uint8_t action;
  uint16_t reason;
  uint32_t selected_model_id;
  uint16_t selected_model_index;
  uint64_t estimated_cost_microunits;
  int64_t expected_utility_microunits;
  uint32_t counterfactual_model_id;
  int64_t counterfactual_utility_microunits;
  uint16_t evaluated_models;
  uint16_t eligible_models;
  uint64_t policy_epoch;
  uint64_t catalog_epoch;
} calybris_decision;

/* Opaque. From calybris_policy_new, released by calybris_policy_free. */
typedef struct calybris_policy calybris_policy;

/* --- functions --------------------------------------------------------- */

/* The ABI version this library was built for. Compare against
 * CALYBRIS_ABI_VERSION before anything else. */
uint32_t calybris_abi_version(void);

/* The crate version, static and NUL-terminated. Do not free. */
const char *calybris_version(void);

/* Builds a policy. On success *out holds a handle to free with
 * calybris_policy_free. `models` may be NULL only when model_count is zero.
 *
 * *out is set to NULL before anything can fail, so a variable that already held
 * a pointer never keeps it after an error. The one exception is a NULL `out`
 * itself, which returns CALYBRIS_ERR_NULL and writes nothing.
 *
 * Failures: CALYBRIS_ERR_NULL, CALYBRIS_ERR_RESERVED_MODEL_ID,
 * CALYBRIS_ERR_INVALID_ENABLED_FLAG, CALYBRIS_ERR_CATALOG_TOO_LARGE, or
 * CALYBRIS_ERR_INVALID_POLICY for anything else the kernel refuses. */
int calybris_policy_new(const calybris_policy_config *config,
                        const calybris_model *models, size_t model_count,
                        calybris_policy **out);

/* Releases a handle. Passing NULL does nothing. Never call twice on the same
 * handle. */
void calybris_policy_free(calybris_policy *policy);

/* How many candidates the policy holds. */
int calybris_policy_model_count(const calybris_policy *policy, size_t *out);

/* Decides one request. */
int calybris_decide(const calybris_policy *policy, const calybris_input *input,
                    calybris_decision *out);

/* Replays a decision. *valid is set to 1 only when the replay matches exactly.
 *
 * *valid is cleared to 0 before anything can fail, so a caller who ignores the
 * status code cannot read a stale 1 left from an earlier call. The one exception
 * is a NULL `valid` itself, which returns CALYBRIS_ERR_NULL and writes
 * nothing. */
int calybris_verify(const calybris_policy *policy, const calybris_input *input,
                    const calybris_decision *decision, uint8_t *valid);

/* Each writes CALYBRIS_DIGEST_HEX_LEN hex characters plus a NUL, so capacity
 * must be at least 65. On CALYBRIS_ERR_BUFFER_TOO_SMALL nothing is written, so
 * a truncated digest can never be mistaken for a whole one. */
int calybris_policy_digest_hex(const calybris_policy *policy, char *out,
                               size_t capacity);
int calybris_input_digest_hex(const calybris_input *input, char *out,
                              size_t capacity);
int calybris_decision_digest_hex(const calybris_decision *decision, char *out,
                                 size_t capacity);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CALYBRIS_H */
