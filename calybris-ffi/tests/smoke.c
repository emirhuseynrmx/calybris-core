/* A C program that uses the ABI the way a caller would.
 *
 * This is the only test that proves the header and the library agree. The Rust
 * unit tests call the same functions, but they call them from Rust, with Rust's
 * idea of the struct layouts — so they cannot catch a header that says
 * something different. A C compiler reading calybris.h can.
 *
 * Build and run it with scripts/check_c_abi.py, which CI also runs.
 *
 * Exits 0 on success. Every failure prints what it expected and returns
 * non-zero, so a CI log says which assertion went.
 */

#include <stdio.h>
#include <string.h>

#include "calybris.h"

/* Pinned in tests/fixtures/calybris_outcome_v1.json, and asserted by the Rust
 * and Python golden tests over the same catalog and request. */
#define EXPECTED_POLICY_HEX                                                    \
  "d3f12aa201a164f2668d3a4055710bc895a2345acb0b89cf39a91f35f6d7c173"
#define EXPECTED_INPUT_HEX                                                     \
  "ccb29ca46a0533292092a00258e6ea6220befbe4f4071e81a57f18b85689c31e"
#define EXPECTED_DECISION_HEX                                                  \
  "55cc31eba5dcf8c2d5702723feaebb359b754019154980dd4fef54b70cd1a554"

static int failures = 0;

#define CHECK(condition, ...)                                                  \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("  FAIL %s:%d  ", __FILE__, __LINE__);                            \
      printf(__VA_ARGS__);                                                     \
      printf("\n");                                                            \
      failures++;                                                              \
    }                                                                          \
  } while (0)

int main(void) {
  printf("calybris C ABI smoke test\n");

  /* The first thing a real caller does. */
  CHECK(calybris_abi_version() == CALYBRIS_ABI_VERSION,
        "abi version %u, header says %u", calybris_abi_version(),
        CALYBRIS_ABI_VERSION);
  CHECK(calybris_version() != NULL && calybris_version()[0] != '\0',
        "no version string");
  printf("  abi %u, version %s\n", calybris_abi_version(), calybris_version());

  calybris_policy_config config;
  memset(&config, 0, sizeof(config));
  config.policy_epoch = 1;
  config.catalog_epoch = 1;
  config.hard_risk_limit_bps = 9000;
  config.minimum_confidence_bps = 1000;
  config.risk_penalty_multiplier_bps = 2000;
  config.latency_penalty_microunits_per_ms = 5;

  calybris_model models[2];
  memset(models, 0, sizeof(models));

  models[0].model_id = 1;
  models[0].provider_id = 0;
  models[0].quality_bps = 9000;
  models[0].risk_ceiling_bps = 9500;
  models[0].enabled = 1;
  models[0].p95_latency_ms = 200;
  models[0].capabilities = 1;
  models[0].region_mask = ~(uint64_t)0;
  models[0].input_cost_microunits_per_million_tokens = 3000000;
  models[0].output_cost_microunits_per_million_tokens = 15000000;

  models[1].model_id = 2;
  models[1].provider_id = 1;
  models[1].quality_bps = 8000;
  models[1].risk_ceiling_bps = 9500;
  models[1].enabled = 1;
  models[1].p95_latency_ms = 100;
  models[1].capabilities = 1;
  models[1].region_mask = ~(uint64_t)0;
  models[1].input_cost_microunits_per_million_tokens = 1000000;
  models[1].output_cost_microunits_per_million_tokens = 5000000;

  calybris_policy *policy = NULL;
  int status = calybris_policy_new(&config, models, 2, &policy);
  CHECK(status == CALYBRIS_OK, "policy_new returned %d", status);
  CHECK(policy != NULL, "policy_new gave no handle");
  if (policy == NULL) {
    printf("cannot continue without a policy\n");
    return 1;
  }

  size_t count = 99;
  status = calybris_policy_model_count(policy, &count);
  CHECK(status == CALYBRIS_OK, "model_count returned %d", status);
  CHECK(count == 2, "model_count said %zu, expected 2", count);

  calybris_input input;
  memset(&input, 0, sizeof(input));
  input.request_sequence = 42;
  input.requested_model_id = 1;
  input.input_tokens = 1000;
  input.output_tokens = 500;
  input.business_value_microunits = 5000000;
  input.budget_limit_microunits = 50000000;
  input.risk_bps = 1000;
  input.confidence_bps = 9000;
  input.required_capabilities = 1;
  input.allowed_provider_mask = ~(uint64_t)0;

  calybris_decision decision;
  memset(&decision, 0, sizeof(decision));
  status = calybris_decide(policy, &input, &decision);
  CHECK(status == CALYBRIS_OK, "decide returned %d", status);
  CHECK(decision.request_sequence == 42, "sequence %llu, expected 42",
        (unsigned long long)decision.request_sequence);
  CHECK(decision.action == CALYBRIS_ACTION_EXECUTE_REQUESTED ||
            decision.action == CALYBRIS_ACTION_SUBSTITUTE,
        "unexpected action %u", (unsigned)decision.action);
  CHECK(decision.selected_model_id == 1 || decision.selected_model_id == 2,
        "selected an unknown model %u",
        (unsigned)decision.selected_model_id);
  CHECK(decision.evaluated_models == 2, "evaluated %u, expected 2",
        (unsigned)decision.evaluated_models);
  printf("  decided: model %u, action %u, utility %lld\n",
         (unsigned)decision.selected_model_id, (unsigned)decision.action,
         (long long)decision.expected_utility_microunits);

  /* Deciding twice must give the same answer. This is the whole point of the
   * kernel, and it has to hold across the boundary too. */
  calybris_decision again;
  memset(&again, 0, sizeof(again));
  status = calybris_decide(policy, &input, &again);
  CHECK(status == CALYBRIS_OK, "second decide returned %d", status);
  CHECK(memcmp(&decision, &again, sizeof(decision)) == 0,
        "two identical calls produced different decisions");

  /* Digests. 65 bytes: 64 hex characters and a NUL. */
  char policy_hex[CALYBRIS_DIGEST_HEX_LEN + 1];
  char input_hex[CALYBRIS_DIGEST_HEX_LEN + 1];
  char decision_hex[CALYBRIS_DIGEST_HEX_LEN + 1];

  status = calybris_policy_digest_hex(policy, policy_hex, sizeof(policy_hex));
  CHECK(status == CALYBRIS_OK, "policy_digest returned %d", status);
  CHECK(strlen(policy_hex) == CALYBRIS_DIGEST_HEX_LEN,
        "policy digest is %zu characters", strlen(policy_hex));

  status = calybris_input_digest_hex(&input, input_hex, sizeof(input_hex));
  CHECK(status == CALYBRIS_OK, "input_digest returned %d", status);
  CHECK(strlen(input_hex) == CALYBRIS_DIGEST_HEX_LEN,
        "input digest is %zu characters", strlen(input_hex));

  status =
      calybris_decision_digest_hex(&decision, decision_hex, sizeof(decision_hex));
  CHECK(status == CALYBRIS_OK, "decision_digest returned %d", status);
  CHECK(strlen(decision_hex) == CALYBRIS_DIGEST_HEX_LEN,
        "decision digest is %zu characters", strlen(decision_hex));

  CHECK(strcmp(policy_hex, input_hex) != 0,
        "the policy and input digests are identical, which cannot be right");
  printf("  policy   %s\n", policy_hex);
  printf("  input    %s\n", input_hex);
  printf("  decision %s\n", decision_hex);

  /* The same bytes the Rust and Python golden tests pin, from
   * tests/fixtures/calybris_outcome_v1.json. This is the cross-language claim:
   * one set of bytes, three callers. The catalog and request above are the ones
   * that fixture was generated from, so these must match exactly.
   *
   * If one of these fails, a digest layout has changed. That needs a new tag —
   * see docs/COMPATIBILITY.md — and never a re-pinned constant here. */
  CHECK(strcmp(policy_hex, EXPECTED_POLICY_HEX) == 0,
        "policy digest\n    got      %s\n    expected %s", policy_hex,
        EXPECTED_POLICY_HEX);
  CHECK(strcmp(input_hex, EXPECTED_INPUT_HEX) == 0,
        "input digest\n    got      %s\n    expected %s", input_hex,
        EXPECTED_INPUT_HEX);
  CHECK(strcmp(decision_hex, EXPECTED_DECISION_HEX) == 0,
        "decision digest\n    got      %s\n    expected %s", decision_hex,
        EXPECTED_DECISION_HEX);
  printf("  digests match the pinned vectors\n");

  /* A buffer one byte short must write nothing at all. */
  char tight[CALYBRIS_DIGEST_HEX_LEN];
  memset(tight, 0x7f, sizeof(tight));
  status = calybris_policy_digest_hex(policy, tight, sizeof(tight));
  CHECK(status == CALYBRIS_ERR_BUFFER_TOO_SMALL,
        "a short buffer returned %d, expected %d", status,
        CALYBRIS_ERR_BUFFER_TOO_SMALL);
  {
    int untouched = 1;
    size_t i;
    for (i = 0; i < sizeof(tight); i++) {
      if (tight[i] != (char)0x7f) {
        untouched = 0;
      }
    }
    CHECK(untouched, "a refused write modified the buffer");
  }

  /* Verification. */
  uint8_t valid = 0;
  status = calybris_verify(policy, &input, &decision, &valid);
  CHECK(status == CALYBRIS_OK, "verify returned %d", status);
  CHECK(valid == 1, "the decision we just made did not verify");

  calybris_decision tampered = decision;
  tampered.estimated_cost_microunits += 1;
  valid = 1;
  status = calybris_verify(policy, &input, &tampered, &valid);
  CHECK(status == CALYBRIS_OK, "verify of a tampered decision returned %d",
        status);
  CHECK(valid == 0, "an edited decision verified");

  /* An invented action must be refused, not reinterpreted. */
  calybris_decision invented = decision;
  invented.action = 99;
  status = calybris_decision_digest_hex(&invented, decision_hex,
                                        sizeof(decision_hex));
  CHECK(status == CALYBRIS_ERR_UNKNOWN_VARIANT,
        "an invented action returned %d, expected %d", status,
        CALYBRIS_ERR_UNKNOWN_VARIANT);

  /* Nulls. */
  status = calybris_decide(NULL, &input, &decision);
  CHECK(status == CALYBRIS_ERR_NULL, "a null policy returned %d", status);
  calybris_policy_free(NULL); /* defined as doing nothing */

  /* A request the kernel refuses. Basis points above 10000 is not a policy
   * anyone meant to write. */
  calybris_input bad = input;
  bad.risk_bps = 60000;
  status = calybris_decide(policy, &bad, &decision);
  CHECK(status == CALYBRIS_ERR_INVALID_INPUT,
        "an out-of-range request returned %d, expected %d", status,
        CALYBRIS_ERR_INVALID_INPUT);

  calybris_policy_free(policy);

  if (failures == 0) {
    printf("  all checks passed\n");
    return 0;
  }
  printf("  %d check(s) failed\n", failures);
  return 1;
}
