//! Generates the outcome golden vectors.
//!
//! Output is the JSON fixture body for `tests/fixtures/calybris_outcome_v1.json`.
//! Run it once, when the format is first frozen. **Never re-run it to make a
//! failing test pass**: a changed value means the format changed, and that needs
//! a new digest tag, not a new fixture.
//!
//! ```text
//! cargo run --example gen_outcome_vectors --features serde
//! ```

use calybris_core::digest::{digest_to_hex, input_digest, policy_digest};
use calybris_core::kernel::{KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS};
use calybris_core::outcome::{
    identity_digest, outcome_digest, selection_digest, DecisionIdentity, Disposition, Observation,
    Outcome, Selection,
};

fn catalog() -> Vec<KernelModel> {
    vec![
        KernelModel {
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
        },
        KernelModel {
            model_id: 2,
            provider_id: 1,
            quality_bps: 8_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 100,
            capabilities: 0b1,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 1_000_000,
            output_cost_microunits_per_million_tokens: 5_000_000,
        },
    ]
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::try_new(1, 1, 9_000, 1_000, 2_000, 5, catalog()).expect("policy")
}

fn request(sequence: u64, budget: u64) -> KernelInput {
    KernelInput {
        request_sequence: sequence,
        requested_model_id: 1,
        input_tokens: 1_000,
        output_tokens: 500,
        budget_limit_microunits: budget,
        business_value_microunits: 5_000_000,
        minimum_quality_bps: 0,
        max_p95_latency_ms: 0,
        risk_bps: 1_000,
        confidence_bps: 9_000,
        required_capabilities: 0b1,
        allowed_provider_mask: ALL_PROVIDERS,
        required_region_mask: 0,
    }
}

const AT: u64 = 1_760_000_000_000_000;

fn main() {
    let policy = policy();
    println!("{{");
    println!("  \"spec\": \"calybris.outcome.v1\",");
    println!(
        "  \"comment\": \"Pinned outcome, selection and identity digests. A failure here means the format changed, which needs a new tag (calyout2), never a re-pinned value.\","
    );
    println!("  \"tags\": {{");
    println!("    \"identity\": \"calyidn1\",");
    println!("    \"selection\": \"calysel1\",");
    println!("    \"outcome\": \"calyout1\"");
    println!("  }},");
    println!(
        "  \"policy_digest_hex\": \"{}\",",
        digest_to_hex(&policy_digest(&policy))
    );
    println!("  \"cases\": [");

    let mut rows: Vec<(String, KernelInput, Outcome)> = Vec::new();

    // 1. The ordinary case: ranked, followed, finished, fully measured.
    let input = request(42, 50_000_000);
    let decision = policy.prescribe(input);
    rows.push((
        "followed-applied-fully-measured".into(),
        input,
        Outcome::applied(
            &policy,
            &input,
            &decision,
            AT,
            Observation {
                realized_cost_microunits: Some(4_100_000),
                realized_latency_ms: Some(238),
                succeeded: Some(true),
            },
        ),
    ));

    // 2. Nobody acted on it.
    rows.push((
        "followed-abandoned".into(),
        input,
        Outcome::abandoned(&policy, &input, &decision, AT),
    ));

    // 3. Still running: cost so far, no verdict.
    let mut in_flight = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(2_000_000),
            realized_latency_ms: None,
            succeeded: None,
        },
    );
    in_flight.disposition = Disposition::InFlight;
    rows.push(("followed-in-flight-partial".into(), input, in_flight));

    // 4. A deliberate exploration at the smallest usable probability.
    let mut explored = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(9_000_000),
            realized_latency_ms: Some(95),
            succeeded: Some(false),
        },
    );
    explored.selection = Selection::explored(2, 1);
    rows.push(("explored-one-basis-point".into(), input, explored));

    // 5. A person chose. No propensity at all.
    let mut human = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(4_100_000),
            realized_latency_ms: Some(238),
            succeeded: Some(true),
        },
    );
    human.selection = Selection::human(2);
    rows.push(("human-no-propensity".into(), input, human));

    // 6. A zero measurement, which must not collide with an absent one.
    let mut zero = Outcome::applied(
        &policy,
        &input,
        &decision,
        AT,
        Observation {
            realized_cost_microunits: Some(0),
            realized_latency_ms: Some(0),
            succeeded: Some(false),
        },
    );
    zero.revision = 7;
    rows.push(("zero-measurements-revision-seven".into(), input, zero));

    // 7. A rejection, abandoned, which is the only thing it can be.
    let rejected_input = request(43, 1);
    let rejection = policy.prescribe(rejected_input);
    rows.push((
        "rejection-abandoned".into(),
        rejected_input,
        Outcome::abandoned(&policy, &rejected_input, &rejection, AT),
    ));

    let last = rows.len() - 1;
    for (i, (label, input, outcome)) in rows.iter().enumerate() {
        let identity = &outcome.identity;
        println!("    {{");
        println!("      \"label\": \"{label}\",");
        println!("      \"request_sequence\": {},", identity.request_sequence);
        println!(
            "      \"input_digest_hex\": \"{}\",",
            digest_to_hex(&input_digest(input))
        );
        println!(
            "      \"decision_digest_hex\": \"{}\",",
            digest_to_hex(&identity.decision_digest)
        );
        println!(
            "      \"identity_digest_hex\": \"{}\",",
            digest_to_hex(&identity_digest(identity))
        );
        println!(
            "      \"selection_digest_hex\": \"{}\",",
            digest_to_hex(&selection_digest(&outcome.selection))
        );
        println!(
            "      \"outcome_digest_hex\": \"{}\"",
            digest_to_hex(&outcome_digest(outcome))
        );
        print!("    }}");
        println!("{}", if i == last { "" } else { "," });

        // The identity has to be reproducible from the three parts, or the
        // vector is pinning something a reader cannot rebuild.
        let decision = if identity.request_sequence == 43 {
            rejection
        } else {
            decision
        };
        assert_eq!(*identity, DecisionIdentity::of(&policy, input, &decision));
    }

    println!("  ]");
    println!("}}");
}
