//! `docs/INVARIANTS.md`, kept honest.
//!
//! The registry is only worth having if its right-hand column is true, so this
//! file reads it and fails when a row names a test that does not exist. It also
//! holds the two invariants about the shape of the API that no other test can
//! express, because they are enforced by whether this file compiles.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use calybris_core::budget::ConservationStatus;
use calybris_core::kernel::{CandidateVerdict, GateKind, KernelAction, KernelReason};
use calybris_core::outcome::{Disposition, IdentityField, SelectionStrategy};
use calybris_core::verify::VerifyResult;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `` `file::test_name` `` in the registry, in the order it appears.
fn registry_entries() -> Vec<(String, String, String)> {
    let text = fs::read_to_string(repo().join("docs/INVARIANTS.md")).expect("registry");
    let mut entries = Vec::new();

    for line in text.lines() {
        if !line.starts_with("| CAL-I") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // "", id, invariant, guarded by, ""
        assert_eq!(cells.len(), 5, "malformed row: {line}");
        let guard = cells[3].trim_matches('`');
        let (file, rest) = guard
            .split_once("::")
            .unwrap_or_else(|| panic!("`{guard}` is not `file::test_name`"));
        // A test inside a module is named `file::module::test`, so the function
        // is the last segment rather than everything after the first `::`.
        let test = rest.rsplit("::").next().unwrap_or(rest);
        entries.push((cells[1].to_string(), file.to_string(), test.to_string()));
    }

    assert!(!entries.is_empty(), "the registry parsed to nothing");
    entries
}

/// CAL-I047
#[test]
fn every_invariant_names_a_test_that_exists() {
    let tests_dir: &Path = &repo().join("tests");
    let mut missing = Vec::new();

    for (id, file, test) in registry_entries() {
        // An integration test, or a sibling crate's own unit tests. Both are
        // places an invariant legitimately lives.
        let candidates = [
            tests_dir.join(format!("{file}.rs")),
            repo().join(&file).join("src/lib.rs"),
        ];

        let found = candidates.iter().find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .map(|source| (path.clone(), source))
        });

        let Some((path, source)) = found else {
            missing.push(format!("{id}: no tests/{file}.rs and no {file}/src/lib.rs"));
            continue;
        };
        if !source.contains(&format!("fn {test}(")) {
            missing.push(format!("{id}: {} has no fn {test}", path.display()));
        }
    }

    assert!(
        missing.is_empty(),
        "the registry names tests that do not exist:\n  {}",
        missing.join("\n  "),
    );
}

/// CAL-I048
///
/// Uniqueness and shape, deliberately not position. An identifier has to mean
/// the same thing next year as it does today, so inserting a row must not
/// renumber the ones below it — which is exactly what requiring a gapless
/// sequence would force.
#[test]
fn the_identifiers_are_unique_and_well_formed() {
    let entries = registry_entries();
    let ids: Vec<&str> = entries.iter().map(|(id, _, _)| id.as_str()).collect();

    let unique: BTreeSet<&&str> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "the same identifier is used twice in the registry"
    );

    for id in &ids {
        let digits = id
            .strip_prefix("CAL-I")
            .unwrap_or_else(|| panic!("{id} is not a CAL-Innn identifier"));
        assert_eq!(digits.len(), 3, "{id} must have three digits");
        assert!(
            digits.chars().all(|c| c.is_ascii_digit()),
            "{id} must be CAL-I followed by digits",
        );
        assert_ne!(digits, "000", "identifiers start at CAL-I001");
    }
}

// --- CAL-I045: the semantics enums ----------------------------------------
//
// Each of these is a match with no wildcard arm. Adding a variant, or marking
// one of these enums `#[non_exhaustive]`, stops this file compiling — which is
// the point: a caller that has handled every case must keep having handled
// every case, and a `_` arm would silently swallow the one they had not thought
// about.

fn name_action(action: KernelAction) -> &'static str {
    match action {
        KernelAction::ExecuteRequested => "execute_requested",
        KernelAction::Substitute => "substitute",
        KernelAction::Reject => "reject",
    }
}

fn name_reason(reason: KernelReason) -> &'static str {
    match reason {
        KernelReason::RequestedModelMaximizesUtility => "requested_model_maximizes_utility",
        KernelReason::AlternativeMaximizesUtility => "alternative_maximizes_utility",
        KernelReason::RiskHardLimit => "risk_hard_limit",
        KernelReason::ConfidenceHardLimit => "confidence_hard_limit",
        KernelReason::NoEnabledModel => "no_enabled_model",
        KernelReason::QualityConstraint => "quality_constraint",
        KernelReason::LatencyConstraint => "latency_constraint",
        KernelReason::CapabilityConstraint => "capability_constraint",
        KernelReason::ProviderConstraint => "provider_constraint",
        KernelReason::RegionConstraint => "region_constraint",
        KernelReason::BudgetConstraint => "budget_constraint",
        KernelReason::NonPositiveUtility => "non_positive_utility",
        KernelReason::RiskCeilingConstraint => "risk_ceiling_constraint",
    }
}

fn name_gate(gate: GateKind) -> &'static str {
    match gate {
        GateKind::Disabled => "disabled",
        GateKind::Quality => "quality",
        GateKind::Latency => "latency",
        GateKind::Capability => "capability",
        GateKind::ProviderUnrepresentable => "provider_unrepresentable",
        GateKind::ProviderNotAllowed => "provider_not_allowed",
        GateKind::Region => "region",
        GateKind::RiskCeiling => "risk_ceiling",
    }
}

fn name_verdict(verdict: &CandidateVerdict) -> &'static str {
    match verdict {
        CandidateVerdict::Rejected { .. } => "rejected",
        CandidateVerdict::OverBudget { .. } => "over_budget",
        CandidateVerdict::NonPositiveUtility(_) => "non_positive_utility",
        CandidateVerdict::Eligible(_) => "eligible",
    }
}

fn name_disposition(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Applied => "applied",
        Disposition::Abandoned => "abandoned",
        Disposition::InFlight => "in_flight",
    }
}

fn name_strategy(strategy: SelectionStrategy) -> &'static str {
    match strategy {
        SelectionStrategy::MaximiseUtility => "maximise_utility",
        SelectionStrategy::Explore => "explore",
        SelectionStrategy::Human => "human",
    }
}

fn name_identity_field(field: IdentityField) -> &'static str {
    match field {
        IdentityField::Policy => "policy",
        IdentityField::Input => "input",
        IdentityField::Decision => "decision",
        IdentityField::RequestSequence => "request_sequence",
    }
}

fn name_conservation(status: &ConservationStatus) -> &'static str {
    match status {
        ConservationStatus::Balanced => "balanced",
        ConservationStatus::Violation { .. } => "violation",
        ConservationStatus::AggregateOverflow => "aggregate_overflow",
    }
}

fn name_verify(result: &VerifyResult) -> &'static str {
    match result {
        VerifyResult::Valid => "valid",
        VerifyResult::Mismatch { .. } => "mismatch",
        VerifyResult::DigestMismatch { .. } => "digest_mismatch",
    }
}

/// CAL-I045
#[test]
fn semantics_enums_stay_exhaustively_matchable() {
    // Compiling is the test. Calling them keeps the compiler from deciding they
    // are dead code, and pins the names each variant reports itself under.
    assert_eq!(name_action(KernelAction::Reject), "reject");
    assert_eq!(
        name_reason(KernelReason::BudgetConstraint),
        "budget_constraint"
    );
    assert_eq!(name_gate(GateKind::RiskCeiling), "risk_ceiling");
    assert_eq!(
        name_verdict(&CandidateVerdict::OverBudget {
            cost_microunits: 1,
            limit_microunits: 0,
        }),
        "over_budget",
    );
    assert_eq!(name_disposition(Disposition::InFlight), "in_flight");
    assert_eq!(name_strategy(SelectionStrategy::Human), "human");
    assert_eq!(name_identity_field(IdentityField::Policy), "policy");
    assert_eq!(name_conservation(&ConservationStatus::Balanced), "balanced");
    assert_eq!(name_verify(&VerifyResult::Valid), "valid");
}

/// CAL-I046
///
/// The mirror of the rule above. An error enum says what went wrong, and a
/// security fix may need to say something new, so every one of them must stay
/// open. There is no compile-time way to assert "this enum is
/// `#[non_exhaustive]`" from outside the crate, so this reads the source.
#[test]
fn error_enums_stay_extendable() {
    let src = repo().join("src");
    let mut open = Vec::new();
    let mut closed = Vec::new();

    let mut files: Vec<PathBuf> = fs::read_dir(&src)
        .expect("src")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "rs"))
        .collect();
    files.sort();

    for path in files {
        let source = fs::read_to_string(&path).expect("source");
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(rest) = line.trim().strip_prefix("pub enum ") else {
                continue;
            };
            let name = rest.trim_end_matches(" {").trim();
            if !name.ends_with("Error") {
                continue;
            }
            // Attributes sit directly above the declaration.
            let extendable = lines[..i]
                .iter()
                .rev()
                .take_while(|l| {
                    let t = l.trim();
                    t.starts_with('#') || t.starts_with("///") || t.starts_with("//")
                })
                .any(|l| l.trim() == "#[non_exhaustive]");
            if extendable {
                open.push(name.to_string());
            } else {
                closed.push(format!("{name} in {}", path.display()));
            }
        }
    }

    assert!(
        !open.is_empty(),
        "no error enums found — this test has stopped checking anything",
    );
    assert!(
        closed.is_empty(),
        "these error enums are not #[non_exhaustive], so a security fix could not \
         add a variant without a breaking change:\n  {}",
        closed.join("\n  "),
    );
}
