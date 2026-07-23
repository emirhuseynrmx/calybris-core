# Calyra Audit Report and README Integration

**Date:** 2026-07-23  
**Status:** Approved design  
**Language:** English only

## Purpose

Add a concise Calyra audit section to the Calybris Core README and publish a
visually polished six-to-eight-page PDF that explains what Calyra validates,
what the recorded Calybris 0.5.7 run demonstrated, and which boundaries remain.
The material must improve release credibility without disclosing Calyra's
proprietary testing methods.

## Public disclosure boundary

The public README and PDF may disclose:

- Calyra's role as a private adversarial validation and evidence engine.
- The named, high-level guarantee categories evaluated.
- Aggregate scenario, invariant, fault, replay, parity, and resource results.
- Exact target version, commit, tree, lockfile, adapter, and pack digests when
  they are already part of the sanitized public evidence.
- Honest limitations, including dirty-tree status and non-release-safe sandbox
  capabilities.
- The distinction between a scenario pass and a verified release attestation.

They must not disclose:

- Scenario definitions, seeds, schedules, or minimized reproducers.
- Fault-injection implementation, application points, or crash-hook mechanics.
- Private fixtures, malformed payloads, corpus contents, or exploit recipes.
- Calyra source structure, internal algorithms, command protocol, or signing
  material.
- Proprietary minimization, orchestration, scoring, or sandbox internals.
- Claims not present in the sanitized evidence bundle.

## README design

Add an **Independent adversarial validation with Calyra** section after the
performance section and before the security posture. It will:

1. Define Calyra in two sentences.
2. State that Calyra creates controlled execution conditions while Calybris
   remains the decision and proof-producing target.
3. Present a compact evidence table with the final sanitized run metrics.
4. Link to the PDF report.
5. Include a clear limitation note: an audit run covers the declared scope and
   is not a claim of bug-free software.

The section must not imply that Calyra is open source or bundled with Calybris.

## PDF design

Create `docs/CALYRA_AUDIT_REPORT_0.5.7.pdf` from a tracked Typst source at
`docs/calyra-audit-report-0.5.7.typ`.

The report will contain six-to-eight pages:

1. **Cover and verdict** — Calybris 0.5.7 target, Calyra name, evidence-backed
   status, and restrained visual identity.
2. **Why Calyra exists** — the validation problem and the separation between
   world construction and target decisions.
3. **Assurance surface** — nine public guarantee categories without test
   mechanics.
4. **Recorded evidence** — scenario, invariant, fault, replay, parity, resource,
   and provenance results.
5. **Trust chain** — target identity, artifact identity, evidence roots, and
   replay relationship at a conceptual level.
6. **Release boundary** — what passed, what remains non-passing, and why dirty
   trees or incomplete sandbox guarantees cannot produce a verified badge.
7. **Method and limitations** — sanitized high-level methodology and explicit
   non-guarantees.
8. **Conclusion** — concise release-readiness interpretation and links.

If the content fits naturally in seven pages, pages seven and eight may be
combined. The report must never pad pages with decorative filler.

## Visual direction

- A4 portrait, generous whitespace, editorial grid.
- White and near-black base with restrained Calyra mint accents.
- Typography optimized for technical reading; no cyberpunk motifs.
- Small diagrams built from Typst primitives, not external network assets.
- Metric cards and a nine-category matrix; no screenshots of private tooling.
- Footer with document title, version, page number, and evidence date.
- Accessibility-conscious contrast and text selectable in the PDF.

## Evidence source and accuracy rules

The document generator must consume or manually bind only values from the final
sanitized Calyra result. Before generation:

1. Align Calyra and Calybris source-digest computation.
2. Build the Python wheel and Rust adapter from the same source state.
3. Re-run Calyra smoke with the release artifact supplied.
4. Require replay equality and Rust/Python parity to be 1,000,000 ppm.
5. Report dirty-tree and sandbox limitations exactly as observed.

No signed or verified release badge may appear unless Calyra's release gate
actually produces one.

## Verification

- Compile the Typst source without warnings or missing assets.
- Render every PDF page to images and inspect for clipping, overflow, weak
  contrast, broken links, and inconsistent spacing.
- Extract PDF text to confirm selectable content and expected page count.
- Verify README links resolve locally and all reported figures match the final
  sanitized JSON.
- Run repository formatting, test, and release-contract checks after adding the
  documentation artifacts.

## Acceptance criteria

- README contains a concise, accurate Calyra section.
- PDF is six-to-eight polished English pages.
- Public content reveals no proprietary Calyra mechanics.
- Every metric is traceable to sanitized evidence.
- Limitations are prominent rather than hidden.
- Typst source and generated PDF are both tracked.
- No push, publication, signed run, or verified badge is created without
  explicit owner approval.
