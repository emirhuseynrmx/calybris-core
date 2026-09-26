# Offline policy estimates

Use `evaluate_exact` with the exact probability from the same authenticated
exploration record. Outcome's rounded basis points are retained for compatibility;
they are insufficient to reconstruct probabilities below one basis point.
Equality after rounding is a consistency check, not authentication. Verify
the policy, decision, outcome binding and exact exploration record separately.

IPS assumes positivity over every target action, a correctly recorded logging
probability, an observed reward defined consistently for all records and no
unmeasured selection confounding. Deterministic logs cannot estimate a policy
that chooses unsupported actions. SNIPS is a ratio estimator with finite-sample
bias. Clipping weights changes the estimand and introduces bias; it is explicit
and rejects zero, negative, NaN or infinite clips.

The reported 95% interval uses a normal approximation to the IPS mean with
sample variance and independent, identically distributed observations of
finite variance. It is not an anytime-valid interval, simultaneous guarantee,
or calibrated confidence for time-correlated trading returns. Serial dependence,
adaptive experiments, heavy tails and repeated model selection require a
separate, justified uncertainty analysis (for example clustered/block resampling
or a pre-specified sequential method). ESS is a weight diagnostic, not an
independence test. Low-sample and low-ESS warnings do not repair these assumptions.

Nonfinite rewards are counted as excluded; this can itself create selection
bias, so investigate missing outcomes. Finite arithmetic overflow returns
`NumericOverflow`, never a successful NaN/Infinity estimate. Use appropriate
reward units or an explicitly chosen clip; do not silently discard large losses.
An empty usable set returns `NoUsableRecords`. No estimate is trading approval.
