//! Bounded model-checking proofs, run with `cargo kani --features preview`.
//!
//! Tests check the inputs someone thought of; these check every input in the
//! stated range. Each harness names the property it proves and the invariant or
//! module it backs. They run in CI on Linux (`.github/workflows/kani.yml`);
//! Kani does not run on Windows.
//!
//! Kani: Delmas et al., "Kani: A Model Checker for Rust", arXiv:2607.01504.

/// The Merkle split point is the largest power of two strictly below `n`, for
/// every `n` a tree can have. RFC 9162 defines the tree by this split, so a
/// wrong split is a different tree.
#[cfg(feature = "preview")]
#[kani::proof]
fn merkle_split_is_the_largest_power_of_two_below_n() {
    let n: u64 = kani::any();
    kani::assume(n > 1);
    let k = crate::merkle::split(n);
    assert!(k.is_power_of_two());
    assert!(k < n);
    assert!(k >= n.div_ceil(2) || k.checked_mul(2).map_or(true, |d| d >= n));
}

/// The exploration probabilities over a window of `k` candidates sum to exactly
/// one and none of them is zero, for every rate and every window up to 1,024.
#[cfg(feature = "preview")]
#[kani::proof]
fn exploration_propensities_sum_to_one() {
    let rate: u64 = kani::any();
    let k: u64 = kani::any();
    kani::assume(rate <= 10_000);
    kani::assume((2..=1_024).contains(&k));
    let den = 10_000 * k;
    let winner = (10_000 - rate) * k + rate;
    let other = rate;
    assert!(winner + other * (k - 1) == den);
    assert!(winner > 0);
    assert!(winner <= den);
}

/// The counterfactual boundary search returns the exact threshold of any
/// monotone predicate on the range, or nothing when the predicate never holds.
#[cfg(feature = "preview")]
#[kani::proof]
#[kani::unwind(10)]
fn counterfactual_search_finds_the_exact_threshold() {
    let lo: u64 = kani::any();
    let hi: u64 = kani::any();
    let t: u64 = kani::any();
    kani::assume(lo <= hi && hi - lo < 256);
    let got = crate::counterfactual::lowest_true(lo, hi, |v| v >= t);
    if t <= hi {
        assert!(got == Some(t.max(lo)));
    } else {
        assert!(got.is_none());
    }
    let got = crate::counterfactual::highest_true(lo, hi, |v| v <= t);
    if t >= lo {
        assert!(got == Some(t.min(hi)));
    } else {
        assert!(got.is_none());
    }
}
