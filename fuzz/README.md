# Fuzz targets

Six coverage-guided targets over the decoders and the kernel. They need nightly
and `cargo-fuzz`.

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run outcome_decode
```

## Where these actually run

**libFuzzer does not link on Windows MSVC.** Its coverage instrumentation
depends on ELF section-boundary symbols (`__start___sancov_cntrs` and friends)
that COFF has no equivalent for, so a Windows build fails at link time with or
without a sanitizer. On a Windows machine these can be compiled
(`cargo +nightly fuzz build <target>`) and no further.

They run in CI, on Linux, in the `fuzz` job. `tests/decoder_robustness.rs`
carries the same properties as proptest tests that run everywhere, so a
developer who cannot run the fuzzer is still checking the properties.

The crate is `#![forbid(unsafe_code)]`, so AddressSanitizer has very little to
find here. What these targets are looking for is panics, failed assertions, and
arithmetic that overflows — `overflow-checks` is on in the fuzz profile so that
an arithmetic mistake is a crash rather than a quietly wrong number.

## The targets

| Target | Input | What would be a finding |
|---|---|---|
| `snapshot_decode` | a budget snapshot | a snapshot reported balanced that does not balance |
| `receipt_decode` | a decision receipt | a receipt that does not survive re-encoding, so two readers could disagree about it |
| `wal_decode` | WAL lines | a panic reading a line, or a hash field that changes across a round trip |
| `outcome_decode` | an outcome record | a record `validate()` accepts that breaks a documented rule |
| `policy_decode` | a signed policy | **a forgery** — any artifact the fuzzer builds that verifies against a real snapshot |
| `kernel_decide` | raw integers | a panic, an overflow, a decision that differs between two identical calls, or `explain` disagreeing with `prescribe` |

`policy_decode` is the one with a security assertion rather than a robustness
one. The fuzzer holds no signing key, so nothing it can produce should ever
verify; if one does, the signature check is not covering what it claims to.

## Seeds

`fuzz/seeds/<target>/` is committed and holds real documents — a balanced
ledger, an abandoned outcome, a human selection with no propensity, an anchored
and an unanchored receipt. A fuzzer started on random bytes spends its whole
budget learning to emit `{`; seeded, it spends it on the fields.

`tests/fuzz_seeds.rs` asserts that every seed decodes as the type its target
decodes, and that the seed directories and the declared targets match. That test
exists because a seed that never decodes makes a target *look* seeded while
leaving it to rediscover the format — and nothing else would notice, since the
fuzzer cannot be run on every machine.

Regenerate them with:

```sh
cargo run --example gen_fuzz_seeds --features full
```

`fuzz/corpus/` and `fuzz/artifacts/` are the fuzzer's own working directories
and are not committed. The CI job copies `seeds/` into `corpus/` before running.

## If a target finds something

The input is written to `fuzz/artifacts/<target>/`. Reproduce it with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
```

Then add that input to `fuzz/seeds/<target>/` along with the fix, so the case is
kept. If the finding is in a digest layout rather than a decoder, read
[docs/COMPATIBILITY.md](../docs/COMPATIBILITY.md) first: changing a layout is
not available as a fix.
