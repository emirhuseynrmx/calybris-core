# Release checklist

This checklist keeps the Rust crate, Python wheel, proof fixtures, and published
artifacts on one auditable version.

## Prepare

1. Update `Cargo.toml`, `bindings/python/Cargo.toml`, and `CHANGELOG.md`.
2. Regenerate proof values only when intentionally introducing a new versioned
   proof tag. Never silently re-pin an existing golden value.
3. Run:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
   cargo test --locked --workspace --all-targets --all-features
   cargo test --locked --no-default-features
   cargo package --locked
   python scripts/release_contract.py --tag v0.5.7
   python -m maturin build --release --locked --out dist
   python -m pip install dist/calybris-*.whl --force-reinstall
   python -m pytest python/tests -q
   ```

4. Confirm Semgrep, Bandit, pip-audit, cargo-audit, and cargo-deny are clean.
5. Review the packaged crate with `cargo package --list`.

## Publish (maintainer approval required)

1. Confirm the tracked tree is clean, then create and push a signed tag from
   the exact approved commit:

   ```bash
   git status --short
   git tag -s v0.5.7 -m "Calybris 0.5.7"
   git push origin v0.5.7
   ```

2. Wait for the tag-triggered Release workflow to pass. It re-runs security and
   patch-SemVer gates on the tag commit, verifies the signed tag and version
   contract, tests installed wheels, emits CycloneDX SBOMs, provenance metadata,
   checksums, and attestations, then publishes PyPI and GitHub Release assets.
   Manual `workflow_dispatch` runs never publish.

3. Publish the Rust crate only after those gates are green, from a clean checkout
   of the same tag:

   ```bash
   git switch --detach v0.5.7
   python scripts/release_contract.py --tag v0.5.7
   cargo publish --locked
   ```

## Verify

```bash
cargo install calybris-core --version 0.5.7
python -m pip install calybris==0.5.7
gh attestation verify calybris-0.5.7-*.whl -R emirhuseynrmx/calybris-core
sha256sum --check SHA256SUMS
```
