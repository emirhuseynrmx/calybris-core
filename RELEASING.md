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
   python -m maturin build --release --out dist
   python -m pip install dist/calybris-*.whl --force-reinstall
   python -m pytest python/tests -q
   ```

4. Confirm Semgrep, Bandit, pip-audit, cargo-audit, and cargo-deny are clean.
5. Review the packaged crate with `cargo package --list`.

## Publish

1. Publish the Rust crate from the exact release commit:

   ```bash
   cargo publish --locked
   ```

2. Create a signed tag:

   ```bash
   git tag -s v0.5.7 -m "Calybris 0.5.7"
   git push origin v0.5.7
   ```

3. The release workflow rebuilds and tests an installed wheel, builds the
   platform wheel matrix and sdist, validates metadata, generates
   `SHA256SUMS`, creates GitHub artifact attestations, publishes to PyPI through
   Trusted Publishing, and attaches distributions to the GitHub release.

## Verify

```bash
cargo install calybris-core --version 0.5.7
python -m pip install calybris==0.5.7
gh attestation verify calybris-0.5.7-*.whl -R emirhuseynrmx/calybris-core
sha256sum --check SHA256SUMS
```
