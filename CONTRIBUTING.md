# Developing

The Rust workspace lives at the repository root; `rust-toolchain.toml` selects the toolchain.
These are the three checks CI runs on every pull request, and each must pass before merging:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The compile-fail tests in `crates/gateway-core/tests/compile-fail` compare compiler output
with checked-in `.stderr` files. If a new Rust release rewords an error, check that the error
is still the intended one, then regenerate them with
`TRYBUILD=overwrite cargo test -p gateway-core --test compile_fail`.
