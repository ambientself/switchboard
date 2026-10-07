# Developing

The Rust workspace lives at the repository root. `rust-toolchain.toml` pins the exact
toolchain, and rustup installs it on first use. These are the checks CI runs on every pull
request, and each must pass before merging:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

The compile-fail tests in `crates/gateway-core/tests/compile-fail` compare compiler output
with checked-in `.stderr` files, which is why the toolchain is pinned to an exact version.
Bumping the pin is a deliberate change that regenerates those files in the same pull request,
with `TRYBUILD=overwrite cargo test -p gateway-core --test compile_fail`, after checking that
each error is still the intended one.

## The mutation check

```sh
python3 scripts/mutation_check.py
```

It breaks each guard in the gateway crates (the core, the identity verifier and the test fakes), one at a time, in a temporary copy of the workspace, and
requires the test suite to fail. It needs Python 3.12 or later and nothing else (if your
`python3` is older, `uv run --python 3.13 scripts/mutation_check.py`), never touches
the working tree, and prints one line per mutation. It takes a long while (a full test run per
mutation), so CI does not run it; run it after changing a guard or the tests that watch one,
and add a mutation for every guard you add.
