//! The guarantees the design puts in types, shown by code that must not compile.
//!
//! Each file under `compile-fail/` is a call path the core must refuse, with the compiler's
//! error checked in beside it. If a change makes one of them compile, this test fails. The
//! `.stderr` files are compiler output, so a new Rust release can change their wording: review
//! such a diff to confirm the error is still the intended one, then regenerate with
//! `TRYBUILD=overwrite cargo test -p gateway-core --test compile_fail`.

#[test]
fn type_level_guards_refuse_to_compile() {
    trybuild::TestCases::new().compile_fail("tests/compile-fail/*.rs");
}
