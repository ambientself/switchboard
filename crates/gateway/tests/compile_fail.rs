//! The guarantees the boot gates put in types, shown by code that must not compile.
//!
//! As in the core: each file under `compile-fail/` must fail with the error checked in beside
//! it. Regenerate the `.stderr` files after a toolchain change with
//! `TRYBUILD=overwrite cargo test -p gateway --test compile_fail`, and review the diff.

#[test]
fn type_level_guards_refuse_to_compile() {
    trybuild::TestCases::new().compile_fail("tests/compile-fail/*.rs");
}
