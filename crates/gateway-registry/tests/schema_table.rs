//! The loader's rules for input schemas, as a table: the subset of JSON Schema 2020-12 the
//! argument check enforces or ignores loads, and anything else is refused at load, with the
//! error that names it. Also, every registry file checked in to the repository still loads.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{base, load, rehash, set, value};
use gateway_registry::{Registry, RegistryError};

/// `wiki__search` approved with `schema` as its input schema.
fn loaded(schema: &str) -> Result<Registry, RegistryError> {
    let mut table = base();
    set(&mut table, "tools.1", "input_schema", value(schema));
    rehash(&mut table);
    load(&table)
}

/// An object schema whose one property, `q`, has `schema`.
fn property(schema: &str) -> String {
    format!(r#"{{ type = "object", properties = {{ q = {schema} }} }}"#)
}

fn refused(schema: &str) -> RegistryError {
    match loaded(schema) {
        Ok(_) => panic!("{schema} loaded"),
        Err(error) => {
            assert!(
                matches!(&error, RegistryError::SchemaUnfollowed { tool, .. }
                    | RegistryError::SchemaMalformed { tool, .. }
                    | RegistryError::SchemaDialect { tool, .. }
                    | RegistryError::SchemaAdditionalPropertiesMalformed { tool, .. }
                    | RegistryError::SchemaRepeatedName { tool, .. }
                    if tool.as_str() == "wiki__search"),
                "{schema}: {error:?}"
            );
            error
        }
    }
}

#[test]
fn every_enforced_keyword_and_annotation_loads() {
    let schemas = [
        r#"{ type = "object", "$schema" = "https://json-schema.org/draft/2020-12/schema" }"#,
        &property(r#"{ type = "string", minLength = 0, maxLength = 2.0 }"#),
        &property(r#"{ type = ["integer", "null"], minimum = -1, maximum = 1.5 }"#),
        &property("{ exclusiveMinimum = 0, exclusiveMaximum = 10 }"),
        &property(r#"{ enum = ["a", 1, [true], { k = "v" }] }"#),
        &property("{ enum = [] }"),
        &property("{ const = { a = [1] } }"),
        &property(r#"{ type = "array", items = { type = "string" }, minItems = 1, maxItems = 3 }"#),
        &property("{ items = false }"),
        &property("{ items = true }"),
        &property("true"),
        &property("false"),
        &property(
            r#"{ type = "object", required = ["a"], properties = { a = {} }, additionalProperties = false }"#,
        ),
        &property(r#"{ type = "object", additionalProperties = { type = "integer" } }"#),
        &property("{ additionalProperties = true }"),
        &property(
            r#"{ title = "T", description = "D", default = 1, examples = [1], deprecated = false, readOnly = true, writeOnly = false, "$comment" = "C", format = "uri" }"#,
        ),
        // Annotation values are not checked at load, though 2020-12 gives them a form: the
        // check reads nothing from them.
        &property(r#"{ format = 7, title = ["not", "text"] }"#),
        // Names that differ, even by case or where one type contains the other, are unique.
        &property(r#"{ type = ["number", "integer", "null"] }"#),
        &property(
            r#"{ type = "object", required = ["a", "A", "b"], properties = { a = {}, A = {}, b = {} } }"#,
        ),
        // A property may be named like a keyword.
        r#"{ type = "object", properties = { pattern = { type = "string" }, "$ref" = true } }"#,
    ];
    for schema in schemas {
        if let Err(error) = loaded(schema) {
            panic!("{schema}: {error}");
        }
    }
}

#[test]
fn a_dialect_other_than_2020_12_is_refused() {
    for (dialect, written) in [
        (
            r#""http://json-schema.org/draft-07/schema#""#,
            "http://json-schema.org/draft-07/schema#",
        ),
        (
            r#""https://json-schema.org/draft/2019-09/schema""#,
            "https://json-schema.org/draft/2019-09/schema",
        ),
        (
            r#""http://json-schema.org/draft-04/schema#""#,
            "http://json-schema.org/draft-04/schema#",
        ),
        // Not the 2020-12 identifier as written: neither with a fragment nor over http.
        (
            r#""https://json-schema.org/draft/2020-12/schema#""#,
            "https://json-schema.org/draft/2020-12/schema#",
        ),
        (
            r#""http://json-schema.org/draft/2020-12/schema""#,
            "http://json-schema.org/draft/2020-12/schema",
        ),
        ("7", "7"),
    ] {
        let schema = format!(r#"{{ type = "object", "$schema" = {dialect} }}"#);
        match refused(&schema) {
            RegistryError::SchemaDialect { dialect, .. } => assert_eq!(dialect, written),
            other => panic!("{schema}: {other:?}"),
        }
    }
    // `$schema` belongs at the root only.
    let schema = property(r#"{ "$schema" = "https://json-schema.org/draft/2020-12/schema" }"#);
    match refused(&schema) {
        RegistryError::SchemaUnfollowed { keyword, at, .. } => {
            assert_eq!(
                (keyword.as_str(), at.as_str()),
                ("$schema", "/properties/q")
            );
        }
        other => panic!("{schema}: {other:?}"),
    }
}

#[test]
fn a_keyword_outside_the_approved_subset_is_refused_wherever_it_is() {
    let keywords = [
        // Not enforced, so not accepted.
        ("pattern", r#""^a""#),
        ("multipleOf", "2"),
        ("uniqueItems", "true"),
        ("contains", "{}"),
        ("minContains", "1"),
        ("maxContains", "1"),
        ("minProperties", "1"),
        ("maxProperties", "1"),
        ("propertyNames", "{}"),
        ("dependentRequired", "{}"),
        ("contentMediaType", r#""text/plain""#),
        ("x-anything", "1"),
        // Not followed.
        ("$ref", r##""#/$defs/a""##),
        ("$dynamicRef", r##""#a""##),
        ("$id", r#""https://example.test/s""#),
        ("$anchor", r#""a""#),
        ("$defs", "{}"),
        ("$vocabulary", "{}"),
        ("allOf", "[{}]"),
        ("anyOf", "[{}]"),
        ("oneOf", "[{}]"),
        ("not", "{}"),
        ("if", "{}"),
        ("then", "{}"),
        ("else", "{}"),
        ("dependentSchemas", "{}"),
        ("patternProperties", "{}"),
        ("unevaluatedProperties", "false"),
        ("unevaluatedItems", "false"),
        ("prefixItems", "[{}]"),
        // Valid only in earlier drafts.
        ("definitions", "{}"),
        ("dependencies", "{}"),
        ("additionalItems", "false"),
        ("$recursiveRef", r##""#""##),
    ];
    for (keyword, keyword_value) in keywords {
        let inside = format!(r#"{{ "{keyword}" = {keyword_value} }}"#);
        for (schema, at) in [
            (
                format!(r#"{{ type = "object", "{keyword}" = {keyword_value} }}"#),
                "",
            ),
            (property(&inside), "/properties/q"),
            (
                property(&format!("{{ items = {inside} }}")),
                "/properties/q/items",
            ),
            (
                property(&format!("{{ additionalProperties = {inside} }}")),
                "/properties/q/additionalProperties",
            ),
        ] {
            match refused(&schema) {
                RegistryError::SchemaUnfollowed {
                    keyword: got,
                    at: got_at,
                    ..
                } => {
                    assert_eq!((got.as_str(), got_at.as_str()), (keyword, at), "{schema}");
                }
                other => panic!("{schema}: {other:?}"),
            }
        }
    }
}

#[test]
fn a_malformed_additional_properties_is_refused_at_load() {
    // #94: read loosely, any of these would leave the object open.
    for malformed in [r#""false""#, "0", "1", "[]", "[false]", r#""{}""#] {
        for (schema, at) in [
            (
                format!(r#"{{ type = "object", additionalProperties = {malformed} }}"#),
                "/additionalProperties",
            ),
            (
                property(&format!("{{ additionalProperties = {malformed} }}")),
                "/properties/q/additionalProperties",
            ),
        ] {
            match refused(&schema) {
                RegistryError::SchemaAdditionalPropertiesMalformed { at: got, .. } => {
                    assert_eq!(got.as_str(), at, "{schema}");
                }
                other => panic!("{schema}: {other:?}"),
            }
        }
    }
}

#[test]
fn a_keyword_not_in_its_2020_12_form_is_refused() {
    let cases = [
        (r#"{ type = "str" }"#, "/properties/q/type"),
        (r#"{ type = "int" }"#, "/properties/q/type"),
        ("{ type = 1 }", "/properties/q/type"),
        (r#"{ type = ["string", 1] }"#, "/properties/q/type"),
        (r#"{ type = ["string", "text"] }"#, "/properties/q/type"),
        (r#"{ required = "a" }"#, "/properties/q/required"),
        ("{ required = [1] }", "/properties/q/required"),
        ("{ required = true }", "/properties/q/required"),
        (r#"{ enum = "a" }"#, "/properties/q/enum"),
        ("{ minLength = -1 }", "/properties/q/minLength"),
        ("{ maxLength = 1.5 }", "/properties/q/maxLength"),
        (r#"{ minItems = "1" }"#, "/properties/q/minItems"),
        ("{ maxItems = -0.5 }", "/properties/q/maxItems"),
        (r#"{ minimum = "1" }"#, "/properties/q/minimum"),
        ("{ maximum = [1] }", "/properties/q/maximum"),
        // Draft-04's boolean form.
        (
            "{ exclusiveMinimum = true }",
            "/properties/q/exclusiveMinimum",
        ),
        (
            "{ exclusiveMaximum = false }",
            "/properties/q/exclusiveMaximum",
        ),
        // Draft-07's list form of items.
        ("{ items = [{}] }", "/properties/q/items"),
        (r#"{ items = "string" }"#, "/properties/q/items"),
        (r#"{ properties = ["a"] }"#, "/properties/q/properties"),
        (
            r#"{ properties = { a = "string" } }"#,
            "/properties/q/properties/a",
        ),
        (r#""string""#, "/properties/q"),
        ("1", "/properties/q"),
    ];
    for (inner, at) in cases {
        let schema = property(inner);
        match refused(&schema) {
            RegistryError::SchemaMalformed { at: got, .. } => {
                assert_eq!(got.as_str(), at, "{schema}");
            }
            other => panic!("{schema}: {other:?}"),
        }
    }
}

#[test]
fn a_type_or_required_list_that_repeats_a_name_is_refused_at_load() {
    // #127: 2020-12 says the names in each list must be unique.
    let nested = [
        (
            r#"{ type = ["string", "string"] }"#,
            "string",
            "/properties/q/type",
        ),
        (
            r#"{ type = ["null", "integer", "null"] }"#,
            "null",
            "/properties/q/type",
        ),
        (
            r#"{ type = "object", required = ["a", "a"], properties = { a = {} } }"#,
            "a",
            "/properties/q/required",
        ),
        (
            r#"{ type = "object", required = ["a", "b", "a"] }"#,
            "a",
            "/properties/q/required",
        ),
        (
            r#"{ type = "array", items = { type = ["string", "string"] } }"#,
            "string",
            "/properties/q/items/type",
        ),
        (
            r#"{ type = "object", additionalProperties = { type = "object", required = ["b", "b"] } }"#,
            "b",
            "/properties/q/additionalProperties/required",
        ),
    ];
    let mut schemas: Vec<(String, &str, &str)> = nested
        .iter()
        .map(|(inner, name, at)| (property(inner), *name, *at))
        .collect();
    // At the root as well.
    schemas.push((
        r#"{ type = "object", required = ["q", "q"], properties = { q = {} } }"#.into(),
        "q",
        "/required",
    ));
    for (schema, name, at) in schemas {
        match refused(&schema) {
            RegistryError::SchemaRepeatedName {
                name: got,
                at: got_at,
                ..
            } => {
                assert_eq!((got.as_str(), got_at.as_str()), (name, at), "{schema}");
            }
            other => panic!("{schema}: {other:?}"),
        }
    }
    // The error names the tool, the name and where the list is.
    let error = refused(&property(r#"{ type = ["string", "string"] }"#));
    assert_eq!(
        error.to_string(),
        "tool `wiki__search`'s input schema names `string` twice in the list at \
         `/properties/q/type`; JSON Schema 2020-12 requires its names to be unique"
    );
}

#[test]
fn a_list_not_of_names_is_malformed_before_it_is_checked_for_repeats() {
    for (inner, at) in [
        (
            r#"{ type = ["string", "string", 1] }"#,
            "/properties/q/type",
        ),
        (r#"{ required = ["a", "a", 1] }"#, "/properties/q/required"),
    ] {
        let schema = property(inner);
        match refused(&schema) {
            RegistryError::SchemaMalformed { at: got, .. } => assert_eq!(got.as_str(), at),
            other => panic!("{schema}: {other:?}"),
        }
    }
}

/// Every file under `directory` named `registry*.toml`, at any depth, skipping build output.
fn registry_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "target" && !name.starts_with('.') {
                registry_files(&path, found);
            }
        } else if name.starts_with("registry") && name.ends_with(".toml") {
            found.push(path);
        }
    }
}

#[test]
fn every_registry_file_in_the_repository_still_loads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut found = Vec::new();
    registry_files(&root.join("crates"), &mut found);
    registry_files(&root.join("deploy"), &mut found);
    found.sort();
    // The demo's, the kind and Compose registries, Compose's withdrawn one, and the receipt
    // gate's: if one moves, this test should be told where.
    assert!(found.len() >= 5, "{found:?}");
    for path in found {
        if let Err(error) = Registry::load(&path) {
            panic!("{}: {error}", path.display());
        }
    }
}
