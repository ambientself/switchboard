//! The argument-to-resource adapter and the undeclared-argument check, as tables.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{base, load, rehash, set, value};
use gateway_core::{Resource, ResourceDeclaration, Resources, ToolName};
use gateway_registry::{ArgumentAdapter, ArgumentError, Registry};
use serde_json::{Value, json};

fn tool(name: &str) -> ToolName {
    ToolName::parse(name).unwrap()
}

fn resource(system: &str, kind: &str, identifier: &str) -> Resource {
    Resource {
        system: system.into(),
        kind: kind.into(),
        identifier: identifier.into(),
    }
}

/// The base registry, with `docs__read` reading two resources and given a schema with nested
/// objects, arrays and an open object.
fn registry() -> Registry {
    let mut table = base();
    set(
        &mut table,
        "tools.0",
        "resources",
        value(
            r#"{ from_arguments = [
                { from_argument = "project", system = "docs", kind = "project" },
                { from_argument = "space", system = "wiki", kind = "space" },
            ] }"#,
        ),
    );
    set(
        &mut table,
        "tools.0",
        "input_schema",
        value(
            r#"{ type = "object", properties = {
                project = { type = "string" },
                space = { type = "string" },
                "a/b" = { type = "string" },
                options = { type = "object", properties = { depth = { type = "integer" } } },
                tags = { type = "array", items = { type = "object", properties = { name = { type = "string" } } } },
                filter = { type = "object" },
                anything = true,
            } }"#,
        ),
    );
    rehash(&mut table);
    load(&table).unwrap()
}

fn adapter<'r>(registry: &'r Registry, name: &str) -> &'r ArgumentAdapter {
    &registry.adapters()[&tool(name)]
}

fn resources(adapter: &ArgumentAdapter, arguments: Value) -> Resources {
    adapter.resources(arguments.as_object().unwrap())
}

#[test]
fn the_adapter_names_one_resource_per_source_or_none_at_all() {
    let registry = registry();
    let adapter = adapter(&registry, "docs__read");
    assert_eq!(adapter.declaration(), ResourceDeclaration::Declared);
    let both = Resources::Named(vec![
        resource("docs", "project", "atlas"),
        resource("wiki", "space", "eng"),
    ]);
    let none = Resources::Named(Vec::new());
    let table = [
        (json!({"project": "atlas", "space": "eng"}), &both),
        (
            json!({"space": "eng", "project": "atlas", "options": {}}),
            &both,
        ),
        (
            json!({"project": "atlas", "space": "eng", "extra": "borealis"}),
            &both,
        ),
        (json!({}), &none),
        (json!({"project": "atlas"}), &none),
        (json!({"space": "eng"}), &none),
        (json!({"project": "atlas", "space": null}), &none),
        (json!({"project": "atlas", "space": 7}), &none),
        (json!({"project": "atlas", "space": true}), &none),
        (json!({"project": "atlas", "space": ["eng"]}), &none),
        (json!({"project": "atlas", "space": {"name": "eng"}}), &none),
        (json!({"project": "", "space": "eng"}), &none),
        (json!({"project": "atlas", "space": ""}), &none),
        (json!({"Project": "atlas", "space": "eng"}), &none),
    ];
    for (arguments, want) in table {
        assert_eq!(&resources(adapter, arguments.clone()), want, "{arguments}");
    }
}

#[test]
fn identifiers_are_passed_on_exactly() {
    let registry = registry();
    let adapter = adapter(&registry, "docs__read");
    for identifier in [" atlas", "ATLAS", "atlas/../borealis", "*", "atlas\n"] {
        assert_eq!(
            resources(adapter, json!({"project": identifier, "space": "eng"})),
            Resources::Named(vec![
                resource("docs", "project", identifier),
                resource("wiki", "space", "eng"),
            ]),
            "{identifier:?}"
        );
    }
}

#[test]
fn a_tool_with_no_resources_names_none_whatever_its_arguments() {
    let registry = registry();
    let adapter = adapter(&registry, "wiki__search");
    assert_eq!(adapter.declaration(), ResourceDeclaration::NoResources);
    assert!(adapter.sources().is_empty());
    for arguments in [
        json!({}),
        json!({"query": "atlas"}),
        json!({"project": "atlas"}),
    ] {
        assert_eq!(resources(adapter, arguments), Resources::Named(Vec::new()));
    }
}

#[test]
fn arguments_the_schema_does_not_declare_are_refused_at_any_depth() {
    let registry = registry();
    let adapter = adapter(&registry, "docs__read");
    let accepted = [
        json!({}),
        json!({"project": "atlas", "space": "eng"}),
        json!({"options": {"depth": 2}}),
        json!({"options": {}}),
        json!({"tags": [{"name": "a"}, {}]}),
        json!({"tags": []}),
        json!({"filter": {"anything": {"at": ["any", "depth"]}}}),
        json!({"anything": {"x": 1}}),
        json!({"a/b": "x"}),
        // Not this check's business: types and required properties.
        json!({"project": 7, "options": "deep"}),
    ];
    for arguments in accepted {
        assert_eq!(adapter.check_arguments(&arguments), Ok(()), "{arguments}");
    }
    let refused = [
        (json!({"other_project": "borealis"}), "/other_project"),
        (
            json!({"project": "atlas", "Project": "borealis"}),
            "/Project",
        ),
        (
            json!({"options": {"depth": 2, "project": "borealis"}}),
            "/options/project",
        ),
        (
            json!({"tags": [{"name": "a"}, {"name": "b", "project": "x"}]}),
            "/tags/1/project",
        ),
        (json!({"a/b": "x", "c~d": "y"}), "/c~0d"),
        (json!({"x/y": "z"}), "/x~1y"),
    ];
    for (arguments, path) in refused {
        match adapter.check_arguments(&arguments) {
            Err(ArgumentError::Undeclared { tool, path: got }) => {
                assert_eq!(tool.as_str(), "docs__read");
                assert_eq!(got.as_str(), path, "{arguments}");
            }
            other => panic!("{arguments}: {other:?}"),
        }
    }
}

#[test]
fn arguments_that_are_not_an_object_are_refused() {
    let registry = registry();
    let adapter = adapter(&registry, "wiki__search");
    for arguments in [json!(null), json!([]), json!("atlas"), json!(7)] {
        assert_eq!(
            adapter.check_arguments(&arguments),
            Err(ArgumentError::NotAnObject {
                tool: tool("wiki__search")
            }),
            "{arguments}"
        );
    }
}

#[test]
fn a_schema_that_lists_no_properties_accepts_any() {
    let mut table = base();
    common::remove(&mut table, "tools.1.input_schema", "properties");
    rehash(&mut table);
    let registry = load(&table).unwrap();
    let adapter = adapter(&registry, "wiki__search");
    assert_eq!(adapter.check_arguments(&json!({"anything": 1})), Ok(()));
}

#[test]
fn a_schema_that_lists_no_property_refuses_every_one() {
    let mut table = base();
    set(
        &mut table,
        "tools.1.input_schema",
        "properties",
        value("{}"),
    );
    rehash(&mut table);
    let registry = load(&table).unwrap();
    let adapter = adapter(&registry, "wiki__search");
    assert_eq!(adapter.check_arguments(&json!({})), Ok(()));
    assert!(adapter.check_arguments(&json!({"query": "x"})).is_err());
}
