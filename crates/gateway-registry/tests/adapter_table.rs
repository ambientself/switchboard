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
        // In each object, an undeclared property is found before any value is checked.
        (
            json!({"options": {"depth": "deep", "project": 7}}),
            "/options/project",
        ),
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
    // A declared property of the wrong type is invalid, not undeclared.
    for (arguments, path) in [
        (json!({"project": 7}), "/project"),
        (json!({"options": "deep"}), "/options"),
        (json!({"options": {"depth": 2.5}}), "/options/depth"),
        (json!({"tags": [{"name": 1}]}), "/tags/0/name"),
    ] {
        assert_eq!(
            answer(adapter, &arguments),
            Answer::Invalid(path.into(), "type"),
            "{arguments}"
        );
    }
}

/// What the argument check answered, with the pointer as text.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Passes,
    Undeclared(String),
    Invalid(String, &'static str),
    NotAnObject,
}

fn answer(adapter: &ArgumentAdapter, arguments: &Value) -> Answer {
    match adapter.check_arguments(arguments) {
        Ok(()) => Answer::Passes,
        Err(ArgumentError::Undeclared { tool, path }) => {
            assert_eq!(&tool, adapter.tool());
            Answer::Undeclared(path.as_str().into())
        }
        Err(ArgumentError::Invalid {
            tool,
            path,
            keyword,
        }) => {
            assert_eq!(&tool, adapter.tool());
            Answer::Invalid(path.as_str().into(), keyword)
        }
        Err(ArgumentError::NotAnObject { .. }) => Answer::NotAnObject,
    }
}

/// `wiki__search` approved with `schema` as its input schema.
fn adapter_with(schema: &str) -> ArgumentAdapter {
    let mut table = base();
    set(&mut table, "tools.1", "input_schema", value(schema));
    rehash(&mut table);
    let registry = load(&table).unwrap_or_else(|error| panic!("{schema}: {error}"));
    adapter(&registry, "wiki__search").clone()
}

/// An object schema whose one property, `v`, has `schema`.
fn property(schema: &str) -> String {
    format!(r#"{{ type = "object", properties = {{ v = {schema} }} }}"#)
}

/// One table case: a schema for the property `v`, values of `v` it accepts, and values it
/// refuses, each with the keyword it fails at `/v`.
struct KeywordCase {
    schema: &'static str,
    accepted: Vec<Value>,
    refused: Vec<(Value, &'static str)>,
}

fn keyword_case(
    schema: &'static str,
    accepted: Vec<Value>,
    refused: Vec<(Value, &'static str)>,
) -> KeywordCase {
    KeywordCase {
        schema,
        accepted,
        refused,
    }
}

#[test]
fn each_enforced_keyword_accepts_and_refuses_as_2020_12_says() {
    let cases = [
        // type, by name and by list.
        keyword_case(
            r#"{ type = "string" }"#,
            vec![json!("x"), json!("")],
            vec![
                (json!(1), "type"),
                (json!(null), "type"),
                (json!(true), "type"),
                (json!(["x"]), "type"),
                (json!({"x": "y"}), "type"),
            ],
        ),
        keyword_case(
            r#"{ type = "integer" }"#,
            // 1.0 is an integer in 2020-12, however it is written.
            vec![
                json!(1),
                json!(-1),
                json!(0),
                json!(1.0),
                json!(-3.0),
                json!(1e3),
                json!(u64::MAX),
            ],
            vec![
                (json!(1.5), "type"),
                (json!(-0.001), "type"),
                (json!("1"), "type"),
                (json!(true), "type"),
            ],
        ),
        keyword_case(
            r#"{ type = "number" }"#,
            vec![json!(1), json!(1.5), json!(1.0), json!(-2)],
            vec![(json!("1"), "type"), (json!(null), "type")],
        ),
        keyword_case(
            r#"{ type = "boolean" }"#,
            vec![json!(true), json!(false)],
            vec![(json!(0), "type"), (json!("true"), "type")],
        ),
        keyword_case(
            r#"{ type = "null" }"#,
            vec![json!(null)],
            vec![
                (json!(false), "type"),
                (json!(0), "type"),
                (json!(""), "type"),
            ],
        ),
        keyword_case(
            r#"{ type = "array" }"#,
            vec![json!([]), json!([1, "x"])],
            vec![(json!({}), "type"), (json!("[]"), "type")],
        ),
        keyword_case(
            r#"{ type = "object" }"#,
            vec![json!({}), json!({"open": {"at": "any depth"}})],
            vec![(json!([]), "type"), (json!(null), "type")],
        ),
        keyword_case(
            r#"{ type = ["string", "null"] }"#,
            vec![json!("x"), json!(null)],
            vec![(json!(1), "type"), (json!(false), "type")],
        ),
        keyword_case(
            r#"{ type = ["integer", "boolean"] }"#,
            vec![json!(2.0), json!(true)],
            vec![(json!(2.5), "type"), (json!("2"), "type")],
        ),
        // enum and const, with numbers compared by value at any depth.
        keyword_case(
            r#"{ enum = ["a", 1, [1, 2], { k = 1 }] }"#,
            vec![
                json!("a"),
                json!(1),
                json!(1.0),
                json!([1, 2]),
                json!([1.0, 2]),
                json!({"k": 1.0}),
            ],
            vec![
                (json!("b"), "enum"),
                (json!("1"), "enum"),
                (json!(2), "enum"),
                (json!(1.5), "enum"),
                (json!([2, 1]), "enum"),
                (json!([1, 2, 3]), "enum"),
                (json!({"k": 2}), "enum"),
                (json!({"k": 1, "j": 1}), "enum"),
                (json!(true), "enum"),
            ],
        ),
        keyword_case(
            "{ enum = [1.0] }",
            vec![json!(1), json!(1.0)],
            vec![(json!(2), "enum"), (json!(1.01), "enum")],
        ),
        keyword_case(
            "{ enum = [] }",
            vec![],
            vec![(json!("x"), "enum"), (json!(null), "enum")],
        ),
        keyword_case(
            "{ const = 1 }",
            vec![json!(1), json!(1.0)],
            vec![
                (json!(2), "const"),
                (json!(1.5), "const"),
                (json!("1"), "const"),
                (json!(true), "const"),
            ],
        ),
        keyword_case(
            "{ const = 1.0 }",
            vec![json!(1), json!(1.0)],
            vec![(json!(0), "const")],
        ),
        keyword_case(
            r#"{ const = { a = [1, "x"] } }"#,
            vec![json!({"a": [1, "x"]}), json!({"a": [1.0, "x"]})],
            vec![
                (json!({"a": [1, "x"], "b": 1}), "const"),
                (json!({"a": ["x", 1]}), "const"),
                (json!({}), "const"),
            ],
        ),
        // Lengths, in code points: "日本語" is three, in nine bytes.
        keyword_case(
            r#"{ type = "string", minLength = 2, maxLength = 3 }"#,
            vec![
                json!("ab"),
                json!("abc"),
                json!("éé"),
                json!("日本語"),
                json!("😀😀"),
            ],
            vec![
                (json!(""), "minLength"),
                (json!("a"), "minLength"),
                (json!("é"), "minLength"),
                (json!("abcd"), "maxLength"),
                (json!("😀😀😀😀"), "maxLength"),
            ],
        ),
        keyword_case(
            "{ minLength = 2.0, maxLength = 2.0 }",
            // A length bound says nothing about a value that is not a string.
            vec![json!("ab"), json!(7), json!(["a", "b", "c"])],
            vec![(json!("a"), "minLength"), (json!("abc"), "maxLength")],
        ),
        // Number bounds, inclusive and exclusive, across integers and floats.
        keyword_case(
            r#"{ type = "number", minimum = 1, maximum = 3 }"#,
            vec![json!(1), json!(1.0), json!(2.5), json!(3), json!(3.0)],
            vec![
                (json!(0), "minimum"),
                (json!(0.999), "minimum"),
                (json!(-5), "minimum"),
                (json!(3.0001), "maximum"),
                (json!(4), "maximum"),
            ],
        ),
        keyword_case(
            "{ exclusiveMinimum = 1, exclusiveMaximum = 3 }",
            vec![
                json!(2),
                json!(1.5),
                json!(1.0001),
                json!(2.999),
                json!("1"),
            ],
            vec![
                (json!(1), "exclusiveMinimum"),
                (json!(1.0), "exclusiveMinimum"),
                (json!(0), "exclusiveMinimum"),
                (json!(3), "exclusiveMaximum"),
                (json!(3.0), "exclusiveMaximum"),
            ],
        ),
        keyword_case(
            "{ minimum = 1.5, exclusiveMaximum = 2.5 }",
            vec![json!(2), json!(1.5), json!(2.4)],
            vec![
                (json!(1), "minimum"),
                (json!(1.4999), "minimum"),
                (json!(2.5), "exclusiveMaximum"),
                (json!(3), "exclusiveMaximum"),
            ],
        ),
        // 2^53 + 1 is not a float: compared as one, it would round to 2^53 and pass.
        keyword_case(
            "{ maximum = 9007199254740992 }",
            vec![
                json!(9_007_199_254_740_992_u64),
                json!(9_007_199_254_740_992.0),
            ],
            vec![(json!(9_007_199_254_740_993_u64), "maximum")],
        ),
        // Item counts, then each item.
        keyword_case(
            r#"{ type = "array", minItems = 1, maxItems = 2 }"#,
            vec![json!([1]), json!([1, "x"])],
            vec![(json!([]), "minItems"), (json!([1, 2, 3]), "maxItems")],
        ),
        keyword_case(
            r#"{ type = "array", items = { type = "integer" } }"#,
            vec![json!([]), json!([1, 2.0])],
            vec![],
        ),
        keyword_case("{ items = true }", vec![json!([1, "x", {"a": []}])], vec![]),
        // The schema true admits anything; false admits nothing (#94).
        keyword_case(
            "true",
            vec![json!(null), json!({"a": {"b": 1}}), json!([1])],
            vec![],
        ),
        keyword_case(
            "false",
            vec![],
            vec![
                (json!(null), "false"),
                (json!(""), "false"),
                (json!({}), "false"),
                (json!([]), "false"),
            ],
        ),
        // required, and an open object accepted as one value.
        keyword_case(
            r#"{ type = "object", required = ["x"] }"#,
            vec![json!({"x": 1}), json!({"x": null, "y": {"z": 2}})],
            vec![(json!({}), "required"), (json!({"y": 1}), "required")],
        ),
        // additionalProperties as a schema checks every value of an object with no properties.
        keyword_case(
            r#"{ type = "object", additionalProperties = { type = "string", maxLength = 1 } }"#,
            vec![json!({}), json!({"a": "x", "b": ""})],
            vec![],
        ),
        // Annotations are accepted and say nothing: a format is not checked.
        keyword_case(
            r#"{ type = "string", title = "T", description = "D", default = "x", examples = ["y"], deprecated = true, readOnly = true, writeOnly = false, "$comment" = "C", format = "email" }"#,
            vec![json!("not an email address")],
            vec![(json!(1), "type")],
        ),
    ];
    for case in cases {
        let adapter = adapter_with(&property(case.schema));
        assert_eq!(
            answer(&adapter, &json!({})),
            Answer::Passes,
            "{}",
            case.schema
        );
        for accepted in case.accepted {
            assert_eq!(
                answer(&adapter, &json!({ "v": accepted })),
                Answer::Passes,
                "{}: {accepted}",
                case.schema
            );
        }
        for (refused, keyword) in case.refused {
            assert_eq!(
                answer(&adapter, &json!({ "v": refused })),
                Answer::Invalid("/v".into(), keyword),
                "{}: {refused}",
                case.schema
            );
        }
    }
}

#[test]
fn a_failure_inside_an_item_or_a_property_is_found_where_it_is() {
    let cases = [
        (
            r#"{ type = "array", items = { type = "integer" } }"#,
            json!({"v": [1, "2"]}),
            Answer::Invalid("/v/1".into(), "type"),
        ),
        // items false admits no item (#94).
        (
            "{ items = false }",
            json!({"v": [1]}),
            Answer::Invalid("/v/0".into(), "false"),
        ),
        (
            r#"{ type = "array", items = { type = "object", required = ["n"] } }"#,
            json!({"v": [{"n": 1}, {}]}),
            Answer::Invalid("/v/1".into(), "required"),
        ),
        (
            r#"{ type = "object", additionalProperties = { type = "string", maxLength = 1 } }"#,
            json!({"v": {"a": "x", "b": 2}}),
            Answer::Invalid("/v/b".into(), "type"),
        ),
        (
            r#"{ type = "object", additionalProperties = { type = "string", maxLength = 1 } }"#,
            json!({"v": {"a": "xy"}}),
            Answer::Invalid("/v/a".into(), "maxLength"),
        ),
        // A property declared false admits no value (#94).
        (
            r#"{ type = "object", properties = { gone = false } }"#,
            json!({"v": {"gone": false}}),
            Answer::Invalid("/v/gone".into(), "false"),
        ),
        (
            r#"{ type = "object", properties = { gone = false } }"#,
            json!({"v": {}}),
            Answer::Passes,
        ),
        // Item counts are checked before the items.
        (
            r#"{ items = { type = "string" }, maxItems = 1 }"#,
            json!({"v": [1, 2]}),
            Answer::Invalid("/v".into(), "maxItems"),
        ),
    ];
    for (schema, arguments, want) in cases {
        let adapter = adapter_with(&property(schema));
        assert_eq!(answer(&adapter, &arguments), want, "{schema}: {arguments}");
    }
}

#[test]
fn required_is_checked_at_the_root_after_undeclared_properties() {
    let adapter = adapter_with(
        r#"{ type = "object", required = ["a", "b"], properties = { a = { type = "string" }, b = true, c = true } }"#,
    );
    let cases = [
        (json!({"a": "x", "b": null}), Answer::Passes),
        (json!({"a": "x", "b": 1, "c": 2}), Answer::Passes),
        (
            json!({"a": "x"}),
            Answer::Invalid(String::new(), "required"),
        ),
        (json!({}), Answer::Invalid(String::new(), "required")),
        (json!({"d": 1}), Answer::Undeclared("/d".into())),
        (
            json!({"a": 1, "b": 1}),
            Answer::Invalid("/a".into(), "type"),
        ),
        (json!([]), Answer::NotAnObject),
    ];
    for (arguments, want) in cases {
        assert_eq!(answer(&adapter, &arguments), want, "{arguments}");
    }
}

#[test]
fn additional_properties_as_a_schema_checks_every_value_of_an_object_with_no_properties() {
    let adapter =
        adapter_with(r#"{ type = "object", additionalProperties = { type = "string" } }"#);
    assert_eq!(answer(&adapter, &json!({})), Answer::Passes);
    assert_eq!(answer(&adapter, &json!({"a": "x"})), Answer::Passes);
    assert_eq!(
        answer(&adapter, &json!({"a": "x", "b": {"at": "depth"}})),
        Answer::Invalid("/b".into(), "type")
    );
    // Where properties are listed, they decide: any other property is undeclared, whatever
    // additionalProperties says.
    let adapter = adapter_with(
        r#"{ type = "object", properties = { a = { type = "string" } }, additionalProperties = { type = "string" } }"#,
    );
    assert_eq!(answer(&adapter, &json!({"a": "x"})), Answer::Passes);
    assert_eq!(
        answer(&adapter, &json!({"b": "x"})),
        Answer::Undeclared("/b".into())
    );
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
    for schema in [
        r#"{ type = "object" }"#,
        r#"{ type = "object", additionalProperties = true }"#,
        r#"{ type = "object", additionalProperties = {} }"#,
    ] {
        let mut table = base();
        set(&mut table, "tools.1", "input_schema", value(schema));
        rehash(&mut table);
        let registry = load(&table).unwrap();
        let adapter = adapter(&registry, "wiki__search");
        for arguments in [json!({}), json!({"anything": {"at": ["any", "depth"]}})] {
            assert_eq!(adapter.check_arguments(&arguments), Ok(()), "{schema}");
        }
    }
}

#[test]
fn closed_objects_without_properties_refuse_every_property_at_any_depth() {
    let cases = [
        (
            r#"{ type = "object", additionalProperties = false }"#,
            json!({}),
            json!({"query": "atlas"}),
            "/query",
        ),
        (
            r#"{ type = "object", additionalProperties = false }"#,
            json!({}),
            json!({"a~/b": null}),
            "/a~0~1b",
        ),
        (
            r#"{ type = "object", properties = { "a/b" = { type = "object", additionalProperties = false } } }"#,
            json!({"a/b": {}}),
            json!({"a/b": {"c~d": false}}),
            "/a~1b/c~0d",
        ),
        (
            r#"{ type = "object", properties = { tags = { type = "array", items = { type = "object", additionalProperties = false } } } }"#,
            json!({"tags": [{}, {}]}),
            json!({"tags": [{}, {"a~/b": []}]}),
            "/tags/1/a~0~1b",
        ),
    ];
    for (schema, accepted, refused, path) in cases {
        let mut table = base();
        set(&mut table, "tools.1", "input_schema", value(schema));
        rehash(&mut table);
        let registry = load(&table).unwrap();
        let adapter = adapter(&registry, "wiki__search");
        assert_eq!(adapter.check_arguments(&accepted), Ok(()), "{schema}");
        match adapter.check_arguments(&refused) {
            Err(ArgumentError::Undeclared { tool, path: got }) => {
                assert_eq!(tool.as_str(), "wiki__search");
                assert_eq!(got.as_str(), path, "{schema}: {refused}");
            }
            other => panic!("{schema}: {refused}: {other:?}"),
        }
    }
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
