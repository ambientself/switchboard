//! Runs every case in `loader_rules.json`, the snapshot loader's rules of decision 0011,
//! section 3, and its rules for a profile's exceptions (section 9), and reports every case that
//! fails, by name.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_core::{PolicySnapshot, SnapshotData};
use serde::Deserialize;
use serde_json::{Map, Value};

const TABLE: &str = include_str!("loader_rules.json");

/// Fewer than this and the table has lost cases without anyone deciding to remove them.
const MINIMUM_CASES: usize = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    #[allow(dead_code)]
    about: String,
    base: Value,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    #[serde(default)]
    tool: Option<Map<String, Value>>,
    #[serde(default)]
    entry: Option<Map<String, Value>>,
    #[serde(default)]
    surface: Option<Map<String, Value>>,
    #[serde(default)]
    tools: Option<Value>,
    #[serde(default)]
    entries: Option<Value>,
    #[serde(default)]
    surfaces: Option<Value>,
    #[serde(default)]
    limits: Option<Value>,
    #[serde(default)]
    profiles: Option<Value>,
    expect: String,
    #[serde(default)]
    names: Vec<String>,
}

/// Sets each field of `change` on the first object of the list at `key`, removing it where the
/// change is null.
fn change_first(data: &mut Value, key: &str, change: &Map<String, Value>) {
    let first = data[key][0]
        .as_object_mut()
        .expect("the base has one to change");
    for (field, value) in change {
        if value.is_null() {
            first.remove(field);
        } else {
            first.insert(field.clone(), value.clone());
        }
    }
}

/// The case's policy data, as JSON.
fn data(base: &Value, case: &Case) -> Value {
    let mut data = base.clone();
    for (key, replacement) in [
        ("tools", &case.tools),
        ("entries", &case.entries),
        ("surfaces", &case.surfaces),
        ("limits", &case.limits),
        ("profiles", &case.profiles),
    ] {
        if let Some(replacement) = replacement {
            data[key] = replacement.clone();
        }
    }
    for (key, change) in [
        ("tools", &case.tool),
        ("entries", &case.entry),
        ("surfaces", &case.surface),
    ] {
        if let Some(change) = change {
            change_first(&mut data, key, change);
        }
    }
    data
}

/// What the case's data came to: `loads`, `does not parse`, or the refusal's variant name and
/// message.
fn outcome(data: Value) -> (String, String) {
    let data: SnapshotData = match serde_json::from_value(data) {
        Ok(data) => data,
        Err(error) => return ("does not parse".to_owned(), error.to_string()),
    };
    match PolicySnapshot::new(data) {
        Ok(_) => ("loads".to_owned(), String::new()),
        Err(error) => {
            let debug = format!("{error:?}");
            let variant = debug
                .split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap_or_default()
                .to_owned();
            (variant, error.to_string())
        }
    }
}

#[test]
fn every_loader_rule_case_holds() {
    let table: Table = serde_json::from_str(TABLE).expect("loader_rules.json does not parse");
    assert!(
        table.cases.len() >= MINIMUM_CASES,
        "only {} cases",
        table.cases.len()
    );
    let mut failures = Vec::new();
    for case in &table.cases {
        let (got, message) = outcome(data(&table.base, case));
        if got != case.expect {
            failures.push(format!(
                "{}: expected {}, got {got}: {message}",
                case.name, case.expect
            ));
            continue;
        }
        for name in &case.names {
            if !message.contains(name.as_str()) {
                failures.push(format!(
                    "{}: the refusal does not name {name}: {message}",
                    case.name
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Each of the nine rules has a case that it refuses and a case that loads, so a rule removed
/// or one that refuses everything is seen.
#[test]
fn each_rule_has_a_refusing_and_a_passing_case() {
    let table: Table = serde_json::from_str(TABLE).unwrap();
    for rule in 1..=9 {
        let prefix = format!("rule {rule}: ");
        let cases: Vec<&Case> = table
            .cases
            .iter()
            .filter(|case| case.name.starts_with(&prefix))
            .collect();
        assert!(
            cases.iter().any(|case| case.expect == "loads"),
            "rule {rule} has no passing case"
        );
        assert!(
            cases
                .iter()
                .any(|case| case.expect != "loads" && case.expect != "does not parse"),
            "rule {rule} has no refusing case"
        );
    }
}

/// Each of the loader's four rules for a profile's exceptions (decision 0011, section 9): one
/// on a profile that does not require currency, one naming a tool not approved or not `write`,
/// one naming a `write` tool settled by a person, and a name or a tool listed twice in one
/// profile, has a case that it refuses and a case that loads.
#[test]
fn each_exception_rule_has_a_refusing_and_a_passing_case() {
    let table: Table = serde_json::from_str(TABLE).unwrap();
    let refusals = [
        ("a", &["ExceptionWithoutCurrency"][..]),
        (
            "b",
            &["ExceptionToolUnapproved", "ExceptionToolNotWrite"][..],
        ),
        ("c", &["ExceptedWriteSettledByPerson"][..]),
        ("d", &["DuplicateException", "ToolInTwoExceptions"][..]),
    ];
    for (rule, variants) in refusals {
        let prefix = format!("exception rule {rule}: ");
        let cases: Vec<&Case> = table
            .cases
            .iter()
            .filter(|case| case.name.starts_with(&prefix))
            .collect();
        assert!(
            cases.iter().any(|case| case.expect == "loads"),
            "exception rule {rule} has no passing case"
        );
        for variant in variants {
            assert!(
                cases.iter().any(|case| case.expect == *variant),
                "exception rule {rule} has no case refused with {variant}"
            );
        }
    }
}
