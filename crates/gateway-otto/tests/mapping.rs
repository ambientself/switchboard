//! The tool mapping (decision 0012, Tools and resources): one Otto name to one gateway name,
//! refused at load when it is not one-to-one, and a name it lacks dropped.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_core::DeploymentName;
use gateway_otto::minter::TestMinter;
use gateway_otto::{GrantKeys, GrantVerifier, MappingError, ToolMapping};
use serde_json::json;

/// The conformance suite's statement of Otto's tools, with each one's name here.
const BASELINE: &str = include_str!("../../../conformance/baseline.json");

#[test]
fn the_conformance_baseline_maps_one_to_one() {
    let mapping = ToolMapping::from_baseline(BASELINE).unwrap();
    let baseline: serde_json::Value = serde_json::from_str(BASELINE).unwrap();
    let tools = baseline["tools"].as_object().unwrap();
    assert_eq!(mapping.len(), tools.len());
    for (otto, tool) in tools {
        assert_eq!(
            mapping.get(otto).map(|name| name.as_str()),
            tool["switchboard"].as_str(),
            "{otto}"
        );
    }
    assert_eq!(
        mapping.get("github_create_pr").map(|name| name.as_str()),
        Some("github__create_pr")
    );
}

#[test]
fn a_mapping_file_is_one_object_of_names() {
    let mapping = ToolMapping::from_json(
        r#"{"github_get_pr": "github__get_pr", "jira_get_issue": "jira__get_issue"}"#,
    )
    .unwrap();
    assert_eq!(mapping.len(), 2);
    assert_eq!(
        mapping.get("jira_get_issue").map(|name| name.as_str()),
        Some("jira__get_issue")
    );
    assert_eq!(mapping.get("jira__get_issue"), None);
    assert!(ToolMapping::from_json("{}").unwrap().is_empty());
}

#[test]
fn a_mapping_that_is_not_one_to_one_is_refused() {
    // One Otto name twice, even with the same target: JSON's last-one-wins would hide it.
    assert_eq!(
        ToolMapping::from_json(
            r#"{"github_get_pr": "github__get_pr", "github_get_pr": "github__get_pr"}"#
        ),
        Err(MappingError::OttoNameRepeated("github_get_pr".to_owned()))
    );
    assert_eq!(
        ToolMapping::from_json(
            r#"{"github_get_pr": "github__get_pr", "github_get_pr": "github__other"}"#
        ),
        Err(MappingError::OttoNameRepeated("github_get_pr".to_owned()))
    );
    // Two Otto names to one gateway name.
    assert_eq!(
        ToolMapping::from_json(
            r#"{"github_get_pr": "github__get_pr", "github_pr": "github__get_pr"}"#
        ),
        Err(MappingError::GatewayNameRepeated {
            gateway: "github__get_pr".parse().unwrap(),
            first: "github_get_pr".to_owned(),
            second: "github_pr".to_owned(),
        })
    );
    // The same in the baseline's form.
    let doubled = json!({"tools": {
        "a": {"switchboard": "x__a", "classification": "read"},
        "b": {"switchboard": "x__a", "classification": "read"},
    }});
    assert!(matches!(
        ToolMapping::from_baseline(&doubled.to_string()),
        Err(MappingError::GatewayNameRepeated { .. })
    ));
    let repeated = r#"{"tools": {"a": {"switchboard": "x__a"}, "a": {"switchboard": "x__b"}}}"#;
    assert_eq!(
        ToolMapping::from_baseline(repeated),
        Err(MappingError::OttoNameRepeated("a".to_owned()))
    );
}

/// Read as a member of a larger document, the mapping is the same as from its own file, and a
/// name given twice, or two names given one target, is refused the same way.
#[test]
fn a_mapping_read_inside_a_document_refuses_what_a_mapping_file_refuses() {
    #[derive(serde::Deserialize)]
    struct Document {
        tool_mapping: ToolMapping,
    }
    let read = |mapping: &str| {
        serde_json::from_str::<Document>(&format!(r#"{{"tool_mapping": {mapping}}}"#))
            .map(|document| document.tool_mapping)
            .map_err(|error| error.to_string())
    };
    let names = r#"{"github_get_pr": "github__get_pr", "jira_get_issue": "jira__get_issue"}"#;
    assert_eq!(read(names), Ok(ToolMapping::from_json(names).unwrap()));
    for refused in [
        r#"{"github_get_pr": "github__get_pr", "github_get_pr": "github__other"}"#,
        r#"{"github_get_pr": "github__get_pr", "github_pr": "github__get_pr"}"#,
        r#"{"": "github__get_pr"}"#,
        r#"{"github_get_pr": "not a tool name"}"#,
    ] {
        let message = ToolMapping::from_json(refused).unwrap_err().to_string();
        let error = read(refused).unwrap_err();
        assert!(error.starts_with(&message), "{refused}: {error}");
    }
}

#[test]
fn each_name_must_be_one() {
    assert_eq!(
        ToolMapping::from_json(r#"{"": "github__get_pr"}"#),
        Err(MappingError::EmptyOttoName)
    );
    for gateway in [
        r#""""#,
        r#""github get pr""#,
        &format!(r#""{}""#, "x".repeat(65)),
    ] {
        assert_eq!(
            ToolMapping::from_json(&format!(r#"{{"github_get_pr": {gateway}}}"#)),
            Err(MappingError::InvalidGatewayName("github_get_pr".to_owned())),
            "{gateway}"
        );
    }
    for text in [
        "",
        "[]",
        r#"{"a": 7}"#,
        r#"{"a": null}"#,
        r#"{"tools": {}}"#,
    ] {
        assert!(
            matches!(ToolMapping::from_json(text), Err(MappingError::Shape(_))),
            "{text}"
        );
    }
    for text in [
        "{}",
        r#"{"tools": []}"#,
        r#"{"tools": {"a": {"name": "x__a"}}}"#,
    ] {
        assert!(
            matches!(
                ToolMapping::from_baseline(text),
                Err(MappingError::Shape(_))
            ),
            "{text}"
        );
    }
}

#[test]
fn a_grant_s_names_are_mapped_and_a_name_with_no_mapping_dropped() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let tools = |names: serde_json::Value| -> Vec<String> {
        accepted(&verifier, &minter.mint(&with(json!({"tools": names}))))
            .tools()
            .iter()
            .map(|tool| tool.as_str().to_owned())
            .collect()
    };
    assert_eq!(tools(json!(["github_get_pr"])), ["github__get_pr"]);
    assert_eq!(
        tools(json!([
            "github_create_pr",
            "github_get_pr",
            "github_get_pr"
        ])),
        ["github__create_pr", "github__get_pr"]
    );
    // Not mapped: dropped, so permitting nothing. This gateway's own name is not Otto's.
    assert_eq!(
        tools(json!(["github_merge_pr", "github_get_pr"])),
        ["github__get_pr"]
    );
    assert!(tools(json!(["github__get_pr"])).is_empty());
    assert!(tools(json!(["unknown"])).is_empty());
}

#[test]
fn the_baseline_mapping_maps_a_grant() {
    let minter = TestMinter::generate();
    let verifier = GrantVerifier::new(
        GrantKeys::new(&[issuer("otto-prod", &minter)]).unwrap(),
        DeploymentName::new(DEPLOYMENT),
        ToolMapping::from_baseline(BASELINE).unwrap(),
    );
    let grant = minter.mint(&with(
        json!({"tools": ["github_get_pr", "github_create_pr"]}),
    ));
    let names: Vec<String> = accepted(&verifier, &grant)
        .tools()
        .iter()
        .map(|tool| tool.as_str().to_owned())
        .collect();
    assert_eq!(names, ["github__create_pr", "github__get_pr"]);
}
