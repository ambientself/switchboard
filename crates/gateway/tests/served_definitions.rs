//! Every approval in the demo registries is of the definition the mock server serves (#51,
//! decision 0013): its `definition_sha256` is the hash of the served name, title, description
//! and input schema, and the approved definition is the served one, field by field. Without
//! this, a drift check comparing what the server serves with the approval would withdraw
//! every demo tool on its first poll.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_registry::{Registry, definition_sha256};
use serde_json::Value;

/// Each demo registry, by where it is.
const REGISTRIES: [(&str, &str); 4] = [
    (
        "crates/gateway-registry/demo/registry.toml",
        include_str!("../../gateway-registry/demo/registry.toml"),
    ),
    (
        "deploy/kind/base/config/registry/registry.toml",
        include_str!("../../../deploy/kind/base/config/registry/registry.toml"),
    ),
    (
        "deploy/compose/config/registry/registry.toml",
        include_str!("../../../deploy/compose/config/registry/registry.toml"),
    ),
    (
        "deploy/compose/config/registry-withdrawn.toml",
        include_str!("../../../deploy/compose/config/registry-withdrawn.toml"),
    ),
];

/// What the mock server's `tools/list` says of `upstream_name`.
fn served(upstream_name: &str) -> Value {
    mock_docs_server::ToolName::parse(upstream_name)
        .unwrap_or_else(|| panic!("the mock server does not know `{upstream_name}`"))
        .definition()
}

#[test]
fn every_demo_approval_hashes_the_definition_the_mock_server_serves() {
    for (place, text) in REGISTRIES {
        let registry =
            Registry::from_toml_str(text).unwrap_or_else(|error| panic!("{place}: {error}"));
        assert!(!registry.approvals().is_empty(), "{place}");
        for (tool, approval) in registry.approvals() {
            let route = &registry.routes()[tool];
            let served = served(&route.upstream_name);
            let text = |key: &str| served.get(key).map(|value| value.as_str().unwrap());
            let hash = definition_sha256(
                text("name").unwrap(),
                text("title"),
                text("description").unwrap(),
                &served["inputSchema"],
            );
            assert_eq!(approval.definition_sha256, hash, "{place}: {tool}");
        }
    }
}

#[test]
fn every_demo_approved_definition_is_the_served_one() {
    for (place, text) in REGISTRIES {
        let registry = Registry::from_toml_str(text).unwrap();
        for (tool, definition) in registry.definitions() {
            let route = &registry.routes()[tool];
            let served = served(&route.upstream_name);
            assert_eq!(served["name"], route.upstream_name, "{place}: {tool}");
            assert_eq!(
                definition.title.as_deref(),
                served.get("title").map(|title| title.as_str().unwrap()),
                "{place}: {tool}"
            );
            assert_eq!(
                definition.description, served["description"],
                "{place}: {tool}"
            );
            assert_eq!(
                definition.input_schema, served["inputSchema"],
                "{place}: {tool}"
            );
        }
    }
}
