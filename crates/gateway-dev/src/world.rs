//! The fixture world as gateway configuration: the testkit's policy, a definition for each of
//! its tools, the profile rules, and the adapter that reads a call's documents.

use gateway::{ResourceAdapter, ToolDefinition};
use gateway_core::{ApprovedTool, Resources};
use gateway_testkit::{
    AUDIENCE, DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME, DOCUMENT_ARGUMENT, FixtureConnector, GROUP_G,
    GROUP_REVIEW, LocalIssuer, PROFILE_REVIEWER, PROFILE_TEAM_A, PROFILE_TEAM_B, PROFILE_USER,
    READ_TOOL, SCOPED_READ_TOOL, TEAM_A, TEAM_A_SUBJECT, TEAM_B, TEAM_B_SUBJECT, USER_ISSUER,
    WORKLOAD_ISSUER, WRITE_TOOL,
};
use serde_json::{Value, json};

/// The deployment name the fixture gateway records on every audit row.
pub const DEPLOYMENT: &str = "switchboard-dev";

/// The `Host` values the fixture gateway serves. It listens on loopback only.
pub const ALLOWED_HOSTS: [&str; 2] = ["127.0.0.1", "localhost"];

/// The definition of each of the fixture connector's tools, as `tools/list` shows them.
pub fn catalog_data() -> Value {
    let document = json!({
        "type": "string",
        "description": "The document's name, such as team-a-notes.",
    });
    json!([
        {
            "name": READ_TOOL,
            "title": "Read a document",
            "description": "Reads one fixture document. The gateway checks the document against the caller's limits before the call runs.",
            "input_schema": {
                "type": "object",
                "properties": {DOCUMENT_ARGUMENT: document},
                "required": [DOCUMENT_ARGUMENT],
            },
        },
        {
            "name": WRITE_TOOL,
            "title": "Write a document",
            "description": "Writes to one fixture document. Nothing is stored; the fixture records that the write happened.",
            "input_schema": {
                "type": "object",
                "properties": {DOCUMENT_ARGUMENT: document, "text": {"type": "string"}},
                "required": [DOCUMENT_ARGUMENT],
            },
        },
        {
            "name": SCOPED_READ_TOOL,
            "title": "Read a document, checked by the tool",
            "description": "Reads one fixture document. The tool checks the document against the caller's scope itself, and refuses one outside it.",
            "input_schema": {
                "type": "object",
                "properties": {DOCUMENT_ARGUMENT: document},
            },
        },
    ])
}

/// The definitions [`catalog_data`] states.
pub fn catalog() -> Result<Vec<ToolDefinition>, serde_json::Error> {
    serde_json::from_value(catalog_data())
}

/// The gateway configuration for the fixture world, trusting `workload` and `user`.
///
/// Identity is enforced against the two issuers, with the fixture's audience and subjects.
/// Audit is on, so the wiring must supply a store. The hosts are [`ALLOWED_HOSTS`] and no
/// `Origin` is allowed. The policy is the testkit's, and each team and user group selects its
/// fixture profile.
pub fn fixture_config(workload: &LocalIssuer, user: &LocalIssuer) -> Value {
    let issuer = |issuer: &LocalIssuer, kind: Value| {
        json!({
            "issuer": issuer.issuer(),
            "audiences": [AUDIENCE],
            "kind": kind,
            "algorithm": issuer.algorithm().as_str(),
            "keys": issuer.jwk_set(),
            "max_lifetime_secs": DEFAULT_MAX_LIFETIME,
            "leeway_secs": DEFAULT_LEEWAY,
        })
    };
    json!({
        "deployment": DEPLOYMENT,
        "identity": {"enforce": [
            issuer(workload, json!({"workload": {"subjects": {
                TEAM_A_SUBJECT: TEAM_A,
                TEAM_B_SUBJECT: TEAM_B,
            }}})),
            issuer(user, json!({"user": {}})),
        ]},
        "audit": {},
        "http": {"allowed_hosts": ALLOWED_HOSTS, "allowed_origins": []},
        "policy": gateway_testkit::policy_data(),
        "catalog": catalog_data(),
        "profiles": {
            "workloads": [
                {"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": PROFILE_TEAM_A},
                {"issuer": WORKLOAD_ISSUER, "team": TEAM_B, "profile": PROFILE_TEAM_B},
            ],
            "users": [
                {"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_USER},
                {"issuer": USER_ISSUER, "group": GROUP_REVIEW, "profile": PROFILE_REVIEWER},
            ],
        },
    })
}

/// Reads the documents a call to one of the fixture connector's tools names, as
/// [`FixtureConnector::resources_of`] says.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixtureResources;

impl ResourceAdapter for FixtureResources {
    fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
        FixtureConnector::resources_of(tool.name.as_str(), arguments)
    }
}
