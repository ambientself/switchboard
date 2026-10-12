//! Approved tool definitions, what `tools/list` is answered from, and the hashes each approval
//! records.

use std::fmt::Write as _;

use gateway_core::{ConnectorName, CredentialMode, Narrowing, ToolName};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::registry::Server;

/// The dialect of every approved input schema. Only JSON Schema 2020-12 loads (decision 0013),
/// so [`binding_sha256`] covers it as a constant.
pub const SCHEMA_DIALECT: &str = "2020-12";

/// An approved tool as callers are shown it. Plain data: the gateway renders it into whichever
/// MCP revision the caller speaks.
///
/// Everything here is the approved text, never what the server says now (design.md section
/// 13: descriptions shown to agents are the approved ones).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolDefinition {
    /// The exposed name, `{system}__{tool}`.
    pub name: ToolName,
    /// A short title for people, if the approval gave one.
    pub title: Option<String>,
    /// The approved description.
    pub description: String,
    /// The approved input schema, a JSON Schema whose `type` is `object`.
    pub input_schema: Value,
    /// Whether the tool is classified `read`. The gateway may show it as MCP's `readOnlyHint`;
    /// it is derived from the classification and cannot be set on its own.
    pub read_only: bool,
}

/// Where a tool's calls go: the server, and the tool's name there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    /// The server that runs the tool. The same name is the approved tool's connector.
    pub server: ConnectorName,
    /// The tool's name on that server, which is what a forwarded `tools/call` names.
    pub upstream_name: String,
}

/// Who approved a tool's definition, when, and the hashes they approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Approval {
    /// The person who approved it.
    pub approved_by: String,
    /// When, as an RFC 3339 date-time with an offset.
    pub approved_at: String,
    /// The SHA-256 of the definition, as [`definition_sha256`] computes it, in lower-case hex.
    pub definition_sha256: String,
    /// The SHA-256 of the tool's binding to its server, as [`binding_sha256`] computes it, in
    /// lower-case hex.
    pub binding_sha256: String,
}

/// The SHA-256 of a tool's approved definition, in lower-case hex. The definition is hashed as
/// it is written in the registry file, which must be exactly what the server serves: an
/// approval does not rewrite a title or a description (decision 0013). The loader refuses a
/// definition that no longer hashes to what was approved.
///
/// The hashed text is one JSON object with the keys `description`, `inputSchema`, `name` (the
/// upstream name) and, only when there is one, `title`. Object keys are sorted by byte at
/// every depth, there is no whitespace, and strings and numbers are written as `serde_json`
/// writes them. For ASCII text that is what Python's
/// `json.dumps(value, sort_keys=True, separators=(",", ":"))` produces.
pub fn definition_sha256(
    upstream_name: &str,
    title: Option<&str>,
    description: &str,
    input_schema: &Value,
) -> String {
    let mut definition = serde_json::Map::new();
    definition.insert("name".into(), Value::String(upstream_name.into()));
    if let Some(title) = title {
        definition.insert("title".into(), Value::String(title.into()));
    }
    definition.insert("description".into(), Value::String(description.into()));
    definition.insert("inputSchema".into(), input_schema.clone());
    sha256_hex(&Value::Object(definition))
}

/// The SHA-256 of a tool's binding to `server`, its server entry, in lower-case hex. Each
/// approval records it beside [`definition_sha256`]. The loader recomputes it from the tool's
/// server entry at boot and on every reload, and refuses a registry in which it differs, so a
/// changed server entry needs its tools approved again (decision 0013).
///
/// The hashed text is one JSON object, written as [`definition_sha256`] writes its own: keys
/// sorted by byte at every depth and no whitespace. Its keys are:
///
/// - `address`: the server's address, as written;
/// - `credential_mode`: how the gateway authenticates to it: `"team_service_identity"`,
///   `"gateway_token"` or `"per_user_grant"`;
/// - `credential_principal`: the identity the credential acts as;
/// - `credential_reference`: the label of the credential the gateway presents;
/// - `destination`: `"in_cluster"` or `"public"`;
/// - `dialect`: the input schema's dialect, always [`SCHEMA_DIALECT`];
/// - `identity`: the server's identity, which the loader requires to be the address's host;
/// - `narrowing`: `"call"`, `"limit"` or `"none"`;
/// - `permits`: what the credential permits, a classification such as `"read"`;
/// - `reach`: the reach, a list of objects with the keys `identifier`, `kind` and `system`,
///   sorted by system, then kind, then identifier;
/// - `reach_test_date`: the reach test's date, `YYYY-MM-DD`, or `null` when none is recorded.
///
/// The server's name, system and owner are not in it, and neither are the reach test's record,
/// the probe record or the reach check: the drift pass repeats the probe and the reach check.
pub fn binding_sha256(server: &Server) -> String {
    let credential = &server.credential;
    let mode = match credential.mode {
        CredentialMode::TeamServiceIdentity => "team_service_identity",
        CredentialMode::GatewayToken => "gateway_token",
        CredentialMode::PerUserGrant => "per_user_grant",
    };
    let narrowing = match server.narrowing {
        Narrowing::Call => "call",
        Narrowing::Limit => "limit",
        Narrowing::None => "none",
    };
    let reach: Vec<Value> = server
        .reach
        .iter()
        .map(|resource| {
            json!({
                "system": resource.system,
                "kind": resource.kind,
                "identifier": resource.identifier,
            })
        })
        .collect();
    let tested = server
        .reach_test
        .as_ref()
        .map_or(Value::Null, |test| Value::String(test.date.clone()));
    let mut binding = serde_json::Map::new();
    binding.insert("dialect".into(), Value::String(SCHEMA_DIALECT.into()));
    binding.insert("identity".into(), Value::String(server.identity.clone()));
    binding.insert("address".into(), Value::String(server.address.clone()));
    binding.insert(
        "destination".into(),
        Value::String(server.destination.as_str().into()),
    );
    binding.insert("credential_mode".into(), Value::String(mode.into()));
    binding.insert(
        "credential_reference".into(),
        Value::String(credential.reference.clone()),
    );
    binding.insert(
        "credential_principal".into(),
        Value::String(credential.principal.clone()),
    );
    binding.insert("narrowing".into(), Value::String(narrowing.into()));
    binding.insert(
        "permits".into(),
        Value::String(server.permits.as_str().into()),
    );
    binding.insert("reach".into(), Value::Array(reach));
    binding.insert("reach_test_date".into(), tested);
    sha256_hex(&Value::Object(binding))
}

/// The SHA-256 of `value`'s canonical text, in lower-case hex.
fn sha256_hex(value: &Value) -> String {
    let mut canonical = String::new();
    write_canonical(value, &mut canonical);
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Writes `value` with its object keys sorted, whatever order the map keeps them in.
fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            out.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        leaf => out.push_str(&leaf.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Credential, Destination, Probe, ProbeResult, ReachCheck, ReachTest};
    use gateway_core::{Classification, Resource};

    #[test]
    fn the_hash_does_not_depend_on_key_order() {
        let one = json!({"type": "object", "properties": {"b": {"type": "string"}, "a": {}}});
        let two = json!({"properties": {"a": {}, "b": {"type": "string"}}, "type": "object"});
        assert_eq!(
            definition_sha256("t", None, "d", &one),
            definition_sha256("t", None, "d", &two)
        );
    }

    #[test]
    fn the_hash_covers_every_part_of_the_definition() {
        let schema = json!({"type": "object"});
        let base = definition_sha256("t", Some("T"), "d", &schema);
        assert_ne!(base, definition_sha256("u", Some("T"), "d", &schema));
        assert_ne!(base, definition_sha256("t", Some("U"), "d", &schema));
        assert_ne!(base, definition_sha256("t", None, "d", &schema));
        assert_ne!(base, definition_sha256("t", Some("T"), "e", &schema));
        assert_ne!(
            base,
            definition_sha256("t", Some("T"), "d", &json!({"type": "array"}))
        );
    }

    #[test]
    fn the_hashed_text_is_compact_sorted_json() {
        // sha256 of {"description":"d","inputSchema":{"a":[1,"x"],"b":null},"name":"t"}
        let schema = json!({"b": null, "a": [1, "x"]});
        assert_eq!(
            definition_sha256("t", None, "d", &schema),
            "b6ded4c5340c96bbe8259bd8a12e7d1e0c53990489adc5099bdc17e8c2ff2e25"
        );
    }

    fn server() -> Server {
        Server {
            name: "s".into(),
            system: "docs".into(),
            owner: "o".into(),
            identity: "h".into(),
            address: "http://h/".into(),
            credential: Credential {
                mode: CredentialMode::TeamServiceIdentity,
                reference: "c".into(),
                principal: "p".into(),
            },
            narrowing: Narrowing::None,
            permits: Classification::Read,
            reach: [resource("atlas")].into(),
            reach_test: Some(ReachTest {
                date: "2026-10-12".into(),
                record: "r".into(),
            }),
            destination: Destination::InCluster,
            probe: Some(Probe {
                result: ProbeResult::Refused,
                date: "2026-10-12".into(),
            }),
            reach_check: Some(ReachCheck {
                tool: ToolName::parse("docs__list").unwrap(),
                arguments: json!({"project": "borealis"}).as_object().unwrap().clone(),
            }),
        }
    }

    fn resource(identifier: &str) -> Resource {
        Resource {
            system: "docs".into(),
            kind: "project".into(),
            identifier: identifier.into(),
        }
    }

    #[test]
    fn the_binding_text_is_compact_sorted_json_of_its_eleven_keys() {
        // sha256 of {"address":"http://h/","credential_mode":"team_service_identity",
        // "credential_principal":"p","credential_reference":"c","destination":"in_cluster",
        // "dialect":"2020-12","identity":"h","narrowing":"none","permits":"read",
        // "reach":[{"identifier":"atlas","kind":"project","system":"docs"}],
        // "reach_test_date":"2026-10-12"}, with no line breaks.
        assert_eq!(
            binding_sha256(&server()),
            "868407b173faebbb7c6b3c3e1d900686e51650c8a61afc2bd012b312ea48add0"
        );
    }

    #[test]
    fn the_binding_covers_the_server_and_its_entry_but_not_the_names_or_records() {
        let base = binding_sha256(&server());
        let changed = |edit: fn(&mut Server)| {
            let mut server = server();
            edit(&mut server);
            binding_sha256(&server)
        };
        assert_ne!(base, changed(|s| s.identity = "i".into()));
        assert_ne!(base, changed(|s| s.address = "http://i/".into()));
        assert_ne!(base, changed(|s| s.destination = Destination::Public));
        assert_ne!(base, changed(|s| s.credential.reference = "d".into()));
        assert_ne!(base, changed(|s| s.credential.principal = "q".into()));
        for mode in [CredentialMode::GatewayToken, CredentialMode::PerUserGrant] {
            let mut server = server();
            server.credential.mode = mode;
            assert_ne!(base, binding_sha256(&server), "{mode:?}");
        }
        for narrowing in [Narrowing::Call, Narrowing::Limit] {
            let mut server = server();
            server.narrowing = narrowing;
            assert_ne!(base, binding_sha256(&server), "{narrowing:?}");
        }
        assert_ne!(base, changed(|s| s.permits = Classification::Propose));
        assert_ne!(base, changed(|s| s.reach.clear()));
        assert_ne!(base, changed(|s| s.reach = [resource("borealis")].into()));
        assert_ne!(
            base,
            changed(|s| {
                s.reach.insert(resource("borealis"));
            })
        );
        assert_ne!(
            base,
            changed(|s| s.reach_test.as_mut().unwrap().date = "2026-10-13".into())
        );
        assert_ne!(base, changed(|s| s.reach_test = None));
        assert_eq!(base, changed(|s| s.name = "t".into()));
        assert_eq!(base, changed(|s| s.system = "wiki".into()));
        assert_eq!(base, changed(|s| s.owner = "p".into()));
        assert_eq!(
            base,
            changed(|s| s.reach_test.as_mut().unwrap().record = "other".into())
        );
        assert_eq!(base, changed(|s| s.probe = None));
        assert_eq!(base, changed(|s| s.reach_check = None));
    }

    #[test]
    fn the_reach_is_hashed_in_order_whatever_order_it_was_written_in() {
        let mut one = server();
        one.reach = [resource("borealis"), resource("atlas")].into();
        let mut two = server();
        two.reach = [resource("atlas"), resource("borealis")].into();
        assert_eq!(binding_sha256(&one), binding_sha256(&two));
    }
}
