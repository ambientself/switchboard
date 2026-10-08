//! Tool definitions: what `tools/list` tells a caller about each tool.

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::ToolName;
use serde::Deserialize;
use thiserror::Error;

/// One approved tool's definition, as configuration states it: the text and schema a caller
/// reads in `tools/list`.
///
/// Design section 13: descriptions shown to agents are the approved ones, never a server's
/// live ones. The policy snapshot holds no definitions, so they are kept here, beside it, until
/// the registry binds each approval to a hash of its definition (#14).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    /// The tool's exposed name. Must be an approved tool.
    pub name: ToolName,
    /// A short title for people, if the tool has one.
    #[serde(default)]
    pub title: Option<String>,
    /// The approved description.
    pub description: String,
    /// The approved input schema: a JSON Schema object whose `type` is `"object"`, which MCP
    /// requires of a tool's input.
    pub input_schema: serde_json::Value,
}

/// Why the tool definitions were refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CatalogError {
    /// Two definitions for one tool; which one a caller sees would be arbitrary.
    #[error("tool `{0}` has more than one definition")]
    Duplicate(ToolName),
    /// A definition whose input schema is not a JSON object with `"type": "object"`.
    #[error("tool `{0}` has an input schema that is not an object schema")]
    SchemaNotObject(ToolName),
    /// An approved tool with no definition: `tools/list` would have nothing to say about it.
    #[error("approved tool `{0}` has no definition")]
    Missing(ToolName),
    /// A definition for a tool nobody approved. The catalog and the snapshot have drifted.
    #[error("tool `{0}` has a definition but is not approved")]
    NotApproved(ToolName),
}

/// Every approved tool's definition, keyed by name.
///
/// The boot gates build it and check it against the snapshot: every approved tool has exactly
/// one definition, and every definition is for an approved tool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolCatalog {
    definitions: BTreeMap<ToolName, ToolDefinition>,
}

impl ToolCatalog {
    /// Builds the catalog, refusing a duplicate definition or a schema that is not an object
    /// schema.
    pub fn new(definitions: Vec<ToolDefinition>) -> Result<Self, CatalogError> {
        let mut catalog = BTreeMap::new();
        for definition in definitions {
            if !is_object_schema(&definition.input_schema) {
                return Err(CatalogError::SchemaNotObject(definition.name));
            }
            if let Some(previous) = catalog.insert(definition.name.clone(), definition) {
                return Err(CatalogError::Duplicate(previous.name));
            }
        }
        Ok(Self {
            definitions: catalog,
        })
    }

    /// Checks that the catalog defines exactly the `approved` tools.
    pub fn check<'a>(
        &self,
        approved: impl IntoIterator<Item = &'a ToolName>,
    ) -> Result<(), CatalogError> {
        let mut unapproved: BTreeSet<&ToolName> = self.definitions.keys().collect();
        for name in approved {
            if !self.definitions.contains_key(name) {
                return Err(CatalogError::Missing(name.clone()));
            }
            unapproved.remove(name);
        }
        match unapproved.into_iter().next() {
            Some(name) => Err(CatalogError::NotApproved(name.clone())),
            None => Ok(()),
        }
    }

    /// The definition of `name`.
    pub fn definition(&self, name: &ToolName) -> Option<&ToolDefinition> {
        self.definitions.get(name)
    }
}

fn is_object_schema(schema: &serde_json::Value) -> bool {
    schema.get("type").and_then(serde_json::Value::as_str) == Some("object")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    fn name(name: &str) -> ToolName {
        ToolName::parse(name).unwrap()
    }

    fn definition(tool: &str) -> ToolDefinition {
        ToolDefinition {
            name: name(tool),
            title: None,
            description: format!("Runs {tool}."),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    #[test]
    fn a_catalog_that_defines_exactly_the_approved_tools_passes() {
        let catalog = ToolCatalog::new(vec![definition("a__one"), definition("b__two")]).unwrap();
        assert_eq!(catalog.check(&[name("b__two"), name("a__one")]), Ok(()));
        assert_eq!(
            catalog
                .definition(&name("a__one"))
                .map(|d| d.description.as_str()),
            Some("Runs a__one.")
        );
        assert_eq!(catalog.definition(&name("c__three")), None);
    }

    #[test]
    fn an_approved_tool_without_a_definition_is_refused() {
        let catalog = ToolCatalog::new(vec![definition("a__one")]).unwrap();
        assert_eq!(
            catalog.check(&[name("a__one"), name("b__two")]),
            Err(CatalogError::Missing(name("b__two")))
        );
    }

    #[test]
    fn a_definition_for_a_tool_nobody_approved_is_refused() {
        let catalog = ToolCatalog::new(vec![definition("a__one"), definition("z__stale")]).unwrap();
        assert_eq!(
            catalog.check(&[name("a__one")]),
            Err(CatalogError::NotApproved(name("z__stale")))
        );
    }

    #[test]
    fn two_definitions_for_one_tool_are_refused() {
        let mut second = definition("a__one");
        second.description = "Something else.".into();
        assert_eq!(
            ToolCatalog::new(vec![definition("a__one"), second]),
            Err(CatalogError::Duplicate(name("a__one")))
        );
    }

    #[test]
    fn an_input_schema_must_be_an_object_schema() {
        for schema in [
            json!({"type": "string"}),
            json!({"properties": {}}),
            json!({"type": ["object"]}),
            json!("object"),
            json!(null),
        ] {
            let mut bad = definition("a__one");
            bad.input_schema = schema.clone();
            assert_eq!(
                ToolCatalog::new(vec![bad]),
                Err(CatalogError::SchemaNotObject(name("a__one"))),
                "{schema}"
            );
        }
    }

    #[test]
    fn definitions_are_read_from_configuration_and_unknown_fields_are_refused() {
        let parse = |json: &str| serde_json::from_str::<ToolDefinition>(json);
        let read =
            parse(r#"{"name": "a__one", "description": "d", "input_schema": {"type": "object"}}"#)
                .unwrap();
        assert_eq!(read.title, None);
        assert!(parse(r#"{"name": "a__one", "input_schema": {"type": "object"}}"#).is_err());
        assert!(parse(r#"{"name": "a__one", "description": "d"}"#).is_err());
        assert!(
            parse(r#"{"name": "a one", "description": "d", "input_schema": {"type": "object"}}"#)
                .is_err(),
            "an invalid tool name was accepted"
        );
        assert!(
            parse(
                r#"{"name": "a__one", "description": "d", "input_schema": {"type": "object"},
                    "inputSchema": {}}"#
            )
            .is_err()
        );
    }
}
