//! Argument-to-resource adapters (planDemo 14d), and the check that refuses arguments a tool's
//! approved schema does not declare (draft 0011, section 1).
//!
//! An adapter is declared in the registry file as a list of sources, each
//! `{from_argument, system, kind}`: the named argument's string value is the identifier of a
//! resource of that system and kind. The core's check 6 then compares the resources against
//! the caller's limit. An adapter that cannot find a resource says so by naming none, which
//! check 6 denies for a tool that declares its resources; it never guesses.

use std::fmt;

use gateway_core::{Resource, ResourceDeclaration, Resources, ToolName};
use serde_json::{Map, Value};
use thiserror::Error;

/// One resource a tool's calls name: the string argument it is read from, and the system and
/// kind of the resource that string identifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceSource {
    /// The top-level argument that holds the identifier, such as `project`.
    pub from_argument: String,
    /// The resource's system, such as `docs`.
    pub system: String,
    /// The resource's kind within the system, such as `project`.
    pub kind: String,
}

/// One tool's adapter: what the gateway runs on a call's arguments before deciding, and before
/// forwarding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentAdapter {
    tool: ToolName,
    sources: Vec<ResourceSource>,
    input_schema: Value,
}

/// Why a call's arguments were refused before forwarding.
///
/// The path is the caller's own text. It is for logs; a sentence shown to a caller should
/// name the tool, not echo the path.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ArgumentError {
    /// The arguments are not a JSON object.
    #[error("the arguments to `{tool}` are not an object")]
    NotAnObject {
        /// The tool called.
        tool: ToolName,
    },
    /// The arguments carry a property the approved schema does not list.
    #[error("the arguments to `{tool}` carry `{path}`, which its approved schema does not declare")]
    Undeclared {
        /// The tool called.
        tool: ToolName,
        /// Where the property is, as a JSON Pointer such as `/options/extra`.
        path: JsonPointer,
    },
}

/// A JSON Pointer (RFC 6901) into a call's arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsonPointer(String);

impl JsonPointer {
    fn child(&self, token: &str) -> Self {
        Self(format!(
            "{}/{}",
            self.0,
            token.replace('~', "~0").replace('/', "~1")
        ))
    }

    /// The pointer as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ArgumentAdapter {
    pub(crate) fn new(tool: ToolName, sources: Vec<ResourceSource>, input_schema: Value) -> Self {
        Self {
            tool,
            sources,
            input_schema,
        }
    }

    /// The tool this adapter serves.
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// Where the resources come from. Empty for a tool that names no resources.
    pub fn sources(&self) -> &[ResourceSource] {
        &self.sources
    }

    /// What the approved tool says about its resources: `declared` when the adapter reads
    /// them from the arguments, `no_resources` otherwise. A registry tool is never
    /// `checks_own_scope`: a proxied server is not trusted to check its own scope.
    pub fn declaration(&self) -> ResourceDeclaration {
        if self.sources.is_empty() {
            ResourceDeclaration::NoResources
        } else {
            ResourceDeclaration::Declared
        }
    }

    /// The resources a call with these arguments names, for the call context's `resources`.
    ///
    /// One resource per source, in the order the file lists them. If any source's argument is
    /// missing, is not a string, or is the empty string, the call names no resources at all:
    /// `Named([])`, which check 6 denies for a `declared` tool. Returning the others would let
    /// a call through with one of its targets unchecked. A tool with no sources always names
    /// none. The result is never `Unknown`: the adapter reads the arguments, so it knows.
    pub fn resources(&self, arguments: &Map<String, Value>) -> Resources {
        let mut named = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            match arguments.get(&source.from_argument) {
                Some(Value::String(identifier)) if !identifier.is_empty() => {
                    named.push(Resource {
                        system: source.system.clone(),
                        kind: source.kind.clone(),
                        identifier: identifier.clone(),
                    });
                }
                _ => return Resources::Named(Vec::new()),
            }
        }
        Resources::Named(named)
    }

    /// Refuses arguments the approved schema does not declare, before a call is forwarded.
    ///
    /// Where an object in the schema lists its `properties`, any other property is refused, at
    /// any depth, whatever the schema says about `additionalProperties`; array elements are
    /// checked against `items`. With no `properties`, `additionalProperties: false` declares
    /// no arguments; otherwise the object is left open and accepted as one value.
    /// The loader has already refused schemas whose keywords this walk cannot
    /// follow, such as `$ref` or `anyOf`. This is not full JSON Schema validation: types,
    /// `required` and formats are not checked here.
    pub fn check_arguments(&self, arguments: &Value) -> Result<(), ArgumentError> {
        if !arguments.is_object() {
            return Err(ArgumentError::NotAnObject {
                tool: self.tool.clone(),
            });
        }
        undeclared(&self.input_schema, arguments, &JsonPointer::default()).map_or(Ok(()), |path| {
            Err(ArgumentError::Undeclared {
                tool: self.tool.clone(),
                path,
            })
        })
    }
}

/// The first property in `value` that `schema` does not declare, if any.
fn undeclared(schema: &Value, value: &Value, at: &JsonPointer) -> Option<JsonPointer> {
    match value {
        Value::Object(object) => {
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                return if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                    object.keys().next().map(|key| at.child(key))
                } else {
                    None
                };
            };
            object
                .iter()
                .find_map(|(key, value)| match properties.get(key) {
                    None => Some(at.child(key)),
                    Some(property) => undeclared(property, value, &at.child(key)),
                })
        }
        Value::Array(items) => {
            let schema = schema.get("items")?;
            items
                .iter()
                .enumerate()
                .find_map(|(index, item)| undeclared(schema, item, &at.child(&index.to_string())))
        }
        _ => None,
    }
}

/// Keywords that can declare or admit properties in ways [`ArgumentAdapter::check_arguments`]
/// does not follow. A schema that uses one is refused at load rather than checked partly.
pub(crate) const UNFOLLOWED_KEYWORDS: [&str; 17] = [
    "$ref",
    "$dynamicRef",
    "$recursiveRef",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "dependentSchemas",
    "dependencies",
    "patternProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "prefixItems",
    "additionalItems",
];

/// Where a schema cannot be followed by the argument check, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SchemaProblem {
    /// A keyword in [`UNFOLLOWED_KEYWORDS`].
    Unfollowed { keyword: String, at: JsonPointer },
    /// `properties` that is not an object, a property or `items` that is not a schema.
    Malformed { at: JsonPointer },
}

/// Checks that every schema the argument check walks (the root, each `properties` entry and
/// each `items`) is one it can follow. Pointers are into the schema.
pub(crate) fn followable(schema: &Value, at: &JsonPointer) -> Result<(), SchemaProblem> {
    let object = match schema {
        Value::Bool(_) => return Ok(()),
        Value::Object(object) => object,
        _ => return Err(SchemaProblem::Malformed { at: at.clone() }),
    };
    if let Some(keyword) = UNFOLLOWED_KEYWORDS
        .iter()
        .find(|keyword| object.contains_key(**keyword))
    {
        return Err(SchemaProblem::Unfollowed {
            keyword: (*keyword).to_owned(),
            at: at.clone(),
        });
    }
    if let Some(properties) = object.get("properties") {
        let at = at.child("properties");
        let Some(properties) = properties.as_object() else {
            return Err(SchemaProblem::Malformed { at });
        };
        for (name, property) in properties {
            followable(property, &at.child(name))?;
        }
    }
    if let Some(items) = object.get("items") {
        followable(items, &at.child("items"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pointer_escapes_its_tokens() {
        let at = JsonPointer::default().child("a/b").child("c~d");
        assert_eq!(at.as_str(), "/a~1b/c~0d");
    }
}
