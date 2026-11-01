//! The mapping from Otto's bare tool names, which a grant lists, to this gateway's tool names
//! (decision 0012, Tools and resources).
//!
//! While one grant serves both gateways it carries Otto's names, because Otto's Go gateway
//! compares bare names. The mapping is reviewed configuration, one name to one name, and is
//! refused when it loads if it is not one-to-one. A name it does not map is dropped, so it
//! permits nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use gateway_core::ToolName;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

/// Why a tool mapping was refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MappingError {
    /// The text is not a mapping of the expected shape.
    #[error("the tool mapping is not valid JSON of the expected shape: {0}")]
    Shape(String),
    /// An Otto name is empty.
    #[error("the tool mapping has an empty Otto tool name")]
    EmptyOttoName,
    /// An Otto name is mapped more than once.
    #[error("Otto tool `{0}` is mapped more than once")]
    OttoNameRepeated(String),
    /// A gateway name is not a valid tool name.
    #[error("Otto tool `{0}` is mapped to a name that is not a valid tool name")]
    InvalidGatewayName(String),
    /// Two Otto names map to one gateway name.
    #[error("Otto tools `{first}` and `{second}` both map to `{gateway}`")]
    GatewayNameRepeated {
        /// The gateway's name.
        gateway: ToolName,
        /// The Otto name mapped to it first.
        first: String,
        /// The other.
        second: String,
    },
}

/// A one-to-one mapping from Otto's bare tool names to this gateway's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolMapping {
    by_otto: BTreeMap<String, ToolName>,
}

impl ToolMapping {
    /// Builds a mapping from pairs of an Otto name and this gateway's name, refusing one that
    /// is not one-to-one.
    pub fn from_pairs<O, G>(pairs: impl IntoIterator<Item = (O, G)>) -> Result<Self, MappingError>
    where
        O: Into<String>,
        G: AsRef<str>,
    {
        let mut by_otto = BTreeMap::new();
        let mut by_gateway: BTreeMap<ToolName, String> = BTreeMap::new();
        for (otto, gateway) in pairs {
            let otto = otto.into();
            if otto.is_empty() {
                return Err(MappingError::EmptyOttoName);
            }
            let gateway = ToolName::parse(gateway.as_ref())
                .map_err(|_| MappingError::InvalidGatewayName(otto.clone()))?;
            if by_otto.contains_key(&otto) {
                return Err(MappingError::OttoNameRepeated(otto));
            }
            if let Some(first) = by_gateway.get(&gateway) {
                return Err(MappingError::GatewayNameRepeated {
                    gateway,
                    first: first.clone(),
                    second: otto,
                });
            }
            by_gateway.insert(gateway.clone(), otto.clone());
            by_otto.insert(otto, gateway);
        }
        Ok(Self { by_otto })
    }

    /// Reads a mapping file: one JSON object whose members are Otto names, each with this
    /// gateway's name as a string. A name given twice is refused, not overwritten.
    ///
    /// ```json
    /// { "github_get_pr": "github__get_pr", "github_create_pr": "github__create_pr" }
    /// ```
    pub fn from_json(text: &str) -> Result<Self, MappingError> {
        let entries: Entries<String> = parse(text)?;
        Self::from_pairs(entries.0)
    }

    /// Reads the mapping the way `conformance/baseline.json` states it: the `tools` member, an
    /// object whose members are Otto names, each an object whose `switchboard` member is this
    /// gateway's name. Other members are ignored.
    pub fn from_baseline(text: &str) -> Result<Self, MappingError> {
        #[derive(Deserialize)]
        struct Baseline {
            tools: Entries<BaselineTool>,
        }
        #[derive(Deserialize)]
        struct BaselineTool {
            switchboard: String,
        }
        let baseline: Baseline = parse(text)?;
        Self::from_pairs(
            baseline
                .tools
                .0
                .into_iter()
                .map(|(otto, tool)| (otto, tool.switchboard)),
        )
    }

    /// This gateway's name for an Otto name, or `None` if the mapping has none.
    pub fn get(&self, otto: &str) -> Option<&ToolName> {
        self.by_otto.get(otto)
    }

    /// Maps a grant's names, dropping each name the mapping does not have.
    pub fn map<'a>(&self, otto: impl IntoIterator<Item = &'a str>) -> BTreeSet<ToolName> {
        otto.into_iter()
            .filter_map(|name| self.get(name).cloned())
            .collect()
    }

    /// How many names the mapping has.
    pub fn len(&self) -> usize {
        self.by_otto.len()
    }

    /// Whether the mapping has no names.
    pub fn is_empty(&self) -> bool {
        self.by_otto.is_empty()
    }
}

/// The mapping as a member of a larger document, such as the gateway's JSON configuration: one
/// object of Otto names to this gateway's, read as [`ToolMapping::from_json`] reads a mapping
/// file. A name given twice is refused, not overwritten, which reading it through
/// `serde_json::Value` first would not do.
impl<'de> Deserialize<'de> for ToolMapping {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Entries::<String>::deserialize(deserializer)?;
        Self::from_pairs(entries.0).map_err(serde::de::Error::custom)
    }
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T, MappingError> {
    serde_json::from_str(text).map_err(|error| MappingError::Shape(error.to_string()))
}

/// A JSON object's members in order, every one kept: `serde_json`'s own map keeps only the last
/// of a repeated name, which would hide a mapping that is not one-to-one.
struct Entries<V>(Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Entries<V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor<V>(PhantomData<V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for EntriesVisitor<V> {
            type Value = Entries<V>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, V>()? {
                    entries.push(entry);
                }
                Ok(Entries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor(PhantomData))
    }
}
