//! A tool's classification.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A tool's fixed label. Every tool has exactly one.
///
/// There is no unset value and no `Default`: a tool whose classification is missing or
/// unrecognized cannot be represented, so it cannot be registered and never runs. That removes
/// the zero-value case Otto's Go gateway has to guard against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "&'static str")]
pub enum Classification {
    /// Reads and changes nothing.
    Read,
    /// Changes something, in a way that can be undone or reviewed.
    Write,
    /// Destroys something. Denied in every profile.
    Destructive,
}

impl Classification {
    /// Every classification, in order.
    pub const ALL: [Classification; 3] = [
        Classification::Read,
        Classification::Write,
        Classification::Destructive,
    ];

    /// The classification's name, as written in configuration and in the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Read => "read",
            Classification::Write => "write",
            Classification::Destructive => "destructive",
        }
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classification that is not one of `read`, `write` or `destructive`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error(
    "`{0}` is not a classification; a tool must be classified `read`, `write` or `destructive`"
)]
pub struct UnrecognizedClassification(pub String);

impl FromStr for Classification {
    type Err = UnrecognizedClassification;

    /// Exact, lower-case match only. Anything else, including a different case or surrounding
    /// space, is refused rather than guessed at.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Classification::ALL
            .into_iter()
            .find(|classification| classification.as_str() == value)
            .ok_or_else(|| UnrecognizedClassification(value.to_owned()))
    }
}

impl TryFrom<String> for Classification {
    type Error = UnrecognizedClassification;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Classification> for &'static str {
    fn from(classification: Classification) -> Self {
        classification.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_classification_parses_from_its_own_name() {
        for classification in Classification::ALL {
            assert_eq!(classification.as_str().parse(), Ok(classification));
        }
    }

    #[test]
    fn anything_else_is_refused() {
        for text in [
            "", "Read", "READ", " read", "read ", "admin", "readonly", "none", "null",
        ] {
            assert_eq!(
                text.parse::<Classification>(),
                Err(UnrecognizedClassification(text.to_owned())),
                "{text:?} parsed as a classification"
            );
        }
    }

    #[test]
    fn configuration_refuses_an_unrecognized_or_missing_classification() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Tool {
            classification: Classification,
        }
        assert!(serde_json::from_str::<Tool>(r#"{"classification": "write"}"#).is_ok());
        assert!(serde_json::from_str::<Tool>(r#"{"classification": "admin"}"#).is_err());
        assert!(serde_json::from_str::<Tool>(r#"{"classification": null}"#).is_err());
        assert!(serde_json::from_str::<Tool>(r#"{}"#).is_err());
    }

    #[test]
    fn serializes_as_its_name() {
        assert_eq!(
            serde_json::to_string(&Classification::Destructive).ok(),
            Some("\"destructive\"".to_owned())
        );
    }
}
