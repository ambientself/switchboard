//! A tool's classification.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A tool's fixed label. Every tool has exactly one, assigned by the person who approves it.
///
/// There is no unset value and no `Default`: a tool whose classification is missing or
/// unrecognized cannot be represented, so it cannot be registered and never runs. That removes
/// the zero-value case Otto's Go gateway has to guard against.
///
/// `Write` and `Destructive` are denied in every profile (decision 0006). What a profile can
/// permit is `Read` and `Propose`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "&'static str")]
pub enum Classification {
    /// Reads and changes nothing.
    Read,
    /// Creates something for a person to review, or changes only what the gateway itself
    /// created for review: a draft pull request, an issue it opens, a commit to its own
    /// proposal branch, a comment on something it created for review. It never changes,
    /// transitions, merges or deploys anything else, so nothing it does takes effect until a
    /// person acts on it.
    ///
    /// The decision function cannot see what the gateway created. A tool is `Propose` only if
    /// it refuses, when it runs, to act on anything else. It must also guard against what
    /// would take effect on its own even there: it refuses a comment a bot would read as a
    /// command and a commit to a pull request a person has marked ready for review, and it
    /// forces a pull request it opens to be a draft. It has no setting that turns a guard off.
    Propose,
    /// Changes something directly: a merge, a push to a branch the gateway did not create for a
    /// proposal, a status transition, a configuration change, a comment on anything the gateway
    /// did not create for review. A comment counts because it can take effect on its own, as a
    /// bot command or a CI trigger. Denied in every profile, which is how production mutation
    /// is denied: anything that changes production without a person acting is a `Write` or
    /// worse.
    Write,
    /// Destroys something. Denied in every profile.
    Destructive,
}

impl Classification {
    /// Every classification, in order.
    pub const ALL: [Classification; 4] = [
        Classification::Read,
        Classification::Propose,
        Classification::Write,
        Classification::Destructive,
    ];

    /// The classification's name, as written in configuration and in the audit record.
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Read => "read",
            Classification::Propose => "propose",
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

/// A classification that is not one of `read`, `propose`, `write` or `destructive`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error(
    "`{0}` is not a classification; a tool must be classified `read`, `propose`, `write` or `destructive`"
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
            "", "Read", "READ", " read", "read ", "admin", "readonly", "none", "null", "proposal",
            "proposes", "Propose",
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
