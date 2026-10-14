//! Names and identifiers.
//!
//! Each is its own type so that a team cannot be passed where a surface is expected. None of
//! them says anything about provenance: whether a team was proved or merely claimed is carried
//! by [`Proved`](crate::Proved) and [`Claimed`](crate::Claimed), not by the name.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

macro_rules! name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps a string as this kind of name.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// The name as a string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }
    };
}

name!(
    /// The issuer that vouched for a principal, such as a cluster or an identity provider.
    Issuer
);
name!(
    /// A subject as its issuer names it. Meaningful only together with the issuer.
    Subject
);
name!(
    /// A team, as the team manifest names it.
    TeamId
);
name!(
    /// A group membership from an identity provider.
    GroupId
);
name!(
    /// A person a delegation says the principal is acting for.
    Person
);
name!(
    /// A named tool surface, served at `/mcp/{surface}`.
    SurfaceName
);
name!(
    /// The name of a profile: the policy set for one kind of caller.
    ProfileName
);
name!(
    /// The connector or proxied server that runs a tool.
    ConnectorName
);
name!(
    /// The gateway deployment that received a call.
    DeploymentName
);
name!(
    /// The revision of the policy snapshot a decision was made from.
    PolicyRevision
);
name!(
    /// The gateway instance that began an audit row: a pod's name, or a container's. The core
    /// records it escaped and capped, like the surface, since it comes from the environment.
    InstanceName
);
name!(
    /// The caller's own identifier for one tool call, recorded so its control plane can find
    /// the decision.
    ToolUseId
);
name!(
    /// The issuer of a delegation, by the name the gateway's configuration gives the key that
    /// verified it (decision 0012, "The issuer is the key"). Not a token issuer: a principal's
    /// is an [`Issuer`].
    DelegationIssuer
);
name!(
    /// The identifier of the key a delegation's signature verified under, as the delegation
    /// names it and the gateway's configuration holds it.
    KeyId
);
name!(
    /// The session a delegation was issued in, as its issuing control plane names it: for
    /// Otto, the grant's `sid`.
    SessionId
);
name!(
    /// The turn a delegation was issued for, as its issuing control plane names it: for Otto,
    /// the grant's `tid`.
    TurnId
);
name!(
    /// The execution a delegation's turn belongs to, as its issuing control plane names it: for
    /// Otto, the grant's `eid`.
    ExecutionId
);

/// The longest a tool name may be.
pub const MAX_TOOL_NAME: usize = 64;

/// A tool's exposed name, `{system}__{tool}`: 1 to 64 characters of ASCII letters, digits,
/// `_` and `-`.
///
/// Validated whenever one is made, including from configuration, so a name held as a
/// `ToolName` is safe to echo into a sentence or a row. What a caller asked for is a
/// [`RequestedTool`] until it is checked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolName(String);

/// A string that is not a valid tool name.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error(
    "not a valid tool name: a tool name is 1 to {MAX_TOOL_NAME} ASCII letters, digits, `_` or `-`"
)]
pub struct InvalidToolName;

impl ToolName {
    /// Checks `value` against the naming rule.
    pub fn parse(value: &str) -> Result<Self, InvalidToolName> {
        let valid = !value.is_empty()
            && value.len() <= MAX_TOOL_NAME
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidToolName)
        }
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ToolName {
    type Err = InvalidToolName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for ToolName {
    type Error = InvalidToolName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ToolName> for String {
    fn from(name: ToolName) -> Self {
        name.0
    }
}

/// The UID of a Kubernetes pod, as the pod's projected ServiceAccount token proves it
/// (decision 0012): a UUID in the lowercase hyphenated form Kubernetes gives it, such as
/// `0f8fad5b-d9cb-469f-a165-70867728950e`.
///
/// Validated whenever one is made, including from JSON, so nothing else can be held as one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PodUid(String);

/// A string that is not a pod UID.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("not a pod UID: a pod UID is a UUID in lowercase hyphenated form")]
pub struct InvalidPodUid;

impl PodUid {
    /// Checks that `value` is a UUID in lowercase hyphenated form: 32 lowercase hexadecimal
    /// digits in groups of 8, 4, 4, 4 and 12, joined by `-`.
    pub fn parse(value: &str) -> Result<Self, InvalidPodUid> {
        let groups: Vec<&str> = value.split('-').collect();
        let valid = groups.len() == 5
            && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
                group.len() == length
                    && group
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidPodUid)
        }
    }

    /// The UID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PodUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for PodUid {
    type Err = InvalidPodUid;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for PodUid {
    type Error = InvalidPodUid;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PodUid> for String {
    fn from(uid: PodUid) -> Self {
        uid.0
    }
}

/// The tool a request names, exactly as the caller sent it: any bytes, any length.
///
/// The decision function checks it against [`ToolName`]'s rule; a name that fails is denied
/// without being echoed back.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestedTool(String);

impl RequestedTool {
    /// Records what the caller asked for.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw request. Never render this into a sentence or a row as it is.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The requested name as a valid [`ToolName`], if it is one.
    pub fn name(&self) -> Result<ToolName, InvalidToolName> {
        ToolName::parse(&self.0)
    }
}

impl From<&str> for RequestedTool {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<ToolName> for RequestedTool {
    fn from(name: ToolName) -> Self {
        Self(name.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_name_follows_the_naming_rule() {
        let longest = "a".repeat(MAX_TOOL_NAME);
        for valid in ["a", "github__get_file", "A-z_0-9", longest.as_str()] {
            assert!(ToolName::parse(valid).is_ok(), "{valid:?} was refused");
        }
        let too_long = "a".repeat(MAX_TOOL_NAME + 1);
        for invalid in [
            "",
            too_long.as_str(),
            "get file",
            "get\nfile",
            "get.file",
            "get/file",
            "g\u{e9}t",
            "`tool`",
        ] {
            assert_eq!(
                ToolName::parse(invalid),
                Err(InvalidToolName),
                "{invalid:?} was accepted"
            );
        }
    }

    #[test]
    fn a_pod_uid_is_a_lowercase_hyphenated_uuid() {
        for valid in [
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ] {
            assert_eq!(
                PodUid::parse(valid).map(|uid| uid.to_string()),
                Ok(valid.to_owned())
            );
        }
        for invalid in [
            "",
            "0F8FAD5B-D9CB-469F-A165-70867728950E",
            "0f8fad5b-d9cb-469f-a165-70867728950E",
            "0f8fad5bd9cb469fa16570867728950e",
            "{0f8fad5b-d9cb-469f-a165-70867728950e}",
            "urn:uuid:0f8fad5b-d9cb-469f-a165-70867728950e",
            "0f8fad5b-d9cb-469f-a165-70867728950e ",
            " 0f8fad5b-d9cb-469f-a165-70867728950e",
            "0f8fad5b-d9cb-469f-a165-70867728950e\n",
            "0f8fad5b-d9cb-469f-a165-70867728950",
            "0f8fad5b-d9cb-469f-a165-70867728950e0",
            "0f8fad5bd-9cb-469f-a165-70867728950e",
            "0f8fad5b-d9cb-469f-a16570867728950e-",
            "0f8fad5b-d9cb-469f-a165-70867728950g",
            "0f8fad5b-d9cb-469f-a165-7086772895+e",
            "0f8fad5b-d9cb-469f-a165-7086772895\u{e9}",
            "0f8fad5b--d9cb-469f-a165-70867728950e",
        ] {
            assert_eq!(
                PodUid::parse(invalid),
                Err(InvalidPodUid),
                "{invalid:?} was accepted"
            );
        }
    }

    #[test]
    fn json_cannot_hold_an_invalid_pod_uid() {
        let uid = serde_json::from_str::<PodUid>(r#""0f8fad5b-d9cb-469f-a165-70867728950e""#);
        assert_eq!(
            uid.ok().map(String::from).as_deref(),
            Some("0f8fad5b-d9cb-469f-a165-70867728950e")
        );
        for invalid in [
            r#""0F8FAD5B-D9CB-469F-A165-70867728950E""#,
            r#""""#,
            "7",
            "null",
        ] {
            assert!(
                serde_json::from_str::<PodUid>(invalid).is_err(),
                "{invalid} was accepted"
            );
        }
    }

    #[test]
    fn configuration_cannot_hold_an_invalid_tool_name() {
        assert!(serde_json::from_str::<ToolName>(r#""github__get_file""#).is_ok());
        assert!(serde_json::from_str::<ToolName>(r#""bad name""#).is_err());
        assert!(serde_json::from_str::<ToolName>(r#""""#).is_err());
    }
}
