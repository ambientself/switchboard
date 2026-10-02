//! Names and identifiers.
//!
//! Each is its own type so that a team cannot be passed where a surface is expected. None of
//! them says anything about provenance: whether a team was proved or merely claimed is carried
//! by [`Proved`](crate::Proved) and [`Claimed`](crate::Claimed), not by the name.

use std::fmt;

use serde::{Deserialize, Serialize};

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
    /// A tool's exposed name, `{system}__{tool}`.
    ToolName
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
    /// The caller's own identifier for one tool call, recorded so its control plane can find
    /// the decision.
    ToolUseId
);
