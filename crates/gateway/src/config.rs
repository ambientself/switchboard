//! The deployment's configuration, as data.
//!
//! Read with serde from JSON (or any format serde reads). Every struct refuses unknown fields,
//! so a misspelt key is an error and not a setting silently left at its default. Parsing only
//! checks shape; [`boot::check`](crate::boot::check) decides whether the configuration may
//! start.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use gateway_core::{DeploymentName, Issuer, SnapshotData, Subject, TeamId};
use gateway_identity::{DEFAULT_GROUPS_CLAIM, IssuerConfig, IssuerKind, SigningAlgorithm};
use serde::Deserialize;

use crate::catalog::ToolDefinition;
use crate::selector::SelectorRules;

/// Everything a deployment configures.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The deployment's name, recorded on every audit row.
    pub deployment: DeploymentName,
    /// Whether and how callers are verified. Absent reads as neither configured nor disabled,
    /// which boot refuses: it is accepted here so the refusal can say which gate is missing.
    #[serde(default)]
    pub identity: IdentitySection,
    /// Whether audit is explicitly disabled. Absent, like `identity`, so boot can say why.
    #[serde(default)]
    pub audit: AuditSection,
    /// What the HTTP endpoint accepts.
    pub http: HttpSection,
    /// The policy snapshot: approved tools, surfaces, profiles and resource limits.
    pub policy: SnapshotData,
    /// The definition of every approved tool.
    pub catalog: Vec<ToolDefinition>,
    /// The rules that select each caller's profile.
    pub profiles: SelectorRules,
}

impl Config {
    /// Reads configuration from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// The identity gate: `"enforce": [issuers]` or `"disabled": true`, and exactly one of them.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Verify every caller against these issuers.
    #[serde(default)]
    pub enforce: Option<Vec<IssuerEntry>>,
    /// Do not verify callers. The gateway starts with a loud warning, lists no tools and
    /// refuses every call, because nothing can be decided without a proved principal.
    #[serde(default)]
    pub disabled: bool,
}

/// The audit gate. The store itself is supplied by the [`Wiring`](crate::Wiring); this says
/// whether audit was explicitly turned off.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Record nothing. The gateway starts with a loud warning. Refused if a store is also
    /// supplied.
    #[serde(default)]
    pub disabled: bool,
}

/// What the HTTP endpoint accepts, against DNS rebinding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSection {
    /// The `Host` values served, without a port. At least one.
    pub allowed_hosts: BTreeSet<String>,
    /// The `Origin` values served when a request carries one. A request with no `Origin`, as
    /// command-line clients send, is not refused for it.
    #[serde(default)]
    pub allowed_origins: BTreeSet<String>,
}

/// One trusted issuer, as configuration states it. Becomes the identity crate's
/// [`IssuerConfig`], whose own checks run when the gate is built.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerEntry {
    /// The issuer, matched exactly against a token's `iss`.
    pub issuer: Issuer,
    /// The audiences accepted for this issuer.
    pub audiences: BTreeSet<String>,
    /// Workload or user.
    pub kind: IssuerKindEntry,
    /// The one algorithm this issuer signs with.
    pub algorithm: Algorithm,
    /// The verification keys, as a JWK set: `{"keys": [...]}`.
    pub keys: serde_json::Value,
    /// The longest a token may live, in seconds.
    pub max_lifetime_secs: u64,
    /// Clock skew tolerated, in seconds.
    pub leeway_secs: u64,
}

/// What an issuer's tokens are about.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IssuerKindEntry {
    /// A workload issuer, with the subject-to-team table.
    Workload {
        /// Subject to team.
        subjects: BTreeMap<Subject, TeamId>,
    },
    /// A user issuer.
    User {
        /// The claim holding the user's groups; `groups` unless stated.
        #[serde(default = "default_groups_claim")]
        groups_claim: String,
    },
}

fn default_groups_claim() -> String {
    DEFAULT_GROUPS_CLAIM.to_owned()
}

/// A signing algorithm, as a token's `alg` header writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
    /// ECDSA with P-256 and SHA-256.
    #[serde(rename = "ES256")]
    Es256,
}

impl IssuerEntry {
    /// Whether this is a workload issuer.
    pub fn is_workload(&self) -> bool {
        matches!(self.kind, IssuerKindEntry::Workload { .. })
    }

    /// The identity crate's configuration for this issuer. Fails only if `keys` is not a JWK
    /// set; everything else is checked when the identity gate is built.
    pub(crate) fn into_config(self) -> Result<IssuerConfig, serde_json::Error> {
        Ok(IssuerConfig {
            keys: serde_json::from_value(self.keys)?,
            issuer: self.issuer,
            audiences: self.audiences,
            kind: match self.kind {
                IssuerKindEntry::Workload { subjects } => IssuerKind::Workload { subjects },
                IssuerKindEntry::User { groups_claim } => IssuerKind::User { groups_claim },
            },
            algorithm: match self.algorithm {
                Algorithm::Rs256 => SigningAlgorithm::Rs256,
                Algorithm::Es256 => SigningAlgorithm::Es256,
            },
            max_lifetime: Duration::from_secs(self.max_lifetime_secs),
            leeway: Duration::from_secs(self.leeway_secs),
        })
    }
}
