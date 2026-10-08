//! The registry file as it is written, before any of it is checked.
//!
//! Every table refuses fields it does not know, so a misspelt key is an error and never a
//! silently ignored setting. Nothing that limits access has a default: a dropped line must not
//! read as "unrestricted". The enums written as a string or a one-key table, such as
//! `resources`, need no attribute for this: a variant they do not know, or a second key, is
//! already refused.

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::{
    Classification, ConnectorName, GroupId, Issuer, ProfileName, Subject, SurfaceName, TeamId,
    ToolName,
};
use serde::Deserialize;
use toml::value::Datetime;

/// The whole file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryFile {
    pub revision: String,
    pub servers: Vec<ServerFile>,
    pub tools: Vec<ToolFile>,
    pub surfaces: Vec<SurfaceFile>,
    pub profiles: Vec<ProfileFile>,
    pub profile_rules: Vec<RuleFile>,
    pub limits: LimitsFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerFile {
    pub name: ConnectorName,
    pub system: String,
    pub owner: String,
    pub identity: String,
    pub address: String,
    pub credential: CredentialFile,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CredentialFile {
    Bearer { reference: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolFile {
    pub name: ToolName,
    pub server: ConnectorName,
    pub upstream_name: String,
    pub classification: Classification,
    #[serde(default)]
    pub title: Option<String>,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub approved_by: String,
    pub approved_at: Datetime,
    pub definition_sha256: String,
    pub resources: ResourcesFile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourcesFile {
    NoResources,
    FromArguments(Vec<SourceFile>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceFile {
    pub from_argument: String,
    pub system: String,
    pub kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SurfaceFile {
    pub name: SurfaceName,
    pub tools: BTreeSet<ToolName>,
    #[serde(default)]
    pub teams: BTreeSet<TeamId>,
    #[serde(default)]
    pub groups: BTreeSet<GroupId>,
    pub principals: PrincipalsFile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrincipalsFile {
    AnyInTeamsAndGroups,
    Only(Vec<PrincipalIdFile>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrincipalIdFile {
    pub issuer: Issuer,
    pub subject: Subject,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileFile {
    pub name: ProfileName,
    pub classifications: BTreeSet<Classification>,
    pub requires_delegation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleFile {
    pub issuer: Issuer,
    pub principal: RulePrincipalFile,
    pub profile: ProfileName,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RulePrincipalFile {
    Workload,
    UserInGroup(GroupId),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LimitsFile {
    #[serde(default)]
    pub teams: BTreeMap<TeamId, Vec<ResourceFile>>,
    #[serde(default)]
    pub groups: BTreeMap<GroupId, Vec<ResourceFile>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceFile {
    pub system: String,
    pub kind: String,
    pub identifier: String,
}
