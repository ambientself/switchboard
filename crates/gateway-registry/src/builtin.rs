//! Built-in connector entries: the `[[connectors]]` of the registry file.
//!
//! A built-in connector is gateway code, not someone else's server, and its entry states what
//! its one credential may be asked for: the vendor permission set (decision 0011, section 1:
//! "Otto's GitHub tokens, requested per permission set, are one entry per set"). A tool's
//! permission set is its entry's. The entry, not the tool's approval, states it, because the
//! credential belongs to the entry: two tools that need different permission sets are served
//! by two entries, and an approval cannot ask for more than its entry's credential carries.
//!
//! An entry lists the tools it serves, and the key custodian reads these entries (design
//! section 9): it checks each token request against the permission set of the tool that asks.
//!
//! An entry that serves an approved tool, `[[built_in_tools]]` in the file, also declares its
//! credential as decision 0011, section 1, has every entry do: the credential's mode and the
//! vendor-side identity it acts as, how it is narrowed on each call, what it permits and, when
//! a tool is declared as the reach, its reach. These are given together or not at all. An entry
//! without them serves no approved tool, as every entry did before built-in tools could be
//! approved, and keeps that meaning: the custodian reads it, and the gateway loads and
//! otherwise ignores it. An entry with them is a connector entry of the snapshot, of kind
//! built-in, so the snapshot loader's rules apply to its tools.
//!
//! # Reach reports
//!
//! Decision 0011, section 4, checks a reach against the vendor's own report of what a
//! credential reaches, where the vendor gives one, as GitHub lists an installation's
//! repositories. Reading that report needs a credential that sees the whole list, broader than
//! any entry's narrowed one, so that credential is a connector entry of its own: one with
//! `reports_reach = true`. The loader holds such an entry to its one job: it declares its
//! credential, narrowed `none` (it reads the whole installation), permitting `read`, with no
//! reach of its own and no reach report; every tool approved on it is `read`; and those tools
//! are served only on [`REACH_SURFACE`], `registry-reach`, restricted to one named principal,
//! the registry's own identity. The key custodian gives such an entry's tool, and no other, an
//! installation-wide token, for `metadata: read` alone (see `key_custodian::policy`).
//!
//! An entry whose reach is checked that way names the report's tool in `reach_report`. It
//! declares a reach that is not empty, and holds only repositories of its own system, which is
//! what the report lists. The tool must be one a reach-report entry of the same system lists,
//! and approved while any of the entry's own tools is, so that nothing is served under a
//! credential whose reach is never checked. The drift pass makes the check (`gateway::drift`).
//!
//! The check is required, not chosen: an entry of [`REPORTED_SYSTEM`], `github`, that declares a
//! reach must name a reach report, as a proxied entry with a reach must name a reach check. An
//! entry of another system may declare a reach without one, since no other vendor's report is
//! built.

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::{
    Classification, ConnectorEntry, ConnectorName, CredentialMode, EntryKind, Narrowing, Resource,
    ToolName,
};
use serde::{Deserialize, Serialize};

use crate::file::ConnectorFile;
use crate::registry::{RegistryError, Server, resource_set};

/// The level of one vendor permission, as GitHub names them: `read` below `write`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Read only.
    Read,
    /// Read and write.
    Write,
}

impl Access {
    /// The level as the file and GitHub write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A built-in connector's entry, checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BuiltInEntry {
    /// The entry's name.
    pub name: ConnectorName,
    /// The system its credential reaches, such as `github`.
    pub system: String,
    /// The vendor permissions its credential may be asked for, each at most at its level.
    pub permissions: BTreeMap<String, Access>,
    /// The tools it serves. Each tool is served by one entry at most.
    pub tools: BTreeSet<ToolName>,
    /// The entry's credential as decision 0011 records it, when the entry serves approved
    /// tools; `None` for an entry the custodian alone reads.
    pub declaration: Option<EntryDeclaration>,
    /// Whether the entry is a reach report's: its credential reads the vendor's report of what
    /// the system's credentials reach (decision 0011, section 4). The loader holds such an
    /// entry to that one job: it declares its credential, narrowed `none`, permitting `read`,
    /// with no reach or reach report of its own; every tool approved on it is `read`; and its
    /// tools are served only on [`REACH_SURFACE`], restricted to one named principal. The key
    /// custodian gives its tools alone an installation-wide token, for `metadata: read` alone.
    pub reports_reach: bool,
    /// The reach report this entry's reach is checked against, if it is.
    pub reach_report: Option<ReachReport>,
}

/// The kind of resource a reach report lists, and so of every resource in the reach of an entry
/// checked against one: GitHub's report lists an installation's repositories.
pub const REPORTED_KIND: &str = "repository";

/// The system whose vendor report is built: GitHub's. An entry of this system that declares a
/// reach must name a reach report.
pub const REPORTED_SYSTEM: &str = "github";

/// The one surface a reach report's tool may be served on: the registry's own, restricted to
/// one named principal, the registry's identity (decision 0011, section 4).
pub const REACH_SURFACE: &str = "registry-reach";

/// The reach report an entry's reach is checked against (decision 0011, section 4): the tool,
/// served by a reach-report entry of the same system, that reads the vendor's report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReachReport {
    /// The tool, by its exposed name.
    pub tool: ToolName,
}

/// A built-in entry's credential as decision 0011, section 1, records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EntryDeclaration {
    /// The credential's mode.
    pub credential: CredentialMode,
    /// The vendor-side identity the credential acts as, such as a GitHub App's name. Never the
    /// secret.
    pub principal: String,
    /// What the credential is narrowed to on each call.
    pub narrowing: Narrowing,
    /// The highest classification any call made with the credential could have.
    pub permits: Classification,
    /// What the credential reaches, for a tool declared as the reach. Empty when not given.
    pub reach: BTreeSet<Resource>,
}

impl BuiltInEntry {
    /// The entry's connector entry in the snapshot, when it is declared.
    pub(crate) fn snapshot_entry(&self) -> Option<ConnectorEntry> {
        let declaration = self.declaration.as_ref()?;
        Some(ConnectorEntry {
            name: self.name.clone(),
            kind: EntryKind::BuiltIn,
            credential: declaration.credential,
            principal: declaration.principal.clone(),
            narrowing: declaration.narrowing,
            permits: declaration.permits,
            reach: declaration.reach.clone(),
            reach_tested_on: None,
        })
    }
}

/// Whether `name` is a permission name as GitHub writes one: lowercase ASCII letters and
/// underscores, such as `pull_requests`, not starting or ending with an underscore.
fn permission_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('_')
        && !name.ends_with('_')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

/// Checks the file's built-in entries against each other and against the proxied servers and
/// tools already checked.
pub(crate) fn built_in(
    entries: Vec<ConnectorFile>,
    servers: &BTreeMap<ConnectorName, Server>,
    proxied_tools: &BTreeSet<ToolName>,
) -> Result<BTreeMap<ConnectorName, BuiltInEntry>, RegistryError> {
    let mut checked: BTreeMap<ConnectorName, BuiltInEntry> = BTreeMap::new();
    let mut served: BTreeMap<ToolName, ConnectorName> = BTreeMap::new();
    for entry in entries {
        if servers.contains_key(&entry.name) || checked.contains_key(&entry.name) {
            return Err(RegistryError::DuplicateEntry(entry.name));
        }
        if entry.system.is_empty() {
            return Err(RegistryError::EmptyField {
                field: "system",
                place: format!("connector `{}`", entry.name),
            });
        }
        // A tool name is under one system only, built-in or proxied.
        if let Some(server) = servers
            .values()
            .find(|server| server.system == entry.system)
        {
            return Err(RegistryError::DuplicateSystem {
                system: entry.system,
                first: server.name.clone(),
                second: entry.name,
            });
        }
        if entry.permissions.is_empty() {
            return Err(RegistryError::EntryWithoutPermissions(entry.name));
        }
        if let Some(bad) = entry.permissions.keys().find(|name| !permission_name(name)) {
            return Err(RegistryError::PermissionName {
                entry: entry.name.clone(),
                permission: bad.clone(),
            });
        }
        if entry.tools.is_empty() {
            return Err(RegistryError::EntryWithoutTools(entry.name));
        }
        for tool in &entry.tools {
            if proxied_tools.contains(tool) {
                return Err(RegistryError::BuiltInToolProxied {
                    tool: tool.clone(),
                    entry: entry.name.clone(),
                });
            }
            if let Some(first) = served.insert(tool.clone(), entry.name.clone()) {
                return Err(RegistryError::ToolOnTwoEntries {
                    tool: tool.clone(),
                    first,
                    second: entry.name.clone(),
                });
            }
        }
        let declaration = match (entry.credential, entry.narrowing, entry.permits) {
            (Some(credential), Some(narrowing), Some(permits)) => {
                if credential.principal.is_empty() {
                    return Err(RegistryError::EmptyField {
                        field: "credential.principal",
                        place: format!("connector `{}`", entry.name),
                    });
                }
                let reach = resource_set(entry.reach.unwrap_or_default(), || {
                    format!("the reach of connector `{}`", entry.name)
                })?;
                Some(EntryDeclaration {
                    credential: credential.mode,
                    principal: credential.principal,
                    narrowing,
                    permits,
                    reach,
                })
            }
            (None, None, None) if entry.reach.is_none() => None,
            _ => return Err(RegistryError::EntryPartlyDeclared(entry.name)),
        };
        let reach_report = entry
            .reach_report
            .map(|report| ReachReport { tool: report.tool });
        let built = BuiltInEntry {
            name: entry.name,
            system: entry.system,
            permissions: entry.permissions,
            tools: entry.tools,
            declaration,
            reports_reach: entry.reports_reach,
            reach_report,
        };
        reach_report_shape(&built)?;
        // A GitHub entry's reach is checked against GitHub's report, or it is not served: the
        // check is not left to the entry to choose (decision 0011, section 4).
        let reaches = built
            .declaration
            .as_ref()
            .is_some_and(|declaration| !declaration.reach.is_empty());
        if built.system == REPORTED_SYSTEM && reaches && built.reach_report.is_none() {
            return Err(RegistryError::ReachReportMissing(built.name));
        }
        checked.insert(built.name.clone(), built);
    }
    for entry in checked.values() {
        if let Some(report) = &entry.reach_report {
            let reported = checked.values().any(|other| {
                other.reports_reach
                    && other.system == entry.system
                    && other.tools.contains(&report.tool)
            });
            if !reported {
                return Err(RegistryError::ReachReport {
                    connector: entry.name.clone(),
                    problem: format!(
                        "names `{}`, which no entry of system `{}` with `reports_reach = true` \
                         lists",
                        report.tool, entry.system
                    ),
                });
            }
        }
    }
    Ok(checked)
}

/// Refuses a reach-report entry that is not held to its one job, and an entry checked against
/// a reach report whose reach is not one the report can be compared with (see the [module
/// documentation](self)).
fn reach_report_shape(entry: &BuiltInEntry) -> Result<(), RegistryError> {
    if entry.reports_reach {
        let problem = match &entry.declaration {
            None => Some("declares no credential"),
            Some(declaration) if declaration.narrowing != Narrowing::None => {
                Some("is not narrowed \"none\", though its credential reads the whole report")
            }
            Some(declaration) if declaration.permits != Classification::Read => {
                Some("permits more than \"read\"")
            }
            Some(declaration) if !declaration.reach.is_empty() => Some("gives a reach"),
            Some(_) if entry.reach_report.is_some() => Some("has a reach report of its own"),
            Some(_) => None,
        };
        if let Some(problem) = problem {
            return Err(RegistryError::ReachReportEntry {
                connector: entry.name.clone(),
                problem: problem.to_owned(),
            });
        }
    }
    if entry.reach_report.is_some() {
        let reach = entry
            .declaration
            .as_ref()
            .map(|declaration| &declaration.reach);
        let comparable = reach.is_some_and(|reach| {
            !reach.is_empty()
                && reach.iter().all(|resource| {
                    resource.system == entry.system && resource.kind == REPORTED_KIND
                })
        });
        if !comparable {
            return Err(RegistryError::ReachReport {
                connector: entry.name.clone(),
                problem: format!(
                    "needs a declared reach that is not empty and holds only resources of system \
                     `{}` and kind `{REPORTED_KIND}`, which is what the report lists",
                    entry.system
                ),
            });
        }
    }
    Ok(())
}
