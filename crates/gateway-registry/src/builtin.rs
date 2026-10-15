//! Built-in connector entries: the `[[connectors]]` of the registry file.
//!
//! A built-in connector is gateway code, not someone else's server, and its entry states what
//! its one credential may be asked for: the vendor permission set (decision 0011, section 1:
//! "Otto's GitHub tokens, requested per permission set, are one entry per set"). A tool's
//! permission set is its entry's. The entry, not the tool's approval, states it, because the
//! credential belongs to the entry: two tools that need different permission sets are served
//! by two entries, and an approval cannot ask for more than its entry's credential carries.
//!
//! Until a built-in connector's tools are approved in this file, an entry lists the tools it
//! serves. Only the key custodian reads these entries (design section 9): it checks each token
//! request against the permission set of the tool that asks. The gateway loads them, so a file
//! with a malformed entry is refused by both, and otherwise ignores them.

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::{ConnectorName, ToolName};
use serde::{Deserialize, Serialize};

use crate::file::ConnectorFile;
use crate::registry::{RegistryError, Server};

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
        checked.insert(
            entry.name.clone(),
            BuiltInEntry {
                name: entry.name,
                system: entry.system,
                permissions: entry.permissions,
                tools: entry.tools,
            },
        );
    }
    Ok(checked)
}
