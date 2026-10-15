//! The custodian's own copy of what each team and tool may ask for (design section 9).
//!
//! It is generated from the registry file, the same file the gateway's snapshot is loaded
//! from, by the same loader. The custodian applies only the loader's checks, not the checks
//! the gateway's boot and reload add (a changed server or route, the boot gates, bytes that are
//! not UTF-8), so a file the loader refuses the custodian refuses too, and a file only the
//! gateway refuses the custodian serves (see the crate's documentation for what follows). From
//! it the custodian keeps three things:
//!
//! - the revision, which every request must carry: the same revision, or one the gateway
//!   derived from it by withdrawing tools, `{base}+withdrawn:{names}`, whose base is checked
//!   (see [`crate::protocol::base_revision`]);
//! - each team's GitHub repositories: the resources of system `github` and kind `repository`
//!   in the team's limit, each identified `owner/name`;
//! - each tool's permission set: the `permissions` of the built-in connector entry of system
//!   `github` that serves it (see [`gateway_registry::BuiltInEntry`]).
//!
//! [`PolicyCell::watch`] reads the file again every few seconds, as the gateway's reloader
//! does, and serves a new copy that loads from the next request on. A file that does not load
//! keeps the copy served now. So does a file whose copy differs under the same revision: the
//! revision is what a request and the record name, so one revision must mean one copy.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use gateway_core::{PolicyRevision, TeamId, ToolName};
use gateway_registry::{Access, Registry, RegistryError};
use thiserror::Error;

use crate::metrics::Counters;
use crate::protocol::{MAX_REPOSITORIES, Refusal, TokenRequest, base_revision, split_repository};

/// The system of a GitHub resource, in a limit and in a connector entry.
pub const GITHUB_SYSTEM: &str = "github";
/// The kind of a GitHub repository in a limit.
pub const REPOSITORY_KIND: &str = "repository";

/// What each team and tool may ask for, at one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodianPolicy {
    revision: PolicyRevision,
    teams: BTreeMap<TeamId, BTreeSet<String>>,
    tools: BTreeMap<ToolName, BTreeMap<String, Access>>,
}

/// Why a request was refused, and a sentence for the operator.
pub type Refused = (Refusal, String);

impl CustodianPolicy {
    /// The copy a loaded registry gives.
    pub fn from_registry(registry: &Registry) -> Self {
        let snapshot = registry.snapshot();
        let teams = snapshot
            .limits()
            .teams
            .iter()
            .map(|(team, resources)| {
                let repositories = resources
                    .iter()
                    .filter(|resource| {
                        resource.system == GITHUB_SYSTEM && resource.kind == REPOSITORY_KIND
                    })
                    .map(|resource| resource.identifier.clone())
                    .collect();
                (team.clone(), repositories)
            })
            .collect();
        let tools = registry
            .connectors()
            .values()
            .filter(|entry| entry.system == GITHUB_SYSTEM)
            .flat_map(|entry| {
                entry
                    .tools
                    .iter()
                    .map(|tool| (tool.clone(), entry.permissions.clone()))
            })
            .collect();
        Self {
            revision: snapshot.revision().clone(),
            teams,
            tools,
        }
    }

    /// The revision this copy was generated at.
    pub fn revision(&self) -> &PolicyRevision {
        &self.revision
    }

    /// Whether `request` is within what its team and tool may ask for, at this revision, for
    /// an installation on `account`. The request must not be malformed (see
    /// [`TokenRequest::malformed`]).
    pub fn check(&self, request: &TokenRequest, account: &str) -> Result<(), Refused> {
        let base = base_revision(&request.revision);
        if base != self.revision.as_str() {
            return Err((
                Refusal::StaleRevision,
                format!(
                    "the request was decided under revision `{base}`, and the custodian holds `{}`",
                    self.revision
                ),
            ));
        }
        let Some(limit) = self.teams.get(&request.team) else {
            return Err((
                Refusal::UnknownTeam,
                format!("team `{}` has no limits", request.team),
            ));
        };
        let Some(stated) = self.tools.get(&request.tool) else {
            return Err((
                Refusal::UnknownTool,
                format!("no GitHub connector entry serves tool `{}`", request.tool),
            ));
        };
        if request.repositories.is_empty() {
            return Err((
                Refusal::NoRepositories,
                "the request names no repository".into(),
            ));
        }
        if request.repositories.len() > MAX_REPOSITORIES {
            return Err((
                Refusal::TooManyRepositories,
                format!(
                    "the request names {} repositories, and one token names at most \
                     {MAX_REPOSITORIES}",
                    request.repositories.len()
                ),
            ));
        }
        for repository in &request.repositories {
            let owner = split_repository(repository).map_or("", |(owner, _)| owner);
            if owner != account {
                return Err((
                    Refusal::OtherAccount,
                    format!(
                        "repository `{repository}` is not on account `{account}`, where the \
                         App is installed"
                    ),
                ));
            }
            if !limit.contains(repository) {
                return Err((
                    Refusal::RepositoryOutsideLimit,
                    format!(
                        "repository `{repository}` is outside team `{}`'s limit",
                        request.team
                    ),
                ));
            }
        }
        if request.permissions.is_empty() {
            return Err((
                Refusal::NoPermissions,
                "the request names no permission".into(),
            ));
        }
        for (permission, level) in &request.permissions {
            if stated.get(permission).is_none_or(|allowed| level > allowed) {
                return Err((
                    Refusal::PermissionOutsideTool,
                    format!(
                        "tool `{}` may not ask for `{permission}: {}`",
                        request.tool,
                        level.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Why the registry file did not give a copy.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The file could not be read or does not load.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The file's copy differs from the one served, under the same revision.
    #[error(
        "the registry's GitHub limits or permission sets changed but its revision is still `{0}`; \
         change the revision with every edit to the policy"
    )]
    RevisionUnchanged(PolicyRevision),
}

/// The copy served now. Cheap to clone; clones share it.
#[derive(Clone)]
pub struct PolicyCell(Arc<RwLock<Arc<CustodianPolicy>>>);

impl PolicyCell {
    /// Loads the registry file at `path`, and returns the bytes it loaded with the copy.
    pub fn load(path: &Path) -> Result<(Self, Vec<u8>), PolicyError> {
        let bytes = std::fs::read(path).map_err(|error| RegistryError::Read {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let registry = Registry::from_toml_str(&String::from_utf8_lossy(&bytes))?;
        let cell = Self(Arc::new(RwLock::new(Arc::new(
            CustodianPolicy::from_registry(&registry),
        ))));
        Ok((cell, bytes))
    }

    /// The copy served now.
    pub fn current(&self) -> Arc<CustodianPolicy> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Serves the copy `text` gives, if it loads and keeps one revision to one copy.
    pub fn apply(&self, text: &str) -> Result<bool, PolicyError> {
        let registry = Registry::from_toml_str(text)?;
        let next = CustodianPolicy::from_registry(&registry);
        let mut served = self.0.write().unwrap_or_else(PoisonError::into_inner);
        if next == **served {
            return Ok(false);
        }
        if next.revision == served.revision {
            return Err(PolicyError::RevisionUnchanged(next.revision));
        }
        *served = Arc::new(next);
        Ok(true)
    }

    /// Reads the file at `path` every `every`, by path, and applies it when its bytes differ
    /// from the last read, `loaded` at first. Runs until dropped. A version that does not load
    /// is logged once; a read that fails is logged at every poll, and keeps the copy served.
    pub async fn watch(
        self,
        path: PathBuf,
        every: Duration,
        loaded: Vec<u8>,
        counters: Arc<Counters>,
    ) {
        let mut last = Some(loaded);
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!(%error, path = %path.display(), "could not read the registry file");
                    continue;
                }
            };
            if last.as_deref() == Some(bytes.as_slice()) {
                continue;
            }
            last = Some(bytes.clone());
            let text = String::from_utf8_lossy(&bytes);
            match self.apply(&text) {
                Ok(true) => {
                    counters.reload(true);
                    tracing::info!(revision = %self.current().revision(), "serving a new copy of policy");
                }
                Ok(false) => {}
                Err(error) => {
                    counters.reload(false);
                    tracing::error!(%error, revision = %self.current().revision(), "kept the copy of policy served now");
                }
            }
        }
    }
}
