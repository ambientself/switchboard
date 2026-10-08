//! Reloading the registry file while the gateway runs (planDemo 14e).
//!
//! [`Reloader::watch`] reads the registry file every few seconds. When its bytes change, it
//! loads the new file and, if it passes, serves its policy from the next request on. A file
//! that fails keeps the policy served now, and the reason is logged once per version of the
//! file, at error level.
//!
//! A reload can change the policy: tools withdrawn, surfaces, profiles, limits, rules and
//! definitions. It cannot change what the running connectors were built for, so a new file is
//! refused, and the gateway must be restarted, if it changes a server, adds or removes one, or
//! routes a tool to an upstream tool the gateway did not start with. Withdrawing a tool is
//! always possible.
//!
//! A new file that changes the policy must also change its `revision`. Audit rows explain a
//! decision only by the revision they record, so two different policies served under one
//! revision would make those rows ambiguous. Such a file is refused and the policy served now
//! stays. A file whose policy is the same as the one served (a comment edited, say) is fine
//! with the same revision.
//!
//! The file is read by path every time, never through a handle kept open, so an edit that
//! replaces the file (`sed -i`, a rename, a ConfigMap update swapping a symlink) is seen. Mount
//! the directory that holds the file, not the file itself: a bind mount of a single file keeps
//! the old inode.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use gateway_core::{PolicyRevision, ToolName};
use gateway_registry::{Registry, RegistryError};
use thiserror::Error;

use crate::boot::{Basis, BootError, check_registry_policy};
use crate::policy::{LivePolicy, ServedPolicy};

/// Why a new registry file was not served. The policy served before stays.
#[derive(Debug, Error)]
pub enum ReloadError {
    /// The file could not be read, or it does not load.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The file's servers are not the ones the gateway started with.
    #[error("the registry's servers changed; restart the gateway to serve them")]
    ServersChanged,
    /// A tool is routed to an upstream tool the connectors were not built for.
    #[error(
        "tool `{0}` is routed somewhere the gateway did not start with; restart the gateway to \
         serve it"
    )]
    RouteChanged(ToolName),
    /// The file changes the policy but keeps the revision of the policy served now.
    #[error(
        "the registry's policy changed but its revision is still `{0}`; change the revision \
         with every edit to the policy"
    )]
    RevisionUnchanged(PolicyRevision),
    /// The policy fails a boot gate.
    #[error(transparent)]
    Boot(#[from] BootError),
}

/// Replaces the served policy with a new registry file's, if it passes.
pub struct Reloader {
    live: Arc<LivePolicy>,
    basis: Basis,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloader")
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

impl Reloader {
    pub(crate) fn new(live: Arc<LivePolicy>, basis: Basis) -> Self {
        Self { live, basis }
    }

    /// Serves `registry`'s policy from the next request on, or refuses it and keeps the policy
    /// served now. Returns the new revision.
    pub fn apply(&self, registry: &Registry) -> Result<PolicyRevision, ReloadError> {
        let started = &self.basis.registry;
        if registry.servers() != started.servers() {
            return Err(ReloadError::ServersChanged);
        }
        for (tool, route) in registry.routes() {
            if started.routes().get(tool) != Some(route) {
                return Err(ReloadError::RouteChanged(tool.clone()));
            }
        }
        let policy = ServedPolicy::from_registry(registry).map_err(BootError::from)?;
        check_registry_policy(registry, &policy, &self.basis)?;
        let served = self.live.current();
        if policy.revision() == served.revision() && policy != *served {
            return Err(ReloadError::RevisionUnchanged(policy.revision().clone()));
        }
        let revision = policy.revision().clone();
        self.live.replace(policy);
        Ok(revision)
    }

    /// Reads `file` every `every`, and applies it whenever its bytes differ from the last ones
    /// read. `loaded` is the text the gateway started with. Never returns.
    pub async fn watch(self, file: PathBuf, every: Duration, loaded: Vec<u8>) {
        let mut seen = loaded;
        let mut last_read_error: Option<String> = None;
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate, and the file was just loaded.
        interval.tick().await;
        loop {
            interval.tick().await;
            let bytes = match std::fs::read(&file) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = error.to_string();
                    if last_read_error.as_ref() != Some(&error) {
                        tracing::error!(
                            event = "policy_reload_refused",
                            file = %file.display(),
                            reason = %error,
                            "cannot read the registry file; the policy served now stays"
                        );
                        last_read_error = Some(error);
                    }
                    continue;
                }
            };
            last_read_error = None;
            if bytes == seen {
                continue;
            }
            seen = bytes;
            self.reload(&file, &seen);
        }
    }

    fn reload(&self, file: &Path, bytes: &[u8]) {
        let applied = std::str::from_utf8(bytes)
            .map_err(|error| {
                ReloadError::Registry(RegistryError::Read {
                    path: file.display().to_string(),
                    message: error.to_string(),
                })
            })
            .and_then(|text| Ok(Registry::from_toml_str(text)?))
            .and_then(|registry| self.apply(&registry));
        match applied {
            Ok(revision) => tracing::info!(
                event = "policy_reloaded",
                file = %file.display(),
                %revision,
                "serving the registry file's new policy"
            ),
            Err(error) => tracing::error!(
                event = "policy_reload_refused",
                file = %file.display(),
                reason = %error,
                served = %self.live.current().revision(),
                "refused the registry file's new version; the policy served now stays"
            ),
        }
    }
}
