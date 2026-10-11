//! Reloading the registry file while the gateway runs (planDemo 14e).
//!
//! [`Reloader::watch`] reads the registry file as soon as it starts, and every few seconds
//! after that. When its bytes change, it loads the new file and, if it passes, serves its
//! policy from the next request on. A file that fails keeps the policy served now, and the
//! reason is logged once per version of the file, at error level.
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
//! Every read that succeeds is recorded in the [`Freshness`] the gates share, whether or not
//! the bytes changed and whether or not they load. Past the deployment's maximum age since the
//! last such read, the policy is stale (decision 0013, section 8): `/readyz` fails, and
//! `tools/call` and `tools/list` are refused with [`POLICY_STALE`](crate::path::POLICY_STALE)
//! and no row, until a read succeeds again. A file that reads but does not load keeps the last
//! good policy, and is not stale.
//!
//! The file is read by path every time, never through a handle kept open, so an edit that
//! replaces the file (`sed -i`, a rename, a ConfigMap update swapping a symlink) is seen. Mount
//! the directory that holds the file, not the file itself: a bind mount of a single file keeps
//! the old inode.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

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

/// When the registry file was last read successfully, and how long after that the policy it
/// holds is stale. Cheap to clone; clones share the time. The boot read counts as the first,
/// from the moment it was made.
#[derive(Clone)]
pub struct Freshness(Arc<FreshnessState>);

struct FreshnessState {
    max_age: Option<Duration>,
    last_read: Mutex<Instant>,
}

impl std::fmt::Debug for Freshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Freshness")
            .field("max_age", &self.0.max_age)
            .field("age", &self.age())
            .finish()
    }
}

impl Freshness {
    /// Last read at `read_at`, and stale `max_age` after the last read; never, with `None`.
    pub(crate) fn new(max_age: Option<Duration>, read_at: Instant) -> Self {
        Self(Arc::new(FreshnessState {
            max_age,
            last_read: Mutex::new(read_at),
        }))
    }

    /// Records a successful read of the registry file, now.
    pub(crate) fn read_now(&self) {
        *self
            .0
            .last_read
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    /// How long ago the registry file was last read successfully.
    pub fn age(&self) -> Duration {
        self.0
            .last_read
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }

    /// How long after a read the policy is stale, or `None` when it never is.
    pub fn max_age(&self) -> Option<Duration> {
        self.0.max_age
    }

    /// Whether the last successful read is older than the maximum age.
    pub fn is_stale(&self) -> bool {
        self.0.max_age.is_some_and(|max_age| self.age() > max_age)
    }
}

/// Replaces the served policy with a new registry file's, if it passes.
pub struct Reloader {
    live: Arc<LivePolicy>,
    basis: Basis,
    freshness: Freshness,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reloader")
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

impl Reloader {
    pub(crate) fn new(live: Arc<LivePolicy>, basis: Basis, freshness: Freshness) -> Self {
        Self {
            live,
            basis,
            freshness,
        }
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

    /// Reads `file` as soon as it starts and every `every` after that, records each read that
    /// succeeds in the gates' [`Freshness`], and applies the file whenever its bytes differ
    /// from the last ones read. `loaded` is the text the gateway started with. Never returns.
    pub async fn watch(self, file: PathBuf, every: Duration, loaded: Vec<u8>) {
        let mut seen = loaded;
        let mut last_read_error: Option<String> = None;
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate, so the file is read as the watch starts. Boot read it
        // too, but a boot slower than the maximum age starts stale, and this read ends that at
        // once rather than a poll later. Unchanged bytes are not loaded again.
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
            // Every read counts, changed or not, loading or not (decision 0013, section 8).
            self.freshness.read_now();
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::Mutex;

    use serde_json::Value;

    use super::*;
    use crate::boot::tests::{registry, registry_text, release_basis};

    /// A log writer the test reads back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_reload_the_receipt_gate_refuses_keeps_the_served_policy_and_says_so() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);

        // A release build serving a read tool at r1.
        let started = registry("read", true);
        let live = Arc::new(LivePolicy::new(
            ServedPolicy::from_registry(&started).unwrap(),
        ));
        let reloader = Reloader::new(
            live.clone(),
            release_basis(started),
            Freshness::new(None, Instant::now()),
        );

        // The same tool reclassified `propose`, at r2: same server, same route.
        let proposed = registry_text("propose", true, "r2");
        reloader.reload(Path::new("registry.toml"), proposed.as_bytes());

        assert_eq!(live.current().revision().as_str(), "r1");
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let refused: Vec<Value> = logged
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == "policy_reload_refused")
            .collect();
        assert_eq!(refused.len(), 1, "{logged}");
        let fields = &refused[0]["fields"];
        assert_eq!(fields["served"], "r1");
        let reason = fields["reason"].as_str().unwrap();
        assert!(
            reason.contains("no receipt store is configured"),
            "{reason}"
        );

        // The read version at r2 is served: the refusal was the gate's, not the file's.
        let read = registry_text("read", true, "r2");
        reloader.reload(Path::new("registry.toml"), read.as_bytes());
        assert_eq!(live.current().revision().as_str(), "r2");
    }
}
