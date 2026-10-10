//! Fetching issuers' keys while the gateway runs.
//!
//! An issuer configured with `keys_url` (see [`crate::deployment`]) has its keys fetched by an
//! [`issuer_keys::KeySource`], which holds the URL to the issuer's own origin and bounds each
//! fetch. [`start::prepare`](crate::start::prepare) fetches each once before the boot gates are
//! built, and refuses to start if a fetch fails. After that, [`KeyRefresher::run`] fetches each
//! again every `keys_refresh_seconds`, one task per issuer, and puts the new set in force with
//! [`Identity::replace_keys`], which checks it exactly as boot does.
//!
//! - **A failed refresh keeps the keys in use.** A fetch that fails (unreachable, a deadline,
//!   a status other than `200`, a body over the cap or not a JWK set) or a set the identity gate
//!   refuses (no usable key, a repeated `kid`) changes nothing. It is logged as
//!   [`REFRESH_FAILED_EVENT`] at `WARN`, naming the issuer and the cause, once for each cause in
//!   a row: the same cause again is not logged again until a refresh succeeds or the cause
//!   changes. There is no maximum age: keys that cannot be refreshed stay in force until one
//!   can be. Whether a gateway should stop accepting tokens once its keys are too old to trust
//!   is a freshness bound, and open question Q11 owns it.
//! - **A refresh that changes the set** is logged as [`REFRESHED_EVENT`] at `INFO`, with the
//!   `kid`s added and removed. A refresh that adds and removes none logs nothing.
//! - **Tokens never cause a fetch.** Only the timer does. Nothing a token carries (`iss`,
//!   `jku`, `x5u`, `kid`) is read here; a token naming an unknown `kid` is refused until the
//!   next scheduled refresh brings its key.
//!
//! Each issuer is fetched again every [`DEFAULT_KEYS_REFRESH`] unless the deployment file says
//! otherwise, and never more often than [`MIN_KEYS_REFRESH`], which loading the file enforces.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use gateway_core::Issuer;
use gateway_identity::{ConfigError, Identity, KeysReplaced};
use issuer_keys::{FetchError, KeySource};
use thiserror::Error;
use tokio::task::JoinSet;

/// How often an issuer's keys are fetched again when the deployment file does not say.
pub const DEFAULT_KEYS_REFRESH: Duration = Duration::from_secs(300);

/// The least time between two fetches of one issuer's keys that the deployment file accepts.
pub const MIN_KEYS_REFRESH: Duration = Duration::from_secs(30);

/// The `event` field of the line logged when a refresh changes an issuer's keys. It names the
/// `issuer`, and the `kid`s `added` and `removed`.
pub const REFRESHED_EVENT: &str = "issuer_keys_refreshed";

/// The `event` field of the warning logged when a refresh fails and the keys in use stay. It
/// names the `issuer` and the `cause`.
pub const REFRESH_FAILED_EVENT: &str = "issuer_keys_refresh_failed";

/// Why a refresh left an issuer's keys as they were.
#[derive(Debug, Error)]
pub enum RefreshError {
    /// The keys could not be fetched.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// The keys were fetched, and the identity gate refused them.
    #[error("the fetched keys were refused: {0}")]
    Refused(#[from] ConfigError),
}

/// One issuer whose keys are fetched on a timer.
struct Refreshed {
    source: KeySource,
    every: Duration,
}

/// Fetches each `keys_url` issuer's keys on its own timer and puts them in force. Made by
/// [`start::prepare`](crate::start::prepare) beside the gates whose identity it refreshes.
pub struct KeyRefresher {
    identity: Arc<Identity>,
    issuers: Vec<Refreshed>,
}

impl fmt::Debug for KeyRefresher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRefresher")
            .field(
                "issuers",
                &self
                    .issuers
                    .iter()
                    .map(|refreshed| (refreshed.source.issuer(), refreshed.every))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl KeyRefresher {
    pub(crate) fn new(identity: Arc<Identity>) -> Self {
        Self {
            identity,
            issuers: Vec::new(),
        }
    }

    /// Adds an issuer, fetched from `source` every `every`.
    pub(crate) fn add(&mut self, source: KeySource, every: Duration) {
        self.issuers.push(Refreshed { source, every });
    }

    /// The issuers refreshed, in the order the deployment file lists them.
    pub fn issuers(&self) -> Vec<&Issuer> {
        self.issuers
            .iter()
            .map(|refreshed| refreshed.source.issuer())
            .collect()
    }

    /// Refreshes every issuer once, now, in turn, logging each as the timer would. Returns each
    /// issuer's result.
    pub async fn refresh_all(&self) -> Vec<Result<KeysReplaced, RefreshError>> {
        let mut results = Vec::with_capacity(self.issuers.len());
        for refreshed in &self.issuers {
            let mut last_failure = None;
            results.push(refresh(&self.identity, &refreshed.source, &mut last_failure).await);
        }
        results
    }

    /// Fetches each issuer's keys every interval, one task per issuer, for ever; with no
    /// issuers, returns at once. The first fetch of each is one interval from now: boot has
    /// just fetched them. Dropping or aborting the returned future stops every task.
    pub async fn run(self) {
        let mut tasks = JoinSet::new();
        for refreshed in self.issuers {
            tasks.spawn(refresh_every(Arc::clone(&self.identity), refreshed));
        }
        while tasks.join_next().await.is_some() {}
    }
}

/// Refreshes one issuer's keys every `every`, for ever.
async fn refresh_every(identity: Arc<Identity>, refreshed: Refreshed) {
    let mut interval = tokio::time::interval(refreshed.every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate, and boot has just fetched the keys.
    interval.tick().await;
    let mut last_failure = None;
    loop {
        interval.tick().await;
        let _ = refresh(&identity, &refreshed.source, &mut last_failure).await;
    }
}

/// Fetches one issuer's keys and puts them in force, or leaves the keys in use. Logs a failure
/// unless `last_failure` already holds its cause, and a change of keys.
async fn refresh(
    identity: &Identity,
    source: &KeySource,
    last_failure: &mut Option<String>,
) -> Result<KeysReplaced, RefreshError> {
    let issuer = source.issuer();
    let replaced = match source.fetch().await {
        Ok(keys) => identity
            .replace_keys(issuer, keys)
            .map_err(RefreshError::from),
        Err(error) => Err(RefreshError::from(error)),
    };
    match &replaced {
        Ok(replaced) => {
            *last_failure = None;
            if !replaced.added.is_empty() || !replaced.removed.is_empty() {
                tracing::info!(
                    event = REFRESHED_EVENT,
                    issuer = issuer.as_str(),
                    added = %kids(&replaced.added),
                    removed = %kids(&replaced.removed),
                    "fetched new keys for the issuer and put them in force"
                );
            }
        }
        Err(error) => {
            let cause = error.to_string();
            if last_failure.as_deref() != Some(cause.as_str()) {
                tracing::warn!(
                    event = REFRESH_FAILED_EVENT,
                    issuer = issuer.as_str(),
                    cause = %cause,
                    "could not refresh the issuer's keys; the keys in use stay"
                );
                *last_failure = Some(cause);
            }
        }
    }
    replaced
}

/// `kid`s as one comma-separated field.
fn kids(kids: &BTreeSet<String>) -> String {
    kids.iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}
