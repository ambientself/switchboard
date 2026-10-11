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
//!   can be. Decision 0013 settles that keys are never refused for their age: refusing every
//!   token because a refresh failed would turn an issuer's outage into the gateway's.
//! - **A refresh that changes the keys** is logged as [`REFRESHED_EVENT`], with the `kid`s
//!   added, removed and changed, each against the set in force before it. A `kid` is changed
//!   when the issuer serves a different JWK under it, in any field: the new JWK is in force from
//!   then on. If the key material changed, tokens signed with the old key no longer verify; a
//!   change to metadata alone (`use`, `key_ops`, `alg`, `x5c`, `x5t`, such as a certificate
//!   re-issued for the same key) can leave them verifying. Issuers rotate by publishing a new
//!   `kid`, so a changed one is logged at `WARN`; a refresh that only adds or removes `kid`s is
//!   logged at `INFO`. A refresh that serves the set in force again logs nothing.
//! - **Each issuer's timer logs [`REFRESH_STARTED_EVENT`]** at `INFO` once, as it starts,
//!   naming the issuer and the seconds between fetches.
//! - **Tokens never cause a fetch.** Only the timer does. Nothing a token carries (`iss`,
//!   `jku`, `x5u`, `kid`) is read here; a token naming an unknown `kid` is refused until the
//!   next scheduled refresh brings its key.
//!
//! Each issuer is fetched again every [`DEFAULT_KEYS_REFRESH`] unless the deployment file says
//! otherwise, and never more often than [`MIN_KEYS_REFRESH`], which loading the file enforces.
//!
//! [`KeyAges`] holds when each issuer's keys were last fetched and put in force: at boot, as the
//! issuer is added to the refresher, then by each refresh that succeeds. A refresh that fails
//! leaves the time as it was. [`crate::metrics`] exports it as
//! `switchboard_issuer_keys_age_seconds{issuer}`.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

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
/// `issuer`, and the `kid`s `added`, `removed` and `changed`, each a comma-separated list. It is
/// at `WARN` when a `kid` is changed, a different key served under a `kid` that stays, and at
/// `INFO` otherwise.
pub const REFRESHED_EVENT: &str = "issuer_keys_refreshed";

/// The `event` field of the line each issuer's timer logs once, at `INFO`, as it starts. It
/// names the `issuer` and `refresh_seconds`, the seconds between fetches.
pub const REFRESH_STARTED_EVENT: &str = "issuer_keys_refresh_started";

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
    /// The issuer's place in the refresher's [`KeyAges`].
    age: usize,
}

/// When the keys of each issuer fetched from a keys URL were last fetched and put in force, in
/// the order the deployment file lists them. Cheap to clone; clones share the times.
#[derive(Clone, Default)]
pub struct KeyAges(Arc<Mutex<Vec<(Issuer, Instant)>>>);

impl fmt::Debug for KeyAges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.ages()).finish()
    }
}

impl KeyAges {
    /// Each issuer, with the time since its keys were last fetched and put in force.
    pub fn ages(&self) -> Vec<(Issuer, Duration)> {
        let now = Instant::now();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(issuer, at)| (issuer.clone(), now.saturating_duration_since(*at)))
            .collect()
    }

    /// Adds `issuer`, its keys fetched now, and returns its place.
    fn add(&self, issuer: &Issuer) -> usize {
        let mut issuers = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        issuers.push((issuer.clone(), Instant::now()));
        issuers.len() - 1
    }

    /// Records that the issuer at `place` had its keys fetched and put in force now.
    fn fetched(&self, place: usize) {
        if let Some((_, at)) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(place)
        {
            *at = Instant::now();
        }
    }
}

/// Fetches each `keys_url` issuer's keys on its own timer and puts them in force. Made by
/// [`start::prepare`](crate::start::prepare) beside the gates whose identity it refreshes.
pub struct KeyRefresher {
    identity: Arc<Identity>,
    issuers: Vec<Refreshed>,
    ages: KeyAges,
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
            ages: KeyAges::default(),
        }
    }

    /// Adds an issuer, fetched from `source` every `every`, whose keys boot has just fetched
    /// and put in force.
    pub(crate) fn add(&mut self, source: KeySource, every: Duration) {
        let age = self.ages.add(source.issuer());
        self.issuers.push(Refreshed { source, every, age });
    }

    /// The issuers refreshed, in the order the deployment file lists them.
    pub fn issuers(&self) -> Vec<&Issuer> {
        self.issuers
            .iter()
            .map(|refreshed| refreshed.source.issuer())
            .collect()
    }

    /// When each issuer's keys were last fetched and put in force. Shared with the refresher,
    /// so the times move on as it refreshes, and after [`KeyRefresher::run`] takes it.
    pub fn ages(&self) -> KeyAges {
        self.ages.clone()
    }

    /// Refreshes every issuer once, now, in turn, logging each as the timer would. Returns each
    /// issuer's result.
    pub async fn refresh_all(&self) -> Vec<Result<KeysReplaced, RefreshError>> {
        let mut results = Vec::with_capacity(self.issuers.len());
        for refreshed in &self.issuers {
            let mut last_failure = None;
            results.push(refresh(&self.identity, refreshed, &self.ages, &mut last_failure).await);
        }
        results
    }

    /// Fetches each issuer's keys every interval, one task per issuer, for ever; with no
    /// issuers, returns at once. Each task logs [`REFRESH_STARTED_EVENT`] as its timer starts.
    /// The first fetch of each is one interval from now: boot has just fetched them. Dropping or
    /// aborting the returned future stops every task.
    pub async fn run(self) {
        let mut tasks = JoinSet::new();
        for refreshed in self.issuers {
            tasks.spawn(refresh_every(
                Arc::clone(&self.identity),
                refreshed,
                self.ages.clone(),
            ));
        }
        while tasks.join_next().await.is_some() {}
    }
}

/// Refreshes one issuer's keys every `every`, for ever.
async fn refresh_every(identity: Arc<Identity>, refreshed: Refreshed, ages: KeyAges) {
    let mut interval = tokio::time::interval(refreshed.every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate, and boot has just fetched the keys.
    interval.tick().await;
    tracing::info!(
        event = REFRESH_STARTED_EVENT,
        issuer = refreshed.source.issuer().as_str(),
        refresh_seconds = refreshed.every.as_secs(),
        "fetching the issuer's keys again on a timer"
    );
    // The cause of the last failure logged, until a refresh succeeds.
    let mut last_failure: Option<String> = None;
    loop {
        interval.tick().await;
        let _ = refresh(&identity, &refreshed, &ages, &mut last_failure).await;
    }
}

/// Fetches one issuer's keys and puts them in force, or leaves the keys in use. Logs a failure
/// unless `last_failure` already holds its cause, and any `kid` added, removed or changed.
async fn refresh(
    identity: &Identity,
    refreshed: &Refreshed,
    ages: &KeyAges,
    last_failure: &mut Option<String>,
) -> Result<KeysReplaced, RefreshError> {
    let issuer = refreshed.source.issuer();
    let replaced = match refreshed.source.fetch().await {
        Ok(keys) => identity
            .replace_keys(issuer, keys)
            .map_err(RefreshError::from),
        Err(error) => Err(RefreshError::from(error)),
    };
    match &replaced {
        Ok(replaced) => {
            *last_failure = None;
            ages.fetched(refreshed.age);
            let any = !replaced.added.is_empty()
                || !replaced.removed.is_empty()
                || !replaced.changed.is_empty();
            if any && replaced.changed.is_empty() {
                tracing::info!(
                    event = REFRESHED_EVENT,
                    issuer = issuer.as_str(),
                    added = %kids(&replaced.added),
                    removed = %kids(&replaced.removed),
                    changed = "",
                    "fetched new keys for the issuer and put them in force"
                );
            } else if any {
                tracing::warn!(
                    event = REFRESHED_EVENT,
                    issuer = issuer.as_str(),
                    added = %kids(&replaced.added),
                    removed = %kids(&replaced.removed),
                    changed = %kids(&replaced.changed),
                    "the issuer served a different JWK under a kid it kept; the new JWK is in \
                     force, and if the key material changed, tokens signed with the old key no \
                     longer verify"
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
