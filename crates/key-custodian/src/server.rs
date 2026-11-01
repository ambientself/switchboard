//! Serving token requests on the custodian's Unix socket.
//!
//! Each connection carries one request and gets one answer. In order:
//!
//! 1. The peer's UID, from the kernel (`SO_PEERCRED` on Linux, `getpeereid` on macOS and the
//!    BSDs), must be the one the configuration names. Any other peer gets a refusal and nothing
//!    it sent is read.
//! 2. The request is one line of JSON, at most [`MAX_REQUEST_BYTES`], read within
//!    [`READ_DEADLINE`], and not malformed.
//! 3. It must be within the custodian's copy of policy (see [`crate::policy`]).
//! 4. The team's bucket must have a request left (see [`crate::rate`]).
//! 5. GitHub is asked for a token narrowed to exactly the request's repositories and
//!    permissions (see [`crate::github`]).
//!
//! The token handed out expires at its lifetime, or at GitHub's own expiry if that is sooner.
//! When the lifetime ends first, the custodian revokes the token then, through GitHub's revoke
//! endpoint. A token GitHub issued that is not handed out, broader than asked for or with no
//! expiry the custodian can read, is revoked the same way at once.
//!
//! A revocation GitHub does not accept (a timeout, a 5xx, a rate-limit answer) is tried again,
//! after [`REVOKE_RETRY_FIRST`] and then twice as long each time, up to [`REVOKE_RETRY_MAX`],
//! until GitHub accepts it or the token reaches GitHub's own expiry, when it stops working
//! anyway. Each failed attempt counts as `revocations_total{result="failed"}` and is logged. So
//! while GitHub refuses revocations, a token stays usable past the end of its lifetime, until
//! an attempt succeeds or until GitHub's expiry, an hour at most after it was issued.
//!
//! # Shutdown
//!
//! The custodian keeps every token it handed out, or issued and did not hand out, until it is
//! revoked or reaches GitHub's expiry. When it stops gracefully ([`crate::Running::stop`]), it
//! stops accepting, waits for the requests in flight to be answered, and then revokes each
//! token it still keeps, all at once, trying a failed revocation again as above. All of this is
//! bounded by one deadline, [`SHUTDOWN_DEADLINE`] by default: what is not done by then is
//! abandoned, and each token not revoked is logged, with when it lapses, and counted in the
//! [`Stopped`] the stop returns. So a token outlives the custodian only if GitHub does not
//! accept its revocation within the deadline, or if the custodian is killed rather than
//! stopped. A token revoked this way may be one the gateway is using for a call in flight,
//! which then fails: a stop ends every token the custodian handed out.
//!
//! Every request, whatever its outcome, writes one record line (see [`crate::record`]) and is
//! counted (see [`crate::metrics`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinSet};

use crate::clock;
use crate::github::GitHubApp;
use crate::metrics::Counters;
use crate::policy::PolicyCell;
use crate::protocol::{Answer, MAX_REQUEST_BYTES, Refusal, Secret, TokenRequest};
use crate::rate::RateLimiter;
use crate::record::{RecordLine, Recorder};

/// How long a peer has to send its request.
pub const READ_DEADLINE: Duration = Duration::from_secs(5);

/// How long the answer may take to write.
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// The most connections served at once. The one peer the custodian serves is the gateway.
pub(crate) const MAX_CONNECTIONS: u32 = 256;

/// How long a graceful stop may take to wait for the requests in flight and revoke the tokens
/// the custodian keeps. The deployment's termination grace must cover it.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// How long the custodian waits to try a failed revocation again, the first time.
pub const REVOKE_RETRY_FIRST: Duration = Duration::from_secs(1);

/// The longest the custodian waits between two attempts to revoke a token.
pub const REVOKE_RETRY_MAX: Duration = Duration::from_secs(60);

/// The custodian's state, shared by every connection.
pub struct Custodian {
    pub(crate) policy: PolicyCell,
    pub(crate) github: GitHubApp,
    pub(crate) rate: RateLimiter,
    pub(crate) lifetime: Duration,
    pub(crate) peer_uid: u32,
    pub(crate) account: String,
    pub(crate) record: Recorder,
    pub(crate) counters: Arc<Counters>,
    /// One permit per connection being served, [`MAX_CONNECTIONS`] in all.
    pub(crate) slots: Arc<Semaphore>,
    /// The tokens not yet revoked or lapsed.
    pub(crate) outstanding: Mutex<Outstanding>,
}

/// The tokens the custodian handed out, or issued and did not hand out, that are not yet
/// revoked or past GitHub's expiry: what a stop revokes.
#[derive(Default)]
pub(crate) struct Outstanding {
    next: u64,
    tokens: BTreeMap<u64, Kept>,
    /// Set once a stop has taken the tokens to revoke them.
    closed: bool,
}

/// One token kept.
struct Kept {
    token: Secret,
    /// GitHub's expiry, in seconds since the epoch.
    lapses_at: u64,
    /// The task that revokes it at the end of its lifetime, if one does.
    revoking: Option<AbortHandle>,
}

/// What a graceful stop did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stopped {
    /// Tokens revoked.
    pub revoked: usize,
    /// Tokens not revoked within the deadline, each logged: each works until GitHub's expiry.
    pub not_revoked: usize,
    /// Requests still in flight at the deadline. A token GitHub issues for one is not revoked.
    pub in_flight: usize,
}

impl Custodian {
    /// Serves `listener` until `shutdown` resolves.
    pub(crate) async fn serve<F>(self: Arc<Self>, listener: UnixListener, shutdown: F)
    where
        F: Future<Output = ()>,
    {
        let mut shutdown = pin!(shutdown);
        loop {
            let stream = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) => {
                        tracing::warn!(%error, "could not accept a connection");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
                () = &mut shutdown => break,
            };
            let Ok(slot) = self.slots.clone().try_acquire_owned() else {
                tracing::warn!("dropped a connection: too many at once");
                continue;
            };
            let custodian = self.clone();
            tokio::spawn(async move {
                custodian.connection(stream).await;
                drop(slot);
            });
        }
    }

    async fn connection(self: Arc<Self>, mut stream: UnixStream) {
        let uid = match stream.peer_cred() {
            Ok(credentials) => credentials.uid(),
            Err(error) => {
                tracing::warn!(%error, "could not read a peer's credentials");
                return;
            }
        };
        let answer = if uid != self.peer_uid {
            let policy = self.policy.current();
            let line = RecordLine::new(clock::now(), uid, policy.revision().as_str());
            self.refuse(
                line,
                Refusal::Peer,
                format!("the custodian serves UID {} only", self.peer_uid),
            )
        } else {
            match read_line(&mut stream).await {
                Ok(bytes) => self.clone().decide(uid, &bytes).await,
                Err(problem) => {
                    let policy = self.policy.current();
                    let line = RecordLine::new(clock::now(), uid, policy.revision().as_str());
                    self.refuse(line, Refusal::Malformed, problem.into())
                }
            }
        };
        let Ok(mut text) = serde_json::to_vec(&answer) else {
            tracing::error!("could not serialize an answer");
            return;
        };
        text.push(b'\n');
        let write = async {
            stream.write_all(&text).await?;
            stream.shutdown().await
        };
        if let Err(error) = tokio::time::timeout(WRITE_DEADLINE, write)
            .await
            .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
        {
            tracing::warn!(%error, "could not write an answer");
        }
    }

    /// Records and counts a refusal, and answers it.
    fn refuse(&self, mut line: RecordLine<'_>, reason: Refusal, message: String) -> Answer {
        line.outcome = "refused";
        line.reason = Some(reason.as_str());
        self.record.write(&line);
        self.counters.refused(reason);
        Answer::Refused { reason, message }
    }

    async fn decide(self: Arc<Self>, uid: u32, bytes: &[u8]) -> Answer {
        let policy = self.policy.current();
        let line = RecordLine::new(clock::now(), uid, policy.revision().as_str());
        let request: TokenRequest = match serde_json::from_slice(bytes) {
            Ok(request) => request,
            Err(_) => {
                return self.refuse(
                    line,
                    Refusal::Malformed,
                    "the request is not a token request in JSON".into(),
                );
            }
        };
        if let Some(problem) = request.malformed() {
            return self.refuse(line.attribution(&request), Refusal::Malformed, problem);
        }
        let mut line = line.request(&request);
        if let Err((reason, message)) = policy.check(&request, &self.account) {
            return self.refuse(line, reason, message);
        }
        if !self.rate.take(&request.team, Instant::now()) {
            return self.refuse(
                line,
                Refusal::RateLimited,
                format!(
                    "team `{}` has asked for too many tokens; try again later",
                    request.team
                ),
            );
        }
        match self
            .github
            .create_token(&request.repositories, &request.permissions)
            .await
        {
            Ok(issued) => {
                let now = clock::now();
                let expires_at = issued.expires_at.min(now + self.lifetime.as_secs());
                // Kept until it lapses, and revoked when its lifetime ends if that is sooner.
                let revoke_at = (expires_at < issued.expires_at).then_some(expires_at);
                self.keep(issued.token.clone(), revoke_at, issued.expires_at);
                line.outcome = "issued";
                line.reason = None;
                line.expires_at = Some(expires_at);
                self.record.write(&line);
                self.counters.issued();
                Answer::Issued {
                    token: issued.token,
                    expires_at,
                }
            }
            Err(error) => {
                if let Some(unissued) = error.unissued {
                    self.keep(unissued.token, Some(clock::now()), unissued.expires_at);
                }
                line.outcome = "failed";
                line.reason = Some(error.failure.as_str());
                self.record.write(&line);
                self.counters.failed(error.failure);
                Answer::Failed {
                    reason: error.failure,
                    message: error.message,
                }
            }
        }
    }

    /// Keeps `token` until it is revoked or lapses at `lapses_at`, GitHub's expiry, and revokes
    /// it at `revoke_at` if given, both in seconds since the epoch.
    fn keep(self: &Arc<Self>, token: Secret, revoke_at: Option<u64>, lapses_at: u64) {
        let mut kept = self
            .outstanding
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = clock::now();
        kept.tokens.retain(|_, each| each.lapses_at > now);
        if kept.closed {
            tracing::error!(
                lapses_at,
                "a token was issued after the stop revoked the others, and is not revoked: it \
                 works until GitHub's expiry"
            );
        }
        let id = kept.next;
        kept.next += 1;
        // The task removes the token once it is done, which waits for this lock.
        let revoking = revoke_at.map(|at| {
            tokio::spawn(self.clone().revoke_at(id, token.clone(), at, lapses_at)).abort_handle()
        });
        kept.tokens.insert(
            id,
            Kept {
                token,
                lapses_at,
                revoking,
            },
        );
    }

    /// Revokes `token`, kept as `id`, at `at`, in seconds since the epoch. A failed attempt is
    /// tried again, after [`REVOKE_RETRY_FIRST`] and then twice as long each time, up to
    /// [`REVOKE_RETRY_MAX`], until GitHub accepts it, or until the next attempt would come at
    /// or after `lapses_at`, GitHub's own expiry, when the token stops working anyway. Then the
    /// token is no longer kept.
    async fn revoke_at(self: Arc<Self>, id: u64, token: Secret, at: u64, lapses_at: u64) {
        let at = UNIX_EPOCH + Duration::from_secs(at);
        let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
        tokio::time::sleep(wait).await;
        let mut retry = REVOKE_RETRY_FIRST;
        loop {
            let Err(error) = self.github.revoke(&token).await else {
                self.counters.revocation(true);
                break;
            };
            self.counters.revocation(false);
            if clock::now() + retry.as_secs() >= lapses_at {
                tracing::error!(
                    message = %error.message,
                    lapses_at,
                    "could not revoke a token, and stopped trying: it works until GitHub's expiry"
                );
                break;
            }
            tracing::warn!(message = %error.message, ?retry, "could not revoke a token; trying again");
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(REVOKE_RETRY_MAX);
        }
        self.outstanding
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .tokens
            .remove(&id);
    }

    /// Revokes `token` now, trying a failed attempt again as [`Self::revoke_at`] does, until
    /// GitHub accepts it or the next attempt would come at or after `until`. Whether it was
    /// revoked.
    async fn revoke_by(self: Arc<Self>, token: Secret, until: tokio::time::Instant) -> bool {
        let mut retry = REVOKE_RETRY_FIRST;
        loop {
            let Err(error) = self.github.revoke(&token).await else {
                self.counters.revocation(true);
                return true;
            };
            self.counters.revocation(false);
            if tokio::time::Instant::now() + retry >= until {
                tracing::warn!(message = %error.message, "could not revoke a token while stopping");
                return false;
            }
            tracing::warn!(message = %error.message, ?retry, "could not revoke a token while stopping; trying again");
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(REVOKE_RETRY_MAX);
        }
    }

    /// For a graceful stop, once the socket accepts no more: waits for the requests in flight,
    /// then revokes every token kept and not yet lapsed, all within `deadline` (see the [module
    /// documentation](self)). Logs each token not revoked by then.
    pub(crate) async fn revoke_outstanding(self: Arc<Self>, deadline: Duration) -> Stopped {
        let until = tokio::time::Instant::now() + deadline;
        let settled = tokio::time::timeout_at(until, self.slots.acquire_many(MAX_CONNECTIONS))
            .await
            .is_ok_and(|permits| permits.is_ok());
        let in_flight = if settled {
            0
        } else {
            let free = u32::try_from(self.slots.available_permits()).unwrap_or(MAX_CONNECTIONS);
            usize::try_from(MAX_CONNECTIONS.saturating_sub(free)).unwrap_or(usize::MAX)
        };
        let kept = {
            let mut kept = self
                .outstanding
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            kept.closed = true;
            std::mem::take(&mut kept.tokens)
        };
        let now = clock::now();
        let mut left: BTreeMap<u64, u64> = BTreeMap::new();
        let mut revoking = JoinSet::new();
        for (id, each) in kept {
            if let Some(task) = each.revoking {
                task.abort();
            }
            if each.lapses_at <= now {
                continue;
            }
            left.insert(id, each.lapses_at);
            let custodian = self.clone();
            revoking.spawn(async move { (id, custodian.revoke_by(each.token, until).await) });
        }
        let mut stopped = Stopped {
            in_flight,
            ..Stopped::default()
        };
        loop {
            match tokio::time::timeout_at(until, revoking.join_next()).await {
                Ok(Some(Ok((id, true)))) => {
                    left.remove(&id);
                    stopped.revoked += 1;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    revoking.abort_all();
                    break;
                }
            }
        }
        for lapses_at in left.values() {
            tracing::error!(
                lapses_at,
                "could not revoke a token before stopping: it works until GitHub's expiry"
            );
        }
        if in_flight > 0 {
            tracing::error!(
                in_flight,
                "requests were still in flight when the stop's deadline passed; a token GitHub \
                 issues for one is not revoked"
            );
        }
        stopped.not_revoked = left.len();
        stopped
    }
}

/// The request line: up to its newline or the end of the stream, at most
/// [`MAX_REQUEST_BYTES`], within [`READ_DEADLINE`].
async fn read_line(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
    let limit = u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX);
    let mut reader = BufReader::new(stream.take(limit));
    let mut line = Vec::new();
    let read = tokio::time::timeout(READ_DEADLINE, reader.read_until(b'\n', &mut line)).await;
    match read {
        Err(_) => Err("the request did not arrive in time"),
        Ok(Err(_)) => Err("the request could not be read"),
        Ok(Ok(_)) if line.last() == Some(&b'\n') => {
            line.pop();
            Ok(line)
        }
        Ok(Ok(_)) if line.len() >= MAX_REQUEST_BYTES => Err("the request is too long"),
        Ok(Ok(_)) => Ok(line),
    }
}
