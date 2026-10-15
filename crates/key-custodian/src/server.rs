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
//! endpoint. A token still outstanding when the custodian stops is not revoked; it lapses at
//! GitHub's expiry, an hour at most after it was issued.
//!
//! Every request, whatever its outcome, writes one record line (see [`crate::record`]) and is
//! counted (see [`crate::metrics`]).

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

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
const MAX_CONNECTIONS: usize = 256;

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
}

impl Custodian {
    /// Serves `listener` until `shutdown` resolves.
    pub(crate) async fn serve<F>(self: Arc<Self>, listener: UnixListener, shutdown: F)
    where
        F: Future<Output = ()>,
    {
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
            let Ok(slot) = slots.clone().try_acquire_owned() else {
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
            return self.refuse(line, Refusal::Malformed, problem);
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
                if expires_at < issued.expires_at {
                    self.clone().revoke_at(issued.token.clone(), expires_at);
                }
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

    /// Revokes `token` at `expires_at`, in seconds since the epoch.
    fn revoke_at(self: Arc<Self>, token: Secret, expires_at: u64) {
        tokio::spawn(async move {
            let at = UNIX_EPOCH + Duration::from_secs(expires_at);
            let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
            tokio::time::sleep(wait).await;
            match self.github.revoke(&token).await {
                Ok(()) => self.counters.revocation(true),
                Err(error) => {
                    self.counters.revocation(false);
                    tracing::error!(message = %error.message, "could not revoke a token at the end of its lifetime");
                }
            }
        });
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
