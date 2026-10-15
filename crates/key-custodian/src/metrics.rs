//! The custodian's counters, in Prometheus text on a listener of its own.
//!
//! [`serve_metrics`] answers `GET /metrics` on the address the configuration's `metrics`
//! names; without it nothing is served. Every label value is from a closed set, so the series
//! are fixed:
//!
//! - `switchboard_custodian_requests_total{outcome,reason}`: each request, `outcome` one of
//!   `issued`, `refused` and `failed`, and `reason` the refusal's or failure's (see
//!   [`Refusal`] and [`Failure`]), empty for `issued`;
//! - `switchboard_custodian_revocations_total{result}`: each token revoked at the end of its
//!   lifetime, or after GitHub widened it, `result` one of `revoked` and `failed`;
//! - `switchboard_custodian_policy_reloads_total{result}`: each new version of the registry
//!   file, `result` one of `loaded` and `refused`.
//!
//! Nothing here holds a token, a key or a name a caller chose.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use tokio::net::TcpListener;

use crate::protocol::{Failure, Refusal};

/// The counters. Shared by the server, the policy watch and the metrics listener.
#[derive(Default)]
pub struct Counters {
    issued: AtomicU64,
    refused: [AtomicU64; Refusal::ALL.len()],
    failed: [AtomicU64; Failure::ALL.len()],
    revoked: AtomicU64,
    revocations_failed: AtomicU64,
    reloads_loaded: AtomicU64,
    reloads_refused: AtomicU64,
}

fn index<T: PartialEq>(all: &[T], item: &T) -> usize {
    all.iter().position(|each| each == item).unwrap_or(0)
}

impl Counters {
    /// Counts a token issued.
    pub fn issued(&self) {
        self.issued.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a refusal.
    pub fn refused(&self, reason: Refusal) {
        self.refused[index(&Refusal::ALL, &reason)].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a failure to get a token.
    pub fn failed(&self, reason: Failure) {
        self.failed[index(&Failure::ALL, &reason)].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a revocation, made or failed.
    pub fn revocation(&self, revoked: bool) {
        let counter = if revoked {
            &self.revoked
        } else {
            &self.revocations_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a new version of the registry file, loaded or refused.
    pub fn reload(&self, loaded: bool) {
        let counter = if loaded {
            &self.reloads_loaded
        } else {
            &self.reloads_refused
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The counters in Prometheus text.
    pub fn render(&self) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let mut text = String::new();
        text.push_str(
            "# HELP switchboard_custodian_requests_total Token requests, by outcome and reason.\n\
             # TYPE switchboard_custodian_requests_total counter\n",
        );
        let _ = writeln!(
            text,
            "switchboard_custodian_requests_total{{outcome=\"issued\",reason=\"\"}} {}",
            load(&self.issued)
        );
        for (reason, counter) in Refusal::ALL.iter().zip(&self.refused) {
            let _ = writeln!(
                text,
                "switchboard_custodian_requests_total{{outcome=\"refused\",reason=\"{}\"}} {}",
                reason.as_str(),
                load(counter)
            );
        }
        for (reason, counter) in Failure::ALL.iter().zip(&self.failed) {
            let _ = writeln!(
                text,
                "switchboard_custodian_requests_total{{outcome=\"failed\",reason=\"{}\"}} {}",
                reason.as_str(),
                load(counter)
            );
        }
        text.push_str(
            "# HELP switchboard_custodian_revocations_total Tokens revoked, by result.\n\
             # TYPE switchboard_custodian_revocations_total counter\n",
        );
        let _ = writeln!(
            text,
            "switchboard_custodian_revocations_total{{result=\"revoked\"}} {}",
            load(&self.revoked)
        );
        let _ = writeln!(
            text,
            "switchboard_custodian_revocations_total{{result=\"failed\"}} {}",
            load(&self.revocations_failed)
        );
        text.push_str(
            "# HELP switchboard_custodian_policy_reloads_total New versions of the registry file, by result.\n\
             # TYPE switchboard_custodian_policy_reloads_total counter\n",
        );
        let _ = writeln!(
            text,
            "switchboard_custodian_policy_reloads_total{{result=\"loaded\"}} {}",
            load(&self.reloads_loaded)
        );
        let _ = writeln!(
            text,
            "switchboard_custodian_policy_reloads_total{{result=\"refused\"}} {}",
            load(&self.reloads_refused)
        );
        text
    }
}

async fn scrape(State(counters): State<Arc<Counters>>) -> String {
    counters.render()
}

/// Serves `GET /metrics` on `listener` until `shutdown` resolves. Any other path is 404.
pub async fn serve_metrics<F>(
    listener: TcpListener,
    counters: Arc<Counters>,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let router = Router::new()
        .route("/metrics", get(scrape))
        .with_state(counters);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}
