//! Logs: one JSON object per line, on standard output. And telemetry: structured events and
//! counters, off the request path, through a bounded queue (decision 0009).
//!
//! [`Telemetry`] is the sending side. [`emit`](Telemetry::emit) counts the event, then puts
//! it on the queue if there is room. It never waits: a full or closed queue drops the event,
//! and the drop is counted. [`Drain`] is the receiving side, a task that writes each event as
//! one `tracing` event, so it reaches the same JSON lines as the rest of the logs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gateway_core::{DeploymentName, escape};
use gateway_identity::{ClaimedCaller, VerifyError};
use gateway_mcp::RejectionKind;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

/// The filter used when `RUST_LOG` is not set: the gateway's events at `info` and above.
pub const DEFAULT_FILTER: &str = "info";

/// Sends every `tracing` event to standard output as one JSON object per line, filtered by
/// `RUST_LOG`, or by [`DEFAULT_FILTER`] when it is unset or does not parse. Each line carries
/// the time, the level, the message, the event's fields and the spans it happened in.
///
/// Does nothing if a subscriber is already installed, so a test or a second caller can call it
/// again.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    // An error means a subscriber is already installed; the first one stays.
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(true)
        .with_writer(std::io::stdout)
        .try_init();
}

/// How many events the queue holds before [`Telemetry::emit`] drops them.
pub const TELEMETRY_QUEUE: usize = 1024;

/// The longest a surface is kept, in characters after escaping, before it is cut short and
/// marked with `…`. The same cap the core puts on a surface in sentences and audit rows.
pub const MAX_SURFACE: usize = 128;

/// A surface as an event records it. It comes from the request's URL, so it is escaped by
/// [`gateway_core::escape`] and capped at [`MAX_SURFACE`] when it is made. Its field is
/// private, so there is no other way to make one and no event holds a surface as it arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface(String);

impl Surface {
    /// The surface named in a request's URL, escaped and capped.
    pub fn new(raw: &str) -> Self {
        Self(escape(raw, MAX_SURFACE))
    }

    /// The escaped surface.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Something that happened on the request path, for the log and the counters.
///
/// Every variant names the deployment, the surface when the URL named one, and the peer's
/// address when it is known. Nothing in an event comes from a token or a body as it arrived:
/// the surface is a [`Surface`]; an identity failure carries the [`VerifyError`], which holds
/// nothing from the token, and the [`ClaimedCaller`], which the identity crate escaped and
/// capped; an unparsable body carries only the [`RejectionKind`].
#[derive(Clone, Debug)]
pub enum Event {
    /// A caller's identity was refused.
    IdentityFailed {
        /// The deployment that refused it.
        deployment: DeploymentName,
        /// The surface the request was for.
        surface: Option<Surface>,
        /// The peer's address.
        source: Option<SocketAddr>,
        /// Which check refused. The log writes its `Display`.
        cause: VerifyError,
        /// The issuer and subject the token claimed, unverified.
        claimed: ClaimedCaller,
    },
    /// A session was initialized.
    Initialize {
        /// The deployment that answered.
        deployment: DeploymentName,
        /// The surface the request was for.
        surface: Option<Surface>,
        /// The peer's address.
        source: Option<SocketAddr>,
    },
    /// A ping was answered.
    Ping {
        /// The deployment that answered.
        deployment: DeploymentName,
        /// The surface the request was for.
        surface: Option<Surface>,
        /// The peer's address.
        source: Option<SocketAddr>,
    },
    /// A discovery request was answered.
    Discover {
        /// The deployment that answered.
        deployment: DeploymentName,
        /// The surface the request was for.
        surface: Option<Surface>,
        /// The peer's address.
        source: Option<SocketAddr>,
    },
    /// A body was refused before it reached the gateway's logic.
    Unparsable {
        /// The deployment that refused it.
        deployment: DeploymentName,
        /// The surface the request was for.
        surface: Option<Surface>,
        /// The peer's address.
        source: Option<SocketAddr>,
        /// Why it was refused. Never the body.
        rejection: RejectionKind,
    },
}

/// A snapshot of the counters. Each kind of event is counted when it is emitted, whether or not
/// the queue had room for it; `dropped` counts the events the queue had no room for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounts {
    /// Identity failures.
    pub identity_failed: u64,
    /// Sessions initialized.
    pub initialize: u64,
    /// Pings answered.
    pub ping: u64,
    /// Discovery requests answered.
    pub discover: u64,
    /// Bodies refused as unparsable.
    pub unparsable: u64,
    /// Events dropped because the queue was full or closed.
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct Counters {
    identity_failed: AtomicU64,
    initialize: AtomicU64,
    ping: AtomicU64,
    discover: AtomicU64,
    unparsable: AtomicU64,
    dropped: AtomicU64,
}

/// The sending side of the telemetry queue. Cloning it is cheap: every clone sends to the same
/// queue and counts in the same counters.
#[derive(Clone, Debug)]
pub struct Telemetry {
    sender: mpsc::Sender<Event>,
    counters: Arc<Counters>,
}

impl Telemetry {
    /// A queue that holds `capacity` events, at least one, and the [`Drain`] that empties it.
    pub fn bounded(capacity: usize) -> (Telemetry, Drain) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let telemetry = Telemetry {
            sender,
            counters: Arc::default(),
        };
        (telemetry, Drain { receiver })
    }

    /// Telemetry with nothing draining it: every event is counted, and counted as dropped. For
    /// code with no runtime to drain on, such as tests that drive the request path by hand.
    pub fn detached() -> Telemetry {
        let (telemetry, drain) = Self::bounded(1);
        drop(drain);
        telemetry
    }

    /// Counts `event`, then queues it if there is room. A full or closed queue drops it and
    /// counts the drop. It never waits.
    pub fn emit(&self, event: Event) {
        let counter = match &event {
            Event::IdentityFailed { .. } => &self.counters.identity_failed,
            Event::Initialize { .. } => &self.counters.initialize,
            Event::Ping { .. } => &self.counters.ping,
            Event::Discover { .. } => &self.counters.discover,
            Event::Unparsable { .. } => &self.counters.unparsable,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if self.sender.try_send(event).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters as they stand.
    pub fn counts(&self) -> TelemetryCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let counters = &self.counters;
        TelemetryCounts {
            identity_failed: read(&counters.identity_failed),
            initialize: read(&counters.initialize),
            ping: read(&counters.ping),
            discover: read(&counters.discover),
            unparsable: read(&counters.unparsable),
            dropped: read(&counters.dropped),
        }
    }
}

/// The receiving side of the telemetry queue.
#[derive(Debug)]
pub struct Drain {
    receiver: mpsc::Receiver<Event>,
}

impl Drain {
    /// Writes each event as one `tracing` event, with an `event` field naming it. Returns when
    /// every [`Telemetry`] is gone and the events already queued are written.
    pub async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            write(&event);
        }
    }
}

/// One event, as one `tracing` event.
fn write(event: &Event) {
    fn surface(surface: &Option<Surface>) -> Option<&str> {
        surface.as_ref().map(Surface::as_str)
    }
    match event {
        Event::IdentityFailed {
            deployment,
            surface: on,
            source,
            cause,
            claimed,
        } => tracing::warn!(
            event = "identity_failed",
            deployment = deployment.as_str(),
            surface = surface(on),
            source = source.map(tracing::field::display),
            cause = %cause,
            claimed_issuer = claimed.issuer().map(|issuer| issuer.get().as_str()),
            claimed_subject = claimed.subject().map(|subject| subject.get().as_str()),
            "refused a caller whose identity was not proved"
        ),
        Event::Initialize {
            deployment,
            surface: on,
            source,
        } => tracing::info!(
            event = "initialize",
            deployment = deployment.as_str(),
            surface = surface(on),
            source = source.map(tracing::field::display),
            "initialized a session"
        ),
        Event::Ping {
            deployment,
            surface: on,
            source,
        } => tracing::info!(
            event = "ping",
            deployment = deployment.as_str(),
            surface = surface(on),
            source = source.map(tracing::field::display),
            "answered a ping"
        ),
        Event::Discover {
            deployment,
            surface: on,
            source,
        } => tracing::info!(
            event = "discover",
            deployment = deployment.as_str(),
            surface = surface(on),
            source = source.map(tracing::field::display),
            "answered a discovery request"
        ),
        Event::Unparsable {
            deployment,
            surface: on,
            source,
            rejection,
        } => tracing::info!(
            event = "unparsable_body",
            deployment = deployment.as_str(),
            surface = surface(on),
            source = source.map(tracing::field::display),
            rejection = ?rejection,
            "refused an unparsable body"
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use gateway_identity::{Identity, IdentityConfig, IssuerKind, SigningAlgorithm, Verification};
    use gateway_testkit::{FIXTURE_NOW, FixedClock, LocalIssuer};
    use serde_json::{Value, json};

    use super::*;

    const DEPLOYMENT: &str = "telemetry-test";

    fn ping(surface: &str) -> Event {
        Event::Ping {
            deployment: DeploymentName::new(DEPLOYMENT),
            surface: Some(Surface::new(surface)),
            source: None,
        }
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_without_waiting() {
        let (telemetry, drain) = Telemetry::bounded(4);
        for _ in 0..4 + 3 {
            telemetry.emit(ping("read"));
        }
        assert_eq!(telemetry.counts().dropped, 3);
        // The drain still holds the four that fit.
        drop(drain);
        telemetry.emit(ping("read"));
        assert_eq!(telemetry.counts().dropped, 4, "a closed queue drops too");
    }

    #[tokio::test]
    async fn the_counters_count_dropped_events_too() {
        let (telemetry, _drain) = Telemetry::bounded(1);
        let clone = telemetry.clone();
        telemetry.emit(ping("read"));
        clone.emit(ping("read"));
        telemetry.emit(Event::Discover {
            deployment: DeploymentName::new(DEPLOYMENT),
            surface: None,
            source: None,
        });
        assert_eq!(
            clone.counts(),
            TelemetryCounts {
                ping: 2,
                discover: 1,
                dropped: 2,
                ..TelemetryCounts::default()
            }
        );
    }

    #[test]
    fn detached_telemetry_counts_every_event_as_dropped() {
        let telemetry = Telemetry::detached();
        telemetry.emit(ping("read"));
        telemetry.emit(ping("read"));
        assert_eq!(
            telemetry.counts(),
            TelemetryCounts {
                ping: 2,
                dropped: 2,
                ..TelemetryCounts::default()
            }
        );
    }

    #[test]
    fn a_surface_is_escaped_and_capped() {
        assert_eq!(
            Surface::new("read\n\u{1b}[2J").as_str(),
            "read\\n\\u{1b}[2J"
        );
        let long = Surface::new(&"s".repeat(10_000));
        assert_eq!(long.as_str().chars().count(), MAX_SURFACE + 1);
        assert!(long.as_str().ends_with('…'));
    }

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

    impl Captured {
        fn lines(&self) -> Vec<Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect()
        }
    }

    /// A refusal that claimed an issuer and a subject: a token from an issuer the gate does not
    /// know.
    fn refusal(subject: &str) -> (VerifyError, ClaimedCaller, String) {
        let now = UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW);
        let known = LocalIssuer::new("https://known.test", SigningAlgorithm::Es256).unwrap();
        let stranger = LocalIssuer::new("https://stranger.test", SigningAlgorithm::Es256).unwrap();
        let gate = Identity::new(
            IdentityConfig::Enforce(vec![known.config(IssuerKind::user(), &["switchboard"])]),
            Arc::new(FixedClock::at(FIXTURE_NOW)),
        )
        .unwrap();
        let token = stranger
            .user_token(subject, "switchboard", &[], now)
            .build();
        let Verification::Failed(failure) = gate.check(Some(&token)) else {
            panic!("a token from an unknown issuer was accepted");
        };
        (failure.detail().clone(), failure.claimed().clone(), token)
    }

    #[tokio::test]
    async fn the_drain_writes_one_line_per_event_and_everything_queued() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);

        let (cause, claimed, token) = refusal("carol\u{7}");
        let deployment = DeploymentName::new(DEPLOYMENT);
        let source: SocketAddr = "192.0.2.7:4242".parse().unwrap();
        let (telemetry, drain) = Telemetry::bounded(8);
        telemetry.emit(Event::IdentityFailed {
            deployment: deployment.clone(),
            surface: Some(Surface::new("read\r\nforged: line")),
            source: Some(source),
            cause,
            claimed,
        });
        telemetry.emit(Event::Initialize {
            deployment: deployment.clone(),
            surface: Some(Surface::new("read")),
            source: Some(source),
        });
        telemetry.emit(ping("read"));
        telemetry.emit(Event::Discover {
            deployment: deployment.clone(),
            surface: None,
            source: None,
        });
        telemetry.emit(Event::Unparsable {
            deployment,
            surface: Some(Surface::new("read")),
            source: Some(source),
            rejection: RejectionKind::ParseError,
        });
        // Every sender is gone before the drain starts: it still writes what was queued.
        drop(telemetry);
        drain.run().await;

        let lines = captured.lines();
        let fields: Vec<&Value> = lines.iter().map(|line| &line["fields"]).collect();
        let names: Vec<&Value> = fields.iter().map(|fields| &fields["event"]).collect();
        assert_eq!(
            names,
            [
                "identity_failed",
                "initialize",
                "ping",
                "discover",
                "unparsable_body"
            ]
        );
        for fields in &fields {
            assert_eq!(fields["deployment"], json!(DEPLOYMENT));
        }

        let levels: Vec<&Value> = lines.iter().map(|line| &line["level"]).collect();
        assert_eq!(levels, ["WARN", "INFO", "INFO", "INFO", "INFO"]);
        assert_eq!(
            fields[0]["message"],
            json!("refused a caller whose identity was not proved")
        );

        let failed = fields[0];
        assert_eq!(failed["surface"], json!("read\\r\\nforged: line"));
        assert_eq!(failed["source"], json!("192.0.2.7:4242"));
        assert_eq!(
            failed["cause"],
            json!("the token's issuer is not configured")
        );
        assert_eq!(failed["claimed_issuer"], json!("https://stranger.test"));
        assert_eq!(failed["claimed_subject"], json!("carol\\u{7}"));
        let raw = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(!raw.contains(&token), "the token reached the log");
        let signature = token.rsplit('.').next().unwrap();
        assert!(
            !raw.contains(signature),
            "part of the token reached the log"
        );

        assert_eq!(fields[1]["surface"], json!("read"));
        assert_eq!(fields[1]["source"], json!("192.0.2.7:4242"));
        assert_eq!(fields[2]["surface"], json!("read"));
        assert!(fields[2].get("source").is_none(), "{}", fields[2]);
        assert!(fields[3].get("surface").is_none(), "{}", fields[3]);
        assert!(fields[3].get("source").is_none(), "{}", fields[3]);
        assert_eq!(fields[4]["surface"], json!("read"));
        assert_eq!(fields[4]["source"], json!("192.0.2.7:4242"));
        assert_eq!(fields[4]["rejection"], json!("ParseError"));
    }
}
