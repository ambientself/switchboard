//! Logs: one JSON object per line, on standard output.

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
