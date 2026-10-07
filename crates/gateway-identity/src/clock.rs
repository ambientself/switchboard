//! The clock verification reads, so tests can choose what time it is.

use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time.
///
/// Verification checks `exp`, `nbf` and `iat` against this and never against the system time
/// directly, so a test decides what time it is rather than racing the wall clock. The real
/// implementation is [`SystemClock`]; the test crate has a fixed one and a steppable one.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The system's clock. The one place in this crate that reads the real time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Whole seconds since the Unix epoch, which is what a token's dates are in. A clock set before
/// the epoch reads as the epoch itself; a token issued after it then fails the issued-in-the-
/// future check, so a broken clock refuses tokens rather than admitting them.
pub(crate) fn unix_seconds(clock: &dyn Clock) -> u64 {
    clock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
