//! Clocks a test controls.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_identity::Clock;

/// A time many fixtures agree on: 2027-01-15 08:00:00 UTC, in seconds since the epoch. Far from
/// any real "now", so a test that accidentally reads the system clock fails loudly.
pub const FIXTURE_NOW: u64 = 1_800_000_000;

/// A clock that always reads the same time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock {
    at: SystemTime,
}

impl FixedClock {
    /// A clock stopped at `unix_seconds` after the epoch.
    pub fn at(unix_seconds: u64) -> Self {
        Self {
            at: UNIX_EPOCH + Duration::from_secs(unix_seconds),
        }
    }
}

impl Default for FixedClock {
    fn default() -> Self {
        Self::at(FIXTURE_NOW)
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.at
    }
}

/// A clock a test moves by hand. Cloning gives another handle to the same time, so a test can
/// hold one while a verifier, a fake connector and a store read it.
#[derive(Clone, Debug)]
pub struct SteppableClock {
    millis: Arc<AtomicU64>,
}

impl SteppableClock {
    /// A clock set to `unix_seconds` after the epoch.
    pub fn at(unix_seconds: u64) -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(unix_seconds.saturating_mul(1000))),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        // Saturating: a clock that wraps would turn a test about expiry into a test about
        // overflow.
        let _ = self
            .millis
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |millis| {
                Some(millis.saturating_add(by))
            });
    }

    /// Sets the clock to `unix_seconds` after the epoch, forward or back.
    pub fn set(&self, unix_seconds: u64) {
        self.millis
            .store(unix_seconds.saturating_mul(1000), Ordering::SeqCst);
    }

    /// The time as whole milliseconds since the epoch.
    pub fn unix_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

impl Default for SteppableClock {
    fn default() -> Self {
        Self::at(FIXTURE_NOW)
    }
}

impl Clock for SteppableClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.unix_millis())
    }
}
