//! A token bucket per team, on the requests that pass the custodian's checks.
//!
//! The bucket is taken after the policy check and before GitHub is asked, so a refused request
//! costs the team nothing, and only a team in the custodian's copy of policy has a bucket.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use gateway_core::TeamId;

/// The default sustained rate: 30 requests a minute per team. See the crate documentation for
/// why.
pub const DEFAULT_PER_MINUTE: u32 = 30;

/// The default burst: 10 requests at once per team.
pub const DEFAULT_BURST: u32 = 10;

struct Bucket {
    tokens: f64,
    filled_at: Instant,
}

/// The buckets, one per team, each `burst` deep and refilled at `per_minute`.
pub struct RateLimiter {
    per_second: f64,
    burst: f64,
    buckets: Mutex<HashMap<TeamId, Bucket>>,
}

impl RateLimiter {
    /// Buckets `burst` deep, refilled at `per_minute`. Both must be at least 1, which the
    /// configuration checks.
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            per_second: f64::from(per_minute) / 60.0,
            burst: f64::from(burst),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one request from `team`'s bucket at `now`; false if it is empty.
    pub fn take(&self, team: &TeamId, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = buckets.entry(team.clone()).or_insert(Bucket {
            tokens: self.burst,
            filled_at: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.filled_at)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.burst);
        bucket.filled_at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_bucket_empties_and_refills() {
        let limiter = RateLimiter::new(60, 2);
        let team = TeamId::new("team-a");
        let other = TeamId::new("team-b");
        let start = Instant::now();
        assert!(limiter.take(&team, start));
        assert!(limiter.take(&team, start));
        assert!(!limiter.take(&team, start));
        assert!(limiter.take(&other, start), "each team has its own bucket");
        assert!(!limiter.take(&team, start + Duration::from_millis(500)));
        assert!(limiter.take(&team, start + Duration::from_millis(1600)));
        assert!(!limiter.take(&team, start + Duration::from_millis(1600)));
        let later = start + Duration::from_secs(3600);
        assert!(limiter.take(&team, later));
        assert!(limiter.take(&team, later));
        assert!(
            !limiter.take(&team, later),
            "the bucket holds no more than its burst"
        );
    }
}
