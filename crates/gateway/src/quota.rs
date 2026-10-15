//! The rate quotas on calls to each server, and from each team to each server (decision 0014,
//! section 2, built with milestone 4's built-in connectors, #12).
//!
//! Each server has a token bucket in each gateway instance, and so has each team on each
//! server, by the caller's proved team. A bucket holds at most its burst of tokens and gains
//! its rate's tokens each minute, a fraction at a time. A call takes one token from its team's
//! bucket, when the caller has a proved team, and one from the server's. A caller with no team,
//! such as a user, is held by the server's quota alone until a per-user limit is decided
//! (decision 0014, Still open). There is no queue: a call that finds a bucket empty is not
//! sent, and waits for nothing.
//!
//! The quotas are taken inside the audited run, after begin, as the caps on calls in flight
//! are, so every allowed decision keeps its row. A proxied server's quotas are taken in its
//! [`Bulkhead`](crate::bulkhead::Bulkhead), after its caps, so a call a cap sheds takes no
//! token. A connector in the gateway's own process has its quotas taken by its
//! [`Bounded`](crate::bound::Bounded) wrapper, before it runs. A call over a quota is completed
//! as `refused`, with a fixed sentence naming the scope and the server, [`server_over_quota`] or
//! [`team_over_quota`], which the row records. Nothing was sent, so a side effect's receipt is
//! settled as `not_performed`, and the sentence tells the caller to try again later. When the
//! team's bucket had a token and the server's did not, the team's token is given back, so a call
//! the server's quota refused costs its team nothing.
//!
//! **The defaults are provisional.** They are set against the vendor quota the first built-in
//! connector meets: GitHub documents a rate of 5,000 REST requests an hour for a GitHub App's
//! installation on an organization that is not on GitHub Enterprise Cloud, and 15,000 for one
//! that is. A server's default, [`DEFAULT_PER_SERVER_PER_MINUTE`], is 80 calls a minute, 4,800
//! an hour, under the lower of those for one instance making one request a call. A team's,
//! [`DEFAULT_PER_TEAM_PER_SERVER_PER_MINUTE`], is half of it, so no one team can use up more
//! than half of a server's quota. Each burst is one minute's rate. The quotas hold in each
//! instance, not across replicas: a deployment with more than one replica, or whose tools make
//! more than one vendor request a call, sets them lower in its deployment file's `[limits]`.
//! They are revisited when the built-in connectors are measured against the vendors.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use gateway_core::TeamId;

/// How many calls a minute each server's quota allows in one instance, unless `[limits]` says
/// otherwise. Provisional: see the [module documentation](self).
pub const DEFAULT_PER_SERVER_PER_MINUTE: u32 = 80;

/// How many calls each server's quota allows at once, after it has been idle, unless
/// `[limits]` says otherwise: one minute's rate.
pub const DEFAULT_PER_SERVER_BURST: u32 = 80;

/// How many calls a minute each team's quota on each server allows in one instance, unless
/// `[limits]` says otherwise: half the server's. Provisional.
pub const DEFAULT_PER_TEAM_PER_SERVER_PER_MINUTE: u32 = 40;

/// How many calls each team's quota on each server allows at once, after it has been idle,
/// unless `[limits]` says otherwise: one minute's rate.
pub const DEFAULT_PER_TEAM_PER_SERVER_BURST: u32 = 40;

/// The sentence for a call refused because its server's rate quota in this gateway instance
/// is used up for now. Nothing was sent.
pub fn server_over_quota(server: &str, tool: &str) -> String {
    format!(
        "Server `{server}` has had as many calls from this gateway as its rate quota allows for \
         now, so this call to tool `{tool}` was not sent. Try it again later."
    )
}

/// The sentence for a call refused because the caller's team's rate quota on its server in
/// this gateway instance is used up for now. Nothing was sent.
pub fn team_over_quota(server: &str, tool: &str) -> String {
    format!(
        "Your team has had as many calls to server `{server}` from this gateway as its rate \
         quota allows for now, so this call to tool `{tool}` was not sent. Try it again later."
    )
}

/// One token bucket's settings: how many calls a minute it allows, and how many at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    /// Tokens gained each minute, a fraction at a time. At least 1.
    pub per_minute: u32,
    /// The most tokens the bucket holds, which it starts with. At least 1.
    pub burst: u32,
}

/// The rate quotas of one gateway instance: each server's, and each team's on each server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateQuotas {
    /// Each server's quota.
    pub per_server: Rate,
    /// Each team's quota on each server.
    pub per_team_per_server: Rate,
}

impl Default for RateQuotas {
    fn default() -> Self {
        Self {
            per_server: Rate {
                per_minute: DEFAULT_PER_SERVER_PER_MINUTE,
                burst: DEFAULT_PER_SERVER_BURST,
            },
            per_team_per_server: Rate {
                per_minute: DEFAULT_PER_TEAM_PER_SERVER_PER_MINUTE,
                burst: DEFAULT_PER_TEAM_PER_SERVER_BURST,
            },
        }
    }
}

/// Which quota refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaScope {
    /// The server's.
    Server,
    /// The caller's team's on the server.
    Team,
}

impl QuotaScope {
    /// The scope's name, as logs and metrics label it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Team => "team",
        }
    }

    /// The scope's sentence for a call to `tool` on `server`.
    pub fn sentence(self, server: &str, tool: &str) -> String {
        match self {
            Self::Server => server_over_quota(server, tool),
            Self::Team => team_over_quota(server, tool),
        }
    }
}

/// One token bucket. The tokens are counted in fractions, so a rate that does not divide a
/// minute evenly is kept exactly enough.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    burst: f64,
    per_second: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: Rate, now: Instant) -> Self {
        let burst = f64::from(rate.burst.max(1));
        Self {
            tokens: burst,
            burst,
            per_second: f64::from(rate.per_minute.max(1)) / 60.0,
            at: now,
        }
    }

    /// Takes a token as of `now`, if the bucket has one.
    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at);
        self.at = self.at.max(now);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Gives back a token taken for a call that was then refused.
    fn give_back(&mut self) {
        self.tokens = (self.tokens + 1.0).min(self.burst);
    }
}

/// One server's buckets: its own, and one for each team that has called it.
#[derive(Debug)]
pub(crate) struct Quotas {
    server: Mutex<Bucket>,
    team_rate: Rate,
    /// One bucket per team that has called the server. Teams come from the team manifests, so
    /// the map is as large as they are at most, and nothing is removed from it.
    teams: Mutex<BTreeMap<TeamId, Arc<Mutex<Bucket>>>>,
}

impl Quotas {
    /// One server's buckets under `quotas`, each full.
    pub(crate) fn new(quotas: RateQuotas) -> Self {
        Self::starting(quotas, Instant::now())
    }

    fn starting(quotas: RateQuotas, now: Instant) -> Self {
        Self {
            server: Mutex::new(Bucket::new(quotas.per_server, now)),
            team_rate: quotas.per_team_per_server,
            teams: Mutex::new(BTreeMap::new()),
        }
    }

    /// Takes a token for a call from `team`, or from a caller with no team, now.
    pub(crate) fn take(&self, team: Option<&TeamId>) -> Result<(), QuotaScope> {
        self.take_at(team, Instant::now())
    }

    /// Takes a token for a call as of `now`: from `team`'s bucket, when there is a team, and
    /// then from the server's. Which quota refused, if one did; a team's token is given back
    /// when the server's quota refuses.
    fn take_at(&self, team: Option<&TeamId>, now: Instant) -> Result<(), QuotaScope> {
        let team = team.map(|team| self.team(team, now));
        if let Some(team) = &team
            && !lock(team).take(now)
        {
            return Err(QuotaScope::Team);
        }
        if !lock(&self.server).take(now) {
            if let Some(team) = &team {
                lock(team).give_back();
            }
            return Err(QuotaScope::Server);
        }
        Ok(())
    }

    /// `team`'s bucket on this server, made full the first time the team calls it.
    fn team(&self, team: &TeamId, now: Instant) -> Arc<Mutex<Bucket>> {
        lock(&self.teams)
            .entry(team.clone())
            .or_insert_with(|| Arc::new(Mutex::new(Bucket::new(self.team_rate, now))))
            .clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a bucket of `rate` takes to gain one token.
pub fn refill_interval(rate: Rate) -> Duration {
    Duration::from_secs_f64(60.0 / f64::from(rate.per_minute.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quotas(server: (u32, u32), team: (u32, u32)) -> RateQuotas {
        RateQuotas {
            per_server: Rate {
                per_minute: server.0,
                burst: server.1,
            },
            per_team_per_server: Rate {
                per_minute: team.0,
                burst: team.1,
            },
        }
    }

    #[test]
    fn a_bucket_allows_its_burst_and_then_refuses() {
        let now = Instant::now();
        let quotas = Quotas::starting(quotas((60, 3), (60, 60)), now);
        for _ in 0..3 {
            assert_eq!(quotas.take_at(None, now), Ok(()));
        }
        assert_eq!(quotas.take_at(None, now), Err(QuotaScope::Server));
    }

    #[test]
    fn a_bucket_refills_at_its_rate_and_never_past_its_burst() {
        let start = Instant::now();
        // 60 a minute: one token a second.
        let quotas = Quotas::starting(quotas((60, 2), (600, 600)), start);
        assert_eq!(quotas.take_at(None, start), Ok(()));
        assert_eq!(quotas.take_at(None, start), Ok(()));
        assert_eq!(quotas.take_at(None, start), Err(QuotaScope::Server));
        // Half a token is not a call.
        let half = start + Duration::from_millis(500);
        assert_eq!(quotas.take_at(None, half), Err(QuotaScope::Server));
        let one = start + Duration::from_secs(1);
        assert_eq!(quotas.take_at(None, one), Ok(()));
        assert_eq!(quotas.take_at(None, one), Err(QuotaScope::Server));
        // An hour idle fills it to its burst, and no further.
        let later = one + Duration::from_secs(3600);
        assert_eq!(quotas.take_at(None, later), Ok(()));
        assert_eq!(quotas.take_at(None, later), Ok(()));
        assert_eq!(quotas.take_at(None, later), Err(QuotaScope::Server));
        assert_eq!(
            refill_interval(Rate {
                per_minute: 60,
                burst: 2
            }),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn a_team_is_held_to_its_own_bucket_and_others_are_served() {
        let now = Instant::now();
        let quotas = Quotas::starting(quotas((60, 10), (60, 2)), now);
        let a = TeamId::new("team-a");
        let b = TeamId::new("team-b");
        assert_eq!(quotas.take_at(Some(&a), now), Ok(()));
        assert_eq!(quotas.take_at(Some(&a), now), Ok(()));
        assert_eq!(quotas.take_at(Some(&a), now), Err(QuotaScope::Team));
        assert_eq!(quotas.take_at(Some(&b), now), Ok(()));
        // A caller with no team meets only the server's quota.
        assert_eq!(quotas.take_at(None, now), Ok(()));
    }

    #[test]
    fn a_team_token_is_given_back_when_the_servers_quota_refuses() {
        let now = Instant::now();
        let quotas = Quotas::starting(quotas((60, 1), (60, 1)), now);
        let a = TeamId::new("team-a");
        let b = TeamId::new("team-b");
        // Team b uses the server's one token.
        assert_eq!(quotas.take_at(Some(&b), now), Ok(()));
        assert_eq!(quotas.take_at(Some(&a), now), Err(QuotaScope::Server));
        // A second later the server has a token again, and team a still has its own.
        let later = now + Duration::from_secs(1);
        assert_eq!(quotas.take_at(Some(&a), later), Ok(()));
    }

    #[test]
    fn the_defaults_are_the_documented_provisional_values() {
        let defaults = RateQuotas::default();
        assert_eq!(defaults.per_server.per_minute, 80);
        assert_eq!(defaults.per_server.burst, 80);
        assert_eq!(defaults.per_team_per_server.per_minute, 40);
        assert_eq!(defaults.per_team_per_server.burst, 40);
        // 80 a minute is under GitHub's 5,000 an hour for one installation.
        assert!(u64::from(defaults.per_server.per_minute) * 60 < 5_000);
    }

    #[test]
    fn each_sentence_names_its_scope_the_server_and_the_tool_and_says_try_again_later() {
        let server = QuotaScope::Server.sentence("github", "github__issue_view");
        assert!(server.starts_with("Server `github` has had"), "{server}");
        assert!(server.contains("tool `github__issue_view` was not sent"));
        assert!(server.ends_with("Try it again later."));
        let team = QuotaScope::Team.sentence("github", "github__issue_view");
        assert!(team.starts_with("Your team has had"), "{team}");
        assert!(team.contains("server `github`"));
        assert!(team.ends_with("Try it again later."));
    }
}
