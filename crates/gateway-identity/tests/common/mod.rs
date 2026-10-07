//! Issuers and configuration shared by the identity tests. Each test file uses a subset.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, LazyLock};

use gateway_core::{Principal, PrincipalId, PrincipalKind};
use gateway_identity::{IssuerConfig, IssuerKind, SigningAlgorithm, TokenVerifier};
use gateway_testkit::{FIXTURE_NOW, FixedClock, LocalIssuer, TokenBuilder};

pub const NOW: u64 = FIXTURE_NOW;
pub const AUDIENCE: &str = "gateway-under-test";
pub const SUBJECT: &str = "system:serviceaccount:team-one:sandbox";
pub const TEAM: &str = "team-one";
pub const GROUPS: [&str; 2] = ["group-1", "group-2"];
/// The leeway and the ceiling [`LocalIssuer::config`] sets, repeated here so a boundary case
/// reads as arithmetic on them.
pub const LEEWAY: u64 = 30;
pub const MAX_LIFETIME: u64 = 3600;

/// Two issuers per algorithm, built once for the whole test binary: an RSA key takes a second
/// or more to generate. Two of each, so a test can have an "other" issuer of the same algorithm
/// whose signatures are well formed and wrong.
static RS_ONE: LazyLock<LocalIssuer> =
    LazyLock::new(|| issuer("https://rs-one.test", SigningAlgorithm::Rs256));
static RS_TWO: LazyLock<LocalIssuer> =
    LazyLock::new(|| issuer("https://rs-two.test", SigningAlgorithm::Rs256));
static ES_ONE: LazyLock<LocalIssuer> =
    LazyLock::new(|| issuer("https://es-one.test", SigningAlgorithm::Es256));
static ES_TWO: LazyLock<LocalIssuer> =
    LazyLock::new(|| issuer("https://es-two.test", SigningAlgorithm::Es256));

fn issuer(name: &str, algorithm: SigningAlgorithm) -> LocalIssuer {
    LocalIssuer::new(name, algorithm).unwrap()
}

/// Every issuer the tests have: the first two are RSA, the last two are EC.
pub fn issuers() -> [&'static LocalIssuer; 4] {
    [&RS_ONE, &RS_TWO, &ES_ONE, &ES_TWO]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Workload,
    User,
}

/// One issuer under test: an algorithm, a kind, and a second issuer of the same algorithm.
#[derive(Clone, Copy)]
pub struct Setup {
    pub algorithm: SigningAlgorithm,
    pub kind: Kind,
    pub issuer: &'static LocalIssuer,
    pub other: &'static LocalIssuer,
}

impl std::fmt::Debug for Setup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.algorithm, self.kind)
    }
}

/// The four combinations of algorithm and kind.
pub fn setups() -> Vec<Setup> {
    let mut all = Vec::new();
    for (algorithm, issuer, other) in [
        (SigningAlgorithm::Rs256, &*RS_ONE, &*RS_TWO),
        (SigningAlgorithm::Es256, &*ES_ONE, &*ES_TWO),
    ] {
        for kind in [Kind::Workload, Kind::User] {
            all.push(Setup {
                algorithm,
                kind,
                issuer,
                other,
            });
        }
    }
    all
}

impl Setup {
    pub fn issuer_kind(&self) -> IssuerKind {
        match self.kind {
            Kind::Workload => IssuerKind::Workload {
                subjects: [(SUBJECT.into(), TEAM.into())].into(),
            },
            Kind::User => IssuerKind::user(),
        }
    }

    pub fn config(&self) -> IssuerConfig {
        self.issuer.config(self.issuer_kind(), &[AUDIENCE])
    }

    pub fn verifier(&self) -> TokenVerifier {
        self.verifier_at(NOW)
    }

    pub fn verifier_at(&self, now: u64) -> TokenVerifier {
        TokenVerifier::new(vec![self.config()], Arc::new(FixedClock::at(now))).unwrap()
    }

    /// A valid token for this setup, issued at [`NOW`].
    pub fn token(&self) -> TokenBuilder<'static> {
        let at = FixedClock::at(NOW);
        let now = gateway_identity::Clock::now(&at);
        match self.kind {
            Kind::Workload => self.issuer.workload_token(SUBJECT, AUDIENCE, now),
            Kind::User => self.issuer.user_token(SUBJECT, AUDIENCE, &GROUPS, now),
        }
    }

    /// The principal a valid token for this setup proves.
    pub fn principal(&self) -> Principal {
        Principal {
            id: PrincipalId {
                issuer: self.issuer.issuer().into(),
                subject: SUBJECT.into(),
            },
            kind: match self.kind {
                Kind::Workload => PrincipalKind::Workload { team: TEAM.into() },
                Kind::User => PrincipalKind::User {
                    groups: GROUPS.iter().map(|&group| group.into()).collect(),
                },
            },
        }
    }
}
