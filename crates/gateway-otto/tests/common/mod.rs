//! What the verifier's tests share: a deployment, a mapping, a fixed time, a typical grant's
//! claims and callers with and without a pod.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::{
    DeploymentName, PodUid, Principal, PrincipalId, PrincipalKind, Proved, Verifier,
};
use gateway_otto::minter::TestMinter;
use gateway_otto::{
    FailureKind, GrantFailure, GrantKeys, GrantVerifier, IssuerConfig, PreviousKeyConfig,
    ToolMapping, VerifiedGrant,
};
use serde_json::{Value, json};

/// The deployment the tests' verifier runs as.
pub const DEPLOYMENT: &str = "switchboard-otto";
/// The other gateway a cutover grant names.
pub const GO_GATEWAY: &str = "otto-gateway";
/// The pod the caller's token proves.
pub const POD: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
/// Another pod of the same team.
pub const OTHER_POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
/// Seconds since the epoch at [`now`].
pub const NOW: i64 = 1_800_000_000;

/// The time the tests verify at.
pub fn now() -> SystemTime {
    at(NOW)
}

/// A time, in seconds since the epoch.
pub fn at(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap())
}

/// A typical grant's claims, issued now for ten minutes. The actor, team and turn are
/// distinctive, so a test can look for them in what a failure shows.
pub fn claims() -> Value {
    json!({
        "aud": [GO_GATEWAY, DEPLOYMENT],
        "iat": NOW,
        "exp": NOW + 600,
        "team": "team-canary-payments",
        "tools": ["github_get_pr", "github_create_pr", "github_not_mapped"],
        "epoch": 7,
        "sid": "session-canary",
        "tid": "turn-canary",
        "eid": "execution-canary",
        "actor": "actor-canary@example.test",
        "pod": POD,
        "egress": "sealed",
    })
}

/// The claims with members replaced or added.
pub fn with(changes: Value) -> Value {
    let mut claims = claims();
    for (name, value) in changes.as_object().unwrap() {
        claims[name] = value.clone();
    }
    claims
}

/// The claims without one member.
pub fn without(name: &str) -> Value {
    let mut claims = claims();
    claims.as_object_mut().unwrap().remove(name);
    claims
}

/// The mapping the tests use: two of Otto's names.
pub fn mapping() -> ToolMapping {
    ToolMapping::from_pairs([
        ("github_get_pr", "github__get_pr"),
        ("github_create_pr", "github__create_pr"),
    ])
    .unwrap()
}

/// One issuer's configuration with the minter's key as its current key.
pub fn issuer(name: &str, minter: &TestMinter) -> IssuerConfig {
    IssuerConfig {
        name: name.to_owned(),
        current_key: minter.public_key_pem(),
        previous_key: None,
        require_pod: false,
        require_egress: false,
    }
}

/// A verifier for one issuer, `otto-prod`, with the minter's key.
pub fn verifier(minter: &TestMinter) -> GrantVerifier {
    verifier_with(vec![issuer("otto-prod", minter)])
}

/// A verifier for one issuer whose grants must carry `pod` and `egress`.
pub fn strict_verifier(minter: &TestMinter) -> GrantVerifier {
    let mut config = issuer("otto-prod", minter);
    config.require_pod = true;
    config.require_egress = true;
    verifier_with(vec![config])
}

/// A verifier for one issuer with a current key and a previous one retiring at `retires_at`.
pub fn rotating_verifier(
    current: &TestMinter,
    previous: &TestMinter,
    retires_at: SystemTime,
) -> GrantVerifier {
    let mut config = issuer("otto-prod", current);
    config.previous_key = Some(PreviousKeyConfig {
        key: previous.public_key_pem(),
        retires_at: Some(retires_at),
    });
    verifier_with(vec![config])
}

/// A verifier for these issuers.
pub fn verifier_with(config: Vec<IssuerConfig>) -> GrantVerifier {
    GrantVerifier::new(
        GrantKeys::new(&config).unwrap(),
        DeploymentName::new(DEPLOYMENT),
        mapping(),
    )
}

/// Makes a caller proved, as the identity verifier would.
struct Given(Principal);

impl Verifier for Given {
    type Evidence = ();
    type Fact = Principal;
    type Error = Infallible;

    fn verify(&self, _: &()) -> Result<Principal, Infallible> {
        Ok(self.0.clone())
    }
}

/// A workload of the grant's team whose token proves `pod`, or no pod.
pub fn workload(pod: Option<&str>) -> Proved<Principal> {
    let principal = Principal {
        id: PrincipalId {
            issuer: "https://cluster.example.test".into(),
            subject: "system:serviceaccount:otto:sandbox".into(),
        },
        kind: PrincipalKind::Workload {
            team: "team-canary-payments".into(),
            pod: pod.map(|pod| PodUid::parse(pod).unwrap()),
        },
    };
    Proved::verify(&Given(principal), &()).unwrap()
}

/// A person signed in through an identity provider: no team, no pod.
pub fn user() -> Proved<Principal> {
    let principal = Principal {
        id: PrincipalId {
            issuer: "https://idp.example.test".into(),
            subject: "person@example.test".into(),
        },
        kind: PrincipalKind::User {
            groups: Default::default(),
        },
    };
    Proved::verify(&Given(principal), &()).unwrap()
}

/// Verifies a grant from the usual caller, at [`now`].
pub fn check(verifier: &GrantVerifier, grant: &str) -> Result<VerifiedGrant, GrantFailure> {
    verifier.verify(grant.as_bytes(), &workload(Some(POD)), now())
}

/// Verifies a grant expecting it to pass.
pub fn accepted(verifier: &GrantVerifier, grant: &str) -> VerifiedGrant {
    check(verifier, grant).unwrap_or_else(|failure| panic!("grant refused: {failure:?}"))
}

/// Verifies a grant expecting it to fail, and returns the failure.
pub fn refused(verifier: &GrantVerifier, grant: &str) -> GrantFailure {
    match check(verifier, grant) {
        Ok(verified) => panic!("grant accepted: {verified:?}"),
        Err(failure) => failure,
    }
}

/// The failures of a binding, found once the signature verified and the claims were read: the
/// only ones that carry the grant's digest (decision 0012, "Failures").
pub const BINDINGS: [FailureKind; 5] = [
    FailureKind::WrongAudience,
    FailureKind::NotYetValid,
    FailureKind::Expired,
    FailureKind::LifetimeOverCeiling,
    FailureKind::WrongPod,
];

/// Whether a failure of `kind` carries the grant's digest when its signature verified.
pub fn carries_digest(kind: FailureKind) -> bool {
    BINDINGS.contains(&kind)
}

/// Asserts a grant fails with `kind`, `signed` saying whether its signature verified. The
/// failure carries the grant's digest only if it did and `kind` is a binding's: a grant refused
/// for its encoding or its claims' shape after a verified signature carries none.
pub fn refused_as(verifier: &GrantVerifier, grant: &str, kind: FailureKind, signed: bool) {
    let failure = refused(verifier, grant);
    assert_eq!(failure.kind(), kind, "{grant}");
    let digest =
        (signed && carries_digest(kind)).then(|| gateway_otto::GrantDigest::of(grant.as_bytes()));
    assert_eq!(failure.digest(), digest, "the digest of {grant}");
}
