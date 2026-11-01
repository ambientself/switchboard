//! What a grant binds beyond its signature: the audience, the pod once required, the egress
//! setting once required; replay within those bounds; and that a failure carries nothing from
//! the claims (decision 0012).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_otto::FailureKind::{self, *};
use gateway_otto::minter::{TestMinter, with_part};
use gateway_otto::{Egress, GrantDigest};
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn the_audience_must_include_this_deployment() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    for aud in [
        json!([DEPLOYMENT]),
        json!([GO_GATEWAY, DEPLOYMENT]),
        json!(["a", DEPLOYMENT, "b"]),
    ] {
        accepted(&verifier, &minter.mint(&with(json!({"aud": aud}))));
    }
    for aud in [
        json!([]),
        json!([GO_GATEWAY]),
        json!(["switchboard-otto-staging"]),
        json!(["Switchboard-Otto"]),
        json!([" switchboard-otto"]),
    ] {
        refused_as(
            &verifier,
            &minter.mint(&with(json!({"aud": aud}))),
            WrongAudience,
            true,
        );
    }
}

#[test]
fn the_pod_is_bound_once_required() {
    let minter = TestMinter::generate();
    let verifier = strict_verifier(&minter);
    let grant = minter.mint(&claims());
    let verify = |caller| verifier.verify(grant.as_bytes(), &caller, now());
    assert_eq!(
        verify(workload(Some(POD))).unwrap().pod().unwrap().as_str(),
        POD
    );
    // Another pod of the same team, a token that proves no pod, and a user.
    for caller in [workload(Some(OTHER_POD)), workload(None), user()] {
        let failure = verify(caller).unwrap_err();
        assert_eq!(failure.kind(), WrongPod);
        assert_eq!(failure.digest(), Some(GrantDigest::of(grant.as_bytes())));
    }
    // A grant without `pod`, when the issuer requires it, is malformed.
    refused_as(&verifier, &minter.mint(&without("pod")), Malformed, true);
}

#[test]
fn the_pod_is_not_checked_until_required() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let grant = minter.mint(&claims());
    // Any caller of the team: the grant's pod is recorded, not compared.
    for caller in [workload(Some(OTHER_POD)), workload(None), user()] {
        let verified = verifier.verify(grant.as_bytes(), &caller, now()).unwrap();
        assert_eq!(verified.pod().unwrap().as_str(), POD);
    }
    let verified = accepted(&verifier, &minter.mint(&without("pod")));
    assert_eq!(verified.pod(), None);
}

#[test]
fn the_egress_setting_is_carried_and_required_once_configured() {
    let minter = TestMinter::generate();
    let lenient = verifier(&minter);
    let strict = strict_verifier(&minter);
    for (value, egress) in [("sealed", Egress::Sealed), ("open", Egress::Open)] {
        let grant = minter.mint(&with(json!({"egress": value})));
        assert_eq!(accepted(&lenient, &grant).egress(), Some(egress));
        assert_eq!(accepted(&strict, &grant).egress(), Some(egress));
    }
    let grant = minter.mint(&without("egress"));
    assert_eq!(accepted(&lenient, &grant).egress(), None);
    refused_as(&strict, &grant, Malformed, true);
}

#[test]
fn a_grant_verifies_any_number_of_times_with_one_digest() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let grant = minter.mint(&claims());
    let expected: [u8; 32] = Sha256::digest(grant.as_bytes()).into();
    for offset in [0, 1, 60, 300, 599] {
        let verified = verifier
            .verify(grant.as_bytes(), &workload(Some(POD)), at(NOW + offset))
            .unwrap();
        assert_eq!(verified.digest().as_bytes(), &expected);
    }
    // The digest is of the grant as presented, not of its decoded claims.
    let digest = accepted(&verifier, &grant).digest();
    let claims_digest = GrantDigest::of(gateway_otto::minter::parts(&grant)[2].as_bytes());
    assert_ne!(digest, claims_digest);
    assert_eq!(digest.to_string().len(), 64);
    assert_eq!(
        digest.to_string(),
        expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    // Two grants with the same claims, minted by two keys, have different digests.
    let other = TestMinter::generate();
    let both = verifier_with(vec![
        issuer("otto-prod", &minter),
        issuer("otto-qa", &other),
    ]);
    let second = accepted(&both, &other.mint(&claims()));
    assert_eq!(second.issuer().as_str(), "otto-qa");
    assert_ne!(second.digest(), digest);
}

/// Grants failing each kind of check after the signature, under distinctive claims.
fn failing_grants(minter: &TestMinter) -> Vec<(FailureKind, String)> {
    let good = minter.mint(&claims());
    let other = TestMinter::generate();
    vec![
        (Version, format!("v1{}", good.strip_prefix("v3").unwrap())),
        (UnknownKey, other.mint(&claims())),
        (
            Encoding,
            with_part(
                &good,
                3,
                &gateway_otto::minter::padded(&gateway_otto::minter::parts(&good)[3]).unwrap(),
            ),
        ),
        (
            Signature,
            with_part(
                &good,
                2,
                &gateway_otto::minter::encode(
                    with(json!({"tid": "turn-canary-2"})).to_string().as_bytes(),
                ),
            ),
        ),
        (Malformed, minter.mint(&with(json!({"epoch": 0})))),
        (
            WrongAudience,
            minter.mint(&with(json!({"aud": ["elsewhere"]}))),
        ),
        (
            NotYetValid,
            minter.mint(&with(json!({"iat": NOW + 600, "exp": NOW + 1200}))),
        ),
        (
            Expired,
            minter.mint(&with(json!({"iat": NOW - 1200, "exp": NOW - 600}))),
        ),
        (
            LifetimeOverCeiling,
            minter.mint(&with(json!({"exp": NOW + 3600}))),
        ),
        (WrongPod, minter.mint(&with(json!({"pod": OTHER_POD})))),
    ]
}

#[test]
fn nothing_from_an_unverified_grant_is_in_its_failure() {
    let minter = TestMinter::generate();
    let verifier = strict_verifier(&minter);
    let canaries = [
        "canary",
        "actor-canary",
        "team-canary-payments",
        "session-canary",
        "turn-canary",
        "execution-canary",
        "github_get_pr",
        "elsewhere",
        OTHER_POD,
        "otto-prod",
    ];
    let mut kinds = Vec::new();
    for (kind, grant) in failing_grants(&minter) {
        let failure = refused(&verifier, &grant);
        assert_eq!(failure.kind(), kind, "{grant}");
        kinds.push(kind);
        for shown in [format!("{failure:?}"), failure.to_string()] {
            for canary in canaries {
                assert!(!shown.contains(canary), "{kind:?} shows {canary}: {shown}");
            }
            assert!(!shown.contains(&grant), "{kind:?} shows the grant: {shown}");
        }
    }
    // Every kind but the retired key is covered here; rotation.rs has that one.
    let mut all: Vec<_> = FailureKind::ALL
        .into_iter()
        .filter(|kind| *kind != RetiredKey)
        .collect();
    all.sort();
    kinds.sort();
    assert_eq!(kinds, all);
}

#[test]
fn each_failure_kind_has_its_own_label() {
    let labels: Vec<&str> = FailureKind::ALL.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(
        labels,
        [
            "version",
            "unknown_key",
            "retired_key",
            "encoding",
            "signature",
            "malformed",
            "wrong_audience",
            "not_yet_valid",
            "expired",
            "lifetime_over_ceiling",
            "wrong_pod",
        ]
    );
}
