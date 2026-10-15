//! Clock skew at the leeway and the ceiling, and one past each (decision 0012: 30 seconds of
//! leeway on `iat` and `exp`, and `exp − iat` at most 15 minutes).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_otto::FailureKind::*;
use gateway_otto::format::{LEEWAY_SECONDS, MAX_LIFETIME_SECONDS};
use gateway_otto::minter::TestMinter;
use serde_json::json;

#[test]
fn the_limits_are_decision_0012s() {
    assert_eq!(LEEWAY_SECONDS, 30);
    assert_eq!(MAX_LIFETIME_SECONDS, 900);
}

#[test]
fn issued_up_to_the_leeway_in_the_future() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    for ahead in [0, 1, 29, 30] {
        let grant = minter.mint(&with(json!({"iat": NOW + ahead, "exp": NOW + ahead + 600})));
        accepted(&verifier, &grant);
    }
    for ahead in [31, 32, 3600] {
        let grant = minter.mint(&with(json!({"iat": NOW + ahead, "exp": NOW + ahead + 600})));
        refused_as(&verifier, &grant, NotYetValid, true);
    }
}

#[test]
fn expired_by_less_than_the_leeway() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    for ago in [-600, 0, 1, 29] {
        let grant = minter.mint(&with(json!({"iat": NOW - ago - 600, "exp": NOW - ago})));
        accepted(&verifier, &grant);
    }
    // `exp` must be after now minus the leeway, so at exactly the leeway it has expired.
    for ago in [30, 31, 3600] {
        let grant = minter.mint(&with(json!({"iat": NOW - ago - 600, "exp": NOW - ago})));
        refused_as(&verifier, &grant, Expired, true);
    }
}

#[test]
fn a_lifetime_of_at_most_fifteen_minutes() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    for lifetime in [1, 600, 899, 900] {
        let grant = minter.mint(&with(json!({"iat": NOW - 10, "exp": NOW - 10 + lifetime})));
        accepted(&verifier, &grant);
    }
    for lifetime in [901, 902, 86_400] {
        let grant = minter.mint(&with(json!({"iat": NOW - 10, "exp": NOW - 10 + lifetime})));
        refused_as(&verifier, &grant, LifetimeOverCeiling, true);
    }
}

#[test]
fn a_grant_minted_to_last_a_year_is_refused_in_its_final_minutes() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let year = 365 * 86_400;
    let grant = minter.mint(&with(json!({"iat": NOW + 600 - year, "exp": NOW + 600})));
    refused_as(&verifier, &grant, LifetimeOverCeiling, true);
}

#[test]
fn the_clock_is_the_one_passed_in() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let grant = minter.mint(&claims());
    let caller = workload(Some(POD));
    let at_offset = |offset: i64| verifier.verify(grant.as_bytes(), &caller, at(NOW + offset));
    assert!(at_offset(0).is_ok());
    assert!(at_offset(569).is_ok());
    assert_eq!(at_offset(630).unwrap_err().kind(), Expired);
    assert_eq!(at_offset(-31).unwrap_err().kind(), NotYetValid);
    // A clock before the epoch reads as the epoch, where every grant is in the future.
    let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(5);
    assert_eq!(
        verifier
            .verify(grant.as_bytes(), &caller, before)
            .unwrap_err()
            .kind(),
        NotYetValid
    );
}

#[test]
fn the_time_checks_run_in_order() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    // Issued in the future and over the ceiling: not yet valid first.
    let grant = minter.mint(&with(json!({"iat": NOW + 60, "exp": NOW + 60 + 3600})));
    refused_as(&verifier, &grant, NotYetValid, true);
    // Expired and over the ceiling: expired first.
    let grant = minter.mint(&with(json!({"iat": NOW - 7200, "exp": NOW - 60})));
    refused_as(&verifier, &grant, Expired, true);
    // For another deployment and expired: the audience first.
    let grant = minter.mint(&with(json!({"aud": ["elsewhere"], "exp": NOW - 60})));
    refused_as(&verifier, &grant, WrongAudience, true);
}
