//! Key rotation (decision 0012, Keys): the previous key is accepted until its absolute end
//! instant and refused from it on, and a restart does not extend it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_otto::FailureKind::*;
use gateway_otto::minter::TestMinter;

#[test]
fn the_previous_key_is_accepted_until_its_end_instant() {
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let retires = NOW + 120;
    let verifier = rotating_verifier(&current, &previous, at(retires));
    let caller = workload(Some(POD));
    let old = previous.mint(&claims());
    let new = current.mint(&claims());

    for seconds in [NOW, retires - 1] {
        let verified = verifier
            .verify(old.as_bytes(), &caller, at(seconds))
            .unwrap();
        assert_eq!(verified.key_id(), &previous.key_id());
        assert_eq!(verified.issuer().as_str(), "otto-prod");
    }
    // Retired from its end instant on, by the clock passed in: no restart.
    for seconds in [retires, retires + 1, retires + 500] {
        let failure = verifier
            .verify(old.as_bytes(), &caller, at(seconds))
            .unwrap_err();
        assert_eq!(failure.kind(), RetiredKey);
        assert_eq!(
            failure.digest(),
            None,
            "a retired key's grant is not checked further"
        );
    }
    // The current key carries on.
    for seconds in [NOW, retires, retires + 500] {
        let verified = verifier
            .verify(new.as_bytes(), &caller, at(seconds))
            .unwrap();
        assert_eq!(verified.key_id(), &current.key_id());
    }
}

#[test]
fn a_restart_does_not_extend_the_previous_key() {
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let retires = NOW + 120;
    let old = previous.mint(&claims());
    let caller = workload(Some(POD));
    // Before the instant, one gateway accepts the old key's grant.
    let before = rotating_verifier(&current, &previous, at(retires));
    assert!(
        before
            .verify(old.as_bytes(), &caller, at(retires - 60))
            .is_ok()
    );
    // A gateway started after the instant from the same configuration refuses it at once.
    let restarted = rotating_verifier(&current, &previous, at(retires));
    assert_eq!(
        restarted
            .verify(old.as_bytes(), &caller, at(retires + 1))
            .unwrap_err()
            .kind(),
        RetiredKey
    );
}

#[test]
fn a_retired_key_is_refused_before_its_signature_is_checked() {
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let verifier = rotating_verifier(&current, &previous, at(NOW - 1));
    let old = previous.mint(&claims());
    let forged = gateway_otto::minter::with_part(&old, 3, &gateway_otto::minter::encode(&[0; 64]));
    refused_as(&verifier, &forged, RetiredKey, false);
}

#[test]
fn a_key_from_neither_slot_is_unknown() {
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let verifier = rotating_verifier(&current, &previous, at(NOW + 120));
    refused_as(
        &verifier,
        &TestMinter::generate().mint(&claims()),
        UnknownKey,
        false,
    );
}
