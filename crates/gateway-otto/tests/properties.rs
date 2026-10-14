//! Properties of the verifier over generated grants and times.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_otto::FailureKind;
use gateway_otto::minter::TestMinter;
use proptest::prelude::*;
use serde_json::json;
use std::sync::LazyLock;

static MINTER: LazyLock<TestMinter> = LazyLock::new(TestMinter::generate);
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/";

proptest! {
    /// One grant, one string: changing any one character of a grant, to any other character a
    /// grant could hold, gives a string that does not verify.
    #[test]
    fn no_other_string_verifies(index in any::<prop::sample::Index>(), replacement in prop::sample::select(ALPHABET)) {
        let verifier = verifier(&MINTER);
        let grant = MINTER.mint(&claims());
        let index = index.index(grant.len());
        prop_assume!(grant.as_bytes()[index] != replacement);
        let mut changed = grant.clone().into_bytes();
        changed[index] = replacement;
        let changed = String::from_utf8(changed).unwrap();
        prop_assert!(check(&verifier, &changed).is_err(), "{changed} verified");
    }

    /// Whatever the times, a grant is accepted exactly when decision 0012's three rules hold,
    /// and otherwise fails on the first that does not, in the order of the checks.
    #[test]
    fn the_time_rules_are_exactly_the_decisions(iat in -2000i64..2000, lifetime in -100i64..1100, now in -2000i64..2000) {
        let verifier = verifier(&MINTER);
        let (iat, exp) = (NOW + iat, NOW + iat + lifetime);
        prop_assume!(iat >= 0 && exp >= 0);
        let grant = MINTER.mint(&with(json!({"iat": iat, "exp": exp})));
        let now = NOW + now;
        let result = verifier.verify(grant.as_bytes(), &workload(Some(POD)), at(now));
        let expected = if iat > now + 30 {
            Some(FailureKind::NotYetValid)
        } else if exp <= now - 30 {
            Some(FailureKind::Expired)
        } else if exp - iat > 900 {
            Some(FailureKind::LifetimeOverCeiling)
        } else {
            None
        };
        prop_assert_eq!(result.err().map(|failure| failure.kind()), expected);
    }

    /// Whatever the claims say, a failure shows none of it.
    #[test]
    fn a_failure_shows_nothing_of_the_claims(actor in "[a-z]{12,20}", team in "[a-z]{12,20}", turn in "[a-z]{12,20}") {
        let verifier = strict_verifier(&MINTER);
        let changes = json!({"actor": actor, "team": team, "tid": turn});
        for broken in [
            json!({"aud": ["elsewhere"]}),
            json!({"exp": NOW - 60}),
            json!({"pod": OTHER_POD}),
            json!({"epoch": 0}),
        ] {
            let mut claims = with(changes.clone());
            for (name, value) in broken.as_object().unwrap() {
                claims[name] = value.clone();
            }
            let failure = refused(&verifier, &MINTER.mint(&claims));
            let shown = format!("{failure:?} {failure}");
            for canary in [&actor, &team, &turn] {
                prop_assert!(!shown.contains(canary.as_str()), "{shown}");
            }
        }
    }
}
