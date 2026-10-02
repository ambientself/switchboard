//! Rules that must hold for every input, not only the ones in the table.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use gateway_core::{Principal, Proved};
use gateway_identity::{
    Identity, IdentityConfig, IssuerConfig, IssuerKind, TokenVerifier, Verification, VerifyError,
};
use gateway_testkit::{FixedClock, LocalIssuer};
use proptest::prelude::*;

use common::{AUDIENCE, NOW, issuers};

fn clock() -> Arc<FixedClock> {
    Arc::new(FixedClock::at(NOW))
}

/// An entry for `issuer` of the given kind in which `subject` is a known workload, so the same
/// subject is valid under every issuer and only the issuer tells the callers apart.
fn entry(issuer: &LocalIssuer, workload: bool, subject: &str) -> IssuerConfig {
    let kind = if workload {
        IssuerKind::Workload {
            subjects: [(subject.into(), "team-one".into())].into(),
        }
    } else {
        IssuerKind::user()
    };
    issuer.config(kind, &[AUDIENCE])
}

fn token<'a>(
    issuer: &'a LocalIssuer,
    workload: bool,
    subject: &str,
    groups: &[&str],
) -> gateway_testkit::TokenBuilder<'a> {
    let now = gateway_identity::Clock::now(&FixedClock::at(NOW));
    if workload {
        issuer.workload_token(subject, AUDIENCE, now)
    } else {
        issuer.user_token(subject, AUDIENCE, groups, now)
    }
}

fn prove(verifier: &TokenVerifier, token: &str) -> Result<Proved<Principal>, VerifyError> {
    Proved::verify(verifier, token).map_err(|failure| failure.detail().clone())
}

/// Two different issuers, from the four the tests hold (two RSA, two EC): so the pair is
/// sometimes the same algorithm, and sometimes not.
fn two_issuers() -> impl Strategy<Value = (usize, usize)> {
    (0..4usize, 0..4usize).prop_filter("two different issuers", |(a, b)| a != b)
}

fn subjects() -> impl Strategy<Value = String> {
    "[a-z0-9:@._/-]{1,32}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// A token signed by issuer A is never accepted under issuer B's entry, whatever it claims:
    /// B's name as its issuer, A's or B's key id, the same subject, the same groups. And with
    /// both configured, each issuer's honest token proves a principal of its own issuer, and
    /// the principals for one subject from the two issuers never compare equal.
    #[test]
    fn a_token_from_one_issuer_is_never_accepted_under_another(
        (a, b) in two_issuers(),
        subject in subjects(),
        workload in any::<bool>(),
        claimed_kid in 0..3usize,
        groups in proptest::sample::subsequence(vec!["g1", "g2", "g3"], 0..=3),
    ) {
        let (issuer_a, issuer_b) = (issuers()[a], issuers()[b]);
        let only_b = TokenVerifier::new(vec![entry(issuer_b, workload, &subject)], clock()).unwrap();
        let both = TokenVerifier::new(
            vec![entry(issuer_a, workload, &subject), entry(issuer_b, workload, &subject)],
            clock(),
        ).unwrap();

        // A forges a token naming B, under whichever key id it likes.
        let forged = token(issuer_a, workload, &subject, &groups).issuer(issuer_b.issuer());
        let forged = match claimed_kid {
            0 => forged,
            1 => forged.kid(issuer_b.key_id()),
            _ => forged.without_kid(),
        }
        .build();
        for verifier in [&only_b, &both] {
            let refusal = prove(verifier, &forged).unwrap_err();
            prop_assert!(
                matches!(
                    refusal,
                    VerifyError::BadSignature | VerifyError::UnknownKeyId | VerifyError::AlgorithmNotAllowed | VerifyError::MissingKeyId
                ),
                "{refusal:?}"
            );
        }

        // Honest tokens each prove their own issuer's principal.
        let from_a = prove(&both, &token(issuer_a, workload, &subject, &groups).build()).unwrap();
        let from_b = prove(&both, &token(issuer_b, workload, &subject, &groups).build()).unwrap();
        prop_assert_eq!(from_a.get().id.issuer.as_str(), issuer_a.issuer());
        prop_assert_eq!(from_b.get().id.issuer.as_str(), issuer_b.issuer());
        prop_assert_eq!(&from_a.get().id.subject, &from_b.get().id.subject);
        prop_assert_ne!(&from_a.get().id, &from_b.get().id);
        prop_assert_ne!(from_a.get(), from_b.get());

        // And A's honest token is not accepted by a verifier that holds only B.
        let refusal = prove(&only_b, &token(issuer_a, workload, &subject, &groups).build()).unwrap_err();
        prop_assert_eq!(refusal, VerifyError::UnknownIssuer);
    }

    /// Whatever is presented, checking that is on never answers `disabled`, and checking that is
    /// off never answers anything else. Text that is not a token never proves anything.
    #[test]
    fn disabled_is_reachable_only_from_the_configuration_that_says_so(
        presented in proptest::option::of(prop_oneof![
            any::<String>(),
            "[A-Za-z0-9_-]{0,40}\\.[A-Za-z0-9_-]{0,40}\\.[A-Za-z0-9_-]{0,40}",
        ]),
    ) {
        let setup = common::setups()[0];
        let enforcing = Identity::new(IdentityConfig::Enforce(vec![setup.config()]), clock()).unwrap();
        let disabled = Identity::new(IdentityConfig::Disabled, clock()).unwrap();
        let verification = enforcing.check(presented.as_deref());
        prop_assert!(matches!(verification, Verification::Failed(_)), "{verification:?}");
        let verification = disabled.check(presented.as_deref());
        prop_assert!(matches!(verification, Verification::Disabled), "{verification:?}");
    }

    /// Changing any one character of a valid token never makes it prove someone else: it is
    /// refused, or it is still the same principal.
    #[test]
    fn tampering_with_a_token_never_changes_who_it_proves(
        setup_index in 0..4usize,
        position in any::<proptest::sample::Index>(),
        replacement in proptest::sample::select(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.".chars().collect::<Vec<_>>()
        ),
    ) {
        let setup = common::setups()[setup_index];
        let verifier = setup.verifier();
        let valid = setup.token().build();
        let mut characters: Vec<char> = valid.chars().collect();
        let at = position.index(characters.len());
        characters[at] = replacement;
        let tampered: String = characters.into_iter().collect();
        if let Ok(proved) = prove(&verifier, &tampered) {
            prop_assert_eq!(proved.get(), &setup.principal());
        }
    }
}
