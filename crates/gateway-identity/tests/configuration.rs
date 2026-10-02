//! What a deployment may and may not configure, the three verification states, and a verifier
//! reading the clock it was given.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use gateway_core::{IDENTITY_FAILURE, Verifier};
use gateway_identity::{
    ConfigError, Identity, IdentityConfig, IssuerConfig, IssuerKind, SigningAlgorithm,
    TokenVerifier, Verification, VerificationState, VerifyError,
};
use gateway_testkit::{FixedClock, SteppableClock};
use serde_json::json;

use common::{Kind, LEEWAY, NOW, Setup, setups};

fn setup(algorithm: SigningAlgorithm, kind: Kind) -> Setup {
    setups()
        .into_iter()
        .find(|setup| setup.algorithm == algorithm && setup.kind == kind)
        .unwrap()
}

fn build(configs: Vec<IssuerConfig>) -> Result<TokenVerifier, ConfigError> {
    TokenVerifier::new(configs, Arc::new(FixedClock::at(NOW)))
}

#[test]
fn configuration_that_could_never_verify_or_is_ambiguous_is_refused() {
    let es_user = setup(SigningAlgorithm::Es256, Kind::User);
    let es_workload = setup(SigningAlgorithm::Es256, Kind::Workload);
    let rs_user = setup(SigningAlgorithm::Rs256, Kind::User);
    let name: gateway_core::Issuer = es_user.issuer.issuer().into();
    let table: Vec<(&str, IssuerConfig, ConfigError)> =
        vec![
            (
                "an empty issuer name",
                {
                    let mut config = es_user.config();
                    config.issuer = "".into();
                    config
                },
                ConfigError::EmptyIssuer,
            ),
            (
                "no audience",
                {
                    let mut config = es_user.config();
                    config.audiences.clear();
                    config
                },
                ConfigError::NoAudience(name.clone()),
            ),
            (
                "an empty audience",
                {
                    let mut config = es_user.config();
                    config.audiences = ["".to_owned()].into();
                    config
                },
                ConfigError::NoAudience(name.clone()),
            ),
            (
                "a zero lifetime ceiling",
                {
                    let mut config = es_user.config();
                    config.max_lifetime = Duration::from_millis(900);
                    config
                },
                ConfigError::NoLifetime(name.clone()),
            ),
            (
                "a workload issuer with no subjects",
                {
                    let mut config = es_workload.config();
                    config.kind = IssuerKind::Workload {
                        subjects: Default::default(),
                    };
                    config.issuer = name.clone();
                    config
                },
                ConfigError::NoSubjects(name.clone()),
            ),
            (
                "an empty groups claim name",
                {
                    let mut config = es_user.config();
                    config.kind = IssuerKind::User {
                        groups_claim: String::new(),
                    };
                    config
                },
                ConfigError::EmptyGroupsClaim(name.clone()),
            ),
            (
                "no keys",
                {
                    let mut config = es_user.config();
                    config.keys.keys.clear();
                    config
                },
                ConfigError::NoKeys(name.clone()),
            ),
            (
                "a key with no kid",
                {
                    let mut config = es_user.config();
                    config.keys.keys[0].common.key_id = None;
                    config
                },
                ConfigError::KeyWithoutId(name.clone()),
            ),
            (
                "two keys with one kid",
                {
                    let mut config = es_user.config();
                    let again = config.keys.keys[0].clone();
                    config.keys.keys.push(again);
                    config
                },
                ConfigError::DuplicateKeyId {
                    issuer: name.clone(),
                    kid: es_user.issuer.key_id().to_owned(),
                },
            ),
            (
                "an RSA key for an ES256 issuer",
                {
                    let mut config = es_user.config();
                    config.keys = rs_user.issuer.jwk_set();
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: rs_user.issuer.key_id().to_owned(),
                    algorithm: "ES256",
                },
            ),
            (
                "an EC key for an RS256 issuer",
                {
                    let mut config = rs_user.config();
                    config.keys = es_user.issuer.jwk_set();
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: rs_user.issuer.issuer().into(),
                    kid: es_user.issuer.key_id().to_owned(),
                    algorithm: "RS256",
                },
            ),
            (
                "a P-384 key for an ES256 issuer",
                {
                    let mut config = es_user.config();
                    config.keys.keys = vec![
                        serde_json::from_value(json!({
                            "kty": "EC", "crv": "P-384", "kid": "p384",
                            "x": "A".repeat(64), "y": "A".repeat(64),
                        }))
                        .unwrap(),
                    ];
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: "p384".into(),
                    algorithm: "ES256",
                },
            ),
            (
                "a key that says it is for another algorithm",
                {
                    let mut config = es_user.config();
                    config.keys.keys[0].common.key_algorithm =
                        Some(jsonwebtoken::jwk::KeyAlgorithm::ES384);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: es_user.issuer.key_id().to_owned(),
                    algorithm: "ES256",
                },
            ),
            (
                "a key that says it is for encryption",
                {
                    let mut config = es_user.config();
                    config.keys.keys[0].common.public_key_use =
                        Some(jsonwebtoken::jwk::PublicKeyUse::Encryption);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: es_user.issuer.key_id().to_owned(),
                    algorithm: "ES256",
                },
            ),
            (
                "a key that is not a key",
                {
                    let mut config = es_user.config();
                    config.keys.keys =
                        vec![serde_json::from_value(json!({
                "kty": "EC", "crv": "P-256", "kid": "bad-base64", "x": "!!", "y": "!!",
            })).unwrap()];
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: "bad-base64".into(),
                    algorithm: "ES256",
                },
            ),
        ];
    for (what, config, expected) in table {
        assert_eq!(build(vec![config]).unwrap_err(), expected, "{what}");
    }
}

#[test]
fn a_list_of_issuers_must_be_non_empty_and_name_each_issuer_once() {
    assert_eq!(build(vec![]).unwrap_err(), ConfigError::NoIssuers);
    let config = setup(SigningAlgorithm::Es256, Kind::User).config();
    let twice = build(vec![config.clone(), config.clone()]).unwrap_err();
    assert_eq!(twice, ConfigError::DuplicateIssuer(config.issuer.clone()));
    // The same issuer name configured twice is refused even if the entries differ, because a
    // token would match both.
    let mut different = config.clone();
    different.audiences = ["another".to_owned()].into();
    assert_eq!(
        build(vec![config.clone(), different]).unwrap_err(),
        ConfigError::DuplicateIssuer(config.issuer)
    );
}

#[test]
fn a_user_and_a_workload_issuer_can_be_configured_together() {
    let user = setup(SigningAlgorithm::Es256, Kind::User);
    let workload = setup(SigningAlgorithm::Rs256, Kind::Workload);
    let verifier = build(vec![user.config(), workload.config()]).unwrap();
    for setup in [user, workload] {
        let proved =
            gateway_core::Proved::verify(&verifier, setup.token().build().as_str()).unwrap();
        assert_eq!(proved.get(), &setup.principal());
    }
}

#[test]
fn checking_is_off_only_when_configuration_says_so() {
    let setup = setup(SigningAlgorithm::Es256, Kind::Workload);
    let clock = || Arc::new(FixedClock::at(NOW));
    let valid = setup.token().build();
    let garbage = "definitely not a token";

    let enforcing = Identity::new(IdentityConfig::Enforce(vec![setup.config()]), clock()).unwrap();
    let proved = enforcing.check(Some(&valid));
    assert_eq!(proved.state(), VerificationState::Proved);
    assert!(
        matches!(&proved, Verification::Proved(principal) if principal.get() == &setup.principal())
    );
    for presented in [Some(garbage), Some(""), None] {
        match enforcing.check(presented) {
            Verification::Failed(failure) => {
                assert_eq!(failure.to_string(), IDENTITY_FAILURE);
                if presented.is_none() {
                    assert_eq!(failure.detail(), &VerifyError::MissingToken);
                }
            }
            other => panic!("checking was on and {presented:?} gave {other:?}"),
        }
    }

    let disabled = Identity::new(IdentityConfig::Disabled, clock()).unwrap();
    for presented in [Some(valid.as_str()), Some(garbage), None] {
        let verification = disabled.check(presented);
        assert!(
            matches!(verification, Verification::Disabled),
            "{verification:?}"
        );
        assert_eq!(verification.state(), VerificationState::Disabled);
    }
}

#[test]
fn enforcement_with_no_issuer_does_not_start_and_is_not_disabled_by_accident() {
    let clock = Arc::new(FixedClock::at(NOW));
    assert_eq!(
        Identity::new(IdentityConfig::Enforce(vec![]), clock).unwrap_err(),
        ConfigError::NoIssuers
    );
}

#[test]
fn the_three_states_have_the_names_a_record_uses() {
    let names: Vec<_> = [
        VerificationState::Proved,
        VerificationState::Disabled,
        VerificationState::Failed,
    ]
    .iter()
    .map(|state| (state.as_str(), state.to_string()))
    .collect();
    assert_eq!(
        names,
        [
            ("proved", "proved".to_owned()),
            ("disabled", "disabled".to_owned()),
            ("failed", "failed".to_owned())
        ]
    );
}

/// The verifier reads the clock it was handed, so a token's validity moves with that clock and
/// with nothing else.
#[test]
fn validity_follows_the_injected_clock() {
    let setup = setup(SigningAlgorithm::Es256, Kind::Workload);
    let clock = SteppableClock::at(NOW);
    let verifier = TokenVerifier::new(vec![setup.config()], Arc::new(clock.clone())).unwrap();
    let check = |token: &str| {
        verifier
            .verify(token)
            .map(|_| ())
            .map_err(|failure| failure.detail().clone())
    };

    // Issued now, lives 600 seconds, with 30 seconds of leeway after that.
    let token = setup.token().build();
    assert_eq!(check(&token), Ok(()));
    clock.advance(Duration::from_secs(600 + LEEWAY - 1));
    assert_eq!(check(&token), Ok(()));
    clock.advance(Duration::from_secs(1));
    assert_eq!(check(&token), Err(VerifyError::Expired));

    // A token issued ten minutes from now is not yet valid, and then it is.
    clock.set(NOW);
    let later = setup
        .token()
        .issued_at(NOW + 600)
        .not_before(NOW + 600)
        .expires_at(NOW + 1200)
        .build();
    assert_eq!(check(&later), Err(VerifyError::NotYetValid));
    clock.set(NOW + 600 - LEEWAY);
    assert_eq!(check(&later), Ok(()));

    // Going back before the epoch is not a way in.
    clock.set(0);
    assert_eq!(check(&later), Err(VerifyError::NotYetValid));
}

/// Design section 7: an unknown subject pays for the signature check before it is refused, so
/// a wrong guess costs the same as a right one. The cost cannot be measured here, but the
/// order can: a token that is wrong in two ways reports the signature, never the subject, so
/// the subject table is not consulted until the signature has verified. The ordering lives in
/// `TokenVerifier::verify_token` and is commented there; this is the test that holds it.
#[test]
fn an_unknown_subject_is_refused_only_after_its_signature_is_checked() {
    for setup in setups()
        .into_iter()
        .filter(|setup| setup.kind == Kind::Workload)
    {
        let verifier = setup.verifier();
        let report = |token: String| {
            verifier
                .verify(&token)
                .map(|_| ())
                .map_err(|failure| failure.detail().clone())
        };
        let unknown = "system:serviceaccount:nobody:nothing";
        assert_eq!(
            report(
                setup
                    .token()
                    .subject(unknown)
                    .signed_by(setup.other)
                    .build()
            ),
            Err(VerifyError::BadSignature),
            "{setup:?}: an unknown subject with a bad signature"
        );
        assert_eq!(
            report(setup.token().subject(unknown).corrupt_signature().build()),
            Err(VerifyError::BadSignature),
            "{setup:?}"
        );
        assert_eq!(
            report(setup.token().subject(unknown).build()),
            Err(VerifyError::UnknownSubject),
            "{setup:?}: an unknown subject with a good signature"
        );
        assert_eq!(
            report(setup.token().build()),
            Ok(()),
            "{setup:?}: a known subject"
        );
    }
}
