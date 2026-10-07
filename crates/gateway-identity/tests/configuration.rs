//! What a deployment may and may not configure, the three verification states, and a verifier
//! reading the clock it was given.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_core::{IDENTITY_FAILURE, Principal, Verifier};
use gateway_identity::{
    ConfigError, Identity, IdentityConfig, IssuerConfig, IssuerKind, MAX_LEEWAY, MIN_RSA_BITS,
    SigningAlgorithm, TokenVerifier, Verification, VerificationState, VerifyError,
};
use gateway_testkit::{FixedClock, SteppableClock};
use jsonwebtoken::jwk::{Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse};
use serde_json::json;

use common::{AUDIENCE, Kind, LEEWAY, NOW, Setup, setups};

fn setup(algorithm: SigningAlgorithm, kind: Kind) -> Setup {
    setups()
        .into_iter()
        .find(|setup| setup.algorithm == algorithm && setup.kind == kind)
        .unwrap()
}

fn build(configs: Vec<IssuerConfig>) -> Result<TokenVerifier, ConfigError> {
    TokenVerifier::new(configs, Arc::new(FixedClock::at(NOW)))
}

fn verify(verifier: &TokenVerifier, token: &str) -> Result<Principal, VerifyError> {
    verifier
        .verify(token)
        .map_err(|failure| failure.detail().clone())
}

/// An RSA modulus of `bytes` bytes whose first byte is `top` and the rest all ones.
fn modulus(top: u8, bytes: usize) -> Vec<u8> {
    let mut modulus = vec![0xff; bytes];
    modulus[0] = top;
    modulus
}

/// An RSA public key with this modulus and an exponent of 65537, as a JWK. Not half of any key
/// pair: configuration can only check a key's shape and length, and that is what these are for.
fn rsa_jwk(kid: &str, modulus: &[u8]) -> Jwk {
    rsa_jwk_with_exponent(kid, modulus, &[1, 0, 1])
}

/// An RSA public key with this modulus and exponent, as a JWK.
fn rsa_jwk_with_exponent(kid: &str, modulus: &[u8], exponent: &[u8]) -> Jwk {
    serde_json::from_value(json!({
        "kty": "RSA", "kid": kid, "n": URL_SAFE_NO_PAD.encode(modulus),
        "e": URL_SAFE_NO_PAD.encode(exponent),
    }))
    .unwrap()
}

/// `modulus(top, bytes)` with its last byte made even.
fn even_modulus(top: u8, bytes: usize) -> Vec<u8> {
    let mut modulus = modulus(top, bytes);
    *modulus.last_mut().unwrap() = 0xfe;
    modulus
}

/// `setup`'s issuer with one key, `key`.
fn with_only(setup: &Setup, key: Jwk) -> IssuerConfig {
    let mut config = setup.config();
    config.keys.keys = vec![key];
    config
}

#[test]
fn configuration_that_could_never_verify_or_is_ambiguous_is_refused() {
    let es_user = setup(SigningAlgorithm::Es256, Kind::User);
    let es_workload = setup(SigningAlgorithm::Es256, Kind::Workload);
    let rs_user = setup(SigningAlgorithm::Rs256, Kind::User);
    let name: gateway_core::Issuer = es_user.issuer.issuer().into();
    let rs_name: gateway_core::Issuer = rs_user.issuer.issuer().into();
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
                "a leeway a second over the maximum",
                {
                    let mut config = es_user.config();
                    config.leeway = MAX_LEEWAY + Duration::from_secs(1);
                    config
                },
                ConfigError::LeewayTooLarge(name.clone()),
            ),
            (
                "a leeway as long as the lifetime ceiling",
                {
                    let mut config = es_user.config();
                    config.leeway = config.max_lifetime;
                    config
                },
                ConfigError::LeewayTooLarge(name.clone()),
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
            (
                "a 512-bit RSA key",
                with_only(&rs_user, rsa_jwk("short", &modulus(0xff, 64))),
                ConfigError::WeakKey {
                    issuer: rs_name.clone(),
                    kid: "short".into(),
                    bits: 512,
                },
            ),
            (
                "an RSA key one bit short",
                with_only(&rs_user, rsa_jwk("short", &modulus(0x7f, 256))),
                ConfigError::WeakKey {
                    issuer: rs_name.clone(),
                    kid: "short".into(),
                    bits: 2047,
                },
            ),
            (
                "an RSA key a byte short, written with a leading zero byte",
                with_only(
                    &rs_user,
                    rsa_jwk("short", &[&[0][..], &modulus(0xff, 255)].concat()),
                ),
                ConfigError::WeakKey {
                    issuer: rs_name.clone(),
                    kid: "short".into(),
                    bits: 2040,
                },
            ),
            (
                "an RSA key whose modulus is zero",
                with_only(&rs_user, rsa_jwk("zero", &[0; 256])),
                ConfigError::KeyDoesNotFit {
                    issuer: rs_name.clone(),
                    kid: "zero".into(),
                    algorithm: "RS256",
                },
            ),
            (
                "an RSA key a bit over 4096 bits",
                with_only(&rs_user, rsa_jwk("long", &modulus(0x01, 513))),
                ConfigError::UnusableRsaKey {
                    issuer: rs_name.clone(),
                    kid: "long".into(),
                    reason: "modulus too large".into(),
                },
            ),
            (
                "an RSA key whose modulus is even",
                with_only(&rs_user, rsa_jwk("even", &even_modulus(0xff, 256))),
                ConfigError::UnusableRsaKey {
                    issuer: rs_name.clone(),
                    kid: "even".into(),
                    reason: "invalid modulus".into(),
                },
            ),
            (
                "an RSA key whose exponent is 2^33 + 1",
                with_only(
                    &rs_user,
                    rsa_jwk_with_exponent("big-e", &modulus(0xff, 256), &[2, 0, 0, 0, 1]),
                ),
                ConfigError::UnusableRsaKey {
                    issuer: rs_name.clone(),
                    kid: "big-e".into(),
                    reason: "public exponent too large".into(),
                },
            ),
            (
                "an RSA key whose exponent is 1",
                with_only(
                    &rs_user,
                    rsa_jwk_with_exponent("small-e", &modulus(0xff, 256), &[1]),
                ),
                ConfigError::UnusableRsaKey {
                    issuer: rs_name.clone(),
                    kid: "small-e".into(),
                    reason: "public exponent too small".into(),
                },
            ),
            (
                "an RSA key whose exponent is even",
                with_only(
                    &rs_user,
                    rsa_jwk_with_exponent("even-e", &modulus(0xff, 256), &[1, 0, 0]),
                ),
                ConfigError::UnusableRsaKey {
                    issuer: rs_name.clone(),
                    kid: "even-e".into(),
                    reason: "invalid exponent".into(),
                },
            ),
            (
                "an RSA key that says it is for another algorithm",
                {
                    let mut config = rs_user.config();
                    config.keys.keys[0].common.key_algorithm = Some(KeyAlgorithm::RS512);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: rs_name.clone(),
                    kid: rs_user.issuer.key_id().to_owned(),
                    algorithm: "RS256",
                },
            ),
            (
                "an RSA key that says it is for encryption",
                {
                    let mut config = rs_user.config();
                    config.keys.keys[0].common.public_key_use = Some(PublicKeyUse::Encryption);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: rs_name.clone(),
                    kid: rs_user.issuer.key_id().to_owned(),
                    algorithm: "RS256",
                },
            ),
            (
                "a key whose operations are for encryption",
                {
                    let mut config = es_user.config();
                    config.keys.keys[0].common.key_operations =
                        Some(vec![KeyOperations::Encrypt, KeyOperations::WrapKey]);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: name.clone(),
                    kid: es_user.issuer.key_id().to_owned(),
                    algorithm: "ES256",
                },
            ),
            (
                "a key listed only for signing",
                {
                    let mut config = rs_user.config();
                    config.keys.keys[0].common.key_operations = Some(vec![KeyOperations::Sign]);
                    config
                },
                ConfigError::KeyDoesNotFit {
                    issuer: rs_name.clone(),
                    kid: rs_user.issuer.key_id().to_owned(),
                    algorithm: "RS256",
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

/// Decision 0006: group names are not qualified by issuer, so a group name used by two user
/// issuers would admit the members of both. Until that is settled, a deployment has at most
/// one user issuer, however many workload issuers it has.
#[test]
fn a_deployment_has_at_most_one_user_issuer() {
    let es_user = setup(SigningAlgorithm::Es256, Kind::User);
    let rs_user = setup(SigningAlgorithm::Rs256, Kind::User);
    // A workload issuer with a name of its own: the one the RSA setups keep as "other".
    let rs_workload = setup(SigningAlgorithm::Rs256, Kind::Workload);
    let other_workload = rs_workload
        .other
        .config(rs_workload.issuer_kind(), &[AUDIENCE]);
    let refused = ConfigError::SecondUserIssuer {
        first: es_user.issuer.issuer().into(),
        second: rs_user.issuer.issuer().into(),
    };
    assert_eq!(
        build(vec![es_user.config(), rs_user.config()]).unwrap_err(),
        refused
    );
    assert_eq!(
        build(vec![
            es_user.config(),
            other_workload.clone(),
            rs_user.config()
        ])
        .unwrap_err(),
        refused
    );
    assert!(build(vec![es_user.config(), other_workload]).is_ok());
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

/// The leeway may be up to [`MAX_LEEWAY`], which is five minutes, and no more.
#[test]
fn leeway_is_at_most_five_minutes() {
    assert_eq!(MAX_LEEWAY, Duration::from_secs(300));
    let setup = setup(SigningAlgorithm::Es256, Kind::Workload);
    let mut config = setup.config();
    config.leeway = MAX_LEEWAY;
    let verifier = build(vec![config.clone()]).unwrap();
    // The whole of it applies: a token that expired just inside it is accepted.
    let expired = setup
        .token()
        .issued_at(NOW - 600)
        .expires_at(NOW - MAX_LEEWAY.as_secs() + 1)
        .build();
    assert_eq!(verify(&verifier, &expired), Ok(setup.principal()));
    config.leeway = MAX_LEEWAY + Duration::from_millis(1);
    assert_eq!(
        build(vec![config]).unwrap_err(),
        ConfigError::LeewayTooLarge(setup.issuer.issuer().into())
    );
}

/// An RSA key of exactly [`MIN_RSA_BITS`] is accepted, counted in bits and not in bytes, and a
/// leading zero byte in its modulus is not counted.
#[test]
fn an_rsa_key_of_2048_bits_is_accepted() {
    assert_eq!(MIN_RSA_BITS, 2048);
    let setup = setup(SigningAlgorithm::Rs256, Kind::Workload);
    for modulus in [
        modulus(0x80, 256),
        [&[0][..], &modulus(0x80, 256)].concat(),
        modulus(0xff, 512),
    ] {
        assert!(build(vec![with_only(&setup, rsa_jwk("long", &modulus))]).is_ok());
    }
}

/// An RSA key is accepted up to the limits the crypto backend checks when it verifies: a
/// modulus of 4096 bits, and an exponent from 3 to 2^33 - 1. Outside them it is refused as
/// configuration (`configuration_that_could_never_verify_or_is_ambiguous_is_refused`), not
/// left to fail every token as a bad signature.
#[test]
fn an_rsa_key_is_accepted_up_to_the_backends_limits() {
    let setup = setup(SigningAlgorithm::Rs256, Kind::Workload);
    for (modulus, exponent) in [
        (modulus(0xff, 512), vec![1, 0, 1]),
        (modulus(0xff, 256), vec![3]),
        (modulus(0xff, 256), vec![1, 0xff, 0xff, 0xff, 0xff]),
    ] {
        let key = rsa_jwk_with_exponent("edge", &modulus, &exponent);
        assert!(
            build(vec![with_only(&setup, key)]).is_ok(),
            "{} bytes, exponent {exponent:?}",
            modulus.len()
        );
    }
    // A key the backend refuses is left out like any other, so a token naming it is refused as
    // naming an unknown key, and never reaches the backend.
    let mut config = setup.config();
    config
        .keys
        .keys
        .insert(0, rsa_jwk("long", &modulus(0x01, 513)));
    let verifier = build(vec![config]).unwrap();
    assert_eq!(
        verify(&verifier, &setup.token().build()),
        Ok(setup.principal())
    );
    assert_eq!(
        verify(&verifier, &setup.token().kid("long").build()),
        Err(VerifyError::UnknownKeyId)
    );
}

/// A key may list the operations it is for, as long as verifying is one of them.
#[test]
fn a_key_listing_verify_among_its_operations_is_used() {
    for setup in setups() {
        for operations in [
            vec![KeyOperations::Verify],
            vec![KeyOperations::Sign, KeyOperations::Verify],
        ] {
            let mut config = setup.config();
            config.keys.keys[0].common.key_operations = Some(operations);
            let verifier = build(vec![config]).unwrap();
            assert_eq!(
                verify(&verifier, &setup.token().build()),
                Ok(setup.principal()),
                "{setup:?}"
            );
        }
    }
}

/// An identity provider's key set can hold keys that are not for this issuer's signatures,
/// such as an encryption key, or an old short key it still publishes. Those are left out and
/// the rest verify. A token naming a key that was left out is refused as naming an unknown key,
/// even when it was signed by that key.
#[test]
fn keys_that_cannot_verify_are_left_out_and_the_rest_are_used() {
    let es = setup(SigningAlgorithm::Es256, Kind::Workload);
    let rs = setup(SigningAlgorithm::Rs256, Kind::Workload);

    let mut encryption = es.other.jwk_set().keys[0].clone();
    encryption.common.key_id = Some("encryption".into());
    encryption.common.public_key_use = Some(PublicKeyUse::Encryption);
    let mut config = es.config();
    config.keys.keys = vec![
        encryption,
        rs.issuer.jwk_set().keys[0].clone(),
        es.issuer.jwk_set().keys[0].clone(),
    ];
    let verifier = build(vec![config]).unwrap();
    assert_eq!(verify(&verifier, &es.token().build()), Ok(es.principal()));
    let under_encryption_key = es.token().signed_by(es.other).kid("encryption").build();
    assert_eq!(
        verify(&verifier, &under_encryption_key),
        Err(VerifyError::UnknownKeyId)
    );
    assert_eq!(
        verify(&verifier, &es.token().kid(rs.issuer.key_id()).build()),
        Err(VerifyError::UnknownKeyId)
    );

    let mut config = rs.config();
    config
        .keys
        .keys
        .insert(0, rsa_jwk("short", &modulus(0xff, 128)));
    let verifier = build(vec![config]).unwrap();
    assert_eq!(verify(&verifier, &rs.token().build()), Ok(rs.principal()));
    assert_eq!(
        verify(&verifier, &rs.token().kid("short").build()),
        Err(VerifyError::UnknownKeyId)
    );
}

/// An issuer none of whose keys can verify is refused, naming the first key and why.
#[test]
fn an_issuer_with_no_key_that_can_verify_is_refused_with_the_first() {
    let es = setup(SigningAlgorithm::Es256, Kind::Workload);
    let rs = setup(SigningAlgorithm::Rs256, Kind::Workload);
    let short = rsa_jwk("short", &modulus(0xff, 128));
    let ec = es.issuer.jwk_set().keys[0].clone();
    let mut config = rs.config();
    config.keys.keys = vec![short.clone(), ec.clone()];
    assert_eq!(
        build(vec![config.clone()]).unwrap_err(),
        ConfigError::WeakKey {
            issuer: rs.issuer.issuer().into(),
            kid: "short".into(),
            bits: 1024,
        }
    );
    config.keys.keys = vec![ec, short];
    assert_eq!(
        build(vec![config]).unwrap_err(),
        ConfigError::KeyDoesNotFit {
            issuer: rs.issuer.issuer().into(),
            kid: es.issuer.key_id().to_owned(),
            algorithm: "RS256",
        }
    );
}

/// A `kid` names one key in the set, counting the keys that are left out, so a token's `kid`
/// can never mean two keys.
#[test]
fn a_kid_is_unique_among_all_of_an_issuers_keys() {
    let es = setup(SigningAlgorithm::Es256, Kind::Workload);
    let mut twin = es.other.jwk_set().keys[0].clone();
    twin.common.key_id = Some(es.issuer.key_id().to_owned());
    twin.common.public_key_use = Some(PublicKeyUse::Encryption);
    let mut config = es.config();
    config.keys.keys.push(twin);
    assert_eq!(
        build(vec![config]).unwrap_err(),
        ConfigError::DuplicateKeyId {
            issuer: es.issuer.issuer().into(),
            kid: es.issuer.key_id().to_owned(),
        }
    );
}

/// Rotation: while an issuer's set holds the old key and the new one, a token under either
/// verifies, chosen by its `kid`; once the old key is removed, its tokens are refused.
#[test]
fn keys_rotate_by_kid() {
    for setup in setups()
        .into_iter()
        .filter(|setup| setup.kind == Kind::Workload)
    {
        let (old, new) = (setup.issuer, setup.other);
        let under_old = setup.token().build();
        let under_new = setup.token().signed_by(new).kid(new.key_id()).build();

        let mut both = setup.config();
        both.keys.keys.extend(new.jwk_set().keys);
        let verifier = build(vec![both]).unwrap();
        assert_eq!(
            verify(&verifier, &under_old),
            Ok(setup.principal()),
            "{setup:?}"
        );
        assert_eq!(
            verify(&verifier, &under_new),
            Ok(setup.principal()),
            "{setup:?}"
        );
        // The kid chooses the key: the new key's signature under the old key's kid fails.
        let mislabelled = setup.token().signed_by(new).kid(old.key_id()).build();
        assert_eq!(
            verify(&verifier, &mislabelled),
            Err(VerifyError::BadSignature),
            "{setup:?}"
        );

        let mut new_only = setup.config();
        new_only.keys = new.jwk_set();
        let verifier = build(vec![new_only]).unwrap();
        assert_eq!(
            verify(&verifier, &under_new),
            Ok(setup.principal()),
            "{setup:?}"
        );
        assert_eq!(
            verify(&verifier, &under_old),
            Err(VerifyError::UnknownKeyId),
            "{setup:?}"
        );
    }
}
