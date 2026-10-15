//! Each refusal of grant-key configuration (decision 0012, Keys), and what a good one holds.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::*;
use gateway_otto::minter::{TestMinter, public_key_pem, small_order_key};
use gateway_otto::{GrantKeys, IssuerConfig, KeyConfigError, PreviousKeyConfig};

fn refused(config: Vec<IssuerConfig>) -> KeyConfigError {
    GrantKeys::new(&config).unwrap_err()
}

fn with_key(name: &str, key: String) -> IssuerConfig {
    let mut config = issuer(name, &TestMinter::generate());
    config.current_key = key;
    config
}

fn with_previous(name: &str, current: &TestMinter, previous: String, end: bool) -> IssuerConfig {
    let mut config = issuer(name, current);
    config.previous_key = Some(PreviousKeyConfig {
        key: previous,
        retires_at: end.then(|| at(NOW + 120)),
    });
    config
}

#[test]
fn a_good_configuration_lists_its_keys() {
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let qa = TestMinter::generate();
    let keys = GrantKeys::new(&[
        with_previous("otto-prod", &current, previous.public_key_pem(), true),
        issuer("otto-qa", &qa),
    ])
    .unwrap();
    let mut listed: Vec<_> = keys
        .key_ids()
        .map(|(id, issuer, retires)| (id.clone(), issuer.as_str().to_owned(), retires))
        .collect();
    listed.sort();
    let mut expected = vec![
        (current.key_id(), "otto-prod".to_owned(), None),
        (
            previous.key_id(),
            "otto-prod".to_owned(),
            Some(at(NOW + 120)),
        ),
        (qa.key_id(), "otto-qa".to_owned(), None),
    ];
    expected.sort();
    assert_eq!(listed, expected);
}

#[test]
fn no_issuers_is_refused() {
    assert_eq!(refused(vec![]), KeyConfigError::NoIssuers);
}

#[test]
fn an_issuer_needs_one_unique_name() {
    assert_eq!(
        refused(vec![issuer("", &TestMinter::generate())]),
        KeyConfigError::EmptyIssuerName
    );
    assert_eq!(
        refused(vec![
            issuer("otto-prod", &TestMinter::generate()),
            issuer("otto-prod", &TestMinter::generate()),
        ]),
        KeyConfigError::DuplicateIssuer("otto-prod".to_owned())
    );
}

#[test]
fn private_key_material_is_refused() {
    let minter = TestMinter::generate();
    let private = minter.private_key_pem();
    let expected = KeyConfigError::PrivateKeyMaterial("otto-prod".to_owned());
    assert_eq!(
        refused(vec![with_key("otto-prod", private.clone())]),
        expected
    );
    // Beside the public key in the same file.
    let both = format!("{}{private}", minter.public_key_pem());
    assert_eq!(refused(vec![with_key("otto-prod", both)]), expected);
    // In the previous key's file.
    assert_eq!(
        refused(vec![with_previous(
            "otto-prod",
            &TestMinter::generate(),
            private.clone(),
            true
        )]),
        expected
    );
    // Other private key formats, named by their armour.
    for kind in [
        "ENCRYPTED PRIVATE",
        "OPENSSH PRIVATE",
        "EC PRIVATE",
        "RSA PRIVATE",
    ] {
        let armour = format!("-----BEGIN {kind} KEY-----\nAAAA\n-----END {kind} KEY-----\n");
        assert_eq!(
            refused(vec![with_key("otto-prod", armour)]),
            expected,
            "{kind}"
        );
    }
    // Private key DER under a public label.
    let body: String = private
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let relabelled = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");
    assert_eq!(refused(vec![with_key("otto-prod", relabelled)]), expected);
}

#[test]
fn anything_but_one_ed25519_public_key_in_pem_is_refused() {
    let expected = KeyConfigError::NotAPublicKey("otto-prod".to_owned());
    let good = TestMinter::generate().public_key_pem();
    let body: String = good
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    // An RSA SubjectPublicKeyInfo's opening bytes, an X25519 key's algorithm, a truncated key.
    let x25519 = good.replace(&body, &{
        use base64::Engine;
        let mut der = base64::engine::general_purpose::STANDARD
            .decode(&body)
            .unwrap();
        der[8] = 0x6e;
        base64::engine::general_purpose::STANDARD.encode(der)
    });
    for text in [
        String::new(),
        "not a key".to_owned(),
        body.clone(),
        good.replace("PUBLIC KEY", "CERTIFICATE"),
        format!("{good}{good}"),
        good.replace(&body, "!!!!"),
        good.replace(&body, "MCowBQYDK2VwAyEA"),
        good.replace(&body, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
        x25519,
    ] {
        assert_eq!(
            refused(vec![with_key("otto-prod", text.clone())]),
            expected,
            "{text}"
        );
    }
    // Surrounding whitespace and wrapped lines are fine.
    GrantKeys::new(&[with_key("otto-prod", format!("\n  {good}\n"))]).unwrap();
}

#[test]
fn a_key_that_is_not_a_canonical_point_is_refused() {
    // A y-coordinate written as itself plus the field prime p = 2^255 − 19, for a small y that
    // is on the curve and not of small order: the same point as y, encoded a second way.
    let non_canonical = (2u8..19)
        .filter_map(|y| {
            let mut bytes = [0xff; 32];
            bytes[0] = 0xed + y;
            bytes[31] = 0x7f;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?;
            (!key.is_weak()).then_some(bytes)
        })
        .next()
        .expect("a non-canonical encoding of a point of large order");
    assert_eq!(
        refused(vec![with_key("otto-prod", public_key_pem(&non_canonical))]),
        KeyConfigError::NotAPublicKey("otto-prod".to_owned())
    );
}

#[test]
fn a_small_order_key_is_refused() {
    assert_eq!(
        refused(vec![with_key(
            "otto-prod",
            public_key_pem(&small_order_key())
        )]),
        KeyConfigError::SmallOrderKey("otto-prod".to_owned())
    );
    // Each point of order 2, 4 or 8 that has a canonical encoding.
    for y_bytes in [
        // y = −1, order 2.
        {
            let mut bytes = [0xff; 32];
            bytes[0] = 0xec;
            bytes[31] = 0x7f;
            bytes
        },
        // y = 0, order 4.
        [0; 32],
    ] {
        assert_eq!(
            refused(vec![with_key("otto-prod", public_key_pem(&y_bytes))]),
            KeyConfigError::SmallOrderKey("otto-prod".to_owned())
        );
    }
    // As the previous key too.
    assert_eq!(
        refused(vec![with_previous(
            "otto-prod",
            &TestMinter::generate(),
            public_key_pem(&small_order_key()),
            true
        )]),
        KeyConfigError::SmallOrderKey("otto-prod".to_owned())
    );
}

#[test]
fn the_same_key_twice_is_refused() {
    let minter = TestMinter::generate();
    assert_eq!(
        refused(vec![with_previous(
            "otto-prod",
            &minter,
            minter.public_key_pem(),
            true
        )]),
        KeyConfigError::KeyRepeated("otto-prod".to_owned())
    );
}

#[test]
fn one_key_under_two_issuers_is_refused() {
    let minter = TestMinter::generate();
    assert_eq!(
        refused(vec![
            issuer("otto-prod", &minter),
            issuer("otto-qa", &minter)
        ]),
        KeyConfigError::KeyUnderTwoIssuers {
            key_id: minter.key_id(),
            first: "otto-prod".to_owned(),
            second: "otto-qa".to_owned(),
        }
    );
    // As one issuer's previous key and another's current key.
    let current = TestMinter::generate();
    assert_eq!(
        refused(vec![
            issuer("otto-qa", &minter),
            with_previous("otto-prod", &current, minter.public_key_pem(), true),
        ]),
        KeyConfigError::KeyUnderTwoIssuers {
            key_id: minter.key_id(),
            first: "otto-qa".to_owned(),
            second: "otto-prod".to_owned(),
        }
    );
}

#[test]
fn a_previous_key_without_an_end_instant_is_refused() {
    assert_eq!(
        refused(vec![with_previous(
            "otto-prod",
            &TestMinter::generate(),
            TestMinter::generate().public_key_pem(),
            false
        )]),
        KeyConfigError::PreviousKeyWithoutEnd("otto-prod".to_owned())
    );
}

#[test]
fn a_previous_key_already_retired_is_configured_and_refused_on_use() {
    // A previous key past its end instant is left in configuration until a change removes it;
    // that does not stop the gateway starting.
    let current = TestMinter::generate();
    let previous = TestMinter::generate();
    let verifier = rotating_verifier(&current, &previous, at(NOW - 3600));
    refused_as(
        &verifier,
        &previous.mint(&claims()),
        gateway_otto::FailureKind::RetiredKey,
        false,
    );
}
