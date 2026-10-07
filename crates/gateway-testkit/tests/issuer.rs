//! The local issuer makes the tokens it is told to, and no key it makes is ever written down.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_core::Verifier;
use gateway_identity::{IssuerKind, SigningAlgorithm, TokenVerifier, VerifyError};
use gateway_testkit::{
    DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME, DEFAULT_TOKEN_LIFETIME, FIXTURE_NOW, FixedClock,
    LocalIssuer,
};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm, PublicKeyUse};
use serde_json::{Value, json};

static RSA: LazyLock<LocalIssuer> =
    LazyLock::new(|| LocalIssuer::new("https://rsa.test", SigningAlgorithm::Rs256).unwrap());
static EC: LazyLock<LocalIssuer> =
    LazyLock::new(|| LocalIssuer::new("https://ec.test", SigningAlgorithm::Es256).unwrap());

fn now() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW)
}

fn issuers() -> [&'static LocalIssuer; 2] {
    [&RSA, &EC]
}

fn parts(token: &str) -> (Value, Value, String) {
    let pieces: Vec<&str> = token.split('.').collect();
    assert_eq!(pieces.len(), 3, "{token}");
    let json = |piece: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(piece).unwrap()).unwrap()
    };
    (json(pieces[0]), json(pieces[1]), pieces[2].to_owned())
}

#[test]
fn a_default_token_has_the_header_and_claims_the_verifier_needs() {
    for issuer in issuers() {
        let (header, claims, signature) =
            parts(&issuer.workload_token("sub-1", "aud-1", now()).build());
        assert_eq!(
            header,
            json!({"alg": issuer.algorithm().as_str(), "kid": issuer.key_id(), "typ": "JWT"})
        );
        assert_eq!(
            claims,
            json!({
                "iss": issuer.issuer(),
                "sub": "sub-1",
                "aud": "aud-1",
                "iat": FIXTURE_NOW,
                "nbf": FIXTURE_NOW,
                "exp": FIXTURE_NOW + DEFAULT_TOKEN_LIFETIME,
            })
        );
        assert!(!signature.is_empty());
    }
}

#[test]
fn a_user_token_carries_its_groups() {
    let (_, claims, _) = parts(&EC.user_token("u", "a", &["g1", "g2"], now()).build());
    assert_eq!(claims["groups"], json!(["g1", "g2"]));
}

#[test]
fn each_adjustment_changes_what_it_says_and_nothing_else() {
    let base = || EC.workload_token("sub-1", "aud-1", now());
    let (header, claims, _) = parts(&base().build());
    let claims_of = |token: String| parts(&token).1;
    let header_of = |token: String| parts(&token).0;
    let changed = |before: &Value, after: &Value| -> BTreeSet<String> {
        let (before, after) = (before.as_object().unwrap(), after.as_object().unwrap());
        before
            .keys()
            .chain(after.keys())
            .filter(|key| before.get(*key) != after.get(*key))
            .cloned()
            .collect()
    };
    let one = |names: &[&str]| {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>()
    };

    assert_eq!(
        changed(&claims, &claims_of(base().issuer("x").build())),
        one(&["iss"])
    );
    assert_eq!(claims_of(base().issuer("x").build())["iss"], "x");
    assert_eq!(claims_of(base().subject("y").build())["sub"], "y");
    assert_eq!(claims_of(base().audience("z").build())["aud"], "z");
    assert_eq!(
        claims_of(base().audiences(&["p", "q"]).build())["aud"],
        json!(["p", "q"])
    );
    assert_eq!(
        changed(&claims, &claims_of(base().issued_at(5).build())),
        one(&["iat"])
    );
    assert_eq!(claims_of(base().issued_at(5).build())["iat"], 5);
    assert_eq!(claims_of(base().not_before(6).build())["nbf"], 6);
    assert_eq!(claims_of(base().expires_at(7).build())["exp"], 7);
    assert_eq!(
        claims_of(base().lifetime(60).build())["exp"],
        FIXTURE_NOW + 60
    );
    assert_eq!(
        claims_of(base().issued_at(100).lifetime(60).build())["exp"],
        160
    );
    assert_eq!(
        changed(&claims, &claims_of(base().without_claim("nbf").build())),
        one(&["nbf"])
    );
    assert!(
        claims_of(base().without_claim("nbf").build())
            .get("nbf")
            .is_none()
    );
    assert_eq!(
        claims_of(base().claim("custom", json!([1])).build())["custom"],
        json!([1])
    );

    assert_eq!(header_of(base().alg("none").build())["alg"], "none");
    assert_eq!(header_of(base().kid("k").build())["kid"], "k");
    assert!(header_of(base().without_kid().build()).get("kid").is_none());
    assert_eq!(
        header_of(base().header("jku", json!("u")).build())["jku"],
        "u"
    );
    assert_eq!(
        changed(&header, &header_of(base().kid("k").build())),
        one(&["kid"])
    );
}

#[test]
fn signing_adjustments_change_the_signature_and_the_header_they_say_they_do() {
    let base = || EC.workload_token("sub-1", "aud-1", now());
    let (_, _, good) = parts(&base().build());

    let corrupted = parts(&base().corrupt_signature().build()).2;
    assert_ne!(corrupted, good);
    assert_eq!(corrupted.len(), good.len());
    assert_eq!(corrupted[1..], good[1..], "one character differs");

    let other = LocalIssuer::new("https://other.test", SigningAlgorithm::Es256).unwrap();
    let by_other = base().signed_by(&other).build();
    assert_ne!(parts(&by_other).2, good);
    assert_eq!(
        parts(&by_other).0["kid"],
        EC.key_id(),
        "the header still names this issuer's key"
    );

    let hmac = base().hmac_signed(b"secret").build();
    assert_eq!(parts(&hmac).0["alg"], "HS256");
    assert!(!parts(&hmac).2.is_empty());

    let unsigned = base().unsigned().build();
    assert_eq!(parts(&unsigned).0["alg"], "none");
    assert_eq!(parts(&unsigned).2, "");
    assert!(unsigned.ends_with('.'));
}

#[test]
fn the_jwk_set_publishes_the_public_half_only_and_says_what_it_is_for() {
    let rsa = RSA.jwk_set();
    assert_eq!(rsa.keys.len(), 1);
    let key = &rsa.keys[0];
    assert_eq!(key.common.key_id.as_deref(), Some(RSA.key_id()));
    assert_eq!(key.common.key_algorithm, Some(KeyAlgorithm::RS256));
    assert_eq!(key.common.public_key_use, Some(PublicKeyUse::Signature));
    assert!(matches!(key.algorithm, AlgorithmParameters::RSA(_)));

    let ec = EC.jwk_set();
    let key = &ec.keys[0];
    assert_eq!(key.common.key_algorithm, Some(KeyAlgorithm::ES256));
    match &key.algorithm {
        AlgorithmParameters::EllipticCurve(params) => assert_eq!(params.curve, EllipticCurve::P256),
        other => panic!("{other:?}"),
    }
    // Public parameters only: no private exponent, no `d`.
    let text = serde_json::to_string(&[rsa, ec]).unwrap();
    for private in ["\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\""] {
        assert!(!text.contains(private), "the JWK set holds {private}");
    }
}

/// The JWKS document is what an issuer serves at its `jwks_uri`. A verifier configured from the
/// document as fetched, and nothing else, verifies the issuer's tokens.
#[test]
fn the_jwks_document_is_the_issuers_key_set_and_verifies_its_tokens() {
    for issuer in issuers() {
        let document = issuer.jwks_document();
        let served: JwkSet = serde_json::from_str(&document).unwrap();
        assert_eq!(served, issuer.jwk_set());
        let document: Value = serde_json::from_str(&document).unwrap();
        assert_eq!(document["keys"][0]["kid"], issuer.key_id());

        let mut config = issuer.config(
            IssuerKind::Workload {
                subjects: [("sub-1".into(), "team-1".into())].into(),
            },
            &["aud-1"],
        );
        config.keys = served;
        let verifier =
            TokenVerifier::new(vec![config], Arc::new(FixedClock::at(FIXTURE_NOW))).unwrap();
        let token = issuer.workload_token("sub-1", "aud-1", now()).build();
        assert!(verifier.verify(&token).is_ok(), "{}", issuer.issuer());
    }
}

/// A corrupted signature differs from the good one in its first character only, for every
/// token, and never verifies.
#[test]
fn a_corrupted_signature_always_differs_and_never_verifies() {
    for issuer in issuers() {
        let config = issuer.config(
            IssuerKind::Workload {
                subjects: [("sub-1".into(), "team-1".into())].into(),
            },
            &["aud-1"],
        );
        let verifier =
            TokenVerifier::new(vec![config], Arc::new(FixedClock::at(FIXTURE_NOW))).unwrap();
        for n in 0..64 {
            let base = || {
                issuer
                    .workload_token("sub-1", "aud-1", now())
                    .claim("n", json!(n))
            };
            let good = parts(&base().build()).2;
            let token = base().corrupt_signature().build();
            let corrupted = parts(&token).2;
            assert_ne!(corrupted[..1], good[..1], "{n}");
            assert_eq!(corrupted[1..], good[1..], "{n}");
            assert_eq!(
                verifier.verify(&token).unwrap_err().detail(),
                &VerifyError::BadSignature,
                "{n}"
            );
        }
    }
}

#[test]
fn an_issuer_entry_trusts_the_issuers_own_key_and_nothing_else() {
    let config = EC.config(IssuerKind::user(), &["aud-1", "aud-2"]);
    assert_eq!(config.issuer.as_str(), "https://ec.test");
    assert_eq!(
        config
            .audiences
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["aud-1", "aud-2"]
    );
    assert_eq!(config.algorithm, SigningAlgorithm::Es256);
    assert_eq!(config.keys, EC.jwk_set());
    assert_eq!(
        config.max_lifetime,
        Duration::from_secs(DEFAULT_MAX_LIFETIME)
    );
    assert_eq!(config.leeway, Duration::from_secs(DEFAULT_LEEWAY));
}

#[test]
fn every_issuer_generates_its_own_keys() {
    let again = LocalIssuer::new("https://ec.test", SigningAlgorithm::Es256).unwrap();
    assert_ne!(again.key_id(), EC.key_id());
    assert_ne!(again.jwk_set(), EC.jwk_set());
    assert_ne!(RSA.key_id(), EC.key_id());
}

fn files_under(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == "target" || name == ".git")
            {
                continue;
            }
            files_under(&path, found);
        } else {
            found.push(path);
        }
    }
}

/// No key is checked in: nothing in the repository's source holds PEM private key armour or a
/// JWK private parameter, so every key a test uses was generated by the run that used it.
#[test]
fn no_private_key_is_checked_in() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    files_under(&root.join("crates"), &mut files);
    files_under(&root.join("conformance"), &mut files);
    // Built from parts so that this file does not contain what it looks for.
    let armour = format!("{} PRIVATE {}", "-----BEGIN", "KEY-----");
    let rsa_armour = format!("{} RSA PRIVATE {}", "-----BEGIN", "KEY-----");
    let mut searched = 0;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        searched += 1;
        for needle in [&armour, &rsa_armour] {
            assert!(
                !text.contains(needle.as_str()),
                "{} holds private key armour",
                file.display()
            );
        }
    }
    assert!(
        searched > 20,
        "only {searched} files were searched; the walk is not finding the sources"
    );
}
