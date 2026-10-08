//! What a refused token claimed: its issuer and subject, escaped and capped, kept beside the
//! failure for the identity-failure event (decision 0009). The cause, the sentence the caller
//! reads and the failure's `Debug` still carry nothing from the token.
//!
//! The table has a case for every reason a token whose payload can be read is refused for, for
//! both algorithms and both kinds of issuer where the reason applies, since the claims are read
//! the same way whichever check refused. No token at all, a token too large to read and a
//! payload that cannot be read claim nothing, and have tests of their own.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_core::{Claimed, IDENTITY_FAILURE, Proved, escape};
use gateway_identity::{
    Claim, ClaimedCaller, Identity, IdentityConfig, IdentityFailure, IssuerConfig, MAX_CLAIMED,
    MAX_TOKEN_BYTES, SigningAlgorithm, TokenVerifier, Verification, VerifyError,
};
use gateway_testkit::{FixedClock, TokenBuilder};
use serde_json::{Value, json};

use common::{Kind, LEEWAY, MAX_LIFETIME, NOW, SUBJECT, Setup, setups};

/// Far enough in the past to be expired whatever the leeway.
const PAST: u64 = NOW - 1000;
const UNLISTED: &str = "https://unlisted.test";
const STRANGER: &str = "system:serviceaccount:other:thing";

type Tamper = for<'a> fn(TokenBuilder<'a>, &'a Setup) -> TokenBuilder<'a>;

/// What a case's token claims as its issuer, or as its subject.
#[derive(Clone, Copy)]
enum Claims {
    /// What a valid token for the setup claims.
    Usual,
    /// Nothing that is a string.
    Nothing,
    /// This text, which needs no escaping.
    Text(&'static str),
}

struct Case {
    name: &'static str,
    reason: VerifyError,
    tamper: Tamper,
    issuer: Claims,
    subject: Claims,
    applies: fn(&Setup) -> bool,
    adjust: fn(&mut IssuerConfig),
}

fn case(name: &'static str, reason: VerifyError, tamper: Tamper) -> Case {
    Case {
        name,
        reason,
        tamper,
        issuer: Claims::Usual,
        subject: Claims::Usual,
        applies: |_| true,
        adjust: |_| {},
    }
}

impl Case {
    fn issuer(mut self, issuer: Claims) -> Self {
        self.issuer = issuer;
        self
    }

    fn subject(mut self, subject: Claims) -> Self {
        self.subject = subject;
        self
    }

    fn only(mut self, applies: fn(&Setup) -> bool) -> Self {
        self.applies = applies;
        self
    }

    fn adjust(mut self, adjust: fn(&mut IssuerConfig)) -> Self {
        self.adjust = adjust;
        self
    }
}

fn workload(setup: &Setup) -> bool {
    setup.kind == Kind::Workload
}

fn user(setup: &Setup) -> bool {
    setup.kind == Kind::User
}

fn es256(setup: &Setup) -> bool {
    setup.algorithm == SigningAlgorithm::Es256
}

fn the_other_algorithm(setup: &Setup) -> &'static str {
    match setup.algorithm {
        SigningAlgorithm::Rs256 => "ES256",
        SigningAlgorithm::Es256 => "RS256",
    }
}

/// An EC key whose point is not on the curve: accepted as configuration, refused at use.
fn add_off_curve_key(config: &mut IssuerConfig) {
    let zeros = "A".repeat(43);
    config.keys.keys.push(
        serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "x": zeros, "y": zeros, "kid": "off-curve", "alg": "ES256", "use": "sig"
        }))
        .unwrap(),
    );
}

fn cases() -> Vec<Case> {
    use Claim::*;
    use Claims::{Nothing, Text};
    use VerifyError::*;
    vec![
        case("a header with no alg", MalformedToken, |t, _| {
            t.header("alg", Value::Null)
        }),
        case("a kid that is not a string", MalformedToken, |t, _| {
            t.header("kid", json!(7))
        }),
        case("no iss", MissingIssuer, |t, _| t.without_claim("iss")).issuer(Nothing),
        case("an iss that is not a string", MissingIssuer, |t, s| {
            t.claim("iss", json!([s.issuer.issuer()]))
        })
        .issuer(Nothing),
        case("an issuer that is not configured", UnknownIssuer, |t, _| {
            t.issuer(UNLISTED)
        })
        .issuer(Text(UNLISTED)),
        case("an alg of the other family", AlgorithmNotAllowed, |t, s| {
            t.alg(the_other_algorithm(s))
        }),
        case("alg none with no signature", AlgorithmNotAllowed, |t, _| {
            t.unsigned()
        }),
        case("an empty crit header", CriticalHeader, |t, _| {
            t.header("crit", json!([]))
        }),
        case("no kid", MissingKeyId, |t, _| t.without_kid()),
        case("a kid the issuer does not have", UnknownKeyId, |t, _| {
            t.kid("no-such-key")
        }),
        case("a key that cannot verify", UnusableKey, |t, _| {
            t.kid("off-curve")
        })
        .only(es256)
        .adjust(add_off_curve_key),
        case(
            "a signature from another issuer's key",
            BadSignature,
            |t, s| t.signed_by(s.other),
        ),
        case("no exp", MissingClaim(ExpiresAt), |t, _| {
            t.without_claim("exp")
        }),
        case("exp as a string", MalformedClaim(ExpiresAt), |t, _| {
            t.claim("exp", json!((NOW + 100).to_string()))
        }),
        case("expired", Expired, |t, _| t.expires_at(PAST)),
        case("not yet valid", NotYetValid, |t, _| {
            t.not_before(NOW + LEEWAY + 1)
        }),
        case("nbf as a string", MalformedClaim(NotBefore), |t, _| {
            t.claim("nbf", json!("soon"))
        }),
        case("another audience", AudienceMismatch, |t, _| {
            t.audience("another-gateway")
        }),
        case("no aud", MissingClaim(Audience), |t, _| {
            t.without_claim("aud")
        }),
        case("aud as a number", MalformedClaim(Audience), |t, _| {
            t.claim("aud", json!(1))
        }),
        case("a lifetime over the ceiling", LifetimeTooLong, |t, _| {
            t.issued_at(NOW).expires_at(NOW + MAX_LIFETIME + 1)
        }),
        case("no iat", MissingClaim(IssuedAt), |t, _| {
            t.without_claim("iat")
        }),
        case("iat as a string", MalformedClaim(IssuedAt), |t, _| {
            t.claim("iat", json!("yesterday"))
        }),
        case("exp before iat", ExpiresBeforeIssue, |t, _| {
            t.issued_at(NOW + 10).expires_at(NOW + 5)
        }),
        case("iat beyond the leeway", IssuedInFuture, |t, _| {
            t.issued_at(NOW + LEEWAY + 1)
        }),
        case("no sub", MissingClaim(Subject), |t, _| {
            t.without_claim("sub")
        })
        .subject(Nothing),
        case("sub as a number", MalformedClaim(Subject), |t, _| {
            t.claim("sub", json!(5))
        })
        .subject(Nothing),
        case("an empty sub", MalformedClaim(Subject), |t, _| {
            t.subject("")
        })
        .subject(Text("")),
        case("a subject not in the table", UnknownSubject, |t, _| {
            t.subject(STRANGER)
        })
        .subject(Text(STRANGER))
        .only(workload),
        case("no groups claim", MissingClaim(Groups), |t, _| {
            t.without_claim("groups")
        })
        .only(user),
        case("groups as a string", MalformedClaim(Groups), |t, _| {
            t.claim("groups", json!("group-1"))
        })
        .only(user),
    ]
}

fn verifier_for(case: &Case, setup: &Setup) -> TokenVerifier {
    let mut config = setup.config();
    (case.adjust)(&mut config);
    TokenVerifier::new(vec![config], Arc::new(FixedClock::at(NOW))).unwrap()
}

fn wanted(claims: Claims, usual: &str) -> Option<&str> {
    match claims {
        Claims::Usual => Some(usual),
        Claims::Nothing => None,
        Claims::Text(text) => Some(text),
    }
}

fn text(claimed: Option<&Claimed<String>>) -> Option<&str> {
    claimed.map(|claimed| claimed.get().as_str())
}

fn refusal(verifier: &TokenVerifier, token: &str) -> IdentityFailure {
    match Proved::verify(verifier, token) {
        Ok(proved) => panic!("accepted as {:?}", proved.get()),
        Err(failure) => failure,
    }
}

/// The sentence the caller reads, the failure's `Display` and `Debug`, and the cause's
/// `Display` hold nothing the token claimed.
fn assert_tells_nothing_claimed(failure: &IdentityFailure, context: &str) {
    assert_eq!(failure.outward(), IDENTITY_FAILURE, "{context}");
    let told = [
        failure.outward().to_owned(),
        failure.to_string(),
        failure.detail().to_string(),
        format!("{failure:?}"),
    ];
    let claimed = failure.claimed();
    for value in [claimed.issuer(), claimed.subject()].into_iter().flatten() {
        let value = value.get();
        if value.is_empty() {
            continue;
        }
        for told in &told {
            assert!(
                !told.contains(value.as_str()),
                "{context}: {told:?} holds {value:?}"
            );
        }
    }
}

#[test]
fn every_refusal_of_a_readable_token_keeps_what_it_claimed() {
    let mut ran = 0;
    for setup in setups() {
        for case in cases().iter().filter(|case| (case.applies)(&setup)) {
            let context = format!("{} [{setup:?}]", case.name);
            let token = (case.tamper)(setup.token(), &setup).build();
            let failure = refusal(&verifier_for(case, &setup), &token);
            assert_eq!(failure.detail(), &case.reason, "{context}");
            let claimed = failure.claimed();
            assert_eq!(
                text(claimed.issuer()),
                wanted(case.issuer, setup.issuer.issuer()),
                "{context}: issuer"
            );
            assert_eq!(
                text(claimed.subject()),
                wanted(case.subject, SUBJECT),
                "{context}: subject"
            );
            assert_tells_nothing_claimed(&failure, &context);
            ran += 1;
        }
    }
    // A guard against the loop running over nothing.
    assert!(ran > 4 * 25, "only {ran} cases ran");
}

#[test]
fn what_a_token_claimed_is_escaped_as_sentences_and_rows_are() {
    let issuer = "https://unlisted.test/\u{202e}";
    let subject = "line\nbreak `tick` caf\u{e9}\\";
    for setup in setups() {
        let token = setup.token().issuer(issuer).subject(subject).build();
        let failure = refusal(&setup.verifier(), &token);
        assert_eq!(failure.detail(), &VerifyError::UnknownIssuer);
        let claimed = failure.claimed();
        assert_eq!(
            text(claimed.issuer()),
            Some("https://unlisted.test/\\u{202e}")
        );
        assert_eq!(
            text(claimed.subject()),
            Some("line\\nbreak \\`tick\\` caf\\u{e9}\\\\")
        );
        // By the core's own function, so the event and an audit row escape alike.
        assert_eq!(
            text(claimed.subject()),
            Some(escape(subject, MAX_CLAIMED).as_str())
        );
        let debug = format!("{claimed:?}");
        for raw in ["\u{202e}", "\u{e9}", "`tick`"] {
            assert!(!debug.contains(raw), "{debug} holds {raw:?}");
        }
        assert_tells_nothing_claimed(&failure, &format!("{setup:?}"));
    }
}

#[test]
fn a_long_claim_is_cut_at_the_cap() {
    let issuer = format!("https://{}.test", "x".repeat(10 * 1024));
    for setup in setups() {
        let token = setup.token().issuer(&issuer).build();
        assert!(token.len() <= MAX_TOKEN_BYTES, "small enough to be read");
        let failure = refusal(&setup.verifier(), &token);
        assert_eq!(failure.detail(), &VerifyError::UnknownIssuer);
        let kept = text(failure.claimed().issuer()).unwrap();
        assert_eq!(kept.chars().count(), MAX_CLAIMED + 1, "{setup:?}");
        assert_eq!(
            kept,
            format!("https://{}…", "x".repeat(MAX_CLAIMED - "https://".len()))
        );
        assert_eq!(text(failure.claimed().subject()), Some(SUBJECT));
    }
}

#[test]
fn a_token_too_large_to_read_claims_nothing() {
    for setup in setups() {
        let token = setup
            .token()
            .claim("padding", json!("x".repeat(MAX_TOKEN_BYTES)))
            .build();
        let failure = refusal(&setup.verifier(), &token);
        assert_eq!(failure.detail(), &VerifyError::TokenTooLarge);
        assert_eq!(failure.claimed(), &ClaimedCaller::default(), "{setup:?}");
    }
}

#[test]
fn a_payload_that_cannot_be_read_claims_nothing() {
    let setup = setups()[0];
    let valid = setup.token().build();
    let parts: Vec<&str> = valid.split('.').collect();
    let array = URL_SAFE_NO_PAD.encode(json!([setup.issuer.issuer(), SUBJECT]).to_string());
    for (name, token) in [
        ("an empty token", String::new()),
        ("text that is not a token", "not.a.token".to_owned()),
        (
            "claims that are not an object",
            format!("{}.{array}.{}", parts[0], parts[2]),
        ),
        (
            "a token with no signature part",
            format!("{}.{}", parts[0], parts[1]),
        ),
        ("a token with four parts", format!("{valid}.extra")),
    ] {
        let failure = refusal(&setup.verifier(), &token);
        assert_eq!(failure.detail(), &VerifyError::MalformedToken, "{name}");
        assert_eq!(failure.claimed(), &ClaimedCaller::default(), "{name}");
    }
}

#[test]
fn the_gate_keeps_what_was_claimed_and_no_token_claims_nothing() {
    let setup = setups().into_iter().find(workload).unwrap();
    let gate = Identity::new(
        IdentityConfig::Enforce(vec![setup.config()]),
        Arc::new(FixedClock::at(NOW)),
    )
    .unwrap();

    let Verification::Failed(failure) = gate.check(None) else {
        panic!("no token was not refused");
    };
    assert_eq!(failure.detail(), &VerifyError::MissingToken);
    assert_eq!(failure.claimed(), &ClaimedCaller::default());

    let token = setup.token().subject(STRANGER).build();
    let verification = gate.check(Some(&token));
    assert!(!format!("{verification:?}").contains(STRANGER));
    let Verification::Failed(failure) = verification else {
        panic!("an unknown subject was not refused");
    };
    assert_eq!(failure.detail(), &VerifyError::UnknownSubject);
    assert_eq!(
        text(failure.claimed().issuer()),
        Some(setup.issuer.issuer())
    );
    assert_eq!(text(failure.claimed().subject()), Some(STRANGER));
}
