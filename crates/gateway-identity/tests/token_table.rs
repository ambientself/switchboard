//! A table of tokens, each made wrong in one way, run against both algorithms and both kinds of
//! issuer. Every refusal asserts the internal reason, which check refused, and that the outward
//! form is the one opaque sentence whatever the reason.
//!
//! A case is data: a name, the one thing wrong with the token, and what the verifier must
//! say. Adding a check to the verifier means adding cases here first and watching them fail.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use gateway_core::{IDENTITY_FAILURE, Principal, PrincipalKind, Proved};
use gateway_identity::{
    Claim, Identity, IdentityConfig, IssuerConfig, IssuerKind, TokenVerifier, Verification,
    VerificationState, VerifyError,
};
use gateway_testkit::{FixedClock, TokenBuilder};
use serde_json::json;

use common::{AUDIENCE, Kind, LEEWAY, MAX_LIFETIME, NOW, Setup, setups};

/// Far enough in the past to be expired whatever the leeway.
const PAST: u64 = NOW - 1000;

type Tamper = for<'a> fn(TokenBuilder<'a>, &'a Setup) -> TokenBuilder<'a>;
type Post = fn(String, &Setup) -> String;
type Adjust = fn(&mut IssuerConfig);
type Expected = fn(Principal) -> Principal;

#[derive(Clone, Copy)]
enum Applies {
    Both,
    Only(Kind),
}

enum Expect {
    /// Verifies, as the principal a valid token for the setup proves, changed by this.
    Accepted(Expected),
    Refused(VerifyError),
}

struct Case {
    name: &'static str,
    applies: Applies,
    tamper: Tamper,
    post: Post,
    adjust: Adjust,
    expect: Expect,
}

fn same(principal: Principal) -> Principal {
    principal
}

fn unchanged(token: String, _: &Setup) -> String {
    token
}

fn no_adjustment(_: &mut IssuerConfig) {}

fn accepted(name: &'static str, tamper: Tamper) -> Case {
    Case {
        name,
        applies: Applies::Both,
        tamper,
        post: unchanged,
        adjust: no_adjustment,
        expect: Expect::Accepted(same),
    }
}

fn refused(name: &'static str, reason: VerifyError, tamper: Tamper) -> Case {
    Case {
        name,
        applies: Applies::Both,
        tamper,
        post: unchanged,
        adjust: no_adjustment,
        expect: Expect::Refused(reason),
    }
}

impl Case {
    fn only(mut self, kind: Kind) -> Self {
        self.applies = Applies::Only(kind);
        self
    }

    fn post(mut self, post: Post) -> Self {
        self.post = post;
        self
    }

    fn adjust(mut self, adjust: Adjust) -> Self {
        self.adjust = adjust;
        self
    }

    fn proving(mut self, change: Expected) -> Self {
        self.expect = Expect::Accepted(change);
        self
    }
}

fn parts(token: &str) -> Vec<&str> {
    token.split('.').collect()
}

/// A token's signature with its header and payload replaced by another token's: well formed
/// in every part, and signed over something else.
fn graft_payload(token: String, setup: &Setup) -> String {
    let donor = setup.token().subject("someone-else").build();
    let (ours, theirs) = (parts(&token), parts(&donor));
    format!("{}.{}.{}", ours[0], theirs[1], ours[2])
}

fn the_other_algorithm(setup: &Setup) -> &'static str {
    match setup.algorithm {
        gateway_identity::SigningAlgorithm::Rs256 => "ES256",
        gateway_identity::SigningAlgorithm::Es256 => "RS256",
    }
}

fn cases() -> Vec<Case> {
    use Claim::*;
    use VerifyError::*;
    vec![
        // --- What is accepted, so a refusal below is not a verifier that refuses everything.
        accepted("a valid token", |t, _| t),
        accepted(
            "an audience array that includes the accepted one",
            |t, _| t.audiences(&["another-gateway", AUDIENCE]),
        ),
        accepted("no nbf, which is optional", |t, _| t.without_claim("nbf")),
        accepted(
            "jku, x5u and embedded jwk headers, which are never used",
            |t, _| {
                t.header("jku", json!("https://attacker.test/keys"))
                    .header("x5u", json!("https://attacker.test/cert"))
                    .header("jwk", json!({"kty": "oct", "k": "AAAA"}))
            },
        ),
        accepted("an extra claim, which is ignored", |t, _| {
            t.claim("scope", json!("everything"))
        }),
        accepted("exp one second inside the leeway", |t, _| {
            t.issued_at(NOW - 200).expires_at(NOW - LEEWAY + 1)
        }),
        accepted("nbf exactly at the leeway", |t, _| {
            t.not_before(NOW + LEEWAY)
        }),
        accepted("iat exactly at the leeway", |t, _| {
            t.issued_at(NOW + LEEWAY)
        }),
        accepted("a lifetime exactly at the ceiling", |t, _| {
            t.issued_at(NOW).expires_at(NOW + MAX_LIFETIME)
        }),
        accepted("a user's subject needs no table", |t, _| {
            t.subject("anyone@example.test")
        })
        .only(Kind::User)
        .proving(|mut principal| {
            principal.id.subject = "anyone@example.test".into();
            principal
        }),
        accepted("a user in no groups", |t, _| t.claim("groups", json!([])))
            .only(Kind::User)
            .proving(|mut principal| {
                principal.kind = PrincipalKind::User {
                    groups: BTreeSet::new(),
                };
                principal
            }),
        accepted("groups read from the configured claim", |t, _| {
            t.without_claim("groups")
                .claim("roles", json!(common::GROUPS))
        })
        .only(Kind::User)
        .adjust(|config| {
            config.kind = IssuerKind::User {
                groups_claim: "roles".into(),
            }
        }),
        // --- The token as a whole.
        refused("an empty token", MalformedToken, |t, _| t).post(|_, _| String::new()),
        refused("text that is not a token", MalformedToken, |t, _| t)
            .post(|_, _| "not.a.token".into()),
        refused("a token with no signature part", MalformedToken, |t, _| t)
            .post(|token, _| token.rsplit_once('.').unwrap().0.to_owned()),
        refused("a token with four parts", MalformedToken, |t, _| t)
            .post(|token, _| format!("{token}.extra")),
        refused("a token larger than the limit", TokenTooLarge, |t, _| {
            t.claim(
                "padding",
                json!("x".repeat(gateway_identity::MAX_TOKEN_BYTES)),
            )
        }),
        // --- Which issuer.
        refused("no iss claim", MissingIssuer, |t, _| t.without_claim("iss")),
        refused("an iss that is not a string", MissingIssuer, |t, _| {
            t.claim("iss", json!(["https://x.test"]))
        }),
        refused("an issuer that is not configured", UnknownIssuer, |t, _| {
            t.issuer("https://unlisted.test")
        }),
        refused(
            "a real issuer that is not in this deployment's list",
            UnknownIssuer,
            |t, s| t.issuer(s.other.issuer()),
        ),
        refused("the issuer with a trailing slash", UnknownIssuer, |t, s| {
            t.issuer(&format!("{}/", s.issuer.issuer()))
        }),
        refused("the issuer in another case", UnknownIssuer, |t, s| {
            t.issuer(&s.issuer.issuer().to_uppercase())
        }),
        // --- Algorithm and key.
        refused("an alg of the other family", AlgorithmNotAllowed, |t, s| {
            t.alg(the_other_algorithm(s))
        }),
        refused(
            "an alg of the same family, signed as the issuer signs",
            AlgorithmNotAllowed,
            |t, s| {
                t.alg(match s.algorithm {
                    gateway_identity::SigningAlgorithm::Rs256 => "RS384",
                    gateway_identity::SigningAlgorithm::Es256 => "ES384",
                })
            },
        ),
        refused(
            "HMAC under a made-up secret",
            AlgorithmNotAllowed,
            |t, _| t.hmac_signed(b"a secret the attacker chose"),
        ),
        refused(
            "HMAC keyed with the issuer's public key",
            AlgorithmNotAllowed,
            |t, s| {
                let public_key = serde_json::to_vec(&s.issuer.jwk_set()).unwrap();
                t.hmac_signed(&public_key)
            },
        ),
        refused("alg none with no signature", AlgorithmNotAllowed, |t, _| {
            t.unsigned()
        }),
        refused(
            "alg none with the signature kept",
            AlgorithmNotAllowed,
            |t, _| t.alg("none"),
        ),
        refused("an alg in lower case", AlgorithmNotAllowed, |t, s| {
            t.alg(&s.algorithm.as_str().to_lowercase())
        }),
        refused("a header with no alg", MalformedToken, |t, _| {
            t.header("alg", serde_json::Value::Null)
        }),
        refused("no kid", MissingKeyId, |t, _| t.without_kid()),
        refused("a kid the issuer does not have", UnknownKeyId, |t, _| {
            t.kid("no-such-key")
        }),
        refused("the kid of another issuer's key", UnknownKeyId, |t, s| {
            t.kid(s.other.key_id())
        }),
        refused("a kid that is not a string", MalformedToken, |t, _| {
            t.header("kid", json!(7))
        }),
        // --- The signature.
        refused(
            "a signature from another issuer's key",
            BadSignature,
            |t, s| t.signed_by(s.other),
        ),
        refused(
            "one changed character in the signature",
            BadSignature,
            |t, _| t.corrupt_signature(),
        ),
        refused("a payload from another token", BadSignature, |t, _| t).post(graft_payload),
        refused("an empty signature", BadSignature, |t, _| t)
            .post(|token, _| format!("{}.", token.rsplit_once('.').unwrap().0)),
        refused(
            "an embedded jwk of the attacker's own key",
            BadSignature,
            |t, s| {
                let attacker = serde_json::to_value(s.other.jwk_set().keys[0].clone()).unwrap();
                t.header("jwk", attacker).signed_by(s.other)
            },
        ),
        // --- Expiry.
        refused("expired", Expired, |t, _| t.expires_at(PAST)),
        refused("expired exactly at the leeway", Expired, |t, _| {
            t.issued_at(NOW - 200).expires_at(NOW - LEEWAY)
        }),
        refused("no exp", MissingClaim(ExpiresAt), |t, _| {
            t.without_claim("exp")
        }),
        refused("exp as a string", MalformedClaim(ExpiresAt), |t, _| {
            t.claim("exp", json!((NOW + 100).to_string()))
        }),
        refused("exp as a fraction", MalformedClaim(ExpiresAt), |t, _| {
            t.claim("exp", json!(NOW as f64 + 100.5))
        }),
        refused("a negative exp", MalformedClaim(ExpiresAt), |t, _| {
            t.claim("exp", json!(-1))
        }),
        // --- Not before.
        refused("not yet valid", NotYetValid, |t, _| {
            t.not_before(NOW + LEEWAY + 1)
        }),
        refused("nbf as a string", MalformedClaim(NotBefore), |t, _| {
            t.claim("nbf", json!("soon"))
        }),
        refused("nbf as null", MalformedClaim(NotBefore), |t, _| {
            t.claim("nbf", serde_json::Value::Null)
        }),
        // --- Audience.
        refused("another audience", AudienceMismatch, |t, _| {
            t.audience("another-gateway")
        }),
        refused(
            "an audience that merely starts with ours",
            AudienceMismatch,
            |t, _| t.audience(&format!("{AUDIENCE}-and-more")),
        ),
        refused("our audience in another case", AudienceMismatch, |t, _| {
            t.audience(&AUDIENCE.to_uppercase())
        }),
        refused("an array of other audiences", AudienceMismatch, |t, _| {
            t.audiences(&["one", "two"])
        }),
        refused("an empty array of audiences", AudienceMismatch, |t, _| {
            t.audiences(&[])
        }),
        refused("no aud", MissingClaim(Audience), |t, _| {
            t.without_claim("aud")
        }),
        refused("aud as a number", MalformedClaim(Audience), |t, _| {
            t.claim("aud", json!(1))
        }),
        refused(
            "an aud array with a number in it",
            MalformedClaim(Audience),
            |t, _| t.claim("aud", json!([AUDIENCE, 1])),
        ),
        // --- Lifetime.
        refused(
            "a lifetime one over the ceiling",
            LifetimeTooLong,
            |t, _| t.issued_at(NOW).expires_at(NOW + MAX_LIFETIME + 1),
        ),
        refused("a lifetime of a year", LifetimeTooLong, |t, _| {
            t.lifetime(365 * 24 * 3600)
        }),
        refused("no iat", MissingClaim(IssuedAt), |t, _| {
            t.without_claim("iat")
        }),
        refused("iat as a string", MalformedClaim(IssuedAt), |t, _| {
            t.claim("iat", json!("yesterday"))
        }),
        refused("exp before iat", ExpiresBeforeIssue, |t, _| {
            t.issued_at(NOW + 10).expires_at(NOW + 5)
        }),
        refused("iat just beyond the leeway", IssuedInFuture, |t, _| {
            t.issued_at(NOW + LEEWAY + 1)
        }),
        // --- Subject.
        refused("no sub", MissingClaim(Subject), |t, _| {
            t.without_claim("sub")
        }),
        refused("an empty sub", MalformedClaim(Subject), |t, _| {
            t.subject("")
        }),
        refused("sub as a number", MalformedClaim(Subject), |t, _| {
            t.claim("sub", json!(5))
        }),
        refused("a subject not in the table", UnknownSubject, |t, _| {
            t.subject("system:serviceaccount:other:thing")
        })
        .only(Kind::Workload),
        refused(
            "a subject differing only in case",
            UnknownSubject,
            |t, _| t.subject(&common::SUBJECT.to_uppercase()),
        )
        .only(Kind::Workload),
        refused("a subject with a trailing space", UnknownSubject, |t, _| {
            t.subject(&format!("{} ", common::SUBJECT))
        })
        .only(Kind::Workload),
        // --- Groups.
        refused("no groups claim", MissingClaim(Groups), |t, _| {
            t.without_claim("groups")
        })
        .only(Kind::User),
        refused("groups as a string", MalformedClaim(Groups), |t, _| {
            t.claim("groups", json!("group-1"))
        })
        .only(Kind::User),
        refused("groups as an object", MalformedClaim(Groups), |t, _| {
            t.claim("groups", json!({"group-1": true}))
        })
        .only(Kind::User),
        refused(
            "a group that is a number",
            MalformedClaim(Groups),
            |t, _| t.claim("groups", json!(["group-1", 2])),
        )
        .only(Kind::User),
        refused("groups as null", MalformedClaim(Groups), |t, _| {
            t.claim("groups", serde_json::Value::Null)
        })
        .only(Kind::User),
        refused(
            "groups in the wrong claim when another is configured",
            MissingClaim(Groups),
            |t, _| t,
        )
        .only(Kind::User)
        .adjust(|config| {
            config.kind = IssuerKind::User {
                groups_claim: "roles".into(),
            }
        }),
        // --- Which check reports first, when a token is wrong in two ways. The order is
        // signature, then exp, nbf, aud, lifetime, sub, then what depends on the subject.
        refused(
            "a bad signature and a wrong algorithm: the algorithm",
            AlgorithmNotAllowed,
            |t, s| t.signed_by(s.other).alg(the_other_algorithm(s)),
        ),
        refused(
            "a bad signature and expired: the signature",
            BadSignature,
            |t, s| t.signed_by(s.other).expires_at(PAST),
        ),
        refused("expired and the wrong audience: expiry", Expired, |t, _| {
            t.expires_at(PAST).audience("another-gateway")
        }),
        refused(
            "not yet valid and the wrong audience: nbf",
            NotYetValid,
            |t, _| t.not_before(NOW + 1000).audience("another-gateway"),
        ),
        refused(
            "the wrong audience and too long: the audience",
            AudienceMismatch,
            |t, _| t.audience("another-gateway").lifetime(MAX_LIFETIME + 1),
        ),
        refused(
            "too long and no sub: the lifetime",
            LifetimeTooLong,
            |t, _| t.lifetime(MAX_LIFETIME + 1).without_claim("sub"),
        ),
        refused(
            "a bad signature and an unknown subject: the signature",
            BadSignature,
            |t, s| {
                t.signed_by(s.other)
                    .subject("system:serviceaccount:other:thing")
            },
        )
        .only(Kind::Workload),
        refused("expired and an unknown subject: expiry", Expired, |t, _| {
            t.expires_at(PAST)
                .subject("system:serviceaccount:other:thing")
        })
        .only(Kind::Workload),
        refused(
            "the wrong audience and an unknown subject: the audience",
            AudienceMismatch,
            |t, _| {
                t.audience("another-gateway")
                    .subject("system:serviceaccount:other:thing")
            },
        )
        .only(Kind::Workload),
        refused(
            "an unlisted issuer and everything else wrong: the issuer",
            UnknownIssuer,
            |t, _| {
                t.issuer("https://unlisted.test")
                    .without_kid()
                    .expires_at(PAST)
                    .audience("another-gateway")
                    .corrupt_signature()
            },
        ),
    ]
}

fn applies(case: &Case, setup: &Setup) -> bool {
    match case.applies {
        Applies::Both => true,
        Applies::Only(kind) => kind == setup.kind,
    }
}

fn config_for(case: &Case, setup: &Setup) -> IssuerConfig {
    let mut config = setup.config();
    (case.adjust)(&mut config);
    config
}

fn token_for(case: &Case, setup: &Setup) -> String {
    (case.post)((case.tamper)(setup.token(), setup).build(), setup)
}

fn verifier_for(case: &Case, setup: &Setup) -> TokenVerifier {
    TokenVerifier::new(vec![config_for(case, setup)], Arc::new(FixedClock::at(NOW))).unwrap()
}

#[test]
fn every_case_gets_the_verdict_the_table_names_for_both_algorithms_and_both_kinds() {
    let mut ran = 0;
    for setup in setups() {
        for case in cases().iter().filter(|case| applies(case, &setup)) {
            let context = format!("{} [{setup:?}]", case.name);
            let token = token_for(case, &setup);
            let verifier = verifier_for(case, &setup);
            let verdict = Proved::verify(&verifier, token.as_str());
            match (&case.expect, verdict) {
                (Expect::Accepted(change), Ok(proved)) => {
                    assert_eq!(proved.get(), &change(setup.principal()), "{context}");
                }
                (Expect::Accepted(_), Err(failure)) => {
                    panic!("{context}: refused as {:?}", failure.detail())
                }
                (Expect::Refused(reason), Err(failure)) => {
                    assert_eq!(failure.detail(), reason, "{context}");
                    // One outward form, whatever the reason.
                    assert_eq!(failure.outward(), IDENTITY_FAILURE, "{context}");
                    assert_eq!(failure.to_string(), IDENTITY_FAILURE, "{context}");
                }
                (Expect::Refused(reason), Ok(proved)) => {
                    panic!(
                        "{context}: accepted as {:?}, expected {reason:?}",
                        proved.get()
                    )
                }
            }
            ran += 1;
        }
    }
    // A guard against the loop running over nothing.
    assert!(ran > 4 * 60, "only {ran} cases ran");
}

#[test]
fn the_identity_gate_records_the_same_verdicts_as_proved_or_failed() {
    for setup in setups() {
        for case in cases().iter().filter(|case| applies(case, &setup)) {
            let gate = Identity::new(
                IdentityConfig::Enforce(vec![config_for(case, &setup)]),
                Arc::new(FixedClock::at(NOW)),
            )
            .unwrap();
            let verification = gate.check(Some(&token_for(case, &setup)));
            let expected = match case.expect {
                Expect::Accepted(_) => VerificationState::Proved,
                Expect::Refused(_) => VerificationState::Failed,
            };
            assert_eq!(verification.state(), expected, "{} [{setup:?}]", case.name);
            if let Verification::Failed(failure) = &verification {
                assert_eq!(failure.to_string(), IDENTITY_FAILURE);
            }
        }
    }
}

/// Every way a token can be refused has a case in the table, for each algorithm and kind where
/// the way applies. The match is exhaustive, so a new kind of refusal does not compile until it
/// is listed here, and the list is then checked against the table.
#[test]
fn the_table_has_a_case_for_every_way_a_token_can_be_refused() {
    fn name(reason: &VerifyError) -> String {
        match reason {
            VerifyError::MissingToken => "MissingToken".into(),
            VerifyError::TokenTooLarge => "TokenTooLarge".into(),
            VerifyError::MalformedToken => "MalformedToken".into(),
            VerifyError::MissingIssuer => "MissingIssuer".into(),
            VerifyError::UnknownIssuer => "UnknownIssuer".into(),
            VerifyError::AlgorithmNotAllowed => "AlgorithmNotAllowed".into(),
            VerifyError::MissingKeyId => "MissingKeyId".into(),
            VerifyError::UnknownKeyId => "UnknownKeyId".into(),
            VerifyError::UnusableKey => "UnusableKey".into(),
            VerifyError::BadSignature => "BadSignature".into(),
            VerifyError::MissingClaim(claim) => format!("MissingClaim({claim:?})"),
            VerifyError::MalformedClaim(claim) => format!("MalformedClaim({claim:?})"),
            VerifyError::Expired => "Expired".into(),
            VerifyError::NotYetValid => "NotYetValid".into(),
            VerifyError::AudienceMismatch => "AudienceMismatch".into(),
            VerifyError::ExpiresBeforeIssue => "ExpiresBeforeIssue".into(),
            VerifyError::LifetimeTooLong => "LifetimeTooLong".into(),
            VerifyError::IssuedInFuture => "IssuedInFuture".into(),
            VerifyError::UnknownSubject => "UnknownSubject".into(),
        }
    }
    // Not reachable from a token in this table: no token at all is the gate's, and an unusable
    // key is a configuration, both with their own tests.
    let elsewhere = ["MissingToken", "UnusableKey"];
    let wanted: BTreeSet<String> = [
        "TokenTooLarge",
        "MalformedToken",
        "MissingIssuer",
        "UnknownIssuer",
        "AlgorithmNotAllowed",
        "MissingKeyId",
        "UnknownKeyId",
        "BadSignature",
        "Expired",
        "NotYetValid",
        "AudienceMismatch",
        "ExpiresBeforeIssue",
        "LifetimeTooLong",
        "IssuedInFuture",
        "UnknownSubject",
        "MissingClaim(ExpiresAt)",
        "MissingClaim(Audience)",
        "MissingClaim(IssuedAt)",
        "MissingClaim(Subject)",
        "MissingClaim(Groups)",
        "MalformedClaim(ExpiresAt)",
        "MalformedClaim(NotBefore)",
        "MalformedClaim(Audience)",
        "MalformedClaim(IssuedAt)",
        "MalformedClaim(Subject)",
        "MalformedClaim(Groups)",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    for listed in &wanted {
        assert!(!elsewhere.contains(&listed.as_str()), "{listed}");
    }
    let covered_by = |kind: Option<Kind>| -> BTreeSet<String> {
        cases()
            .iter()
            .filter(|case| match (case.applies, kind) {
                (Applies::Both, _) => true,
                (Applies::Only(only), Some(kind)) => only == kind,
                (Applies::Only(_), None) => true,
            })
            .filter_map(|case| match &case.expect {
                Expect::Refused(reason) => Some(name(reason)),
                Expect::Accepted(_) => None,
            })
            .collect()
    };
    let covered = covered_by(None);
    let missing: Vec<&String> = wanted.difference(&covered).collect();
    assert!(missing.is_empty(), "no case for {missing:?}");
    let unexpected: Vec<&String> = covered
        .difference(&wanted)
        .filter(|name| !elsewhere.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "cases for reasons the list does not name: {unexpected:?}"
    );
}

/// A token whose kid names a key that is in the set but cannot verify: the key is accepted as
/// configuration, because only its shape can be checked there, and then refuses at use.
#[test]
fn a_key_that_cannot_verify_refuses_every_token_under_it() {
    let setup = setups()
        .into_iter()
        .find(|s| {
            s.kind == Kind::Workload && s.algorithm == gateway_identity::SigningAlgorithm::Es256
        })
        .unwrap();
    let mut config = setup.config();
    let zeros = "A".repeat(43);
    config.keys.keys.push(
        serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "x": zeros, "y": zeros, "kid": "off-curve", "alg": "ES256", "use": "sig"
        }))
        .unwrap(),
    );
    let verifier = TokenVerifier::new(vec![config], Arc::new(FixedClock::at(NOW))).unwrap();
    let failure =
        Proved::verify(&verifier, setup.token().kid("off-curve").build().as_str()).unwrap_err();
    assert_eq!(failure.detail(), &VerifyError::UnusableKey);
    assert_eq!(failure.to_string(), IDENTITY_FAILURE);
}

#[test]
fn two_local_issuers_never_share_a_key() {
    // Keys are generated when an issuer is built, never checked in, so two issuers of one
    // algorithm have different keys.
    let issuers = common::issuers();
    for (i, one) in issuers.iter().enumerate() {
        for two in &issuers[i + 1..] {
            assert_ne!(one.key_id(), two.key_id());
            assert_ne!(one.jwk_set(), two.jwk_set());
        }
    }
}

/// A refusal over a claim reads as one sentence in the log, for every claim, including the
/// groups claim, whose name is configured.
#[test]
fn a_refusal_over_a_claim_reads_as_a_sentence() {
    assert_eq!(
        VerifyError::MissingClaim(Claim::Groups).to_string(),
        "the token has no groups claim"
    );
    assert_eq!(
        VerifyError::MalformedClaim(Claim::Subject).to_string(),
        "the token's `sub` claim is malformed"
    );
    for claim in [
        Claim::Issuer,
        Claim::Subject,
        Claim::Audience,
        Claim::ExpiresAt,
        Claim::NotBefore,
        Claim::IssuedAt,
        Claim::Groups,
    ] {
        for sentence in [
            VerifyError::MissingClaim(claim.clone()).to_string(),
            VerifyError::MalformedClaim(claim).to_string(),
        ] {
            assert_eq!(sentence.matches("claim").count(), 1, "{sentence}");
            assert!(!sentence.contains("the the"), "{sentence}");
        }
    }
}
