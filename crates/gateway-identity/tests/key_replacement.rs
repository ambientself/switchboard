//! Replacing an issuer's keys while the gate runs. A new set is put in force whole, and only if
//! it passes every check a set gets at boot; a refused set changes nothing; and keys can only be
//! given to an issuer the gate was built with.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_core::Issuer;
use gateway_identity::{
    Clock, ConfigError, Identity, IdentityConfig, IssuerKind, KeysReplaced, SigningAlgorithm,
    Verification, VerifyError,
};
use gateway_testkit::{FixedClock, LocalIssuer};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde_json::json;

use common::{AUDIENCE, NOW, SUBJECT, TEAM, issuers};

/// The EC issuer after it rotates: the same issuer name, a new key pair, and so a new `kid`.
static ROTATED: LazyLock<LocalIssuer> =
    LazyLock::new(|| LocalIssuer::new(ec().issuer(), SigningAlgorithm::Es256).unwrap());

/// An issuer the gate is not built with, holding a key of its own.
static UNLISTED: LazyLock<LocalIssuer> =
    LazyLock::new(|| LocalIssuer::new("https://unlisted.test", SigningAlgorithm::Es256).unwrap());

fn ec() -> &'static LocalIssuer {
    issuers()[2]
}

fn rsa() -> &'static LocalIssuer {
    issuers()[0]
}

fn name(issuer: &LocalIssuer) -> Issuer {
    issuer.issuer().into()
}

fn workload() -> IssuerKind {
    IssuerKind::Workload {
        subjects: [(SUBJECT.into(), TEAM.into())].into(),
    }
}

/// A gate enforcing the EC issuer and the RSA issuer, each with its own one key.
fn gate() -> Identity {
    let configs = [ec(), rsa()]
        .map(|issuer| issuer.config(workload(), &[AUDIENCE]))
        .to_vec();
    Identity::new(
        IdentityConfig::Enforce(configs),
        Arc::new(FixedClock::at(NOW)),
    )
    .unwrap()
}

/// A valid token signed with `issuer`'s key, naming its `kid`.
fn token(issuer: &LocalIssuer) -> String {
    issuer
        .workload_token(SUBJECT, AUDIENCE, FixedClock::at(NOW).now())
        .build()
}

/// Whether the gate proves `token`, or which check refused it.
fn outcome(gate: &Identity, token: &str) -> Result<(), VerifyError> {
    match gate.check(Some(token)) {
        Verification::Proved(_) => Ok(()),
        Verification::Failed(failure) => Err(failure.detail().clone()),
        Verification::Disabled => panic!("an enforcing gate read as disabled"),
    }
}

fn set(keys: &[&Jwk]) -> JwkSet {
    JwkSet {
        keys: keys.iter().map(|&key| key.clone()).collect(),
    }
}

fn key(issuer: &LocalIssuer) -> Jwk {
    issuer.jwk_set().keys[0].clone()
}

fn kids(kids: &[&str]) -> BTreeSet<String> {
    kids.iter().map(|&kid| kid.to_owned()).collect()
}

/// An RSA public key with a 1024-bit modulus, as a JWK. Not half of any key pair: only its
/// length matters.
fn weak_rsa_key(kid: &str) -> Jwk {
    let mut modulus = vec![0xff; 128];
    modulus[0] = 0xc1;
    serde_json::from_value(json!({
        "kty": "RSA", "kid": kid, "n": URL_SAFE_NO_PAD.encode(modulus),
        "e": URL_SAFE_NO_PAD.encode([1, 0, 1]),
    }))
    .unwrap()
}

#[test]
fn a_token_under_a_new_kid_is_refused_before_and_accepted_after() {
    let gate = gate();
    assert_eq!(
        outcome(&gate, &token(&ROTATED)),
        Err(VerifyError::UnknownKeyId)
    );

    let replaced = gate
        .replace_keys(&name(ec()), set(&[&key(ec()), &key(&ROTATED)]))
        .unwrap();
    assert_eq!(
        replaced,
        KeysReplaced {
            added: kids(&[ROTATED.key_id()]),
            removed: kids(&[]),
        }
    );
    assert_eq!(outcome(&gate, &token(&ROTATED)), Ok(()));
    assert_eq!(outcome(&gate, &token(ec())), Ok(()));
}

#[test]
fn a_token_under_a_dropped_kid_is_accepted_before_and_refused_after() {
    let gate = gate();
    assert_eq!(outcome(&gate, &token(ec())), Ok(()));

    let replaced = gate.replace_keys(&name(ec()), ROTATED.jwk_set()).unwrap();
    assert_eq!(
        replaced,
        KeysReplaced {
            added: kids(&[ROTATED.key_id()]),
            removed: kids(&[ec().key_id()]),
        }
    );
    assert_eq!(outcome(&gate, &token(ec())), Err(VerifyError::UnknownKeyId));
    assert_eq!(outcome(&gate, &token(&ROTATED)), Ok(()));
}

/// Each set the boot checks would refuse is refused with the error boot gives, and none of it
/// is applied: not the usable keys beside a bad one, and not the configuration the next
/// replacement builds on.
#[test]
fn each_refused_set_leaves_the_keys_in_use() {
    let mut without_kid = key(&ROTATED);
    without_kid.common.key_id = None;
    let mut ec_without_kid = key(ec());
    ec_without_kid.common.key_id = None;
    let weak = weak_rsa_key("weak-1024");
    let cases: Vec<(&str, Issuer, JwkSet, ConfigError)> = vec![
        (
            "an empty set",
            name(ec()),
            set(&[]),
            ConfigError::NoKeys(name(ec())),
        ),
        (
            "a key with no kid",
            name(ec()),
            set(&[&without_kid]),
            ConfigError::KeyWithoutId(name(ec())),
        ),
        (
            "a usable new key beside a key with no kid",
            name(ec()),
            set(&[&key(&ROTATED), &ec_without_kid]),
            ConfigError::KeyWithoutId(name(ec())),
        ),
        (
            "two keys with one kid",
            name(ec()),
            set(&[&key(&ROTATED), &key(&ROTATED)]),
            ConfigError::DuplicateKeyId {
                issuer: name(ec()),
                kid: ROTATED.key_id().to_owned(),
            },
        ),
        (
            "no key that fits the algorithm",
            name(ec()),
            rsa().jwk_set(),
            ConfigError::KeyDoesNotFit {
                issuer: name(ec()),
                kid: rsa().key_id().to_owned(),
                algorithm: "ES256",
            },
        ),
        (
            "a 1024-bit RSA key",
            name(rsa()),
            set(&[&weak]),
            ConfigError::WeakKey {
                issuer: name(rsa()),
                kid: "weak-1024".to_owned(),
                bits: 1024,
            },
        ),
    ];
    for (case, issuer, keys, refused) in cases {
        let gate = gate();
        assert_eq!(gate.replace_keys(&issuer, keys), Err(refused), "{case}");
        assert_eq!(outcome(&gate, &token(ec())), Ok(()), "{case}");
        assert_eq!(outcome(&gate, &token(rsa())), Ok(()), "{case}");
        assert_eq!(
            outcome(&gate, &token(&ROTATED)),
            Err(VerifyError::UnknownKeyId),
            "{case}"
        );
        // Later replacements build on the configuration in use, not on the refused set: putting
        // back each issuer's own keys changes nothing and is not refused.
        for issuer in [ec(), rsa()] {
            assert_eq!(
                gate.replace_keys(&name(issuer), issuer.jwk_set()),
                Ok(KeysReplaced::default()),
                "{case}, then {}",
                issuer.issuer()
            );
        }
    }
}

#[test]
fn keys_for_an_issuer_that_is_not_configured_are_refused_and_change_nothing() {
    let gate = gate();
    let near_miss: Issuer = format!("{}/", ec().issuer()).as_str().into();
    for issuer in [
        name(&UNLISTED),
        near_miss,
        name(ec()).as_str().to_uppercase().as_str().into(),
    ] {
        assert_eq!(
            gate.replace_keys(&issuer, UNLISTED.jwk_set()),
            Err(ConfigError::UnknownIssuerForKeys(issuer.clone()))
        );
    }
    assert_eq!(
        ConfigError::UnknownIssuerForKeys(name(&UNLISTED)).to_string(),
        "keys were supplied for issuer `https://unlisted.test`, which is not configured"
    );
    assert_eq!(
        outcome(&gate, &token(&UNLISTED)),
        Err(VerifyError::UnknownIssuer)
    );
    assert_eq!(outcome(&gate, &token(ec())), Ok(()));
    assert_eq!(outcome(&gate, &token(rsa())), Ok(()));
    // The keys in use are the configured ones still, so a replacement for a configured issuer
    // reports its change against them.
    assert_eq!(
        gate.replace_keys(&name(ec()), ec().jwk_set()),
        Ok(KeysReplaced::default())
    );
}

#[test]
fn replacing_one_issuers_keys_leaves_the_others_alone() {
    let gate = gate();
    gate.replace_keys(&name(ec()), ROTATED.jwk_set()).unwrap();
    assert_eq!(outcome(&gate, &token(rsa())), Ok(()));

    // A later replacement for the other issuer keeps the first replacement.
    assert_eq!(
        gate.replace_keys(&name(rsa()), rsa().jwk_set()),
        Ok(KeysReplaced::default())
    );
    assert_eq!(outcome(&gate, &token(&ROTATED)), Ok(()));
    assert_eq!(outcome(&gate, &token(ec())), Err(VerifyError::UnknownKeyId));
    assert_eq!(outcome(&gate, &token(rsa())), Ok(()));
}

#[test]
fn a_disabled_gate_refuses_keys_and_stays_disabled() {
    let gate = Identity::new(IdentityConfig::Disabled, Arc::new(FixedClock::at(NOW))).unwrap();
    let refused = gate.replace_keys(&name(ec()), ec().jwk_set()).unwrap_err();
    assert_eq!(refused, ConfigError::KeysWhileDisabled(name(ec())));
    assert_eq!(
        refused.to_string(),
        "keys were supplied for issuer `https://es-one.test`, but identity checking is disabled"
    );
    let valid = token(ec());
    for presented in [Some(valid.as_str()), None] {
        let verification = gate.check(presented);
        assert!(
            matches!(verification, Verification::Disabled),
            "{verification:?}"
        );
    }
}

/// While one thread swaps the EC issuer's keys back and forth between one set and a larger one,
/// checks on other threads only ever see one set or the other. The key in both sets is never
/// missing, and the key in one set is either in force or unknown, never anything else.
///
/// Each swap is in force when it returns, and the checking threads see both sets: the swaps go
/// on, up to a deadline, until each thread's checks have found the extra key both in force and
/// unknown. So a replacement that was ignored fails here, not only one that was half applied.
#[test]
fn checks_during_replacement_see_the_old_set_or_the_new() {
    let gate = gate();
    let one = ec().jwk_set();
    let both = set(&[&key(ec()), &key(&ROTATED)]);
    let (kept, rotated) = (token(ec()), token(&ROTATED));
    let stop = AtomicBool::new(false);
    let checks = AtomicUsize::new(0);
    // For each checking thread: whether it found the extra key in force, and unknown.
    let saw = [
        [AtomicBool::new(false), AtomicBool::new(false)],
        [AtomicBool::new(false), AtomicBool::new(false)],
    ];
    let saw_both = || {
        saw.iter()
            .flatten()
            .all(|seen| seen.load(Ordering::Relaxed))
    };

    std::thread::scope(|scope| {
        let checking: Vec<_> = saw
            .iter()
            .map(|[in_force, unknown]| {
                let (gate, kept, rotated, stop, checks) = (&gate, &kept, &rotated, &stop, &checks);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        assert_eq!(outcome(gate, kept), Ok(()));
                        match outcome(gate, rotated) {
                            Ok(()) => in_force.store(true, Ordering::Relaxed),
                            Err(VerifyError::UnknownKeyId) => {
                                unknown.store(true, Ordering::Relaxed)
                            }
                            Err(other) => panic!("a check during replacement gave {other:?}"),
                        }
                        checks.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        // Start once the checks are running, so the swaps happen under them. A checking thread
        // that has already stopped has panicked, and the scope reports it.
        while checks.load(Ordering::Relaxed) == 0 && !checking.iter().any(|t| t.is_finished()) {
            std::thread::yield_now();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut swaps = 0;
        let swapped = loop {
            if swaps >= 200 && saw_both() {
                break Ok(());
            }
            if Instant::now() > deadline || checking.iter().any(|t| t.is_finished()) {
                break Err(format!("after {swaps} swaps, the checks saw {saw:?}"));
            }
            if let Err(error) = gate.replace_keys(&name(ec()), both.clone()) {
                break Err(error.to_string());
            }
            if outcome(&gate, &rotated) != Ok(()) {
                break Err("the larger set was not in force once it replaced the smaller".into());
            }
            if let Err(error) = gate.replace_keys(&name(ec()), one.clone()) {
                break Err(error.to_string());
            }
            if outcome(&gate, &rotated) != Err(VerifyError::UnknownKeyId) {
                break Err("the smaller set was not in force once it replaced the larger".into());
            }
            swaps += 1;
        };
        // Stopped before anything is unwrapped, so a failure ends the checking threads too.
        stop.store(true, Ordering::Relaxed);
        swapped.unwrap();
    });

    assert_eq!(outcome(&gate, &kept), Ok(()));
    assert_eq!(outcome(&gate, &rotated), Err(VerifyError::UnknownKeyId));
}
