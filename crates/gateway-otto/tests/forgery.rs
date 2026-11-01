//! Format and forgery (decision 0012, Tests): the version, the key ID, the signature checked
//! before the claims are read, every non-canonical encoding, and the shape of the claims.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use gateway_otto::FailureKind::{self, *};
use gateway_otto::GrantDigest;
use gateway_otto::format::{MAX_GRANT_BYTES, VERSION};
use gateway_otto::minter::{
    SmallOrderRMinter, TestMinter, encode, padded, parts, with_non_canonical_s, with_part,
    with_trailing_bits,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};

#[test]
fn a_well_formed_grant_verifies_with_what_it_says() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let grant = minter.mint(&claims());
    let verified = accepted(&verifier, &grant);
    assert_eq!(verified.issuer().as_str(), "otto-prod");
    assert_eq!(verified.key_id(), &minter.key_id());
    assert_eq!(verified.digest(), GrantDigest::of(grant.as_bytes()));
    assert_eq!(verified.team().as_str(), "team-canary-payments");
    assert_eq!(verified.epoch(), 7);
    assert_eq!(verified.session(), "session-canary");
    assert_eq!(verified.turn(), "turn-canary");
    assert_eq!(verified.execution(), "execution-canary");
    assert_eq!(verified.actor().get().as_str(), "actor-canary@example.test");
    assert_eq!(verified.pod().map(|pod| pod.as_str()), Some(POD));
    assert_eq!(verified.egress(), Some(gateway_otto::Egress::Sealed));
    let tools: Vec<&str> = verified.tools().iter().map(|tool| tool.as_str()).collect();
    assert_eq!(tools, ["github__create_pr", "github__get_pr"]);
}

#[test]
fn the_version_is_matched_before_anything_else() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    let rest = good.strip_prefix("v3").unwrap();
    // Otto's `v1` HMAC grants and its model broker's `v2` tokens, whatever follows.
    for version in ["v1", "v2", "V3", "v3 ", "v", "v33", ""] {
        refused_as(&verifier, &format!("{version}{rest}"), Version, false);
    }
    // A grant signed over another version is still refused for its version.
    let resigned = minter.sign("v2", minter.key_id().as_str(), &parts(&good)[2]);
    refused_as(&verifier, &resigned, Version, false);
    // Nothing else is read first: not the length, the parts or the key.
    refused_as(
        &verifier,
        &format!("v1.{}", "a".repeat(9000)),
        Version,
        false,
    );
    refused_as(&verifier, "not-a-grant", Version, false);
    refused_as(&verifier, "v1", Version, false);
    refused_as(&verifier, "", Version, false);
}

#[test]
fn a_grant_has_four_parts_and_a_bounded_length() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    refused_as(&verifier, VERSION, Malformed, false);
    refused_as(
        &verifier,
        &format!("{good}.{}", parts(&good)[3]),
        Malformed,
        false,
    );
    let three = parts(&good)[..3].join(".");
    refused_as(&verifier, &three, Malformed, false);
    refused_as(
        &verifier,
        &format!("v3.{}", "a".repeat(9000)),
        Malformed,
        false,
    );
    // Signed grants padded by an unknown claim: the longest within the limit verifies, and the
    // shortest over it is refused.
    let grants: Vec<String> = (5000..7000)
        .map(|length| minter.mint(&with(json!({"pad": "x".repeat(length)}))))
        .collect();
    let within = grants
        .iter()
        .rfind(|grant| grant.len() <= MAX_GRANT_BYTES)
        .unwrap();
    assert!(within.len() > MAX_GRANT_BYTES - 3, "{}", within.len());
    accepted(&verifier, within);
    let over = grants
        .iter()
        .find(|grant| grant.len() > MAX_GRANT_BYTES)
        .unwrap();
    assert!(over.len() < MAX_GRANT_BYTES + 3, "{}", over.len());
    refused_as(&verifier, over, Malformed, false);
}

#[test]
fn the_key_id_must_name_a_configured_key() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    // Another environment's key, under its own ID.
    let other = TestMinter::generate();
    refused_as(&verifier, &other.mint(&claims()), UnknownKey, false);
    // An ID that is not one, or is empty.
    let good = minter.mint(&claims());
    for id in ["", "not-a-key-id", "AAAAAAAAAAAAAAAAAAAAAA"] {
        refused_as(&verifier, &with_part(&good, 1, id), UnknownKey, false);
    }
    // The configured ID, encoded non-canonically, names no key.
    let id = minter.key_id();
    refused_as(
        &verifier,
        &with_part(&good, 1, &padded(id.as_str()).unwrap()),
        UnknownKey,
        false,
    );
    let trailing = with_trailing_bits(id.as_str()).unwrap();
    assert_eq!(
        base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::URL_SAFE,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        )
        .decode(&trailing)
        .unwrap(),
        URL_SAFE_NO_PAD.decode(id.as_str()).unwrap(),
        "the test's non-canonical ID decodes to the same bytes"
    );
    refused_as(
        &verifier,
        &with_part(&good, 1, &trailing),
        UnknownKey,
        false,
    );
}

#[test]
fn a_signature_that_does_not_verify_is_refused_without_a_digest() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    let other = TestMinter::generate();

    // Claims changed under a genuine signature: widened tools, another actor.
    for changes in [
        json!({"tools": ["github_get_pr", "github_merge_pr"]}),
        json!({"actor": "someone-else@example.test"}),
    ] {
        let tampered = with_part(&good, 2, &encode(with(changes).to_string().as_bytes()));
        refused_as(&verifier, &tampered, Signature, false);
    }
    // Claims swapped from another genuine grant of the same key.
    let another = minter.mint(&with(json!({"tid": "turn-other"})));
    refused_as(
        &verifier,
        &with_part(&good, 2, &parts(&another)[2]),
        Signature,
        false,
    );
    // Another environment's signature, filed under this key's ID.
    let forged = other.sign(VERSION, minter.key_id().as_str(), &parts(&good)[2]);
    refused_as(&verifier, &forged, Signature, false);
    // A 64-byte hash keyed with the public key's bytes, as a verifier that confuses public and
    // secret keys would make. Its top four bits are cleared so that S is below the group order
    // and the signature itself is what is checked, whatever the key.
    let mut hash = Sha512::new();
    hash.update(minter.public_key());
    hash.update(format!("v3.{}.{}", minter.key_id(), parts(&good)[2]));
    let mut keyed: [u8; 64] = hash.finalize().into();
    keyed[63] &= 0x0f;
    refused_as(
        &verifier,
        &with_part(&good, 3, &encode(&keyed)),
        Signature,
        false,
    );
    // All zeros, and a bit flipped.
    refused_as(
        &verifier,
        &with_part(&good, 3, &encode(&[0; 64])),
        Signature,
        false,
    );
    let mut flipped = URL_SAFE_NO_PAD.decode(&parts(&good)[3]).unwrap();
    flipped[5] ^= 1;
    refused_as(
        &verifier,
        &with_part(&good, 3, &encode(&flipped)),
        Signature,
        false,
    );
}

/// Verification is strict: a signature whose R is of small order is refused as a bad
/// signature, with no digest, though it meets RFC 8032's equation under an ordinary key and a
/// lax verifier accepts it.
#[test]
fn a_signature_only_a_lax_verifier_accepts_is_refused() {
    let minter = SmallOrderRMinter::generate();
    let mut config = issuer("otto-prod", &TestMinter::generate());
    config.current_key = minter.public_key_pem();
    let verifier = verifier_with(vec![config]);
    let grant = minter.mint(&claims());

    // The grant is what the strict rule alone refuses: the key is configured, S is canonical,
    // and the lax check passes.
    let parts = parts(&grant);
    assert_eq!(parts[1], minter.key_id().as_str());
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&parts[3])
        .unwrap()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&minter.public_key()).unwrap();
    assert!(!key.is_weak());
    let signed = gateway_otto::format::signed_bytes(
        parts[0].as_bytes(),
        parts[1].as_bytes(),
        parts[2].as_bytes(),
    );
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    assert!(
        ed25519_dalek::Verifier::verify(&key, &signed, &signature).is_ok(),
        "the lax check refuses the grant, so it tests nothing"
    );
    assert!(key.verify_strict(&signed, &signature).is_err());

    refused_as(&verifier, &grant, Signature, false);
}

#[test]
fn the_signature_is_checked_before_the_claims_are_read() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    // Under a bad signature, claims that would fail every later check, or not decode at all,
    // still fail as a bad signature.
    for encoded in [
        "!!!not base64!!!".to_owned(),
        encode(b"not json"),
        encode(
            with(json!({"exp": NOW - 3600, "aud": ["elsewhere"]}))
                .to_string()
                .as_bytes(),
        ),
        encode(without("actor").to_string().as_bytes()),
    ] {
        refused_as(&verifier, &with_part(&good, 2, &encoded), Signature, false);
    }
}

#[test]
fn a_signature_must_be_64_canonical_bytes() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    // Not base64url, or the wrong length: no signature to check.
    for signature in [
        "",
        "!!!",
        &encode(&[1; 63]),
        &encode(&[1; 65]),
        &encode(&[1; 32]),
    ] {
        refused_as(&verifier, &with_part(&good, 3, signature), Encoding, false);
    }
    // The same signature with S + ℓ: refused as non-canonical, before it is verified.
    refused_as(&verifier, &with_non_canonical_s(&good), Encoding, false);
}

#[test]
fn every_part_must_be_canonical_unpadded_base64url() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let good = minter.mint(&claims());
    let signature = &parts(&good)[3];

    // The signature with padding, or a non-zero trailing bit: it verifies, and is refused for
    // its encoding, with the digest of the grant as presented.
    let padded_signature = with_part(&good, 3, &padded(signature).unwrap());
    refused_as(&verifier, &padded_signature, Encoding, true);
    let trailing_signature = with_part(&good, 3, &with_trailing_bits(signature).unwrap());
    refused_as(&verifier, &trailing_signature, Encoding, true);

    // Claims encoded non-canonically and signed that way.
    let id = minter.key_id();
    let claims_needing_padding = (0..3)
        .map(|extra| with(json!({"pad": "x".repeat(extra)})))
        .map(|claims| encode(claims.to_string().as_bytes()))
        .find(|encoded| encoded.len() % 4 != 0)
        .unwrap();
    let signed_padded = minter.sign(
        VERSION,
        id.as_str(),
        &padded(&claims_needing_padding).unwrap(),
    );
    refused_as(&verifier, &signed_padded, Encoding, true);
    let signed_trailing = minter.sign(
        VERSION,
        id.as_str(),
        &with_trailing_bits(&claims_needing_padding).unwrap(),
    );
    refused_as(&verifier, &signed_trailing, Encoding, true);
    // The standard alphabet's `+` and `/` in place of `-` and `_`, signed as given.
    let standard = base64::engine::general_purpose::STANDARD_NO_PAD;
    let with_plus = (0..200)
        .map(|n| with(json!({"pad": "?".repeat(n)})))
        .map(|claims| standard.encode(claims.to_string()))
        .find(|encoded| encoded.contains('+') || encoded.contains('/'))
        .unwrap();
    refused_as(
        &verifier,
        &minter.sign(VERSION, id.as_str(), &with_plus),
        Encoding,
        true,
    );
    // Signed claims that are not base64url at all.
    refused_as(
        &verifier,
        &minter.sign(VERSION, id.as_str(), "a=b"),
        Encoding,
        true,
    );
}

#[test]
fn signed_claims_of_the_wrong_shape_are_malformed() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let malformed =
        |claims: &[u8]| refused_as(&verifier, &minter.mint_bytes(claims), Malformed, true);
    for bytes in [&b"not json"[..], b"", b"[]", b"null", b"\"claims\"", b"{"] {
        malformed(bytes);
    }
    // Every claim the format requires, missing, null, empty or of the wrong type.
    for name in [
        "aud", "iat", "exp", "team", "tools", "epoch", "sid", "tid", "eid", "actor",
    ] {
        malformed(without(name).to_string().as_bytes());
        malformed(with(json!({name: null})).to_string().as_bytes());
        malformed(with(json!({name: {"value": 1}})).to_string().as_bytes());
    }
    for name in ["team", "sid", "tid", "eid", "actor"] {
        malformed(with(json!({name: ""})).to_string().as_bytes());
        malformed(with(json!({name: 7})).to_string().as_bytes());
    }
    for changes in [
        json!({"tools": []}),
        json!({"tools": [""]}),
        json!({"tools": ["github_get_pr", ""]}),
        json!({"tools": "github_get_pr"}),
        json!({"tools": [7]}),
        json!({"aud": DEPLOYMENT}),
        json!({"aud": [7]}),
        json!({"epoch": 0}),
        json!({"epoch": -1}),
        json!({"epoch": 7.5}),
        json!({"epoch": "7"}),
        json!({"iat": -1}),
        json!({"exp": -1}),
        json!({"iat": NOW as f64 + 0.5}),
        json!({"exp": "tomorrow"}),
        // A pod or an egress setting that is present must be one.
        json!({"pod": null}),
        json!({"pod": "pod-name"}),
        json!({"pod": POD.to_uppercase()}),
        json!({"egress": null}),
        json!({"egress": "closed"}),
        json!({"egress": true}),
        json!({"egress": {"sealed": null}}),
        json!({"egress": {"open": null}}),
    ] {
        malformed(with(changes).to_string().as_bytes());
    }
    // Every claim, in order, as a JSON array rather than an object: with and without the pod
    // and egress setting, and for an issuer that requires them.
    let positional = json!([
        [DEPLOYMENT],
        NOW,
        NOW + 600,
        "team-canary-payments",
        ["github_get_pr"],
        7,
        "session-canary",
        "turn-canary",
        "execution-canary",
        "actor-canary@example.test",
        POD,
        "sealed",
    ]);
    let short = Value::Array(positional.as_array().unwrap()[..10].to_vec()).to_string();
    let positional = positional.to_string();
    malformed(positional.as_bytes());
    malformed(format!(" \n{positional}").as_bytes());
    malformed(short.as_bytes());
    let strict = strict_verifier(&minter);
    refused_as(
        &strict,
        &minter.mint_bytes(positional.as_bytes()),
        Malformed,
        true,
    );
    // The object form of the same claims, with leading whitespace, verifies.
    accepted(
        &strict,
        &minter.mint_bytes(format!(" \n{}", claims()).as_bytes()),
    );
    // A claim this format names, given twice.
    let twice = claims()
        .to_string()
        .replacen('{', r#"{"actor":"first@example.test","#, 1);
    malformed(twice.as_bytes());
}

#[test]
fn claims_the_format_does_not_name_are_ignored() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let grant = minter.mint(&with(json!({
        "iss": "someone",
        "nbf": "not a number",
        "scope": ["everything"],
        "future_claim": {"nested": [1, 2, 3]},
    })));
    accepted(&verifier, &grant);
    // Repeated, too: they are not read.
    let twice = claims()
        .to_string()
        .replacen('{', r#"{"extra":1,"extra":2,"#, 1);
    accepted(&verifier, &minter.mint_bytes(twice.as_bytes()));
}

/// The bad grants the conformance suite sends Otto's gateway
/// (`TestTurnGrantIsRequiredAndVerified`), re-minted in this format.
#[test]
fn the_baseline_kinds_are_refused_in_the_new_format() {
    let minter = TestMinter::generate();
    let verifier = verifier(&minter);
    let other = TestMinter::generate();
    let good = minter.mint(&claims());
    let resign = |changes| with_part(&good, 2, &encode(with(changes).to_string().as_bytes()));
    let cases: Vec<(&str, String, FailureKind, bool)> = vec![
        ("wrong_key", other.mint(&claims()), UnknownKey, false),
        (
            "tampered_claims",
            resign(json!({"actor": "someone-else@example.test"})),
            Signature,
            false,
        ),
        (
            "widened_tools",
            resign(json!({"tools": ["github_get_pr", "github_merge_pr"]})),
            Signature,
            false,
        ),
        (
            "expired",
            minter.mint(&with(json!({"iat": NOW - 660, "exp": NOW - 60}))),
            Expired,
            true,
        ),
        (
            "no_tools",
            minter.mint(&with(json!({"tools": []}))),
            Malformed,
            true,
        ),
        (
            "no_epoch",
            minter.mint(&with(json!({"epoch": 0}))),
            Malformed,
            true,
        ),
        (
            "wrong_version",
            format!("v2{}", good.strip_prefix("v3").unwrap()),
            Version,
            false,
        ),
        ("not_a_grant", "not-a-grant".to_owned(), Version, false),
        (
            "oversized",
            format!("v3.{}", "a".repeat(9000)),
            Malformed,
            false,
        ),
        (
            "missing_actor",
            minter.mint(&with(json!({"actor": ""}))),
            Malformed,
            true,
        ),
        (
            "missing_team",
            minter.mint(&with(json!({"team": ""}))),
            Malformed,
            true,
        ),
        (
            "missing_session",
            minter.mint(&with(json!({"sid": ""}))),
            Malformed,
            true,
        ),
        (
            "missing_exec",
            minter.mint(&with(json!({"eid": ""}))),
            Malformed,
            true,
        ),
        (
            "missing_turn",
            minter.mint(&with(json!({"tid": ""}))),
            Malformed,
            true,
        ),
        (
            "empty_tool_entry",
            minter.mint(&with(json!({"tools": [""]}))),
            Malformed,
            true,
        ),
    ];
    for (name, grant, kind, signed) in cases {
        let failure = refused(&verifier, &grant);
        assert_eq!(failure.kind(), kind, "{name}");
        assert_eq!(failure.digest().is_some(), signed, "{name}");
    }
    // Two of the suite's cases differ here. `legacy_headers` sends no grant, which is the
    // request path's to refuse, not the verifier's. `qualified_tool` names a tool by its
    // qualified name: Otto refuses the grant, while here it verifies and the name, which the
    // mapping does not have, is dropped, so the grant permits nothing.
    let qualified = minter.mint(&with(
        json!({"tools": ["mcp__otto-gateway__github_get_pr"]}),
    ));
    assert!(accepted(&verifier, &qualified).tools().is_empty());
}
