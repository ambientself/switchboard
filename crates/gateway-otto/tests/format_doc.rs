//! docs/turn-grant-format.md is what Otto's owners implement from, so its constants and its
//! example must be what this crate does. The example's grant verifies here at the example's
//! time; its key ID, key file, claims and digest are what this crate computes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{at, issuer, workload};
use gateway_core::DeploymentName;
use gateway_otto::format::{
    KEY_ID_DOMAIN, LEEWAY_SECONDS, MAX_GRANT_BYTES, MAX_LIFETIME_SECONDS, SIGNING_DOMAIN, VERSION,
};
use gateway_otto::minter::TestMinter;
use gateway_otto::{GrantDigest, GrantKeys, GrantVerifier, KeyId, ToolMapping};

const DOC: &str = include_str!("../../../docs/turn-grant-format.md");

/// The first fenced block after `<!-- example: {name} -->`.
fn example(name: &str) -> &'static str {
    let marker = format!("<!-- example: {name} -->");
    let after = &DOC[DOC.find(&marker).unwrap_or_else(|| panic!("no {marker}")) + marker.len()..];
    let opened = &after[after.find("```").unwrap()..];
    let body = &opened[opened.find('\n').unwrap() + 1..];
    &body[..body.find("```").unwrap()]
}

fn values() -> BTreeMap<&'static str, &'static str> {
    example("values")
        .lines()
        .filter_map(|line| line.rsplit_once(' '))
        .map(|(name, value)| (name.trim(), value))
        .collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_document_states_the_constants() {
    let text = |bytes: &[u8]| {
        let (nul, name) = bytes.split_last().unwrap();
        assert_eq!(*nul, 0, "a domain prefix ends in a NUL byte");
        format!("\"{}\" || 0x00", std::str::from_utf8(name).unwrap())
    };
    assert!(
        DOC.contains(&text(KEY_ID_DOMAIN)),
        "{}",
        text(KEY_ID_DOMAIN)
    );
    assert!(
        DOC.contains(&text(SIGNING_DOMAIN)),
        "{}",
        text(SIGNING_DOMAIN)
    );
    assert!(DOC.contains(&format!("exactly `{VERSION}`")));
    assert!(DOC.contains(&format!("at most {MAX_GRANT_BYTES} bytes")));
    assert!(DOC.contains(&format!("`iat` ≤ now + {LEEWAY_SECONDS}")));
    assert!(DOC.contains(&format!("`exp` > now − {LEEWAY_SECONDS}")));
    assert!(DOC.contains(&format!("`exp − iat` ≤ {MAX_LIFETIME_SECONDS}")));
    assert!(
        DOC.contains("SHA-256( \"otto/gateway-turn-grant/kid/v3\" || 0x00 || public key )[0..16]")
    );
}

#[test]
fn the_example_verifies() {
    let values = values();
    let public_key: [u8; 32] = hex(values["public key"]).try_into().unwrap();
    assert_eq!(KeyId::of(&public_key).as_str(), values["key ID"]);

    // The key file, configured as it is written.
    let mut config = issuer("otto-example", &TestMinter::generate());
    config.current_key = example("key file").to_owned();
    config.require_pod = true;
    config.require_egress = true;
    let keys = GrantKeys::new(&[config]).unwrap();
    assert_eq!(keys.key_ids().next().unwrap().0.as_str(), values["key ID"]);
    assert_eq!(
        gateway_otto::minter::public_key_pem(&public_key),
        example("key file"),
        "the key file is as the minter writes it"
    );

    let grant: String = example("grant").split_whitespace().collect();
    assert_eq!(grant.len(), 512);
    assert!(DOC.contains("It is 512 bytes long."));
    let mapping = ToolMapping::from_pairs([("github_get_pr", "github__get_pr")]).unwrap();
    let verifier = GrantVerifier::new(keys, DeploymentName::new(values["deployment"]), mapping);
    let now: i64 = values["now"].parse().unwrap();
    let pod = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let verified = verifier
        .verify(grant.as_bytes(), &workload(Some(pod)), at(now))
        .unwrap();
    assert_eq!(verified.digest().to_string(), values["digest"]);
    assert_eq!(verified.digest(), GrantDigest::of(grant.as_bytes()));
    assert_eq!(verified.actor().get().as_str(), "requester@example.test");

    // The claims part is the compact form of the claims shown.
    let claims_part = grant.split('.').nth(2).unwrap();
    let signed = URL_SAFE_NO_PAD.decode(claims_part).unwrap();
    let shown: serde_json::Value = serde_json::from_str(example("claims")).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&signed).unwrap(),
        shown
    );
    let compact: String = example("claims")
        .split('"')
        .enumerate()
        .map(|(index, piece)| {
            if index % 2 == 0 {
                piece.split_whitespace().collect()
            } else {
                format!("\"{piece}\"")
            }
        })
        .collect();
    assert_eq!(std::str::from_utf8(&signed).unwrap(), compact);

    // The last character of the claims part, with its unused bits set, as the example says.
    assert_eq!(claims_part.len() % 4, 3);
    assert!(claims_part.ends_with('0'));
    for replacement in ['1', '2', '3'] {
        let changed = grant.replacen(
            &format!("{claims_part}."),
            &format!("{}{replacement}.", &claims_part[..claims_part.len() - 1]),
            1,
        );
        let failure = verifier
            .verify(changed.as_bytes(), &workload(Some(pod)), at(now))
            .unwrap_err();
        assert_eq!(
            failure.kind(),
            gateway_otto::FailureKind::Signature,
            "{replacement}"
        );
    }
    // The last character of the signature part, likewise: the signature still verifies, and the
    // grant is refused for its encoding, with no digest: only a binding's failure carries one.
    assert!(grant.ends_with('w'));
    for replacement in "xyz0123456789-_".chars() {
        let changed = format!("{}{replacement}", &grant[..grant.len() - 1]);
        let failure = verifier
            .verify(changed.as_bytes(), &workload(Some(pod)), at(now))
            .unwrap_err();
        assert_eq!(
            failure.kind(),
            gateway_otto::FailureKind::Encoding,
            "{replacement}"
        );
        assert_eq!(failure.digest(), None, "{replacement}");
    }
}
