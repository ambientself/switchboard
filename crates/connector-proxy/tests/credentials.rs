//! The file-backed credential source: what it reads, what it refuses, and that its secret shows
//! up in no handle, no debug output and no error.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{GATEWAY_TOKEN, temporary_file};
use connector_proxy::{CredentialFileError, FileCredentials, MAX_CREDENTIAL_BYTES};
use gateway_core::{ConnectorName, CredentialError, CredentialSource};
use gateway_testkit::{Caller, Fixture, block_on};

const DOCS: &str = "docs";

fn load(contents: &[u8]) -> Result<FileCredentials, CredentialFileError> {
    let path = temporary_file(contents);
    let loaded = FileCredentials::load([(ConnectorName::new(DOCS), &path)]);
    std::fs::remove_file(&path).unwrap();
    loaded
}

#[test]
fn a_handle_is_issued_for_a_configured_connector_and_carries_only_a_label() {
    let credentials = load(format!("{GATEWAY_TOKEN}\n").as_bytes()).unwrap();
    let fixture = Fixture::new().unwrap();
    let caller = fixture.principal(Caller::TeamA).unwrap();

    let handle = block_on(credentials.credential_for(&ConnectorName::new(DOCS), &caller)).unwrap();

    assert_eq!(handle.label(), "gateway credential for docs");
    assert!(!format!("{handle:?}").contains(GATEWAY_TOKEN));
    assert_eq!(
        credentials.connectors().collect::<Vec<_>>(),
        [&ConnectorName::new(DOCS)]
    );
}

#[test]
fn a_connector_with_no_file_is_refused_a_credential() {
    let credentials = load(GATEWAY_TOKEN.as_bytes()).unwrap();
    let fixture = Fixture::new().unwrap();
    let caller = fixture.principal(Caller::TeamA).unwrap();

    let issued = block_on(credentials.credential_for(&ConnectorName::new("other"), &caller));

    assert!(
        matches!(issued, Err(CredentialError::Refused(_))),
        "{issued:?}"
    );
}

#[test]
fn the_source_never_shows_its_secret() {
    let credentials = load(GATEWAY_TOKEN.as_bytes()).unwrap();

    let shown = format!("{credentials:?}");

    assert!(!shown.contains(GATEWAY_TOKEN), "{shown}");
    assert!(shown.contains(DOCS), "{shown}");
}

#[test]
fn an_empty_file_is_refused() {
    for contents in [&b""[..], b"\n", b"  \t\r\n"] {
        let refused = load(contents);
        assert!(
            matches!(refused, Err(CredentialFileError::Empty { .. })),
            "{contents:?}: {refused:?}"
        );
    }
}

#[test]
fn a_file_with_a_space_or_control_character_inside_the_token_is_refused_without_naming_it() {
    for contents in [
        "dummy secret-with-space",
        "dummy-secret\nsecond-line",
        "dummy-secret\u{7f}",
        "dummy-sécret",
    ] {
        let refused = load(contents.as_bytes());
        let Err(error @ CredentialFileError::NotAToken { .. }) = refused else {
            panic!("{contents:?}: {refused:?}");
        };
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("dummy"), "{shown}");
    }
}

#[test]
fn a_file_that_is_not_utf_8_is_refused() {
    let refused = load(b"dummy-\xff-token");
    assert!(
        matches!(refused, Err(CredentialFileError::NotAToken { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_file_larger_than_the_limit_is_refused() {
    let size = usize::try_from(MAX_CREDENTIAL_BYTES).unwrap();
    assert!(load(&vec![b'x'; size]).is_ok());
    let refused = load(&vec![b'x'; size + 1]);
    assert!(
        matches!(refused, Err(CredentialFileError::TooLarge { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_missing_file_is_refused() {
    let missing = std::env::temp_dir().join("connector-proxy-test-no-such-file");
    let refused = FileCredentials::load([(ConnectorName::new(DOCS), &missing)]);
    assert!(
        matches!(refused, Err(CredentialFileError::Unreadable { .. })),
        "{refused:?}"
    );
}

#[test]
fn two_files_for_one_connector_are_refused() {
    let first = temporary_file(b"dummy-first");
    let second = temporary_file(b"dummy-second");
    let refused = FileCredentials::load([
        (ConnectorName::new(DOCS), &first),
        (ConnectorName::new(DOCS), &second),
    ]);
    std::fs::remove_file(&first).unwrap();
    std::fs::remove_file(&second).unwrap();
    assert!(
        matches!(refused, Err(CredentialFileError::Duplicate(ref name)) if name.as_str() == DOCS),
        "{refused:?}"
    );
}
