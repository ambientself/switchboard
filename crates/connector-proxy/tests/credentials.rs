//! The file-backed credential source: what it reads, what it refuses, that it reads the file
//! again on every call, and that its secret shows up in no handle, no debug output and no
//! error.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::{
    GATEWAY_TOKEN, Harness, ProjectedVolume, Scripted, Step, TemporaryFile, json_response,
    temporary_file, text_result, upstream,
};
use connector_proxy::{
    CredentialFileError, FileCredentials, MAX_CREDENTIAL_BYTES, ProxyConnector, outcome,
};
use gateway_core::audit::Answer;
use gateway_core::{ConnectorName, CredentialError, CredentialSource};
use gateway_testkit::{CONNECTOR, Caller, Fixture, READ_TOOL, block_on};
use serde_json::json;

const DOCS: &str = "docs";

/// A second dummy credential, the one a rotation puts in place of [`GATEWAY_TOKEN`].
const ROTATED_TOKEN: &str = "dummy-gateway-credential-after-rotation";

fn load(contents: &[u8]) -> Result<FileCredentials, CredentialFileError> {
    let path = temporary_file(contents);
    let loaded = FileCredentials::load([(ConnectorName::new(DOCS), &path)]);
    std::fs::remove_file(&path).unwrap();
    loaded
}

/// A source loaded from a file holding `contents`, and the file, which the source reads again
/// on every call.
fn held(contents: &[u8]) -> (FileCredentials, TemporaryFile) {
    let file = TemporaryFile::new(contents);
    let loaded = FileCredentials::load([(ConnectorName::new(DOCS), file.path())]).unwrap();
    (loaded, file)
}

#[test]
fn a_handle_is_issued_for_a_configured_connector_and_carries_only_a_label() {
    let (credentials, _file) = held(format!("{GATEWAY_TOKEN}\n").as_bytes());
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
    let (credentials, _file) = held(GATEWAY_TOKEN.as_bytes());
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
    let (credentials, _file) = held(GATEWAY_TOKEN.as_bytes());

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

/// A connector to `server` for the fixture's connector, with the credential in `path`.
fn connector_with(server: &Scripted, path: &std::path::Path) -> ProxyConnector {
    let credentials = FileCredentials::load([(ConnectorName::new(CONNECTOR), path)]).unwrap();
    ProxyConnector::new(upstream(server.url()), Arc::new(credentials)).unwrap()
}

async fn answering_server() -> Scripted {
    Scripted::start(|request| vec![Step::Write(json_response(&text_result(request, "fine")))]).await
}

fn arguments() -> serde_json::Value {
    json!({"project": "atlas", "document": "plan"})
}

#[tokio::test]
async fn a_token_the_kubelet_rotates_is_the_one_sent_next() {
    let server = answering_server().await;
    let mut volume = ProjectedVolume::new(GATEWAY_TOKEN);
    let connector = connector_with(&server, &volume.token());
    let harness = Harness::new();

    let before = harness.call(&connector, READ_TOOL, arguments()).await;
    volume.rotate(ROTATED_TOKEN);
    let after = harness.call(&connector, READ_TOOL, arguments()).await;

    assert!(matches!(before, Answer::Ok(_)), "{before:?}");
    assert!(matches!(after, Answer::Ok(_)), "{after:?}");
    let sent: Vec<Option<String>> = server
        .received()
        .iter()
        .map(|request| request.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(
        sent,
        [
            Some(format!("Bearer {GATEWAY_TOKEN}")),
            Some(format!("Bearer {ROTATED_TOKEN}")),
        ]
    );
}

/// Runs one call to `server` with `connector` and checks it was refused for its credential, that
/// nothing reached the server, and that neither the answer nor the audit rows hold `token`.
async fn assert_refused_unsent(server: &Scripted, connector: &ProxyConnector, token: &str) {
    let harness = Harness::new();

    let answer = harness.call(connector, READ_TOOL, arguments()).await;

    assert_eq!(answer, Answer::Refused(outcome::NO_CREDENTIAL.to_owned()));
    assert!(server.received().is_empty(), "{:?}", server.received());
    let rows = format!("{:?}", harness.rows());
    assert!(!rows.contains(token), "{rows}");
}

#[tokio::test]
async fn a_file_removed_after_boot_refuses_the_call_and_sends_nothing() {
    let server = answering_server().await;
    let file = TemporaryFile::new(format!("{GATEWAY_TOKEN}\n").as_bytes());
    let connector = connector_with(&server, file.path());
    let credentials =
        FileCredentials::load([(ConnectorName::new(CONNECTOR), file.path())]).unwrap();
    let path = file.path().to_owned();

    drop(file);

    assert_refused_unsent(&server, &connector, GATEWAY_TOKEN).await;
    assert_refusal_names_the_file(&credentials, &path, GATEWAY_TOKEN);
}

#[tokio::test]
async fn a_file_grown_past_the_limit_after_boot_refuses_the_call_and_sends_nothing() {
    let server = answering_server().await;
    let file = TemporaryFile::new(format!("{GATEWAY_TOKEN}\n").as_bytes());
    let connector = connector_with(&server, file.path());
    let credentials =
        FileCredentials::load([(ConnectorName::new(CONNECTOR), file.path())]).unwrap();
    let size = usize::try_from(MAX_CREDENTIAL_BYTES).unwrap() + 1;
    let grown = GATEWAY_TOKEN.repeat(size / GATEWAY_TOKEN.len() + 1);

    std::fs::write(file.path(), &grown.as_bytes()[..size]).unwrap();

    assert_refused_unsent(&server, &connector, GATEWAY_TOKEN).await;
    assert_refusal_names_the_file(&credentials, file.path(), GATEWAY_TOKEN);
}

/// Asks `credentials` for the fixture connector's credential, and checks that it is refused
/// with a reason that names the connector and `path` and does not hold `token`.
fn assert_refusal_names_the_file(
    credentials: &FileCredentials,
    path: &std::path::Path,
    token: &str,
) {
    let fixture = Fixture::new().unwrap();
    let caller = fixture.principal(Caller::TeamA).unwrap();

    let issued = block_on(credentials.credential_for(&ConnectorName::new(CONNECTOR), &caller));

    let Err(CredentialError::Refused(reason)) = issued else {
        panic!("{issued:?}");
    };
    assert!(reason.contains(CONNECTOR), "{reason}");
    assert!(reason.contains(&path.display().to_string()), "{reason}");
    assert!(!reason.contains(token), "{reason}");
}
