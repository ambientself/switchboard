//! The client: a deadline on every request, and a typed error for each way it can fail.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{request, scratch};
use gateway_core::ErrorKind;
use key_custodian::{ClientError, CustodianClient, Failure, Refusal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

#[tokio::test]
async fn a_custodian_that_does_not_answer_is_given_up_at_the_deadline() {
    let dir = scratch();
    let socket = dir.join("c.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let held = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });
    let client = CustodianClient::new(&socket, Duration::from_millis(300));
    let error = client.token(&request()).await.unwrap_err();
    assert!(matches!(error, ClientError::Deadline(_)), "{error:?}");
    assert_eq!(error.error_kind(), ErrorKind::Other);
    held.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn no_custodian_is_unavailable() {
    let dir = scratch();
    let client = CustodianClient::new(dir.join("none.sock"), Duration::from_secs(1));
    let error = client.token(&request()).await.unwrap_err();
    assert!(matches!(error, ClientError::Unavailable(_)), "{error:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A one-connection server that answers `answer` to whatever it is sent.
async fn answering(answer: &'static [u8]) -> (CustodianClient, std::path::PathBuf) {
    let dir = scratch();
    let socket = dir.join("c.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer).await;
        stream.write_all(answer).await.unwrap();
    });
    (CustodianClient::new(&socket, Duration::from_secs(2)), dir)
}

#[tokio::test]
async fn each_answer_is_typed() {
    let (client, dir) =
        answering(b"{\"refused\":{\"reason\":\"rate_limited\",\"message\":\"later\"}}\n").await;
    let error = client.token(&request()).await.unwrap_err();
    assert!(
        matches!(&error, ClientError::Refused { reason: Refusal::RateLimited, message } if message == "later"),
        "{error:?}"
    );
    assert_eq!(error.error_kind(), ErrorKind::CustodianRefusal);
    let _ = std::fs::remove_dir_all(&dir);

    let (client, dir) =
        answering(b"{\"failed\":{\"reason\":\"vendor_refused\",\"message\":\"422\"}}\n").await;
    let error = client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Failed {
                reason: Failure::VendorRefused,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.error_kind(), ErrorKind::VendorRefusal);
    let _ = std::fs::remove_dir_all(&dir);

    let (client, dir) = answering(b"{\"issued\":{\"token\":\"t\",\"expires_at\":7}}\n").await;
    let token = client.token(&request()).await.unwrap();
    assert_eq!(token.expose(), "t");
    assert_eq!(token.expires_at(), 7);
    let _ = std::fs::remove_dir_all(&dir);

    let (client, dir) = answering(b"{\"something\":1}\n").await;
    let error = client.token(&request()).await.unwrap_err();
    assert!(matches!(error, ClientError::Protocol), "{error:?}");
    let _ = std::fs::remove_dir_all(&dir);

    let (client, dir) = answering(b"").await;
    let error = client.token(&request()).await.unwrap_err();
    assert!(matches!(error, ClientError::Unavailable(_)), "{error:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
