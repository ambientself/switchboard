//! An https fetch installs no process-wide crypto provider.
//!
//! The source passes ring to its own TLS client and never installs it as the process default,
//! so the rest of the gateway chooses its own. `ClientConfig::builder()` would read the default
//! and, with only ring built, install it. This file is its own test binary with one test, so no
//! other test installs a provider first.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use gateway_core::Issuer;
use issuer_keys::{FetchOptions, KeySource, SourceFiles};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A JWK set with one RSA key. The modulus is a dummy: parsing a set does not decode it.
const KEYS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"ZHVtbXk","e":"AQAB"}]}"#;

/// A loopback HTTPS server with a certificate for `127.0.0.1` from a CA made for this test,
/// answering every request with [`KEYS`]. Gives its origin and the CA as PEM. Its own config is
/// given ring explicitly, so it installs nothing either.
async fn https_server() -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = params.self_signed(&ca_key).unwrap().pem();
    let signer = rcgen::Issuer::new(params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &signer)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{KEYS}",
                    KEYS.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (origin, ca_pem)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_https_fetch_installs_no_process_default_provider() {
    assert!(CryptoProvider::get_default().is_none());

    let (origin, ca_pem) = https_server().await;
    let directory = std::env::temp_dir().join(format!(
        "issuer-keys-process-provider-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let ca_file = directory.join("ca.pem");
    std::fs::write(&ca_file, ca_pem).unwrap();

    let source = KeySource::with_files(
        &Issuer::new(&origin),
        &format!("{origin}/openid/v1/jwks"),
        &SourceFiles {
            ca_file: Some(ca_file),
            token_file: None,
        },
        FetchOptions::default(),
    )
    .unwrap();
    let fetched = source.fetch().await;
    let _ = std::fs::remove_dir_all(&directory);

    let keys = fetched.unwrap();
    assert_eq!(keys.keys[0].common.key_id.as_deref(), Some("test-key-1"));
    assert!(
        CryptoProvider::get_default().is_none(),
        "an https fetch installed a process-wide crypto provider"
    );
}
