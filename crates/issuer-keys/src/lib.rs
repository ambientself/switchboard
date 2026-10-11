//! Fetching one issuer's signing keys.
//!
//! A [`KeySource`] fetches the JWK set of one configured issuer from a URL on the issuer's own
//! origin. It returns `jsonwebtoken`'s [`JwkSet`](jsonwebtoken::jwk::JwkSet), the type the
//! identity crate's `Identity::replace_keys` takes; this crate puts nothing in force itself, runs
//! no timer, and is never used by the identity crate, which stays offline.
//!
//! The source rules are checked when the source is built, so a deployment with a bad keys URL
//! does not start:
//!
//! - **The URL is configured, never discovered.** The keys URL is given explicitly beside the
//!   issuer. There is no OIDC discovery, and nothing a token says (`jku`, `x5u`, an embedded
//!   `jwk`, or `iss`) is ever fetched. For a Kubernetes issuer the path is `/openid/v1/jwks`.
//! - **The issuer's own origin.** The keys URL has the same scheme, host and port as the issuer
//!   parsed as a URL, so `https` is required unless the issuer itself is `http`. It carries no
//!   user name, password or fragment.
//! - **Only the configured CAs.** An `https` keys URL needs a CA file, a PEM bundle read when
//!   the source is built; a file that cannot be read, is not PEM or holds no certificate is
//!   refused. Those CAs are the only ones trusted: no roots are compiled in and none are read
//!   from the system. The certificate is verified against the keys URL's host, a DNS name or
//!   an IP address. The TLS client is rustls with ring, passed to the client itself and never
//!   installed as the process default, and offers only HTTP/1.1. An `http` keys URL takes no
//!   CA file.
//! - **A token, if configured, to the keys URL only.** A token file is read again on every
//!   fetch, since the kubelet rotates a projected token in place, and its token is sent as
//!   `Authorization: Bearer` with that one request. It is refused beside an `http` keys URL.
//!   The token is kept nowhere and appears in no error and no `Debug` output.
//!
//! Each fetch is one `GET`, bounded inside this crate:
//!
//! - **A deadline**, 5 s by default ([`DEFAULT_DEADLINE`]), over the whole exchange: connecting,
//!   the TLS handshake, the response head, and the last byte of the body.
//! - **A body cap**, 256 KiB by default ([`DEFAULT_MAX_BODY_BYTES`]), enforced from the declared
//!   length if there is one and otherwise as the body arrives, so an oversized body is never
//!   read in full.
//! - **No redirect.** Any status other than `200` is an error, and a `3xx` is never followed.
//!   No proxy is read from the environment.
//!
//! The body must parse as a JWK set. Every error names its cause and none echoes the body.

#![forbid(unsafe_code)]

mod source;

pub use source::{
    DEFAULT_DEADLINE, DEFAULT_MAX_BODY_BYTES, FetchError, FetchOptions, KeySource, MAX_TOKEN_BYTES,
    Position, SourceError, SourceFiles, TokenFault,
};
