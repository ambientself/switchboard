//! What a proxied server's configuration must hold before a connector is built for it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{GATEWAY_TOKEN, credentials, credentials_for, upstream};
use connector_proxy::{
    DEFAULT_DEADLINE, DEFAULT_MAX_RESPONSE_BYTES, Destination, ProxyConnector, Upstream,
    UpstreamError,
};
use gateway_core::{ConnectorName, ToolName};
use gateway_testkit::{CONNECTOR, READ_TOOL};

const URL: &str = "http://127.0.0.1:9/mcp";

fn refusal(upstream: Upstream) -> UpstreamError {
    ProxyConnector::new(upstream, credentials()).unwrap_err()
}

#[test]
fn a_new_upstream_has_the_default_bounds() {
    let upstream = Upstream::new(CONNECTOR, URL);
    assert_eq!(upstream.deadline, DEFAULT_DEADLINE);
    assert_eq!(upstream.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(5));
    assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 65_536);
}

/// A server whose destination is never set is held to the stricter class (decision 0013,
/// section 3): a plain `http` URL is refused, so a caller that forgets to pass an entry's
/// destination fails closed.
#[test]
fn a_new_upstream_is_held_to_the_public_class() {
    let read = ToolName::parse(READ_TOOL).unwrap();
    let upstream = Upstream::new(CONNECTOR, URL).tool(read, "read");
    assert_eq!(upstream.destination, Destination::Public);
    assert_eq!(
        refusal(upstream),
        UpstreamError::HttpNotInCluster(ConnectorName::new(CONNECTOR))
    );
}

#[test]
fn a_complete_configuration_is_accepted() {
    let connector = ProxyConnector::new(upstream(URL), credentials()).unwrap();
    assert_eq!(connector.connector(), &ConnectorName::new(CONNECTOR));
}

#[test]
fn only_an_http_or_https_url_with_a_host_is_accepted() {
    for url in [
        "ftp://127.0.0.1/mcp",
        "wss://127.0.0.1/mcp",
        "/mcp",
        "127.0.0.1:9",
        "http://user:dummy-password@127.0.0.1:9/mcp",
        "http://user@127.0.0.1:9/mcp",
        "not a url",
    ] {
        let refused = refusal(upstream(url));
        assert!(
            matches!(refused, UpstreamError::BadUrl { .. }),
            "{url}: {refused:?}"
        );
    }
}

#[test]
fn a_server_with_no_tools_is_refused() {
    assert_eq!(
        refusal(common::in_cluster(CONNECTOR, URL)),
        UpstreamError::NoTools(ConnectorName::new(CONNECTOR))
    );
}

#[test]
fn an_empty_upstream_name_is_refused() {
    let read = ToolName::parse(READ_TOOL).unwrap();
    assert_eq!(
        refusal(common::in_cluster(CONNECTOR, URL).tool(read.clone(), "")),
        UpstreamError::EmptyUpstreamName(read)
    );
}

#[test]
fn a_zero_deadline_is_refused() {
    assert_eq!(
        refusal(Upstream {
            deadline: Duration::ZERO,
            ..upstream(URL)
        }),
        UpstreamError::ZeroDeadline(ConnectorName::new(CONNECTOR))
    );
}

#[test]
fn a_zero_cap_is_refused() {
    assert_eq!(
        refusal(Upstream {
            max_response_bytes: 0,
            ..upstream(URL)
        }),
        UpstreamError::ZeroCap(ConnectorName::new(CONNECTOR))
    );
}

#[test]
fn a_connector_without_a_credential_is_refused_at_build() {
    let refused =
        ProxyConnector::new(upstream(URL), credentials_for("other", GATEWAY_TOKEN)).unwrap_err();
    assert_eq!(
        refused,
        UpstreamError::NoCredential(ConnectorName::new(CONNECTOR))
    );
}

#[test]
fn the_connector_never_shows_its_secret() {
    let connector = ProxyConnector::new(upstream(URL), credentials()).unwrap();
    let shown = format!("{connector:?}");
    assert!(!shown.contains(GATEWAY_TOKEN), "{shown}");
    assert!(shown.contains(URL), "{shown}");
}
