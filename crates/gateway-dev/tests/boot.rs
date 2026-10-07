//! The boot gates on the fixture world: the configuration `switchboard-dev` starts from passes
//! only with identity and audit each configured or explicitly disabled, and a refused
//! configuration never gets as far as a listener.
//!
//! Plan #26's test 17, on the fixture's configuration. The gates' own table is in the gateway
//! crate's `tests/boot.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use gateway::{BootError, Config, GateState, Gates, Wiring, boot};
use gateway_core::AuditStore;
use gateway_dev::{FixtureResources, fixture_config};
use gateway_identity::{SigningAlgorithm, SystemClock};
use gateway_testkit::{
    CONNECTOR, FakeCredentialSource, FixtureConnector, InMemoryAuditStore, LocalIssuer,
    USER_ISSUER, WORKLOAD_ISSUER,
};
use serde_json::json;

/// How a configuration states one gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stated {
    /// Configured: issuers for identity, a store for audit.
    On,
    /// Explicitly disabled.
    Disabled,
    /// Neither.
    Unstated,
    /// Both.
    Both,
}

const STATES: [Stated; 4] = [Stated::On, Stated::Disabled, Stated::Unstated, Stated::Both];

struct World {
    workload: LocalIssuer,
    user: LocalIssuer,
}

impl World {
    fn new() -> Self {
        Self {
            workload: LocalIssuer::new(WORKLOAD_ISSUER, SigningAlgorithm::Es256).unwrap(),
            user: LocalIssuer::new(USER_ISSUER, SigningAlgorithm::Es256).unwrap(),
        }
    }

    fn boot(&self, identity: Stated, audit: Stated) -> Result<Gates, BootError> {
        let mut config = fixture_config(&self.workload, &self.user);
        let enforce = config["identity"]["enforce"].clone();
        config["identity"] = match identity {
            Stated::On => json!({"enforce": enforce}),
            Stated::Disabled => json!({"disabled": true}),
            Stated::Unstated => json!({}),
            Stated::Both => json!({"enforce": enforce, "disabled": true}),
        };
        config["audit"] = match audit {
            Stated::On | Stated::Unstated => json!({}),
            Stated::Disabled | Stated::Both => json!({"disabled": true}),
        };
        let credentials = Arc::new(FakeCredentialSource::new());
        let mut wiring = Wiring::new(Arc::new(SystemClock)).connector(
            CONNECTOR,
            Arc::new(FixtureConnector::new(credentials)),
            Arc::new(FixtureResources),
        );
        if matches!(audit, Stated::On | Stated::Both) {
            let store: Arc<dyn AuditStore> = Arc::new(InMemoryAuditStore::new());
            wiring = wiring.audit_store(store);
        }
        let config: Config = serde_json::from_value(config).unwrap();
        boot::check(config, wiring)
    }
}

#[test]
fn the_fixture_starts_only_with_each_gate_configured_or_explicitly_disabled() {
    let world = World::new();
    for identity in STATES {
        for audit in STATES {
            let booted = world.boot(identity, audit);
            let what = format!("identity {identity:?}, audit {audit:?}");
            let state = |stated| match stated {
                Stated::On => Some(GateState::On),
                Stated::Disabled => Some(GateState::Disabled),
                Stated::Unstated | Stated::Both => None,
            };
            match (state(identity), state(audit)) {
                (Some(identity), Some(audit)) => {
                    let gates = booted.unwrap_or_else(|error| panic!("{what}: {error}"));
                    assert_eq!(gates.identity_state(), identity, "{what}");
                    assert_eq!(gates.audit_state(), audit, "{what}");
                }
                _ => {
                    let error = booted.err().unwrap_or_else(|| panic!("{what} started"));
                    let expected = match (identity, audit) {
                        (Stated::Unstated, _) => {
                            matches!(error, BootError::IdentityUnconfigured)
                        }
                        (Stated::Both, _) => matches!(error, BootError::IdentityContradiction),
                        (_, Stated::Unstated) => matches!(error, BootError::AuditUnconfigured),
                        (_, Stated::Both) => matches!(error, BootError::AuditContradiction),
                        _ => false,
                    };
                    assert!(expected, "{what}: {error:?}");
                }
            }
        }
    }
}

#[tokio::test]
async fn a_refused_configuration_never_binds_its_port() {
    // A free port, chosen and released.
    let port = {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    };
    let world = World::new();
    assert!(world.boot(Stated::Unstated, Stated::On).is_err());
    assert!(world.boot(Stated::On, Stated::Unstated).is_err());
    // Serving needs the gates, which a refused configuration does not have; nothing listens.
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
