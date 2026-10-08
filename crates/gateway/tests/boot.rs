//! The boot gates, design section 12, over the testkit's world: its policy, its connector and
//! two local issuers whose keys are written into the configuration as a deployment would.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use gateway::{
    BootError, CatalogError, Config, DISABLED_ROW, GateState, Gates, NO_PROFILE, ResourceAdapter,
    SelectorError, Wiring, boot,
};
use gateway_core::audit::{self, Answer, Begun, RequestMetadata};
use gateway_core::{
    ApprovedTool, AuditStore, CallContext, CallerContext, RequestedTool, Resources, ToolName,
    decide,
};
use gateway_identity::SigningAlgorithm;
use gateway_identity::{ConfigError, Verification};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME, DRAFT_TOOL, FIXTURE_NOW,
    FakeCredentialSource, Fixture, FixtureConnector, GROUP_G, InMemoryAuditStore, LocalIssuer,
    PROFILE_TEAM_A, PROFILE_TEAM_B, PROFILE_USER, READ_TOOL, SCOPED_READ_TOOL, SURFACE_READ,
    SteppableClock, TEAM_A, TEAM_A_DOCUMENT, TEAM_A_SUBJECT, TEAM_B, TEAM_B_SUBJECT, USER_ISSUER,
    USER_SUBJECT, WORKLOAD_ISSUER, WRITE_TOOL, block_on, policy_data,
};
use serde_json::{Value, json};

/// The fixture connector's adapter: the testkit's `resources_of`, chosen by the approved tool.
struct FixtureResources;

impl ResourceAdapter for FixtureResources {
    fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
        FixtureConnector::resources_of(tool.name.as_str(), arguments)
    }
}

struct World {
    workload_issuer: LocalIssuer,
    user_issuer: LocalIssuer,
    clock: SteppableClock,
    store: Arc<InMemoryAuditStore>,
    connector: Arc<FixtureConnector>,
}

impl World {
    fn new() -> Self {
        Self {
            workload_issuer: LocalIssuer::new(WORKLOAD_ISSUER, SigningAlgorithm::Es256).unwrap(),
            user_issuer: LocalIssuer::new(USER_ISSUER, SigningAlgorithm::Es256).unwrap(),
            clock: SteppableClock::at(FIXTURE_NOW),
            store: Arc::new(InMemoryAuditStore::new()),
            connector: Arc::new(FixtureConnector::new(Arc::new(FakeCredentialSource::new()))),
        }
    }

    fn issuer(issuer: &LocalIssuer, kind: Value) -> Value {
        json!({
            "issuer": issuer.issuer(),
            "audiences": [AUDIENCE],
            "kind": kind,
            "algorithm": "ES256",
            "keys": serde_json::to_value(issuer.jwk_set()).unwrap(),
            "max_lifetime_secs": DEFAULT_MAX_LIFETIME,
            "leeway_secs": DEFAULT_LEEWAY,
        })
    }

    /// A configuration that starts, with identity enforced against both local issuers and
    /// audit on, once the wiring supplies a store.
    fn config(&self) -> Value {
        let definition = |name: &str| {
            json!({
                "name": name,
                "description": format!("The fixture's {name}."),
                "input_schema": {"type": "object", "properties": {"document": {"type": "string"}}},
            })
        };
        json!({
            "deployment": "boot-test",
            "identity": {"enforce": [
                Self::issuer(&self.workload_issuer, json!({"workload": {"subjects": {
                    TEAM_A_SUBJECT: TEAM_A,
                    TEAM_B_SUBJECT: TEAM_B,
                }}})),
                Self::issuer(&self.user_issuer, json!({"user": {}})),
            ]},
            "audit": {},
            "http": {"allowed_hosts": ["localhost"], "allowed_origins": ["http://localhost"]},
            "policy": policy_data(),
            "catalog": [
                definition(READ_TOOL),
                definition(DRAFT_TOOL),
                definition(WRITE_TOOL),
                definition(SCOPED_READ_TOOL),
            ],
            "profiles": {
                "workloads": [
                    {"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": PROFILE_TEAM_A},
                    {"issuer": WORKLOAD_ISSUER, "team": TEAM_B, "profile": PROFILE_TEAM_B},
                ],
                "users": [{"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_USER}],
            },
        })
    }

    /// Wiring with the fixture connector and no audit store.
    fn wiring_without_store(&self) -> Wiring {
        Wiring::new(Arc::new(self.clock.clone())).connector(
            CONNECTOR,
            self.connector.clone(),
            Arc::new(FixtureResources),
        )
    }

    fn wiring(&self) -> Wiring {
        self.wiring_without_store().audit_store(self.store.clone())
    }

    fn boot(&self, config: Value, wiring: Wiring) -> Result<Gates, BootError> {
        let config: Config = serde_json::from_value(config).unwrap();
        boot::check(config, wiring)
    }

    fn token(&self, subject: &str) -> String {
        self.workload_issuer
            .workload_token(subject, AUDIENCE, gateway_identity::Clock::now(&self.clock))
            .build()
    }

    fn user_token(&self, groups: &[&str]) -> String {
        self.user_issuer
            .user_token(
                USER_SUBJECT,
                AUDIENCE,
                groups,
                gateway_identity::Clock::now(&self.clock),
            )
            .build()
    }
}

/// Sets `path` (dotted; a number steps into an array) in `config` to `value`, or removes it if
/// `value` is `None`. The last step names a key of an object.
fn set(config: &mut Value, path: &str, value: Option<Value>) {
    let mut keys: Vec<&str> = path.split('.').collect();
    let last = keys.pop().unwrap();
    let mut target = config;
    for key in keys {
        target = match key.parse::<usize>() {
            Ok(index) => target.get_mut(index),
            Err(_) => target.get_mut(key),
        }
        .unwrap();
    }
    let object = target.as_object_mut().unwrap();
    match value {
        Some(value) => object.insert(last.to_owned(), value),
        None => object.remove(last),
    };
}

// --- The identity and audit gates ----------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stated {
    Configured,
    Disabled,
    Neither,
    Both,
}

const STATES: [Stated; 4] = [
    Stated::Configured,
    Stated::Disabled,
    Stated::Neither,
    Stated::Both,
];

#[test]
fn identity_and_audit_each_start_configured_or_disabled_and_refuse_neither_or_both() {
    let world = World::new();
    for identity in STATES {
        for audit in STATES {
            let mut config = world.config();
            let issuers = config["identity"]["enforce"].clone();
            config["identity"] = match identity {
                Stated::Configured => json!({"enforce": issuers}),
                Stated::Disabled => json!({"disabled": true}),
                Stated::Neither => json!({}),
                Stated::Both => json!({"enforce": issuers, "disabled": true}),
            };
            let disabled = matches!(audit, Stated::Disabled | Stated::Both);
            config["audit"] = json!({"disabled": disabled});
            let supplied = matches!(audit, Stated::Configured | Stated::Both);
            let wiring = if supplied {
                world.wiring()
            } else {
                world.wiring_without_store()
            };
            let case = format!("identity {identity:?}, audit {audit:?}");
            let booted = world.boot(config, wiring);
            match (identity, audit) {
                (Stated::Neither, _) => {
                    assert!(
                        matches!(booted, Err(BootError::IdentityUnconfigured)),
                        "{case}: {booted:?}"
                    );
                }
                (Stated::Both, _) => {
                    assert!(
                        matches!(booted, Err(BootError::IdentityContradiction)),
                        "{case}: {booted:?}"
                    );
                }
                (_, Stated::Neither) => {
                    assert!(
                        matches!(booted, Err(BootError::AuditUnconfigured)),
                        "{case}: {booted:?}"
                    );
                }
                (_, Stated::Both) => {
                    assert!(
                        matches!(booted, Err(BootError::AuditContradiction)),
                        "{case}: {booted:?}"
                    );
                }
                _ => {
                    let gates = booted.unwrap_or_else(|error| panic!("{case}: {error}"));
                    let state = |stated| match stated {
                        Stated::Configured => GateState::On,
                        _ => GateState::Disabled,
                    };
                    assert_eq!(gates.identity_state(), state(identity), "{case}");
                    assert_eq!(gates.audit_state(), state(audit), "{case}");
                    let ours: Arc<dyn AuditStore> = world.store.clone();
                    assert_eq!(
                        Arc::ptr_eq(gates.audit_store(), &ours),
                        audit == Stated::Configured,
                        "{case}: the supplied store must be used exactly when audit is on"
                    );
                }
            }
        }
    }
}

#[test]
fn a_gate_written_out_as_off_is_still_unconfigured() {
    let world = World::new();
    for identity in [
        json!({}),
        json!({"disabled": false}),
        json!({"enforce": null}),
    ] {
        let mut config = world.config();
        config["identity"] = identity.clone();
        let booted = world.boot(config, world.wiring());
        assert!(
            matches!(booted, Err(BootError::IdentityUnconfigured)),
            "{identity}: {booted:?}"
        );
    }
    let mut config = world.config();
    set(&mut config, "identity", None);
    assert!(matches!(
        world.boot(config, world.wiring()),
        Err(BootError::IdentityUnconfigured)
    ));

    let mut config = world.config();
    set(&mut config, "audit", None);
    let booted = world.boot(config, world.wiring_without_store());
    assert!(
        matches!(booted, Err(BootError::AuditUnconfigured)),
        "{booted:?}"
    );
}

#[test]
fn enforcing_identity_against_no_issuer_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["identity"] = json!({"enforce": []});
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(booted, Err(BootError::Identity(ConfigError::NoIssuers))),
        "{booted:?}"
    );
}

#[test]
fn an_issuer_the_identity_crate_refuses_is_refused_at_boot() {
    let world = World::new();
    let mut config = world.config();
    config["identity"]["enforce"][0]["audiences"] = json!([]);
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::Identity(ConfigError::NoAudience(issuer))) if issuer.as_str() == WORKLOAD_ISSUER),
        "{booted:?}"
    );
}

#[test]
fn an_issuer_whose_keys_are_not_a_jwk_set_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["identity"]["enforce"][1]["keys"] = json!({"not": "a key set"});
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::IssuerKeys { issuer, .. }) if issuer.as_str() == USER_ISSUER),
        "{booted:?}"
    );
}

#[test]
fn configuration_with_an_unknown_field_is_not_read() {
    let world = World::new();
    // The configuration as written is read, so each refusal below is for the added key.
    assert!(serde_json::from_value::<Config>(world.config()).is_ok());
    for path in [
        "audit.disable",
        "identity.enabled",
        "http.allowed_host",
        "policy_revision",
        // One per struct the gateway's own sections nest, down to each issuer and each rule. The
        // policy section is gateway-core's snapshot and is not probed here yet (#41).
        "identity.enforce.0.audience",
        "identity.enforce.1.max_lifetime",
        "identity.enforce.0.kind.workload.subject",
        "identity.enforce.1.kind.user.groups",
        "catalog.0.schema",
        "profiles.default",
        "profiles.workloads.0.group",
        "profiles.users.0.team",
    ] {
        let mut config = world.config();
        set(&mut config, path, Some(json!(true)));
        assert!(
            serde_json::from_value::<Config>(config).is_err(),
            "{path} was accepted"
        );
    }
}

#[test]
fn config_reads_from_json_text() {
    let world = World::new();
    let config = Config::from_json(&world.config().to_string()).unwrap();
    assert_eq!(config.deployment.as_str(), "boot-test");
}

// --- What the gates hold once they pass ----------------------------------------------------

#[test]
fn passed_gates_hold_what_the_configuration_and_wiring_gave() {
    let world = World::new();
    let gates = world.boot(world.config(), world.wiring()).unwrap();
    assert_eq!(gates.deployment().as_str(), "boot-test");
    assert!(gates.allowed_hosts().contains("localhost"));
    assert!(gates.allowed_origins().contains("http://localhost"));
    assert_eq!(gates.snapshot().revision().as_str(), "fixture-1");
    let read = ToolName::parse(READ_TOOL).unwrap();
    assert_eq!(
        gates
            .policy()
            .catalog()
            .definition(&read)
            .map(|d| d.description.as_str()),
        Some("The fixture's fixture__read.")
    );
    let fixture = CONNECTOR.into();
    let ours: Arc<dyn gateway_core::Connector> = world.connector.clone();
    assert!(Arc::ptr_eq(gates.connector(&fixture).unwrap(), &ours));
    let snapshot = gates.snapshot();
    let tool = snapshot.tool(&read).unwrap();
    let adapter = gates.resource_adapter(&tool.connector).unwrap();
    assert_eq!(
        adapter.resources(tool, &Fixture::arguments_naming(TEAM_A_DOCUMENT)),
        FixtureConnector::resources_of(READ_TOOL, &Fixture::arguments_naming(TEAM_A_DOCUMENT))
    );
    assert!(gates.connector(&"other".into()).is_none());
    assert!(gates.resource_adapter(&"other".into()).is_none());
}

#[test]
fn passed_gates_select_profiles_for_callers_their_identity_gate_proves() {
    let world = World::new();
    let gates = world.boot(world.config(), world.wiring()).unwrap();
    let profile_of = |token: &str| match gates.identity().check(Some(token)) {
        Verification::Proved(principal) => {
            gates.policy().select(principal.get()).as_str().to_owned()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(profile_of(&world.token(TEAM_A_SUBJECT)), PROFILE_TEAM_A);
    assert_eq!(profile_of(&world.token(TEAM_B_SUBJECT)), PROFILE_TEAM_B);
    assert_eq!(profile_of(&world.user_token(&[GROUP_G])), PROFILE_USER);
    // The testkit's stand-in selector reads only the first group; this one reads them all.
    assert_eq!(
        profile_of(&world.user_token(&["a-first-group", GROUP_G])),
        PROFILE_USER
    );
    assert_eq!(profile_of(&world.user_token(&["unlisted"])), NO_PROFILE);
}

#[test]
fn with_audit_disabled_an_allowed_call_runs_and_nothing_is_recorded() {
    let world = World::new();
    let mut config = world.config();
    config["audit"] = json!({"disabled": true});
    let gates = world.boot(config, world.wiring_without_store()).unwrap();
    assert_eq!(gates.audit_state(), GateState::Disabled);

    let Verification::Proved(principal) =
        gates.identity().check(Some(&world.token(TEAM_A_SUBJECT)))
    else {
        panic!("team A's token was refused");
    };
    let arguments = Fixture::arguments_naming(TEAM_A_DOCUMENT);
    let call = CallContext {
        caller: CallerContext {
            profile: gates.policy().select(principal.get()),
            principal,
            delegation: None,
            surface: SURFACE_READ.into(),
            deployment: gates.deployment().clone(),
        },
        tool: RequestedTool::new(READ_TOOL),
        resources: FixtureConnector::resources_of(READ_TOOL, &arguments),
    };
    let decision = decide(&gates.snapshot(), &call);
    let store = gates.audit_store().as_ref();
    let begun = block_on(audit::begin(
        store,
        decision,
        arguments,
        RequestMetadata::default(),
    ));
    let Ok(Begun::Allowed(guard)) = begun else {
        panic!("{begun:?}");
    };
    assert_eq!(guard.row().as_str(), DISABLED_ROW);
    let connector = gates.connector(&guard.tool().connector).unwrap().clone();
    let ran = block_on(audit::run(connector.as_ref(), guard));
    let finished = block_on(audit::finish(store, ran, 0));
    assert!(
        matches!(finished.answer(), Answer::Ok(_)),
        "{:?}",
        finished.answer()
    );
    assert!(finished.failure().is_none());
    assert_eq!(world.connector.received().len(), 1);
    assert!(world.store.rows().is_empty());
}

// --- HTTP, policy and tool definitions -----------------------------------------------------

#[test]
fn no_allowed_host_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["http"]["allowed_hosts"] = json!([]);
    assert!(matches!(
        world.boot(config, world.wiring()),
        Err(BootError::NoAllowedHosts)
    ));
}

#[test]
fn policy_the_core_refuses_is_refused_at_boot() {
    let world = World::new();
    let mut config = world.config();
    config["policy"]["surfaces"][0]["tools"] = json!([READ_TOOL, "fixture__unapproved"]);
    let booted = world.boot(config, world.wiring());
    assert!(matches!(booted, Err(BootError::Policy(_))), "{booted:?}");
}

#[test]
fn an_approved_tool_without_a_definition_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["catalog"].as_array_mut().unwrap().remove(1);
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::Catalog(CatalogError::Missing(tool))) if tool.as_str() == DRAFT_TOOL),
        "{booted:?}"
    );
}

#[test]
fn an_approved_tool_on_no_surface_still_needs_a_definition() {
    let world = World::new();
    let mut config = world.config();
    let tools = config["policy"]["tools"].as_array_mut().unwrap();
    tools.push(json!({"name": "spare__read", "classification": "read", "connector": CONNECTOR, "resources": "no_resources"}));
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::Catalog(CatalogError::Missing(tool))) if tool.as_str() == "spare__read"),
        "{booted:?}"
    );
}

#[test]
fn a_definition_for_an_unapproved_tool_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["catalog"].as_array_mut().unwrap().push(json!({
        "name": "fixture__delete", "description": "Not approved.", "input_schema": {"type": "object"},
    }));
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::Catalog(CatalogError::NotApproved(tool))) if tool.as_str() == "fixture__delete"),
        "{booted:?}"
    );
}

// --- Connectors ----------------------------------------------------------------------------

#[test]
fn a_served_tool_whose_connector_is_not_registered_is_refused() {
    let world = World::new();
    let wiring = Wiring::new(Arc::new(world.clock.clone())).audit_store(world.store.clone());
    let booted = world.boot(world.config(), wiring);
    assert!(
        matches!(&booted, Err(BootError::UnregisteredConnector { connector, .. }) if connector.as_str() == CONNECTOR),
        "{booted:?}"
    );
}

#[test]
fn a_connector_registered_under_another_name_does_not_serve_the_tool() {
    let world = World::new();
    let wiring = Wiring::new(Arc::new(world.clock.clone()))
        .audit_store(world.store.clone())
        .connector(
            "fixture-two",
            world.connector.clone(),
            Arc::new(FixtureResources),
        );
    let booted = world.boot(world.config(), wiring);
    assert!(
        matches!(&booted, Err(BootError::UnregisteredConnector { connector, .. }) if connector.as_str() == CONNECTOR),
        "{booted:?}"
    );
}

#[test]
fn an_approved_tool_on_no_surface_needs_no_connector() {
    let world = World::new();
    let mut config = world.config();
    config["policy"]["tools"].as_array_mut().unwrap().push(json!({
        "name": "spare__read", "classification": "read", "connector": "unregistered", "resources": "no_resources",
    }));
    config["catalog"].as_array_mut().unwrap().push(json!({
        "name": "spare__read", "description": "Spare.", "input_schema": {"type": "object"},
    }));
    let booted = world.boot(config, world.wiring());
    assert!(booted.is_ok(), "{booted:?}");
}

#[test]
fn a_connector_registered_twice_is_refused() {
    let world = World::new();
    let wiring = world.wiring().connector(
        CONNECTOR,
        world.connector.clone(),
        Arc::new(FixtureResources),
    );
    let booted = world.boot(world.config(), wiring);
    assert!(
        matches!(&booted, Err(BootError::DuplicateConnector(name)) if name.as_str() == CONNECTOR),
        "{booted:?}"
    );
}

#[test]
fn a_proxied_connector_needs_the_policy_to_come_from_the_registry() {
    // Nothing in this configuration reads a proxied server's arguments, so it is refused.
    let world = World::new();
    let wiring = world.wiring().proxied("proxied", world.connector.clone());
    let booted = world.boot(world.config(), wiring);
    assert!(
        matches!(&booted, Err(BootError::ProxiedWithoutRegistry(name)) if name.as_str() == "proxied"),
        "{booted:?}"
    );
}

// --- Profile selection ---------------------------------------------------------------------

#[test]
fn two_rules_for_one_key_are_refused() {
    let world = World::new();
    let mut config = world.config();
    config["profiles"]["users"]
        .as_array_mut()
        .unwrap()
        .push(json!({"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_TEAM_B}));
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(
            booted,
            Err(BootError::Selector(SelectorError::DuplicateUserRule { .. }))
        ),
        "{booted:?}"
    );
}

#[test]
fn a_rule_selecting_a_profile_the_policy_lacks_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["profiles"]["workloads"][1]["profile"] = json!("workload-misspelt");
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(&booted, Err(BootError::UnknownProfile(profile)) if profile.as_str() == "workload-misspelt"),
        "{booted:?}"
    );
}

#[test]
fn a_policy_that_defines_the_reserved_profile_is_refused() {
    let world = World::new();
    let mut config = world.config();
    config["policy"]["profiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": NO_PROFILE, "classifications": ["read"], "requires_delegation": false,
        }));
    let booted = world.boot(config, world.wiring());
    assert!(
        matches!(booted, Err(BootError::ReservedProfile)),
        "{booted:?}"
    );
}

#[test]
fn a_rule_must_name_a_configured_issuer_of_its_kind() {
    let world = World::new();
    let cases = [
        ("workloads", USER_ISSUER, "workload"),
        ("workloads", "https://unconfigured.example.test", "workload"),
        ("users", WORKLOAD_ISSUER, "user"),
        ("users", "https://unconfigured.example.test", "user"),
    ];
    for (rules, issuer, expected) in cases {
        let mut config = world.config();
        config["profiles"][rules][0]["issuer"] = json!(issuer);
        let booted = world.boot(config, world.wiring());
        assert!(
            matches!(&booted, Err(BootError::RuleIssuerNotConfigured { kind, issuer: named })
                if *kind == expected && named.as_str() == issuer),
            "{rules} naming {issuer}: {booted:?}"
        );
    }
}

#[test]
fn with_identity_disabled_rule_issuers_are_not_checked() {
    let world = World::new();
    let mut config = world.config();
    config["identity"] = json!({"disabled": true});
    config["profiles"]["users"][0]["issuer"] = json!("https://unconfigured.example.test");
    let booted = world.boot(config, world.wiring());
    assert!(booted.is_ok(), "{booted:?}");
}

#[test]
fn gates_can_be_shared_between_threads() {
    fn shared<T: Send + Sync + 'static>() {}
    shared::<Gates>();
}
