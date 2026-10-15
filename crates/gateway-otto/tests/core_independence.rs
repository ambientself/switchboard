//! What is specific to Otto stays in this crate: no crate of the core depends on it (design
//! section 1). The core is identity, policy, audit, credentials, connectors, proxied servers,
//! tool surfaces and the registry.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const CORE: [(&str, &str); 7] = [
    (
        "gateway-core",
        include_str!("../../gateway-core/Cargo.toml"),
    ),
    (
        "gateway-identity",
        include_str!("../../gateway-identity/Cargo.toml"),
    ),
    ("issuer-keys", include_str!("../../issuer-keys/Cargo.toml")),
    (
        "audit-postgres",
        include_str!("../../audit-postgres/Cargo.toml"),
    ),
    (
        "connector-proxy",
        include_str!("../../connector-proxy/Cargo.toml"),
    ),
    (
        "gateway-registry",
        include_str!("../../gateway-registry/Cargo.toml"),
    ),
    ("gateway-mcp", include_str!("../../gateway-mcp/Cargo.toml")),
];

#[test]
fn no_core_crate_names_the_otto_adapter() {
    for (name, manifest) in CORE {
        assert!(
            !manifest.contains("gateway-otto") && !manifest.contains("gateway_otto"),
            "{name} depends on the Otto adapter"
        );
    }
}
