//! The deployment file and the files it names (issue #9, step 9a): what loads, and every way a
//! missing, partial or unknown field is refused before anything starts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use files::{CLUSTER_ISSUER, Files, TEAM_A_SA, TEAM_B_SA, cluster_issuer, deployment_file};
use gateway::deployment::{DeploymentFile, TeamManifest};
use gateway::{AuditChoice, DeploymentError, IssuerKindEntry};
use gateway_registry::Registry;
use gateway_testkit::LocalIssuer;

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

fn files(name: &str) -> Files {
    Files::new(name, &issuer().jwks_document(), "http://127.0.0.1:9/mcp")
}

/// The deployment file with `old` replaced by `new`, loaded.
fn load_edited(name: &str, old: &str, new: &str) -> Result<gateway::Deployment, DeploymentError> {
    let files = files(name);
    let text = deployment_file("[audit]\nmode = \"disabled\"\n");
    assert_eq!(
        text.matches(old).count(),
        1,
        "`{old}` is not in the file once"
    );
    files.write("gateway.toml", &text.replace(old, new));
    files.load_with(&[])
}

fn refused(name: &str, old: &str, new: &str) -> String {
    match load_edited(name, old, new) {
        Ok(loaded) => panic!("{name}: loaded {loaded:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn a_deployment_loads_with_every_file_it_names_read() {
    let files = files("loads");
    let loaded = files.load();
    assert_eq!(loaded.deployment.as_str(), "files-test");
    assert_eq!(loaded.listen.to_string(), "127.0.0.1:0");
    assert!(loaded.http.allowed_hosts.contains("127.0.0.1"));
    // Relative paths are read from the deployment file's directory.
    assert_eq!(loaded.registry_file, files.path("registry/registry.toml"));
    assert_eq!(loaded.poll, Duration::from_secs(1));
    assert_eq!(loaded.audit, AuditChoice::Disabled);
    assert_eq!(
        loaded.credentials.get("docs-credential"),
        Some(&files.path("docs-credential"))
    );
    let issuers = loaded.identity.enforce.as_ref().unwrap();
    assert!(!loaded.identity.disabled);
    assert_eq!(issuers.len(), 1);
    assert_eq!(issuers[0].issuer.as_str(), CLUSTER_ISSUER);
    assert_eq!(issuers[0].max_lifetime_secs, 3600);
    assert_eq!(issuers[0].leeway_secs, 30);
    assert_eq!(issuers[0].keys["keys"][0]["kid"], issuer().key_id());
    let IssuerKindEntry::Workload { subjects } = &issuers[0].kind else {
        panic!("{:?}", issuers[0].kind);
    };
    let teams: Vec<(&str, &str)> = subjects
        .iter()
        .map(|(subject, team)| (subject.as_str(), team.as_str()))
        .collect();
    assert_eq!(teams, [(TEAM_A_SA, "team-a"), (TEAM_B_SA, "team-b")]);
}

#[test]
fn the_database_url_comes_from_the_variable_the_file_names() {
    let files = files("database-url");
    files.write(
        "gateway.toml",
        &deployment_file("[audit]\nmode = \"postgres\"\nurl_env = \"TEST_AUDIT_URL\"\n"),
    );
    let url = "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard";
    let loaded = files.load_with(&[("TEST_AUDIT_URL", url)]).unwrap();
    assert_eq!(loaded.audit, AuditChoice::Postgres { url: url.into() });
    assert!(!loaded.audit.section().disabled);
    // The URL holds a password, so it is never printed.
    assert!(!format!("{loaded:?}").contains("dummy"), "{loaded:?}");

    for env in [&[][..], &[("TEST_AUDIT_URL", "")], &[("OTHER", url)]] {
        let error = files.load_with(env).unwrap_err();
        assert!(
            matches!(&error, DeploymentError::NoDatabaseUrl(name) if name == "TEST_AUDIT_URL"),
            "{error}"
        );
    }
}

#[test]
fn identity_and_audit_can_each_be_disabled_explicitly() {
    let files = files("disabled");
    let text = deployment_file("[audit]\nmode = \"disabled\"\n");
    let start = text.find("[identity]").unwrap();
    let end = text.find("[audit]").unwrap();
    let disabled = format!(
        "{}[identity]\nmode = \"disabled\"\n\n{}",
        &text[..start],
        &text[end..]
    );
    files.write("gateway.toml", &disabled);
    let loaded = files.load();
    assert!(loaded.identity.disabled);
    assert_eq!(loaded.identity.enforce, None);
    assert!(loaded.audit.section().disabled);
}

/// With no `listen`, the gateway is reachable from its own machine only: it binds the IPv4
/// loopback address, never every interface.
#[test]
fn the_default_listen_address_is_loopback_only() {
    let loaded = load_edited("default-listen", "listen = \"127.0.0.1:0\"\n", "").unwrap();
    assert_eq!(loaded.listen, gateway::deployment::DEFAULT_LISTEN);
    assert_eq!(loaded.listen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(!loaded.listen.ip().is_unspecified());
    assert_eq!(loaded.listen.port(), 8080);
}

#[test]
fn listen_replaces_the_default() {
    let loaded = load_edited(
        "given-listen",
        "listen = \"127.0.0.1:0\"\n",
        "listen = \"0.0.0.0:9000\"\n",
    )
    .unwrap();
    assert_eq!(loaded.listen, "0.0.0.0:9000".parse::<SocketAddr>().unwrap());
}

#[test]
fn a_missing_field_is_refused() {
    for (field, line) in [
        ("deployment", "deployment = \"files-test\"\n"),
        ("poll_seconds", "poll_seconds = 1\n"),
        ("file", "file = \"registry/registry.toml\"\n"),
        ("mode", "mode = \"enforce\"\n"),
        ("audiences", "audiences = [\"switchboard\"]\n"),
        ("algorithm", "algorithm = \"RS256\"\n"),
        ("max_lifetime_seconds", "max_lifetime_seconds = 3600\n"),
        ("leeway_seconds", "leeway_seconds = 30\n"),
        (
            "credentials",
            "[credentials]\ndocs-credential = \"docs-credential\"\n",
        ),
        ("allowed_hosts", "allowed_hosts = [\"127.0.0.1\"]\n"),
    ] {
        let said = refused(&format!("missing-{field}"), line, "");
        assert!(
            said.contains(&format!("missing field `{field}`")),
            "{field}: {said}"
        );
    }
    let said = refused("missing-audit", "[audit]\nmode = \"disabled\"\n", "");
    assert!(said.contains("missing field `audit`"), "{said}");
}

#[test]
fn an_unknown_field_is_refused_in_every_table() {
    for (place, anchor) in [
        ("top", "listen = \"127.0.0.1:0\"\n"),
        ("http", "allowed_origins = []\n"),
        ("registry", "poll_seconds = 1\n"),
        ("identity", "mode = \"enforce\"\n"),
        ("issuer", "leeway_seconds = 30\n"),
        ("audit", "mode = \"disabled\"\n"),
    ] {
        let said = refused(
            &format!("unknown-{place}"),
            anchor,
            &format!("{anchor}refresh_seconds = 5\n"),
        );
        assert!(
            said.contains("unknown field `refresh_seconds`"),
            "{place}: {said}"
        );
    }
}

#[test]
fn a_field_that_does_not_belong_to_the_mode_or_kind_is_refused() {
    // Disabled identity with issuers still listed.
    let said = refused(
        "disabled-with-issuers",
        "mode = \"enforce\"",
        "mode = \"disabled\"",
    );
    assert!(said.contains("unknown field `issuers`"), "{said}");
    // Disabled audit with a URL variable.
    let said = refused(
        "disabled-audit-with-url",
        "[audit]\nmode = \"disabled\"\n",
        "[audit]\nmode = \"disabled\"\nurl_env = \"X\"\n",
    );
    assert!(said.contains("unknown field `url_env`"), "{said}");
    // An unknown mode.
    let said = refused(
        "unknown-mode",
        "mode = \"enforce\"",
        "mode = \"audit-only\"",
    );
    assert!(said.contains("unknown variant `audit-only`"), "{said}");

    let said = refused(
        "workload-without-manifest",
        "subjects_file = \"teams.toml\"\n",
        "",
    );
    assert!(said.contains("needs `subjects_file`"), "{said}");
    let said = refused(
        "workload-with-groups",
        "subjects_file = \"teams.toml\"\n",
        "subjects_file = \"teams.toml\"\ngroups_claim = \"groups\"\n",
    );
    assert!(said.contains("only a user issuer takes"), "{said}");
    let said = refused(
        "user-with-manifest",
        "kind = \"workload\"",
        "kind = \"user\"",
    );
    assert!(said.contains("only a workload issuer takes"), "{said}");
    let said = refused("unknown-kind", "kind = \"workload\"", "kind = \"service\"");
    assert!(said.contains("unknown variant `service`"), "{said}");
    let said = refused(
        "unknown-algorithm",
        "algorithm = \"RS256\"",
        "algorithm = \"HS256\"",
    );
    assert!(said.contains("unknown variant `HS256`"), "{said}");
}

/// The keys file line in the deployment file the tests edit.
const KEYS_FILE: &str = "keys_file = \"jwks.json\"\n";

#[test]
fn an_issuer_takes_a_keys_url_instead_of_a_keys_file() {
    let url = "keys_url = \"https://kubernetes.default.svc.cluster.local/openid/v1/jwks\"\n";
    let loaded = load_edited("keys-url", KEYS_FILE, url).unwrap();
    let issuers = loaded.identity.enforce.as_ref().unwrap();
    // Nothing is fetched until the gateway starts.
    assert_eq!(issuers[0].keys, serde_json::Value::Null);
    assert_eq!(loaded.keys_urls.len(), 1);
    assert_eq!(loaded.keys_urls[0].issuer.as_str(), CLUSTER_ISSUER);
    assert_eq!(
        loaded.keys_urls[0].url,
        "https://kubernetes.default.svc.cluster.local/openid/v1/jwks"
    );
    assert_eq!(loaded.keys_urls[0].refresh, gateway::DEFAULT_KEYS_REFRESH);
    assert_eq!(gateway::DEFAULT_KEYS_REFRESH, Duration::from_secs(300));
    // The URL is not printed.
    assert!(!format!("{:?}", loaded.keys_urls).contains("openid"));

    for (seconds, refresh) in [(30, 30), (45, 45), (86_400, 86_400)] {
        let loaded = load_edited(
            &format!("keys-refresh-{seconds}"),
            KEYS_FILE,
            &format!("{url}keys_refresh_seconds = {seconds}\n"),
        )
        .unwrap();
        assert_eq!(loaded.keys_urls[0].refresh, Duration::from_secs(refresh));
    }

    // A keys file is still read, and lists no keys URL.
    let loaded = files("keys-file").load();
    assert!(loaded.keys_urls.is_empty());
}

#[test]
fn an_issuer_takes_exactly_one_place_for_its_keys() {
    let url = "keys_url = \"https://kubernetes.default.svc.cluster.local/openid/v1/jwks\"\n";
    let said = refused("keys-both", KEYS_FILE, &format!("{KEYS_FILE}{url}"));
    assert_eq!(
        said,
        format!("issuer `{CLUSTER_ISSUER}` has both `keys_file` and `keys_url`; give one")
    );
    let said = refused("keys-neither", KEYS_FILE, "");
    assert_eq!(
        said,
        format!("issuer `{CLUSTER_ISSUER}` needs `keys_file` or `keys_url`, where its keys are")
    );

    // The refresh interval belongs to a keys URL.
    let said = refused(
        "keys-file-refresh",
        KEYS_FILE,
        &format!("{KEYS_FILE}keys_refresh_seconds = 60\n"),
    );
    assert_eq!(
        said,
        format!(
            "issuer `{CLUSTER_ISSUER}` has `keys_refresh_seconds`, which only an issuer with \
             `keys_url` takes"
        )
    );
    // At least 30 seconds.
    for seconds in [0, 1, 29] {
        let said = refused(
            &format!("keys-refresh-{seconds}"),
            KEYS_FILE,
            &format!("{url}keys_refresh_seconds = {seconds}\n"),
        );
        assert_eq!(
            said,
            format!(
                "issuer `{CLUSTER_ISSUER}` has `keys_refresh_seconds = {seconds}`; it must be at \
                 least 30"
            )
        );
    }
    let said = refused(
        "keys-refresh-negative",
        KEYS_FILE,
        &format!("{url}keys_refresh_seconds = -1\n"),
    );
    assert!(said.contains("not a valid deployment file"), "{said}");

    // A token or CA file for fetching the keys is not taken yet (issue #88).
    for field in ["keys_token_file", "keys_ca_file"] {
        let said = refused(
            &format!("keys-{field}"),
            KEYS_FILE,
            &format!("{url}{field} = \"token\"\n"),
        );
        assert!(said.contains(&format!("unknown field `{field}`")), "{said}");
    }
}

#[test]
fn a_user_issuer_takes_an_optional_groups_claim() {
    for (claim, expected) in [("", "groups"), ("groups_claim = \"roles\"\n", "roles")] {
        let loaded = load_edited(
            &format!("user-{expected}"),
            "kind = \"workload\"\naudiences = [\"switchboard\"]\nalgorithm = \"RS256\"\nkeys_file = \"jwks.json\"\nsubjects_file = \"teams.toml\"\n",
            &format!(
                "kind = \"user\"\naudiences = [\"switchboard\"]\nalgorithm = \"RS256\"\nkeys_file = \"jwks.json\"\n{claim}"
            ),
        )
        .unwrap();
        let issuers = loaded.identity.enforce.unwrap();
        assert_eq!(
            issuers[0].kind,
            IssuerKindEntry::User {
                groups_claim: expected.into()
            }
        );
    }
}

#[test]
fn the_registry_must_be_read_again_at_least_every_so_often() {
    let said = refused("poll-zero", "poll_seconds = 1", "poll_seconds = 0");
    assert!(said.contains("at least 1"), "{said}");
    let said = refused("poll-negative", "poll_seconds = 1", "poll_seconds = -1");
    assert!(said.contains("not a valid deployment file"), "{said}");
}

#[test]
fn keys_and_manifests_that_cannot_be_read_are_refused() {
    let files = files("unreadable");
    std::fs::remove_file(files.path("jwks.json")).unwrap();
    let error = files.load_with(&[]).unwrap_err();
    assert!(
        matches!(&error, DeploymentError::Read { path, .. } if path.ends_with("jwks.json")),
        "{error}"
    );

    files.write("jwks.json", "keys: not json");
    let error = files.load_with(&[]).unwrap_err();
    assert!(matches!(error, DeploymentError::Keys { .. }), "{error}");

    files.write("jwks.json", &issuer().jwks_document());
    for manifest in [
        "\"system:serviceaccount:team-a:mock-workload\" = \"team-a\"\n",
        "[subjects]\n\"a\" = \"team-a\"\n[teams]\n",
        "[subjects]\n\"a\" = 1\n",
        "[subjects]\n\"a\" = \"team-a\"\n\"a\" = \"team-b\"\n",
    ] {
        files.write("teams.toml", manifest);
        let error = files.load_with(&[]).unwrap_err();
        assert!(
            matches!(error, DeploymentError::Manifest { .. }),
            "{manifest}: {error}"
        );
    }
    std::fs::remove_file(files.path("teams.toml")).unwrap();
    let error = files.load_with(&[]).unwrap_err();
    assert!(matches!(error, DeploymentError::Read { .. }), "{error}");

    let missing = gateway::Deployment::load(Path::new("/nonexistent/gateway.toml"), |_| None);
    assert!(matches!(missing, Err(DeploymentError::Read { .. })));
}

#[test]
fn the_demo_deployment_files_are_valid_deployment_files() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for place in ["deploy/compose/config", "deploy/kind/base/config"] {
        let read = |name: &str| std::fs::read_to_string(repo.join(place).join(name)).unwrap();
        let file: DeploymentFile = toml::from_str(&read("gateway.toml"))
            .unwrap_or_else(|error| panic!("{place}/gateway.toml: {error}"));
        assert_eq!(file.registry.poll_seconds, 2, "{place}");
        let manifest: TeamManifest = toml::from_str(&read("teams.toml"))
            .unwrap_or_else(|error| panic!("{place}/teams.toml: {error}"));
        assert_eq!(manifest.subjects.len(), 2, "{place}");
        assert!(
            manifest
                .subjects
                .keys()
                .all(|subject| !subject.as_str().contains("stranger")),
            "{place}: the stranger is in the manifest"
        );
        Registry::from_toml_str(&read("registry/registry.toml"))
            .unwrap_or_else(|error| panic!("{place}/registry/registry.toml: {error}"));
    }
    let withdrawn =
        std::fs::read_to_string(repo.join("deploy/compose/config/registry-withdrawn.toml"))
            .unwrap();
    let withdrawn = Registry::from_toml_str(&withdrawn).unwrap();
    assert_eq!(withdrawn.snapshot().revision().as_str(), "demo-2");
    assert!(
        withdrawn
            .snapshot()
            .tool(&files::READ_TOOL.parse().unwrap())
            .is_none()
    );
}
