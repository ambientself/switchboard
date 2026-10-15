//! The deployment file and the files it names (issue #9, step 9a): what loads, and every way a
//! missing, partial or unknown field is refused before anything starts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use files::{
    CLUSTER_ISSUER, Files, REACH_TOKEN_FILE, REACH_URL, TEAM_A_SA, TEAM_B_SA, cluster_issuer,
    deployment_file,
};
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
    for reference in ["docs-team-a-credential", "docs-team-b-credential"] {
        assert_eq!(
            loaded.credentials.get(reference),
            Some(&files.path(reference))
        );
    }
    assert_eq!(loaded.credentials.len(), 2);
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

/// Decision 0014, section 3: the begin and finish pools are 16 and 4 connections unless the
/// file says otherwise, each from 1 to 64.
#[test]
fn the_audit_pools_are_16_and_4_unless_given_and_each_from_1_to_64() {
    let url = "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard";
    let load = |name: &str, pools: &str| {
        let files = files(name);
        files.write(
            "gateway.toml",
            &deployment_file(&format!(
                "[audit]\nmode = \"postgres\"\nurl_env = \"TEST_AUDIT_URL\"\n{pools}"
            )),
        );
        files.load_with(&[("TEST_AUDIT_URL", url)])
    };
    let sizes = |loaded: gateway::Deployment| (loaded.audit_pools.begin, loaded.audit_pools.finish);
    assert_eq!(gateway::deployment::MAX_AUDIT_POOL_SIZE, 64);
    assert_eq!(sizes(load("pools-default", "").unwrap()), (16, 4));
    // With audit disabled there is no store, and the sizes are the defaults.
    assert_eq!(sizes(files("pools-disabled").load()), (16, 4));
    for (pools, expected) in [
        ("begin_pool_size = 5\nfinish_pool_size = 3\n", (5, 3)),
        ("begin_pool_size = 1\nfinish_pool_size = 64\n", (1, 64)),
        ("begin_pool_size = 64\nfinish_pool_size = 1\n", (64, 1)),
        ("begin_pool_size = 32\n", (32, 4)),
        ("finish_pool_size = 8\n", (16, 8)),
    ] {
        assert_eq!(
            sizes(load("pools-given", pools).unwrap()),
            expected,
            "{pools}"
        );
    }
    for field in ["begin_pool_size", "finish_pool_size"] {
        for size in [0, 65, 1_000] {
            let error = load("pools-refused", &format!("{field} = {size}\n")).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("`audit.{field}` is {size}; it must be from 1 to 64"),
            );
        }
        let error = load("pools-negative", &format!("{field} = -1\n")).unwrap_err();
        assert!(
            error.to_string().contains("not a valid deployment file"),
            "{error}"
        );
    }
    // The sizes belong to a Postgres store.
    let said = refused(
        "pools-disabled-audit",
        "[audit]\nmode = \"disabled\"\n",
        "[audit]\nmode = \"disabled\"\nbegin_pool_size = 8\n",
    );
    assert!(said.contains("unknown field `begin_pool_size`"), "{said}");
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
            "[credentials]\ndocs-team-a-credential = \"docs-team-a-credential\"\n\
             docs-team-b-credential = \"docs-team-b-credential\"\n",
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

    // A CA file and a token file belong to a keys URL too.
    for field in ["keys_ca_file", "keys_token_file"] {
        let said = refused(
            &format!("keys-file-{field}"),
            KEYS_FILE,
            &format!("{KEYS_FILE}{field} = \"issuer-file\"\n"),
        );
        assert_eq!(
            said,
            format!(
                "issuer `{CLUSTER_ISSUER}` has `{field}`, which only an issuer with `keys_url` \
                 takes"
            )
        );
    }
}

#[test]
fn a_keys_url_takes_a_ca_file_and_a_token_file_read_from_the_deployment_files_directory() {
    let url = "keys_url = \"https://kubernetes.default.svc.cluster.local/openid/v1/jwks\"\n";
    let files = files("keys-fetch-files");
    let text = deployment_file("[audit]\nmode = \"disabled\"\n").replace(
        KEYS_FILE,
        &format!("{url}keys_ca_file = \"issuer/ca.pem\"\nkeys_token_file = \"issuer/token\"\n"),
    );
    files.write("gateway.toml", &text);
    let loaded = files.load();
    let keys_url = &loaded.keys_urls[0];
    assert_eq!(keys_url.ca_file, Some(files.path("issuer/ca.pem")));
    assert_eq!(keys_url.token_file, Some(files.path("issuer/token")));
    // Neither file is read until the gateway starts, and the token not until it fetches.
    assert!(!files.path("issuer").exists());

    // Absolute paths are kept as they are.
    let text = deployment_file("[audit]\nmode = \"disabled\"\n").replace(
        KEYS_FILE,
        &format!(
            "{url}keys_ca_file = \"/etc/switchboard/ca.pem\"\nkeys_token_file = \"/run/secrets/token\"\n"
        ),
    );
    files.write("gateway.toml", &text);
    let loaded = files.load();
    let keys_url = &loaded.keys_urls[0];
    assert_eq!(keys_url.ca_file, Some("/etc/switchboard/ca.pem".into()));
    assert_eq!(keys_url.token_file, Some("/run/secrets/token".into()));

    // Both are optional here; the gateway refuses an https keys URL with no CA file when it
    // starts.
    let loaded = load_edited("keys-no-fetch-files", KEYS_FILE, url).unwrap();
    assert_eq!(loaded.keys_urls[0].ca_file, None);
    assert_eq!(loaded.keys_urls[0].token_file, None);
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

/// Decision 0013, section 8: a user's groups are as fresh as the token that carries them, so a
/// user issuer's tokens may live at most an hour. A workload issuer's lifetime has no such
/// ceiling.
#[test]
fn a_user_issuers_token_lifetime_is_at_most_an_hour() {
    let workload = "kind = \"workload\"\naudiences = [\"switchboard\"]\nalgorithm = \"RS256\"\nkeys_file = \"jwks.json\"\nsubjects_file = \"teams.toml\"\nmax_lifetime_seconds = 3600\n";
    let user = |seconds: u64| {
        format!(
            "kind = \"user\"\naudiences = [\"switchboard\"]\nalgorithm = \"RS256\"\nkeys_file = \"jwks.json\"\nmax_lifetime_seconds = {seconds}\n"
        )
    };
    assert_eq!(gateway::deployment::MAX_USER_LIFETIME_SECONDS, 3600);
    for seconds in [1, 3600] {
        let loaded = load_edited(
            &format!("user-lifetime-{seconds}"),
            workload,
            &user(seconds),
        )
        .unwrap();
        assert_eq!(
            loaded.identity.enforce.unwrap()[0].max_lifetime_secs,
            seconds
        );
    }
    for seconds in [3601, 86_400, u64::MAX] {
        let said = refused(
            &format!("user-lifetime-{seconds}"),
            workload,
            &user(seconds),
        );
        assert_eq!(
            said,
            format!(
                "user issuer `{CLUSTER_ISSUER}` has `max_lifetime_seconds = {seconds}`; a user \
                 issuer's must be at most 3600, since a user's groups are as fresh as the token"
            )
        );
    }
    for seconds in [3601, 86_400] {
        let loaded = load_edited(
            &format!("workload-lifetime-{seconds}"),
            "max_lifetime_seconds = 3600\n",
            &format!("max_lifetime_seconds = {seconds}\n"),
        )
        .unwrap();
        assert_eq!(
            loaded.identity.enforce.unwrap()[0].max_lifetime_secs,
            seconds
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

/// Decision 0013, section 8: the policy's maximum age is 60 s unless given, and never under two
/// polls.
#[test]
fn the_maximum_age_defaults_to_a_minute_and_is_at_least_two_polls() {
    let loaded = files("max-age-default").load();
    assert_eq!(loaded.max_age, Duration::from_secs(60));
    assert_eq!(loaded.max_age, gateway::DEFAULT_MAX_AGE);

    let loaded = load_edited(
        "max-age-given",
        "poll_seconds = 1\n",
        "poll_seconds = 1\nmax_age_seconds = 2\n",
    )
    .unwrap();
    assert_eq!(loaded.max_age, Duration::from_secs(2));

    let said = refused(
        "max-age-one-poll",
        "poll_seconds = 1\n",
        "poll_seconds = 2\nmax_age_seconds = 3\n",
    );
    assert_eq!(
        said,
        "`registry.max_age_seconds` is 3, and must be at least twice `registry.poll_seconds`, 4"
    );
    // The default is held to the same floor.
    let said = refused(
        "max-age-slow-poll",
        "poll_seconds = 1\n",
        "poll_seconds = 31\n",
    );
    assert!(said.contains("`registry.max_age_seconds` is 60"), "{said}");
    let said = refused(
        "max-age-negative",
        "poll_seconds = 1\n",
        "poll_seconds = 1\nmax_age_seconds = -1\n",
    );
    assert!(said.contains("not a valid deployment file"), "{said}");
}

/// Decision 0013, section 5: `[drift]` is optional, its interval 300 s unless given, and
/// refused below 5 or above 900.
#[test]
fn the_drift_interval_defaults_to_five_minutes_and_is_5_to_900_seconds() {
    let loaded = files("drift-default").load();
    assert_eq!(loaded.drift_interval, Duration::from_secs(300));
    assert_eq!(loaded.drift_interval, gateway::DEFAULT_DRIFT_INTERVAL);
    let table = |seconds: &str| format!("[drift]\ninterval_seconds = {seconds}\n");
    // The deployment file's `[drift]` holds only the reach settings; without them it is empty.
    let reach = format!(
        "[drift]\nreach_token_file = \"{REACH_TOKEN_FILE}\"\nreach_url = \"{REACH_URL}\"\n\
         reach_host = \"127.0.0.1\"\n"
    );
    let loaded = load_edited("drift-empty", &reach, "[drift]\n").unwrap();
    assert_eq!(loaded.drift_interval, Duration::from_secs(300));
    assert_eq!(loaded.reach, None);
    for seconds in [5, 10, 900] {
        let loaded = load_edited(
            &format!("drift-{seconds}"),
            "[drift]\n",
            &table(&seconds.to_string()),
        )
        .unwrap();
        assert_eq!(loaded.drift_interval, Duration::from_secs(seconds));
    }
    for seconds in [0, 4, 901] {
        let said = refused(
            &format!("drift-{seconds}"),
            "[drift]\n",
            &table(&seconds.to_string()),
        );
        assert_eq!(
            said,
            format!("`drift.interval_seconds` is {seconds}; it must be from 5 to 900")
        );
    }
    let said = refused(
        "drift-unknown-field",
        "[drift]\n",
        "[drift]\ninterval = 10\n",
    );
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
        let drift = file.drift.clone().unwrap();
        assert_eq!(drift.interval_seconds, Some(10), "{place}");
        // The reach check calls this gateway's own listener, on its registry-reach surface,
        // with a Host it serves.
        assert_eq!(
            drift.reach_url.as_deref(),
            Some("http://127.0.0.1:8080/mcp/registry-reach"),
            "{place}"
        );
        assert!(
            file.http
                .allowed_hosts
                .contains(drift.reach_host.as_deref().unwrap()),
            "{place}"
        );
        assert!(drift.reach_token_file.is_some(), "{place}");
        let manifest: TeamManifest = toml::from_str(&read("teams.toml"))
            .unwrap_or_else(|error| panic!("{place}/teams.toml: {error}"));
        // Each team's workload, and the registry's own workload identity in team registry.
        assert_eq!(manifest.subjects.len(), 3, "{place}");
        assert_eq!(
            manifest
                .subjects
                .values()
                .filter(|team| team.as_str() == "registry")
                .count(),
            1,
            "{place}"
        );
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
    assert_eq!(withdrawn.snapshot().revision().as_str(), "demo-11");
    for tool in [files::READ_TOOL, files::TEAM_B_READ_TOOL] {
        assert!(withdrawn.snapshot().tool(&tool.parse().unwrap()).is_none());
    }
    for tool in [files::LIST_TOOL, files::TEAM_B_LIST_TOOL] {
        assert!(withdrawn.snapshot().tool(&tool.parse().unwrap()).is_some());
    }
}

/// Writes two minters' public keys and `mapping` beside a deployment file whose audit is
/// disabled and whose `[grants]` table is `grants`, and loads it.
fn with_grants_mapping(
    name: &str,
    grants: &str,
    mapping: &str,
) -> Result<gateway::Deployment, DeploymentError> {
    let files = files(name);
    let current = gateway_otto::minter::TestMinter::from_seed([7; 32]);
    let previous = gateway_otto::minter::TestMinter::from_seed([8; 32]);
    files.write("otto.pem", &current.public_key_pem());
    files.write("otto-previous.pem", &previous.public_key_pem());
    files.write("otto-tools.json", mapping);
    files.write(
        "gateway.toml",
        &deployment_file(&format!("[audit]\nmode = \"disabled\"\n\n{grants}\n")),
    );
    files.load_with(&[])
}

fn with_grants(name: &str, grants: &str) -> Result<gateway::Deployment, DeploymentError> {
    with_grants_mapping(
        name,
        grants,
        r#"{"github_get_pr": "github__get_pr", "github_create_pr": "github__create_pr"}"#,
    )
}

const GRANTS: &str = r#"[grants]
mode = "enforce"
tool_mapping_file = "otto-tools.json"

[[grants.issuers]]
name = "otto-prod"
key_file = "otto.pem"
require_pod = true
require_egress = false

[grants.issuers.previous]
key_file = "otto-previous.pem"
retires_at = 2026-11-01T02:00:00+02:00
"#;

/// The `[grants]` table reads each issuer's key files and the mapping from the deployment
/// file's directory, and its previous key's end as an absolute instant. Left out, grant
/// checking is on with no issuer; `mode = "disabled"` stands alone.
#[test]
fn the_grants_table_reads_its_key_files_and_mapping() {
    let loaded = with_grants("grants", GRANTS).unwrap();
    let config = loaded.grants.enforce.expect("grant checking enforced");
    assert!(!loaded.grants.disabled);
    assert_eq!(config.tool_mapping.len(), 2);
    let issuer = &config.issuers[0];
    assert_eq!(issuer.name, "otto-prod");
    assert!(issuer.require_pod);
    assert!(!issuer.require_egress);
    assert!(issuer.current_key.starts_with("-----BEGIN PUBLIC KEY-----"));
    let previous = issuer.previous_key.as_ref().unwrap();
    assert_ne!(previous.key, issuer.current_key);
    assert_eq!(previous.retires_at, Some(1_793_491_200));

    let left_out = files("grants-left-out").load();
    assert_eq!(left_out.grants, gateway::GrantsSection::default());
    let disabled = with_grants("grants-disabled", "[grants]\nmode = \"disabled\"\n").unwrap();
    assert!(disabled.grants.disabled);
    assert!(disabled.grants.enforce.is_none());
    let crowded = with_grants(
        "grants-disabled-crowded",
        "[grants]\nmode = \"disabled\"\ntool_mapping_file = \"otto-tools.json\"\n",
    );
    assert!(
        matches!(crowded, Err(DeploymentError::Parse { .. })),
        "{crowded:?}"
    );
}

/// Each way the table is refused as it loads: a local time for the previous key's end, a
/// mapping that is not one to one, a key file that cannot be read, and a field it does not
/// know. A previous key with no end loads, and the boot gates refuse it.
#[test]
fn the_grants_table_is_refused_as_it_loads() {
    let local = with_grants(
        "grants-local",
        &GRANTS.replace("2026-11-01T02:00:00+02:00", "2026-11-01T02:00:00"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        local.contains("the previous key of turn-grant issuer `otto-prod` has a `retires_at`"),
        "{local}"
    );
    let missing = with_grants(
        "grants-missing",
        &GRANTS.replace("\"otto.pem\"", "\"nowhere.pem\""),
    )
    .unwrap_err()
    .to_string();
    assert!(missing.contains("nowhere.pem"), "{missing}");
    let unknown = with_grants(
        "grants-unknown",
        &GRANTS.replace("require_egress", "require_egres"),
    );
    assert!(
        matches!(unknown, Err(DeploymentError::Parse { .. })),
        "{unknown:?}"
    );
    let mapping = with_grants_mapping(
        "grants-mapping",
        GRANTS,
        r#"{"github_get_pr": "github__get_pr", "github_get_pr": "github__other"}"#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        mapping.contains("otto-tools.json` was refused"),
        "{mapping}"
    );

    let no_end = with_grants(
        "grants-no-end",
        &GRANTS.replace("retires_at = 2026-11-01T02:00:00+02:00\n", ""),
    )
    .unwrap();
    let issuer = &no_end.grants.enforce.unwrap().issuers[0];
    assert_eq!(issuer.previous_key.as_ref().unwrap().retires_at, None);
}
