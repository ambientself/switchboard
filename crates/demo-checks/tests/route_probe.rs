//! `deploy/route-check/probe.sh`, the route check's probe (decision 0010, "The route check"),
//! against fake servers on loopback, a fake `getent` and a fake `curl` that drops the ports it is
//! told to. Only a connection that times out before it is made, or a reset on a row flagged
//! reject_ok, counts as refused; a connection that is made and then gets no answer in time, and
//! a name that does not resolve, could not be probed; an answer of any kind is open. An
//! unreachable gateway fails the run before any route is tried, and no attempt carries a
//! credential.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use common::{
    Recorder, Run, black_hole, closed_port, dropped, fake_curl, fake_getent, read, repo, require,
    scratch,
};

/// `url` with its host replaced by `host`, keeping the port and the path.
fn named(url: &str, host: &str) -> String {
    url.replace("127.0.0.1", host)
}

/// One run of the probe.
struct Probe {
    gateway: String,
    routes: String,
    expect: Option<&'static str>,
    hosts: String,
    dropped: Vec<String>,
    dir: PathBuf,
}

impl Probe {
    fn new(name: &str, gateway: &str, routes: &str) -> Self {
        require(&["sh", "curl"]);
        Probe {
            gateway: gateway.to_owned(),
            routes: routes.to_owned(),
            expect: None,
            hosts: String::new(),
            dropped: Vec::new(),
            dir: scratch(name),
        }
    }

    fn expect(mut self, expect: &'static str) -> Self {
        self.expect = Some(expect);
        self
    }

    /// `name` resolves to `address` (or `slow`, a lookup that times out).
    fn host(mut self, name: &str, address: &str) -> Self {
        self.hosts.push_str(&format!("{name} {address}\n"));
        self
    }

    /// Requests to `url`'s port time out before they connect, as on a dropped route.
    fn dropping(mut self, url: &str) -> Self {
        self.dropped.push(url.to_owned());
        self
    }

    fn run(&self) -> Run {
        let bin = self.dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        fake_getent(&bin);
        let dropped: Vec<&str> = self.dropped.iter().map(String::as_str).collect();
        fake_curl(&bin, &dropped);
        let hosts = common::write(&self.dir, "hosts", &self.hosts);
        // A .curlrc that would add a bearer: the probe must not read it.
        let home = self.dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        common::write(
            &home,
            ".curlrc",
            "header = \"Authorization: Bearer from-curlrc\"\n",
        );
        let mut command = Command::new("sh");
        command
            .arg(repo().join("deploy/route-check/probe.sh"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("FAKE_HOSTS", &hosts)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("GATEWAY_URL", &self.gateway)
            .env("ROUTES", &self.routes)
            .env("PROBE_TIMEOUT", "1");
        for proxy in [
            "http_proxy",
            "HTTP_PROXY",
            "https_proxy",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
            "EXPECT",
        ] {
            command.env_remove(proxy);
        }
        if let Some(expect) = self.expect {
            command.env("EXPECT", expect);
        }
        Run::from(command.output().unwrap())
    }
}

/// The probe's ROUTE lines.
fn attempts(run: &Run) -> Vec<&str> {
    run.lines("ROUTE ")
}

fn assert_result(run: &Run, pass: bool) {
    let (status, last) = if pass {
        (Some(0), "RESULT: PASS")
    } else {
        (Some(1), "RESULT: FAIL")
    };
    assert_eq!(run.status, status, "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some(last),
        "{}",
        run.transcript()
    );
}

/// No request a server was sent carries an Authorization header.
fn assert_no_credential(server: &Recorder) {
    for head in server.heads() {
        assert!(
            !head.to_ascii_lowercase().contains("\nauthorization:"),
            "a request carried a credential:\n{head}"
        );
        assert!(head.starts_with("POST "), "{head}");
    }
}

#[test]
fn dropped_routes_are_refused_by_name_and_by_address() {
    let gateway = Recorder::start(401);
    let hole = dropped();
    let by_name = named(&hole, "hole.test");
    let routes = format!(
        "# a comment\n\
         dropped\t{by_name}\t127.0.0.1\t\n\
         \n\
         literal\t{hole}\t127.0.0.1\treject_ok\n"
    );
    let run = Probe::new("dropped", &gateway.url, &routes)
        .host("hole.test", "127.0.0.1")
        .dropping(&hole)
        .run();
    assert_result(&run, true);
    assert_eq!(
        attempts(&run),
        [
            format!("ROUTE dropped name {by_name} refused"),
            "ROUTE dropped address 127.0.0.1 refused".to_owned(),
            "ROUTE literal address 127.0.0.1 refused".to_owned(),
        ],
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(&format!(
            "PASS gateway reached: {} answered HTTP 401\n",
            gateway.url
        )),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains("PASS every route refused (3 attempts)\n")
    );
    assert_eq!(gateway.heads().len(), 1);
    assert_no_credential(&gateway);
}

#[test]
fn a_refused_connection_counts_as_refused_only_with_reject_ok() {
    let gateway = Recorder::start(401);
    let closed = closed_port();
    let run = Probe::new(
        "closed",
        &gateway.url,
        &format!("closed\t{closed}\t127.0.0.1\n"),
    )
    .run();
    assert_result(&run, false);
    assert_eq!(
        attempts(&run),
        ["ROUTE closed address 127.0.0.1 could-not-probe"],
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains("NOTE closed address 127.0.0.1: curl exit 7\n")
    );

    let run = Probe::new(
        "closed-reject-ok",
        &gateway.url,
        &format!("closed\t{closed}\t127.0.0.1\treject_ok\n"),
    )
    .run();
    assert_result(&run, true);
    assert_eq!(
        attempts(&run),
        ["ROUTE closed address 127.0.0.1 refused"],
        "{}",
        run.transcript()
    );
}

#[test]
fn a_name_that_does_not_resolve_could_not_be_probed() {
    let gateway = Recorder::start(401);
    let hole = dropped();
    let nowhere = named(&hole, "nowhere.test");
    let slow = named(&hole, "slow.test");
    let routes = format!(
        "unknown\t{nowhere}\t127.0.0.1\n\
         lookup\t{nowhere}\tresolve\n\
         timeout\t{slow}\t127.0.0.1\n"
    );
    let run = Probe::new("unresolved", &gateway.url, &routes)
        .host("slow.test", "slow")
        .dropping(&hole)
        .run();
    assert_result(&run, false);
    assert_eq!(
        attempts(&run),
        [
            format!("ROUTE unknown name {nowhere} could-not-probe"),
            "ROUTE unknown address 127.0.0.1 refused".to_owned(),
            format!("ROUTE lookup name {nowhere} could-not-probe"),
            "ROUTE lookup address nowhere.test could-not-probe".to_owned(),
            format!("ROUTE timeout name {slow} could-not-probe"),
            "ROUTE timeout address 127.0.0.1 refused".to_owned(),
        ],
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains(&format!(
        "NOTE unknown name {nowhere}: nowhere.test does not resolve\n"
    )));
    assert!(
        run.stdout
            .contains("FAIL 4 of 6 attempts were not refused\n")
    );
}

#[test]
fn a_resolve_row_tries_each_address_the_name_resolves_to() {
    let gateway = Recorder::start(401);
    let hole = dropped();
    let by_name = named(&hole, "hole.test");
    let run = Probe::new(
        "resolve",
        &gateway.url,
        &format!("resolved\t{by_name}\tresolve\n"),
    )
    .host("hole.test", "127.0.0.1")
    .dropping(&hole)
    .run();
    assert_result(&run, true);
    assert_eq!(
        attempts(&run),
        [
            format!("ROUTE resolved name {by_name} refused"),
            "ROUTE resolved address 127.0.0.1 refused".to_owned(),
        ],
        "{}",
        run.transcript()
    );
}

/// A connection that is made and then gets no answer in time is not a refusal: something took
/// it, so the route is open at the network level. A slow server, a stalled TLS handshake or a
/// tarpit looks like this. It could not be probed, which fails the run under either EXPECT.
#[test]
fn a_connection_that_gets_no_answer_in_time_could_not_be_probed() {
    let gateway = Recorder::start(401);
    let silent = black_hole();
    let by_name = named(&silent, "silent.test");
    for (expect, flags) in [("refused", ""), ("refused", "reject_ok"), ("open", "")] {
        let run = Probe::new(
            &format!("silent-{expect}-{flags}"),
            &gateway.url,
            &format!("silent\t{by_name}\t127.0.0.1\t{flags}\n"),
        )
        .host("silent.test", "127.0.0.1")
        .expect(expect)
        .run();
        assert_result(&run, false);
        assert_eq!(
            attempts(&run),
            [
                format!("ROUTE silent name {by_name} could-not-probe"),
                "ROUTE silent address 127.0.0.1 could-not-probe".to_owned(),
            ],
            "{}",
            run.transcript()
        );
        assert!(
            run.stdout.contains(
                "NOTE silent address 127.0.0.1: connected, but nothing answered in 1s (curl exit 28)\n"
            ),
            "{}",
            run.transcript()
        );
        assert!(
            run.stdout
                .contains(&format!("FAIL 2 of 2 attempts were not {expect}\n")),
            "{}",
            run.transcript()
        );
    }
}

#[test]
fn a_server_that_answers_is_open_and_fails_the_run() {
    let gateway = Recorder::start(401);
    // Any status is an answer, a refusal of the missing credential included.
    let server = Recorder::start(401);
    let by_name = named(&server.url, "server.test");
    let run = Probe::new(
        "open",
        &gateway.url,
        &format!("server\t{by_name}\t127.0.0.1\treject_ok\n"),
    )
    .host("server.test", "127.0.0.1")
    .run();
    assert_result(&run, false);
    assert_eq!(
        attempts(&run),
        [
            format!("ROUTE server name {by_name} open"),
            "ROUTE server address 127.0.0.1 open".to_owned(),
        ],
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains("FAIL 2 of 2 attempts were not refused\n")
    );
    let heads = server.heads();
    assert_eq!(heads.len(), 2);
    // The name attempt reached the server by its name.
    let port = server
        .url
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches("/mcp");
    assert!(
        heads
            .iter()
            .any(|head| head.contains(&format!("\r\nHost: server.test:{port}\r\n"))),
        "{heads:?}"
    );
    assert_no_credential(&server);
    assert_no_credential(&gateway);
}

#[test]
fn expect_open_inverts_the_result() {
    let gateway = Recorder::start(401);
    let server = Recorder::start(200);
    let run = Probe::new(
        "expect-open",
        &gateway.url,
        &format!("server\t{}\t127.0.0.1\n", server.url),
    )
    .expect("open")
    .run();
    assert_result(&run, true);
    assert_eq!(attempts(&run), ["ROUTE server address 127.0.0.1 open"]);
    assert!(run.stdout.contains("PASS every route open (1 attempts)\n"));

    let hole = dropped();
    let run = Probe::new(
        "expect-open-dropped",
        &gateway.url,
        &format!("dropped\t{hole}\t127.0.0.1\n"),
    )
    .expect("open")
    .dropping(&hole)
    .run();
    assert_result(&run, false);
    assert_eq!(attempts(&run), ["ROUTE dropped address 127.0.0.1 refused"]);
    assert!(run.stdout.contains("FAIL 1 of 1 attempts were not open\n"));
}

#[test]
fn an_unreachable_gateway_fails_before_any_route_is_tried() {
    let server = Recorder::start(401);
    let by_name = named(&server.url, "server.test");
    let routes_text = format!("server\t{by_name}\t127.0.0.1\n");
    for (name, gateway, exit) in [
        ("refused", closed_port(), 7),
        ("dropped", dropped(), 28),
        ("silent", black_hole(), 28),
    ] {
        for expect in ["refused", "open"] {
            let mut probe = Probe::new(
                &format!("no-gateway-{name}-{expect}"),
                &gateway,
                &routes_text,
            )
            .host("server.test", "127.0.0.1")
            .expect(expect);
            if name == "dropped" {
                probe = probe.dropping(&gateway);
            }
            let run = probe.run();
            assert_result(&run, false);
            assert_eq!(
                run.stdout,
                format!("FAIL gateway unreachable: {gateway} (curl exit {exit})\nRESULT: FAIL\n"),
                "{}",
                run.transcript()
            );
        }
    }
    assert!(server.heads().is_empty(), "{:?}", server.heads());
}

#[test]
fn rows_the_probe_cannot_try_fail_the_run() {
    let gateway = Recorder::start(401);
    let server = Recorder::start(200);
    let with_user = server.url.replace("127.0.0.1", "probe:pw@127.0.0.1");
    for (name, routes, text) in [
        ("empty", String::new(), "FAIL no route was tried"),
        (
            "comments",
            "# nothing\n".to_owned(),
            "FAIL no route was tried",
        ),
        (
            "flag",
            format!("server\t{}\t127.0.0.1\tsometimes\n", server.url),
            "FAIL routes line 1: unknown flags sometimes",
        ),
        (
            "scheme",
            "server\tftp://127.0.0.1/\t127.0.0.1\n".to_owned(),
            "FAIL routes line 1: the URL is not http or https: ftp://127.0.0.1/",
        ),
        (
            "address",
            format!("server\t{}\tserver.test\n", server.url),
            "FAIL routes line 1: addresses are not address literals: server.test",
        ),
        // curl would look these up as names, and a lookup that times out would read as refused.
        (
            "hex-name",
            format!("server\t{}\tdeadbeef\n", server.url),
            "FAIL routes line 1: addresses are not address literals: deadbeef",
        ),
        (
            "octet",
            format!("server\t{}\t127.0.0.1,10.0.0.256\n", server.url),
            "FAIL routes line 1: addresses are not address literals: 127.0.0.1,10.0.0.256",
        ),
        (
            "five-parts",
            format!("server\t{}\t1.2.3.4.5\n", server.url),
            "FAIL routes line 1: addresses are not address literals: 1.2.3.4.5",
        ),
        (
            "leading-zero",
            format!("server\t{}\t127.0.0.01\n", server.url),
            "FAIL routes line 1: addresses are not address literals: 127.0.0.01",
        ),
        (
            "no-address",
            format!("server\t{}\n", server.url),
            "FAIL routes line 1: no addresses",
        ),
        (
            "user",
            format!("server\t{with_user}\t127.0.0.1\n"),
            "FAIL routes line 1: the URL carries a user name or password",
        ),
    ] {
        let run = Probe::new(&format!("bad-{name}"), &gateway.url, &routes).run();
        assert_result(&run, false);
        assert!(run.stdout.contains(text), "{name}\n{}", run.transcript());
        assert!(attempts(&run).is_empty(), "{name}\n{}", run.transcript());
    }
    assert!(server.heads().is_empty(), "{:?}", server.heads());

    let run = Probe::new("bad-expect", &gateway.url, "")
        .expect("dropped")
        .run();
    assert_result(&run, false);
    assert!(
        run.stdout
            .contains("FAIL EXPECT is refused or open, not dropped")
    );
    // The gateway was not asked either.
    assert_eq!(gateway.heads().len(), 11);
}

/// route-check.sh starts `/usr/local/bin/route-probe.sh` from the demo image; the image must
/// put this script there, runnable, with the routes beside it.
#[test]
fn the_image_installs_the_probe_where_the_operator_starts_it() {
    let dockerfile = read("deploy/Dockerfile");
    assert!(
        dockerfile.contains(
            "\nCOPY --chmod=0755 deploy/route-check/probe.sh /usr/local/bin/route-probe.sh\n"
        ),
        "{dockerfile}"
    );
    assert!(
        dockerfile.contains("\nCOPY deploy/route-check/routes/ /usr/share/switchboard/routes/\n"),
        "{dockerfile}"
    );
    assert!(
        read("deploy/route-check/route-check.sh")
            .contains("\nPROBE_COMMAND=/usr/local/bin/route-probe.sh\n")
    );
    let mode = std::fs::metadata(repo().join("deploy/route-check/probe.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "probe.sh is not executable");
    // It needs only what the image has: POSIX sh, curl and getent.
    let script = read("deploy/route-check/probe.sh");
    assert!(script.starts_with("#!/bin/sh\n"));
    let words: Vec<&str> = script
        .lines()
        .skip(1)
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')))
        .collect();
    for tool in ["jq", "awk", "sed", "tr", "cut", "bash", "nslookup", "dig"] {
        assert!(!words.contains(&tool), "probe.sh uses {tool:?}");
    }
    assert!(words.contains(&"curl") && words.contains(&"getent"));
}

/// The kind run's routes: mock-docs by its Service name, and by the addresses route-check.sh
/// puts in for {{ADDR}}. Kind has no metadata or workload-identity endpoint.
#[test]
fn the_kind_routes_name_mock_docs_by_its_service() {
    let text = read("deploy/route-check/routes/kind.tsv");
    let rows: Vec<Vec<&str>> = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split('\t').collect())
        .collect();
    assert_eq!(
        rows,
        [[
            "mock-docs",
            "http://mock-docs.mock-docs.svc.cluster.local:8080/mcp",
            "{{ADDR}}"
        ]]
    );
    for address in ["169.254.169.254", "169.254.170.23"] {
        assert!(
            text.lines()
                .any(|line| line.starts_with('#') && line.contains(address)),
            "kind.tsv does not say why it lists no row for {address}"
        );
    }
    // The Service and port the row names are the ones the kind manifests deploy.
    let manifest = read("deploy/kind/base/mock-docs.yaml");
    assert!(manifest.contains("namespace: mock-docs"), "{manifest}");
    assert!(manifest.contains("port: 8080"), "{manifest}");
}
