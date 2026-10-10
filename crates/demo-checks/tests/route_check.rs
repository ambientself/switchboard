//! `deploy/route-check/route-check.sh`, the route check's operator step (decision 0010, "The
//! route check"), against a fake `kubectl` that serves a cluster from files and records every
//! call. A clean pod passes. Each way the pod could go around the gateway fails the run, and so
//! does anything the step could not read. The probe's wait is bounded. `rbac.yaml` grants the
//! step no more than it needs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{Recorder, Run, dropped, fake_curl, fake_getent, read, repo, require, scratch, write};
use serde_json::{Value, json};

const CONTEXT: &str = "kind-switchboard-demo";
const OPERATOR: &str = "system:serviceaccount:route-check:operator";
const WORKLOAD_USER: &str = "system:serviceaccount:team-a:mock-workload";
const NODE: &str = "switchboard-demo-control-plane";
const KINDNETD: &str = "docker.io/kindest/kindnetd:v20260528-9350166c";
const GATEWAY_URL: &str = "http://gateway.switchboard.svc.cluster.local:8080/mcp";
const PROBE_IMAGE: &str = "switchboard-demo:dev";
const ROUTES: &str = "# the test's routes\n\
mock-docs\thttp://mock-docs.mock-docs.svc.cluster.local:8080/mcp\t{{ADDR}}\t\n\
metadata\thttp://169.254.169.254/latest/meta-data/\t169.254.169.254\treject_ok\n";
const PASSING_PROBE: &str = "ROUTE mock-docs name http://mock-docs.mock-docs.svc.cluster.local:8080/mcp refused\n\
ROUTE mock-docs address 10.244.0.7 refused\n\
ROUTE mock-docs address 10.96.12.34 refused\n\
ROUTE metadata address 169.254.169.254 refused\n\
RESULT: PASS\n";

/// A fake `kubectl` that serves the cluster from files in `$FAKE_DIR`. It appends each call,
/// with every argument, to `calls.log`, drops the global flags, and answers:
/// - the SubjectAccessReviews it is given (saved to `reviews.json`): allowed when one of the
///   matchers in `sar-yes` matches, left out when one in `sar-drop` does, not allowed with an
///   evaluationError (as when an authorization webhook times out) when one in `sar-error` does,
///   and refused if `sar-fails` exists;
/// - `kubectl debug` by saving the partial container spec to `debug-custom.json` and the
///   container's name to `probe-container`, and, when `$PROBE_SCRIPT` is set, by running that
///   script with the spec's variables and saving its output and exit code as the probe's;
/// - `get pod` with the probe's container terminated (exit code in `probe-exit`), or running if
///   `probe-running` exists, or with the contents of `probe-pod` if that exists, after waiting
///   the seconds in `probe-pod-delay` if that exists;
/// - every other read from a file named for it; a missing file is NotFound.
const FAKE_KUBECTL: &str = r#"#!/usr/bin/env bash
set -u
d=$FAKE_DIR
printf '%s\n' "$*" >>"$d/calls.log"
while [ $# -gt 0 ]; do
  case $1 in
    --kubeconfig | --context) shift 2 ;;
    --as=* | --request-timeout=*) shift ;;
    *) break ;;
  esac
done
args="$*"
serve() {
  if [ -f "$d/$1" ]; then cat "$d/$1"; else echo "Error from server (NotFound): $1" >&2; exit 1; fi
}
case $args in
  "version -o json") serve version.json ;;
  "get daemonsets -n kube-system -o json") serve daemonsets.json ;;
  "get pods -n kube-system -l "*) serve kindnet-pods.json ;;
  "logs -n kube-system "*) serve kindnet.log ;;
  "get pods -n "*" -l "*) serve workload-pods.json ;;
  "get node "*) serve node.json ;;
  "get serviceaccount "*) serve serviceaccount.json ;;
  "get configmap "*) set -- $args; serve "configmap-$5-$3.json" ;;
  "get service "*) set -- $args; serve "service-$5-$3.json" ;;
  "get endpointslices -n "*) set -- $args; serve "endpointslices-$4.json" ;;
  "create -f - -o json")
    cat >"$d/reviews.json"
    [ ! -f "$d/sar-fails" ] || { echo 'Error from server (Forbidden)' >&2; exit 1; }
    jq -c --argjson yes "$(cat "$d/sar-yes" 2>/dev/null || echo '[]')" \
      --argjson drop "$(cat "$d/sar-drop" 2>/dev/null || echo '[]')" \
      --argjson error "$(cat "$d/sar-error" 2>/dev/null || echo '[]')" '
      def matches($m): . as $r | all($m | to_entries[]; ($r[.key] // "") == .value);
      .items[] | .spec.resourceAttributes as $r
      | select(any($drop[]; . as $m | $r | matches($m)) | not)
      | . + {status: (if any($error[]; . as $m | $r | matches($m))
          then {allowed: false, evaluationError: "webhook: context deadline exceeded"}
          else {allowed: any($yes[]; . as $m | $r | matches($m))} end)}' "$d/reviews.json"
    ;;
  "debug pod/"*)
    while [ $# -gt 0 ]; do
      case $1 in
        -c) printf '%s' "$2" >"$d/probe-container"; shift ;;
        --custom=*) cp "${1#--custom=}" "$d/debug-custom.json" ;;
      esac
      shift
    done
    if [ -n "${PROBE_SCRIPT:-}" ]; then
      variable() { jq -r --arg name "$1" '.env[] | select(.name == $name) | .value' "$d/debug-custom.json"; }
      ROUTES=$(variable ROUTES) GATEWAY_URL=$(variable GATEWAY_URL) EXPECT=$(variable EXPECT) \
        PROBE_TIMEOUT=1 FAKE_HOSTS="$d/hosts" sh "$PROBE_SCRIPT" >"$d/probe.log" 2>&1
      echo "$?" >"$d/probe-exit"
    fi
    ;;
  "get pod "*)
    if [ -f "$d/probe-pod-delay" ]; then sleep "$(cat "$d/probe-pod-delay")"; fi
    if [ -f "$d/probe-pod" ]; then cat "$d/probe-pod"; exit 0; fi
    if [ -f "$d/probe-running" ]; then
      state='{"running": {"startedAt": "2026-10-08T00:00:00Z"}}'
    else
      state="{\"terminated\": {\"exitCode\": $(cat "$d/probe-exit"), \"reason\": \"Completed\"}}"
    fi
    jq --arg name "$(cat "$d/probe-container")" --argjson state "$state" \
      '.items[0] | .status.ephemeralContainerStatuses = [{name: $name, state: $state}]' "$d/workload-pods.json"
    ;;
  "logs pod/"*) serve probe.log ;;
  *) echo "fake kubectl: unexpected call: $args" >&2; exit 1 ;;
esac
"#;

/// The cluster the fake `kubectl` serves. `Cluster::clean()` is one that passes every check.
struct Cluster {
    pod: Value,
    daemonsets: Value,
    kindnet_pod: Value,
    kindnet_log: String,
    configmaps: Vec<(&'static str, &'static str, Value)>,
    service_account: Value,
    sar_yes: Value,
    sar_drop: Value,
    sar_error: Value,
    sar_fails: bool,
    probe_log: String,
    probe_exit: i64,
    probe_running: bool,
    /// Files the fake does not serve, so their reads fail.
    unreadable: Vec<&'static str>,
    /// Files the fake serves as given, in place of what the cluster would write.
    raw: Vec<(&'static str, &'static str)>,
    /// The mock-docs Service's ClusterIP and its EndpointSlice's endpoints.
    cluster_ip: &'static str,
    endpoints: Value,
    /// The routes file and the gateway's URL, in place of `ROUTES` and `GATEWAY_URL`.
    routes: Option<String>,
    gateway_url: Option<String>,
    /// Run deploy/route-check/probe.sh for `kubectl debug`, with these `NAME ADDRESS` lines for
    /// the fake `getent`, in place of the probe's log and exit code above.
    run_probe: Option<String>,
    /// URLs whose ports the probe's curl drops (a fake curl), for `run_probe`.
    dropped: Vec<String>,
    /// Seconds the fake waits before answering each `get pod`.
    probe_pod_delay: Option<u32>,
}

impl Cluster {
    fn clean() -> Self {
        Cluster {
            pod: json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "agent-0", "namespace": "team-a", "labels": {"app": "agent"}},
                "spec": {
                    "nodeName": NODE,
                    "serviceAccountName": "mock-workload",
                    "containers": [{
                        "name": "agent",
                        "image": "switchboard-demo:dev",
                        "env": [
                            {"name": "GATEWAY_URL", "value": GATEWAY_URL},
                            {"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}}
                        ],
                        "envFrom": [{"configMapRef": {"name": "agent-settings"}}]
                    }],
                    "volumes": [
                        {"name": "gateway-token", "projected": {"sources": [
                            {"serviceAccountToken": {"audience": "switchboard", "expirationSeconds": 600, "path": "token"}}
                        ]}},
                        {"name": "kube-api-access-x7k2p", "projected": {"sources": [
                            {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                            {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
                        ]}}
                    ]
                },
                "status": {"phase": "Running"}
            }),
            daemonsets: json!({"items": [
                {"metadata": {"name": "kindnet"}, "spec": {"selector": {"matchLabels": {"app": "kindnet"}}}},
                {"metadata": {"name": "kube-proxy"}, "spec": {"selector": {"matchLabels": {"k8s-app": "kube-proxy"}}}}
            ]}),
            kindnet_pod: json!({
                "metadata": {"name": "kindnet-9qv4m", "namespace": "kube-system"},
                "spec": {
                    "nodeName": NODE,
                    "containers": [{
                        "name": "kindnet-cni",
                        "image": KINDNETD,
                        "env": [
                            {"name": "HOST_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}},
                            {"name": "POD_SUBNET", "value": "10.244.0.0/16"}
                        ]
                    }]
                },
                "status": {"phase": "Running"}
            }),
            kindnet_log: "I1008 01:34:18.796478       1 main.go:187] noMask IPv4 subnets: [10.244.0.0/16]\n\
I1008 01:34:19.016360       1 controller.go:173] \"Starting controller\" name=\"kube-network-policies\"\n\
I1008 01:34:19.623632       1 controller.go:185] \"Policy engine is ready.\"\n"
                .to_owned(),
            configmaps: vec![
                ("team-a", "agent-settings", json!({"data": {"LOG_LEVEL": "info"}})),
                (
                    "team-a",
                    "kube-root-ca.crt",
                    json!({"data": {"ca.crt": "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n"}}),
                ),
            ],
            service_account: json!({"metadata": {"name": "mock-workload", "namespace": "team-a"}}),
            sar_yes: json!([]),
            sar_drop: json!([]),
            sar_error: json!([]),
            sar_fails: false,
            probe_log: PASSING_PROBE.to_owned(),
            probe_exit: 0,
            probe_running: false,
            unreadable: Vec::new(),
            raw: Vec::new(),
            cluster_ip: "10.96.12.34",
            endpoints: json!([{"addresses": ["10.244.0.7"]}]),
            routes: None,
            gateway_url: None,
            run_probe: None,
            dropped: Vec::new(),
            probe_pod_delay: None,
        }
    }

    fn pod_spec(&mut self) -> &mut Value {
        &mut self.pod["spec"]
    }

    fn agent(&mut self) -> &mut Value {
        &mut self.pod["spec"]["containers"][0]
    }

    fn write(&self, dir: &Path) {
        let save = |name: &str, value: &Value| {
            write(dir, name, &serde_json::to_string_pretty(value).unwrap());
        };
        save("workload-pods.json", &json!({"items": [self.pod]}));
        if !self.daemonsets.is_null() {
            save("daemonsets.json", &self.daemonsets);
        }
        save("kindnet-pods.json", &json!({"items": [self.kindnet_pod]}));
        write(dir, "kindnet.log", &self.kindnet_log);
        save(
            "version.json",
            &json!({"serverVersion": {"gitVersion": "v1.36.1"}}),
        );
        save(
            "node.json",
            &json!({"metadata": {"name": NODE}, "status": {"nodeInfo": {
                "osImage": "Debian GNU/Linux 12 (bookworm)",
                "kubeletVersion": "v1.36.1",
                "containerRuntimeVersion": "containerd://2.1.1"
            }}}),
        );
        save("serviceaccount.json", &self.service_account);
        for (namespace, name, configmap) in &self.configmaps {
            save(&format!("configmap-{namespace}-{name}.json"), configmap);
        }
        save(
            "service-mock-docs-mock-docs.json",
            &json!({"spec": {"clusterIP": self.cluster_ip, "clusterIPs": [self.cluster_ip]}}),
        );
        save(
            "endpointslices-mock-docs.json",
            &json!({"items": [{"endpoints": self.endpoints}]}),
        );
        save("sar-yes", &self.sar_yes);
        save("sar-drop", &self.sar_drop);
        save("sar-error", &self.sar_error);
        if self.sar_fails {
            write(dir, "sar-fails", "");
        }
        write(dir, "probe.log", &self.probe_log);
        write(dir, "probe-exit", &self.probe_exit.to_string());
        if self.probe_running {
            write(dir, "probe-running", "");
        }
        if let Some(delay) = self.probe_pod_delay {
            write(dir, "probe-pod-delay", &delay.to_string());
        }
        if let Some(hosts) = &self.run_probe {
            write(dir, "hosts", hosts);
        }
        for name in &self.unreadable {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        for (name, contents) in &self.raw {
            write(dir, name, contents);
        }
    }
}

/// One run of the script: what it printed, its report, the fake's calls, and how long it took.
struct Checked {
    run: Run,
    report: Option<Value>,
    calls: Vec<String>,
    dir: PathBuf,
    elapsed: Duration,
}

impl Checked {
    fn passed(&self, text: &str) -> bool {
        self.run
            .lines("PASS ")
            .iter()
            .any(|line| line.contains(text))
    }

    fn report(&self) -> &Value {
        self.report
            .as_ref()
            .unwrap_or_else(|| panic!("no report\n{}", self.run.transcript()))
    }

    /// The run failed, with a FAIL line containing `text`, and a report saying so.
    fn assert_failed(&self, text: &str) {
        assert_eq!(self.run.status, Some(1), "{}", self.run.transcript());
        assert!(
            self.run.failed(text),
            "no FAIL line contains {text:?}\n{}",
            self.run.transcript()
        );
        assert!(
            self.run.stdout.trim_end().ends_with(')')
                && self
                    .run
                    .stdout
                    .lines()
                    .last()
                    .unwrap()
                    .starts_with("RESULT: FAIL"),
            "{}",
            self.run.transcript()
        );
        assert_eq!(self.report()["result"], "FAIL");
        let checks = self.report()["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .any(|check| check["result"] == "FAIL"
                    && check["name"].as_str().unwrap().contains(text)),
            "the report has no failed check containing {text:?}: {checks:#?}"
        );
    }
}

/// Runs route-check.sh against `cluster`, with a probe wait of `probe_wait` seconds. A run that
/// is still going after `limit` is killed, and the test fails.
fn check_with(name: &str, cluster: &Cluster, probe_wait: u32, limit: Duration) -> Checked {
    require(&["bash", "jq", "awk", "grep"]);
    let dir = scratch(name);
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let kubectl = write(&bin, "kubectl", FAKE_KUBECTL);
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755)).unwrap();
    fake_getent(&bin);
    let dropped: Vec<&str> = cluster.dropped.iter().map(String::as_str).collect();
    fake_curl(&bin, &dropped);
    cluster.write(&dir);
    write(&dir, "probe-container", "");
    let routes = write(
        &dir,
        "routes.tsv",
        cluster.routes.as_deref().unwrap_or(ROUTES),
    );
    let gateway_url = cluster.gateway_url.as_deref().unwrap_or(GATEWAY_URL);
    let report = dir.join("report.json");
    let kubeconfig = dir.join("kubeconfig");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let stdout = std::fs::File::create(dir.join("stdout")).unwrap();
    let stderr = std::fs::File::create(dir.join("stderr")).unwrap();
    let started = Instant::now();
    let mut command = Command::new("bash");
    command
        .arg(repo().join("deploy/route-check/route-check.sh"))
        .arg(format!("--kubeconfig={}", kubeconfig.display()))
        .args(["--context", CONTEXT, "--as", OPERATOR])
        .args(["--namespace", "team-a", "--selector", "app=agent"])
        .args(["--gateway-ns", "switchboard", "--server-ns", "mock-docs"])
        .args(["--server-service", "mock-docs/mock-docs"])
        .args(["--server-audience", "mock-docs"])
        .arg("--routes")
        .arg(&routes)
        .args(["--gateway-url", gateway_url, "--probe-image", PROBE_IMAGE])
        .arg("--report")
        .arg(&report)
        .args(["--environment", "kind"])
        .args(["--probe-wait", &probe_wait.to_string()])
        .env("PATH", path)
        .env("FAKE_DIR", &dir)
        .env("KUBECONFIG", "/nonexistent/caller-kubeconfig")
        .env_remove("PROBE_SCRIPT")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    if cluster.run_probe.is_some() {
        command.env("PROBE_SCRIPT", repo().join("deploy/route-check/probe.sh"));
        for proxy in ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"] {
            command.env_remove(proxy);
        }
    }
    let mut child = command.spawn().unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "route-check.sh was still running after {limit:?}\n--- stdout\n{}",
                std::fs::read_to_string(dir.join("stdout")).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let elapsed = started.elapsed();
    let run = Run {
        status: status.code(),
        stdout: std::fs::read_to_string(dir.join("stdout")).unwrap(),
        stderr: std::fs::read_to_string(dir.join("stderr")).unwrap(),
    };
    let report = std::fs::read_to_string(&report)
        .ok()
        .map(|text| serde_json::from_str(&text).unwrap());
    let calls = std::fs::read_to_string(dir.join("calls.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    Checked {
        run,
        report,
        calls,
        dir,
        elapsed,
    }
}

fn check(name: &str, cluster: &Cluster) -> Checked {
    check_with(name, cluster, 5, Duration::from_secs(60))
}

/// permissions.tsv as it must be: decision 0010's control 1, every family.
const PERMISSIONS: &[(&str, &str, &str, &str)] = &[
    ("get", "secrets", "-", "namespaced"),
    ("list", "secrets", "-", "namespaced"),
    ("watch", "secrets", "-", "namespaced"),
    ("get", "configmaps", "-", "namespaced"),
    ("list", "configmaps", "-", "namespaced"),
    ("watch", "configmaps", "-", "namespaced"),
    ("create", "pods", "-", "namespaced"),
    ("create", "deployments.apps", "-", "namespaced"),
    ("update", "deployments.apps", "-", "namespaced"),
    ("patch", "deployments.apps", "-", "namespaced"),
    ("create", "replicasets.apps", "-", "namespaced"),
    ("update", "replicasets.apps", "-", "namespaced"),
    ("patch", "replicasets.apps", "-", "namespaced"),
    ("create", "statefulsets.apps", "-", "namespaced"),
    ("update", "statefulsets.apps", "-", "namespaced"),
    ("patch", "statefulsets.apps", "-", "namespaced"),
    ("create", "daemonsets.apps", "-", "namespaced"),
    ("update", "daemonsets.apps", "-", "namespaced"),
    ("patch", "daemonsets.apps", "-", "namespaced"),
    ("create", "jobs.batch", "-", "namespaced"),
    ("update", "jobs.batch", "-", "namespaced"),
    ("patch", "jobs.batch", "-", "namespaced"),
    ("create", "cronjobs.batch", "-", "namespaced"),
    ("update", "cronjobs.batch", "-", "namespaced"),
    ("patch", "cronjobs.batch", "-", "namespaced"),
    ("create", "pods", "exec", "namespaced"),
    ("get", "pods", "exec", "namespaced"),
    ("create", "pods", "attach", "namespaced"),
    ("get", "pods", "attach", "namespaced"),
    ("create", "pods", "portforward", "namespaced"),
    ("get", "pods", "portforward", "namespaced"),
    ("patch", "pods", "ephemeralcontainers", "namespaced"),
    ("update", "pods", "ephemeralcontainers", "namespaced"),
    ("create", "serviceaccounts", "token", "namespaced"),
    ("impersonate", "users", "-", "cluster"),
    ("impersonate", "groups", "-", "cluster"),
    ("impersonate", "serviceaccounts", "-", "namespaced"),
    ("impersonate", "uids.authentication.k8s.io", "-", "cluster"),
    (
        "impersonate",
        "userextras.authentication.k8s.io",
        "scopes",
        "cluster",
    ),
    ("bind", "roles.rbac.authorization.k8s.io", "-", "namespaced"),
    (
        "escalate",
        "roles.rbac.authorization.k8s.io",
        "-",
        "namespaced",
    ),
    (
        "bind",
        "clusterroles.rbac.authorization.k8s.io",
        "-",
        "namespaced",
    ),
    (
        "escalate",
        "clusterroles.rbac.authorization.k8s.io",
        "-",
        "cluster",
    ),
    (
        "create",
        "rolebindings.rbac.authorization.k8s.io",
        "-",
        "namespaced",
    ),
    (
        "create",
        "clusterrolebindings.rbac.authorization.k8s.io",
        "-",
        "cluster",
    ),
    ("get", "nodes", "proxy", "cluster"),
    ("create", "nodes", "proxy", "cluster"),
    ("get", "pods", "proxy", "namespaced"),
    ("create", "pods", "proxy", "namespaced"),
    ("get", "services", "proxy", "namespaced"),
    ("create", "services", "proxy", "namespaced"),
];

#[test]
fn the_permissions_list_holds_every_family_of_control_one() {
    let rows: Vec<Vec<String>> = read("deploy/route-check/permissions.tsv")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect();
    let want: Vec<Vec<String>> = PERMISSIONS
        .iter()
        .map(|(verb, resource, sub, scope)| {
            vec![
                (*verb).to_owned(),
                (*resource).to_owned(),
                (*sub).to_owned(),
                (*scope).to_owned(),
            ]
        })
        .collect();
    assert_eq!(rows, want);
}

/// The reviews a clean run must ask: each row of the list, as the workload's ServiceAccount, in
/// each namespace for a namespaced row, and across the cluster for every row.
fn expected_reviews() -> BTreeSet<String> {
    let mut want = BTreeSet::new();
    for (verb, resource, sub, scope) in PERMISSIONS {
        let (resource, group) = resource.split_once('.').unwrap_or((resource, ""));
        let sub = if *sub == "-" { "" } else { sub };
        let namespaces: &[&str] = if *scope == "namespaced" {
            &["team-a", "switchboard", "mock-docs", ""]
        } else {
            &[""]
        };
        for namespace in namespaces {
            want.insert(format!("{verb}|{group}|{resource}|{sub}|{namespace}"));
        }
    }
    want
}

#[test]
fn a_clean_pod_passes() {
    let checked = check("clean", &Cluster::clean());
    let run = &checked.run;
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(run.lines("FAIL ").is_empty(), "{}", run.transcript());
    assert!(
        run.stdout
            .lines()
            .last()
            .unwrap()
            .starts_with("RESULT: PASS ("),
        "{}",
        run.transcript()
    );
    for text in [
        "a running pod matches app=agent in team-a: team-a/agent-0",
        "network policy is enforced: kindnet, default-on (kindnetd v20260528-9350166c, kind v0.32.0)",
        "no Secret volume",
        "no variable from a Secret (secretKeyRef)",
        "no variables from a Secret (envFrom secretRef)",
        "no string in a token format",
        "no projected token for a server's audience",
        "team-a/mock-workload may not impersonate users (cluster)",
        "team-a/mock-workload may not get secrets (team-a,switchboard,mock-docs,cluster)",
        "the probe ended within 5 s (exit 0)",
        "the probe passed: every route refused (4 attempts, EXPECT=refused)",
    ] {
        assert!(
            checked.passed(text),
            "no PASS {text:?}\n{}",
            run.transcript()
        );
    }

    // Every call names the kubeconfig, the context and the operator it acts as, and a timeout:
    // 30 s, or, while waiting for the probe, no more than the wait has left.
    let kubeconfig = checked.dir.join("kubeconfig");
    let prefix = format!(
        "--kubeconfig {} --context {CONTEXT} --as={OPERATOR} --request-timeout=",
        kubeconfig.display()
    );
    assert!(!checked.calls.is_empty());
    for call in &checked.calls {
        assert!(call.starts_with(&prefix), "{call}");
        let timeout = call[prefix.len()..].split_once(' ').unwrap().0;
        if call.ends_with(" get pod agent-0 -n team-a -o json") {
            let seconds: u32 = timeout.strip_suffix('s').unwrap().parse().unwrap();
            assert!((1..=5).contains(&seconds), "{call}");
        } else {
            assert_eq!(timeout, "30s", "{call}");
        }
        // Never Secret data, never exec, never an impersonated review.
        assert!(!call.contains("secret"), "{call}");
        assert!(!call.contains(" exec "), "{call}");
        assert!(!call.contains("auth can-i"), "{call}");
    }

    // The reviews: the workload's ServiceAccount, its groups, and every row in every scope.
    let reviews: Value =
        serde_json::from_str(&std::fs::read_to_string(checked.dir.join("reviews.json")).unwrap())
            .unwrap();
    let items = reviews["items"].as_array().unwrap();
    let mut asked = BTreeSet::new();
    for item in items {
        assert_eq!(item["kind"], "SubjectAccessReview");
        assert_eq!(item["spec"]["user"], WORKLOAD_USER);
        assert_eq!(
            item["spec"]["groups"],
            json!([
                "system:serviceaccounts",
                "system:serviceaccounts:team-a",
                "system:authenticated"
            ])
        );
        let r = &item["spec"]["resourceAttributes"];
        let text = |key: &str| r[key].as_str().unwrap_or("").to_owned();
        asked.insert(format!(
            "{}|{}|{}|{}|{}",
            text("verb"),
            text("group"),
            text("resource"),
            text("subresource"),
            text("namespace")
        ));
    }
    assert_eq!(items.len(), asked.len());
    assert_eq!(asked, expected_reviews());

    // The probe: an ephemeral container under the restricted profile, with only the probe's
    // variables, and {{ADDR}} replaced by the Service's ClusterIP and endpoint address.
    let container = std::fs::read_to_string(checked.dir.join("probe-container")).unwrap();
    assert!(container.starts_with("route-probe-"), "{container}");
    let debug: Vec<&String> = checked
        .calls
        .iter()
        .filter(|call| call.contains(" debug "))
        .collect();
    assert_eq!(debug.len(), 1, "{:?}", checked.calls);
    assert!(
        debug[0].contains(&format!(
            "--request-timeout=30s debug pod/agent-0 -n team-a --image={PROBE_IMAGE} --profile=restricted -c {container} --custom="
        )) && debug[0].ends_with("/probe-env.json -- /usr/local/bin/route-probe.sh"),
        "{}",
        debug[0]
    );
    let custom: Value = serde_json::from_str(
        &std::fs::read_to_string(checked.dir.join("debug-custom.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        custom,
        json!({"env": [
            {"name": "ROUTES", "value": ROUTES.replace("{{ADDR}}", "10.244.0.7,10.96.12.34").trim_end()},
            {"name": "GATEWAY_URL", "value": GATEWAY_URL},
            {"name": "EXPECT", "value": "refused"}
        ]})
    );
    assert!(
        checked
            .calls
            .iter()
            .any(|call| call.ends_with(&format!("logs pod/agent-0 -n team-a -c {container}")))
    );
}

#[test]
fn the_report_has_every_field() {
    let mut cluster = Cluster::clean();
    cluster.service_account["metadata"]["annotations"] = json!({
        "eks.amazonaws.com/role-arn": "arn:aws:iam::000000000000:role/dummy-for-test",
        "unrelated.example/annotation": "x"
    });
    let checked = check("report", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    // The cloud identity is recorded for the owner, and never fails the run.
    assert!(checked.run.stdout.contains(
        "NOTE cloud identity for the owner to check: eks.amazonaws.com/role-arn=arn:aws:iam::000000000000:role/dummy-for-test"
    ));
    let report = checked.report();
    let date = report["date"].as_str().unwrap();
    assert_eq!(date.len(), 20, "{date}");
    assert!(date.ends_with('Z') && date.as_bytes()[10] == b'T', "{date}");
    let fields = [
        ("environment", json!("kind")),
        ("kubernetes_version", json!("v1.36.1")),
        ("kind_version", json!("kind v0.32.0")),
        (
            "node_image",
            json!("Debian GNU/Linux 12 (bookworm), kubelet v1.36.1, containerd://2.1.1"),
        ),
        ("network_plugin", json!("kindnet")),
        (
            "enforcement",
            json!("default-on (kindnetd v20260528-9350166c, kind v0.32.0)"),
        ),
        ("pod", json!("team-a/agent-0")),
        ("node", json!(NODE)),
        ("service_account", json!("team-a/mock-workload")),
        (
            "cloud_identity",
            json!({"eks.amazonaws.com/role-arn": "arn:aws:iam::000000000000:role/dummy-for-test"}),
        ),
        (
            "token_audiences",
            json!([
                {"volume": "gateway-token", "audience": "switchboard"},
                {"volume": "kube-api-access-x7k2p", "audience": ""}
            ]),
        ),
        ("expect", json!("refused")),
        ("probe_result", json!("PASS")),
        ("result", json!("PASS")),
    ];
    for (key, want) in &fields {
        assert_eq!(&report[key], want, "{key}");
    }
    assert!(
        report["probe_container"]
            .as_str()
            .unwrap()
            .starts_with("route-probe-")
    );
    let checks = report["checks"].as_array().unwrap();
    // The pod, the plugin, three Secret checks, the token scan, the audiences, every
    // permission, the probe's end and its result.
    assert_eq!(
        checks.len(),
        2 + 3 + 2 + PERMISSIONS.len() + 2,
        "{checks:#?}"
    );
    assert!(checks.iter().all(|check| check["result"] == "PASS"));
    let routes = report["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 4);
    assert_eq!(
        routes[1],
        json!({
            "line": "ROUTE mock-docs address 10.244.0.7 refused",
            "row": "mock-docs",
            "by": "address",
            "target": "10.244.0.7",
            "result": "refused",
            "well_formed": true
        })
    );
    let mut keys: Vec<&str> = report
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut want: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
    want.extend(["date", "probe_container", "checks", "routes"]);
    want.sort_unstable();
    assert_eq!(keys, want);
}

#[test]
fn a_secret_volume_fails() {
    for (name, volume) in [
        (
            "secret",
            json!({"name": "creds", "secret": {"secretName": "docs-credential"}}),
        ),
        (
            "projected",
            json!({"name": "creds", "projected": {"sources": [{"secret": {"name": "docs-credential"}}]}}),
        ),
        (
            "csi",
            json!({"name": "creds", "csi": {"driver": "secrets-store.csi.k8s.io"}}),
        ),
    ] {
        let mut cluster = Cluster::clean();
        cluster.pod_spec()["volumes"]
            .as_array_mut()
            .unwrap()
            .push(volume);
        check(&format!("secret-volume-{name}"), &cluster).assert_failed("no Secret volume: creds");
    }
}

#[test]
fn a_variable_from_a_secret_fails() {
    let mut cluster = Cluster::clean();
    cluster.agent()["env"].as_array_mut().unwrap().push(json!({
        "name": "DOCS_TOKEN",
        "valueFrom": {"secretKeyRef": {"name": "docs-credential", "key": "token"}}
    }));
    check("secret-key-ref", &cluster)
        .assert_failed("no variable from a Secret (secretKeyRef): agent/DOCS_TOKEN");

    // In an init container too.
    let mut cluster = Cluster::clean();
    cluster.pod_spec()["initContainers"] = json!([{
        "name": "setup",
        "env": [{"name": "DOCS_TOKEN", "valueFrom": {"secretKeyRef": {"name": "docs-credential", "key": "token"}}}]
    }]);
    check("secret-key-ref-init", &cluster)
        .assert_failed("no variable from a Secret (secretKeyRef): setup/DOCS_TOKEN");
}

#[test]
fn variables_from_a_secret_fail() {
    let mut cluster = Cluster::clean();
    cluster.agent()["envFrom"]
        .as_array_mut()
        .unwrap()
        .push(json!({"secretRef": {"name": "docs-credential"}}));
    check("env-from-secret", &cluster)
        .assert_failed("no variables from a Secret (envFrom secretRef): agent/docs-credential");
}

/// A dummy GitHub token in the classic format: ghp_ and 36 characters. Each dummy token in this
/// file is split with `concat!` where its prefix ends, so no whole token is in the source for a
/// secret scanner to flag; the test still sees the whole string.
const DUMMY_GHP: &str = concat!("ghp", "_0123456789abcdefghijklmnopqrstuvwxyz");

#[test]
fn a_config_map_holding_a_github_token_fails_without_printing_it() {
    let mut cluster = Cluster::clean();
    cluster.configmaps[0].2["data"]["GITHUB_TOKEN"] = json!(DUMMY_GHP);
    let checked = check("configmap-ghp", &cluster);
    checked.assert_failed("ConfigMap agent-settings key GITHUB_TOKEN (token-patterns.txt:");
    assert!(!checked.run.stdout.contains(DUMMY_GHP));
    assert!(!checked.run.stderr.contains(DUMMY_GHP));
    assert!(!checked.report().to_string().contains(DUMMY_GHP));
}

#[test]
fn every_listed_token_format_is_found_wherever_the_pod_reads_it() {
    // Dummy values in each format the patterns file lists, none of them real.
    let samples = [
        ("GITHUB_CLASSIC", DUMMY_GHP.to_owned()),
        (
            "GITHUB_OAUTH",
            concat!("gho", "_0123456789abcdefghijklmnopqrstuvwxyz").to_owned(),
        ),
        (
            "GITHUB_USER",
            concat!("ghu", "_0123456789abcdefghijklmnopqrstuvwxyz").to_owned(),
        ),
        (
            "GITHUB_SERVER",
            concat!("ghs", "_0123456789abcdefghijklmnopqrstuvwxyz").to_owned(),
        ),
        (
            "GITHUB_REFRESH",
            concat!("ghr", "_0123456789abcdefghijklmnopqrstuvwxyz").to_owned(),
        ),
        (
            "GITHUB_FINE_GRAINED",
            concat!("github_pat", "_11ABCDEFG0123456789abc_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm")
                .to_owned(),
        ),
        (
            "SLACK_BOT",
            concat!("xoxb", "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx").to_owned(),
        ),
        (
            "SLACK_USER",
            concat!("xoxp", "-123456789012-123456789012-1234567890123-0123456789abcdef").to_owned(),
        ),
        ("SLACK_APP_WORKSPACE", concat!("xoxa", "-2-0123456789abcdef").to_owned()),
        ("SLACK_REFRESH", concat!("xoxr", "-0123456789abcdef").to_owned()),
        ("SLACK_LEGACY", concat!("xoxs", "-0123456789abcdef").to_owned()),
        (
            "SLACK_APP_LEVEL",
            concat!("xapp", "-1-A0123456789-0123456789012-abcdef0123456789").to_owned(),
        ),
        ("SLACK_CONFIG", concat!("xoxe.xoxp", "-1-Mi0yLTEyMzQ1Njc4OTAx").to_owned()),
        ("SLACK_ROTATING", concat!("xoxe", "-1-My0xLTEyMzQ1Njc4OTAx").to_owned()),
        // AWS's own documentation example key ID, and its temporary twin.
        ("AWS_KEY", concat!("AKIA", "IOSFODNN7EXAMPLE").to_owned()),
        ("AWS_TEMPORARY_KEY", concat!("ASIA", "IOSFODNN7EXAMPLE").to_owned()),
        (
            "ATLASSIAN",
            concat!("ATATT", "3xFfGF0abcdefghijklmnopqrstuvwxyz0123456789").to_owned(),
        ),
        ("GITLAB", concat!("glpat", "-abcdefghij0123456789").to_owned()),
        ("NEW_RELIC_USER", concat!("NRAK", "-ABCDEFGHIJKLMNOPQRSTUVWXYZ0").to_owned()),
        (
            "NEW_RELIC_INSERT",
            concat!("NRII", "-abcdefghijklmnopqrstuvwxyz012345").to_owned(),
        ),
        (
            "NEW_RELIC_LICENSE",
            concat!("0123456789abcdef0123456789abcdef0123", "NRAL").to_owned(),
        ),
        (
            "AKAMAI",
            concat!("akab", "-abcdefghij012345-abcdefghij012345").to_owned(),
        ),
        // The shapes of the access and client tokens in Akamai's docs examples.
        (
            "AKAMAI_DOCS_ACCESS",
            concat!("akab", "-acc35t0k3nodujqunph3w7hzp7-gtm6ij").to_owned(),
        ),
        (
            "AKAMAI_DOCS_CLIENT",
            concat!("akab", "-c113ntt0k3n4qtari252bfxxbsl-yvsdj").to_owned(),
        ),
        (
            "SALESFORCE",
            concat!("00D5g000004XyZa", "!AQ8AQExampleSessionTokenValue.abc").to_owned(),
        ),
    ];
    let mut cluster = Cluster::clean();
    let data = &mut cluster.configmaps[0].2["data"];
    for (key, value) in &samples {
        // Inside other text, on a later line, so the patterns are not anchored to a whole value.
        data[*key] = json!(format!("# set by hand\nexport {key}={value}; echo done\n"));
    }
    // A ConfigMap's binary data, a mounted ConfigMap and a literal variable are read too.
    cluster.configmaps[0].2["binaryData"] = json!({"blob": "dG9rZW46IHhveGItMTIzNDU2Nzg5MDEyLTEyMzQ1Njc4OTAxMjMtQWJDZEVmR2hJaktsTW5PcFFyU3RVdld4"});
    cluster.configmaps.push((
        "team-a",
        "mounted",
        json!({"data": {"settings.toml": format!("token = \"{DUMMY_GHP}\"\n")}}),
    ));
    cluster.pod_spec()["volumes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "settings", "configMap": {"name": "mounted"}}));
    cluster.agent()["env"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "AWS_ACCESS_KEY_ID", "value": concat!("AKIA", "IOSFODNN7EXAMPLE")}));
    let checked = check("token-formats", &cluster);
    let failed = checked.run.lines("FAIL no string in a token format: ");
    assert_eq!(failed.len(), 1, "{}", checked.run.transcript());
    for (key, value) in &samples {
        assert!(
            failed[0].contains(&format!("ConfigMap agent-settings key {key} (")),
            "{key} was not found: {}",
            failed[0]
        );
        assert!(
            !checked.run.stdout.contains(value.as_str()),
            "{key} printed"
        );
    }
    for place in [
        "ConfigMap agent-settings key blob (",
        "ConfigMap mounted key settings.toml (",
        "variable agent/AWS_ACCESS_KEY_ID (",
    ] {
        assert!(failed[0].contains(place), "{place}: {}", failed[0]);
    }
    assert_eq!(checked.run.status, Some(1));
}

#[test]
fn every_token_pattern_names_its_source() {
    let patterns = read("deploy/route-check/token-patterns.txt");
    let lines: Vec<&str> = patterns.lines().collect();
    let mut count = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        count += 1;
        assert!(
            i > 0 && lines[i - 1].starts_with("# "),
            "pattern {line:?} has no comment naming its source above it"
        );
    }
    assert!(count >= 10, "{patterns}");
}

#[test]
fn an_unreadable_config_map_fails() {
    let mut cluster = Cluster::clean();
    cluster
        .configmaps
        .retain(|(_, name, _)| *name != "agent-settings");
    check("configmap-unreadable", &cluster)
        .assert_failed("no string in a token format: could not read ConfigMap agent-settings");
}

/// kubectl output that is not one JSON object: cut short, empty, and two objects. jq reads the
/// last two without an error, as nothing or as two values.
const NOT_ONE_OBJECT: [(&str, &str); 3] = [
    ("cut-short", "{\"items\": [{\"metadata\": "),
    ("empty", ""),
    ("two-objects", "{}\n{}\n"),
];

/// Runs the check once for each output in `NOT_ONE_OBJECT` served as `file`, and once for each
/// of `shapes` (JSON that jq parses but cannot take), and expects each run to fail with `text`
/// and never to pass a check containing it.
fn fails_when_unparsed(name: &str, file: &'static str, shapes: &[&'static str], text: &str) {
    let cases = NOT_ONE_OBJECT
        .iter()
        .map(|(case, contents)| ((*case).to_owned(), *contents))
        .chain(
            shapes
                .iter()
                .enumerate()
                .map(|(i, shape)| (format!("shape-{i}"), *shape)),
        );
    let label = text.split(':').next().unwrap();
    for (case, contents) in cases {
        let mut cluster = Cluster::clean();
        cluster.raw = vec![(file, contents)];
        let checked = check(&format!("{name}-{case}"), &cluster);
        checked.assert_failed(text);
        assert!(
            !checked.passed(label),
            "{case}: a check {label:?} passed\n{}",
            checked.run.transcript()
        );
    }
}

#[test]
fn a_config_map_that_cannot_be_parsed_fails() {
    fails_when_unparsed(
        "configmap-unparsed",
        "configmap-team-a-agent-settings.json",
        &[
            r#"{"data": "LOG_LEVEL=info"}"#,
            r#"{"data": ["info"]}"#,
            r#"{"binaryData": {"blob": "not base64 %%%"}}"#,
        ],
        "no string in a token format: could not read ConfigMap agent-settings",
    );
}

#[test]
fn workload_pods_that_cannot_be_parsed_fail() {
    fails_when_unparsed(
        "pods-unparsed",
        "workload-pods.json",
        &[
            r#"{"kind": "List"}"#,
            r#"{"items": [{"metadata": {"name": 7}, "status": {"phase": "Running"}}]}"#,
        ],
        "a running pod matches app=agent in team-a: could not read the pods",
    );
}

#[test]
fn daemonsets_that_cannot_be_parsed_fail() {
    fails_when_unparsed(
        "daemonsets-unparsed",
        "daemonsets.json",
        &[r#"{"items": [{"metadata": {"name": 7}}]}"#],
        "network policy enforcement: could not read the DaemonSets in kube-system",
    );
}

#[test]
fn kindnet_pods_that_cannot_be_parsed_fail() {
    fails_when_unparsed(
        "kindnet-pods-unparsed",
        "kindnet-pods.json",
        &[r#"{"items": "kindnet-9qv4m"}"#],
        "network policy enforcement: could not read (could not read the kindnet pods)",
    );
}

/// A kindnetd container whose flags jq cannot take. Before the flags' read was checked, it
/// counted as no flag set, and the image's default passed.
#[test]
fn a_kindnet_container_that_cannot_be_parsed_fails() {
    for (name, field, value) in [
        ("args", "args", json!("--network-policy=false")),
        (
            "command",
            "command",
            json!("/bin/kindnetd --network-policy=false"),
        ),
        ("env", "env", json!("NETWORK_POLICY=false")),
    ] {
        let mut cluster = Cluster::clean();
        cluster.kindnet_pod["spec"]["containers"][0][field] = value;
        let checked = check(&format!("kindnet-container-unparsed-{name}"), &cluster);
        checked.assert_failed(
            "network policy enforcement: could not read (could not read the kindnetd container of kindnet-9qv4m)",
        );
        assert!(!checked.passed("network policy is enforced"), "{name}");
        assert_eq!(checked.report()["enforcement"], "could not read");
    }
}

/// A pod spec in a shape jq cannot take fails each check that reads that part of it, and the
/// run goes on to the checks after it.
#[test]
fn a_pod_spec_that_cannot_be_parsed_fails() {
    for (name, field, texts) in [
        (
            "volumes",
            "volumes",
            &[
                "no Secret volume: could not read the pod's volumes",
                "no string in a token format: could not read which ConfigMaps the pod reads",
                "no projected token for a server's audience: could not read the pod's projected volumes",
            ][..],
        ),
        (
            "env",
            "env",
            &[
                "no variable from a Secret (secretKeyRef): could not read the pod's variables",
                "no string in a token format: could not read the pod's variables",
            ][..],
        ),
        (
            "envfrom",
            "envFrom",
            &[
                "no variables from a Secret (envFrom secretRef): could not read the pod's envFrom",
                "no string in a token format: could not read which ConfigMaps the pod reads",
            ][..],
        ),
    ] {
        let mut cluster = Cluster::clean();
        if field == "volumes" {
            cluster.pod_spec()[field] = json!("gateway-token");
        } else {
            cluster.agent()[field] = json!("GATEWAY_URL");
        }
        let checked = check(&format!("pod-spec-unparsed-{name}"), &cluster);
        for text in texts {
            checked.assert_failed(text);
        }
        assert!(
            checked.passed("the probe passed"),
            "{name}: the run stopped\n{}",
            checked.run.transcript()
        );
    }

    // A projected token whose source is not an object.
    let mut cluster = Cluster::clean();
    cluster.pod_spec()["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"] =
        json!("mock-docs");
    let checked = check("pod-spec-unparsed-token", &cluster);
    checked.assert_failed(
        "no projected token for a server's audience: could not read the pod's projected volumes",
    );
    assert!(checked.report()["token_audiences"].is_null());
}

#[test]
fn a_service_account_that_cannot_be_parsed_fails() {
    fails_when_unparsed(
        "serviceaccount-unparsed",
        "serviceaccount.json",
        &[r#"{"metadata": {"annotations": "eks.amazonaws.com/role-arn"}}"#],
        "cloud identity of team-a/mock-workload: could not read the ServiceAccount",
    );
}

#[test]
fn a_server_service_that_cannot_be_parsed_fails() {
    fails_when_unparsed(
        "service-unparsed",
        "service-mock-docs-mock-docs.json",
        &[r#"{"spec": {"clusterIPs": "10.96.12.34"}}"#],
        "the probe ran: could not read the servers' addresses",
    );
    fails_when_unparsed(
        "endpointslices-unparsed",
        "endpointslices-mock-docs.json",
        &[r#"{"items": [{"endpoints": [{"addresses": "10.244.0.7"}]}]}"#],
        "the probe ran: could not read the servers' addresses",
    );
}

/// The pod read while waiting for the probe cannot be parsed: the wait fails as could not read,
/// not as a probe that ended.
#[test]
fn a_probe_pod_that_cannot_be_parsed_fails() {
    for (case, contents) in NOT_ONE_OBJECT.iter().copied().chain([(
        "shape",
        r#"{"status": {"ephemeralContainerStatuses": "route-probe"}}"#,
    )]) {
        let mut cluster = Cluster::clean();
        cluster.raw = vec![("probe-pod", contents)];
        let checked = check_with(
            &format!("probe-pod-unparsed-{case}"),
            &cluster,
            1,
            Duration::from_secs(60),
        );
        checked.assert_failed("the probe ended within 1 s: could not read pod agent-0");
        assert!(!checked.passed("the probe ended"), "{case}");
        assert!(!checked.passed("the probe passed"), "{case}");
    }
}

#[test]
fn a_projected_token_for_a_servers_audience_fails() {
    let mut cluster = Cluster::clean();
    cluster.pod_spec()["volumes"].as_array_mut().unwrap().push(json!({
        "name": "docs-token",
        "projected": {"sources": [{"serviceAccountToken": {"audience": "mock-docs", "path": "token"}}]}
    }));
    let checked = check("audience", &cluster);
    checked.assert_failed("no projected token for a server's audience: mock-docs");
    assert!(
        checked.report()["token_audiences"]
            .as_array()
            .unwrap()
            .contains(&json!({"volume": "docs-token", "audience": "mock-docs"}))
    );
}

#[test]
fn any_review_answered_yes_fails() {
    for (name, yes, text) in [
        (
            "impersonate",
            json!({"verb": "impersonate", "resource": "users"}),
            "team-a/mock-workload may not impersonate users: it may, in cluster",
        ),
        (
            "secrets",
            json!({"verb": "get", "resource": "secrets", "namespace": "mock-docs"}),
            "team-a/mock-workload may not get secrets: it may, in mock-docs",
        ),
        (
            "ephemeral",
            json!({"verb": "patch", "resource": "pods", "subresource": "ephemeralcontainers", "namespace": "switchboard"}),
            "team-a/mock-workload may not patch pods/ephemeralcontainers: it may, in switchboard",
        ),
        (
            "cronjobs",
            json!({"verb": "create", "group": "batch", "resource": "cronjobs"}),
            "team-a/mock-workload may not create cronjobs.batch: it may, in team-a,switchboard,mock-docs,cluster",
        ),
    ] {
        let mut cluster = Cluster::clean();
        cluster.sar_yes = json!([yes]);
        check(&format!("sar-yes-{name}"), &cluster).assert_failed(text);
    }
}

#[test]
fn a_review_with_no_answer_fails() {
    let mut cluster = Cluster::clean();
    cluster.sar_drop = json!([{"verb": "create", "resource": "pods", "subresource": "exec", "namespace": "switchboard"}]);
    check("sar-dropped", &cluster).assert_failed(
        "team-a/mock-workload may not create pods/exec: could not read the answer for switchboard",
    );

    // An answer that could not be settled: not allowed, but an authorizer failed.
    let mut cluster = Cluster::clean();
    cluster.sar_error = json!([{"verb": "get", "resource": "secrets", "namespace": "team-a"}]);
    check("sar-error", &cluster).assert_failed(
        "team-a/mock-workload may not get secrets: could not read the answer for team-a",
    );

    let mut cluster = Cluster::clean();
    cluster.sar_fails = true;
    check("sar-refused", &cluster).assert_failed(
        "team-a/mock-workload may do none of control 1: could not create the SubjectAccessReviews",
    );
}

#[test]
fn versions_that_cannot_be_read_fail() {
    let mut cluster = Cluster::clean();
    cluster.unreadable = vec!["version.json"];
    let checked = check("version-unreadable", &cluster);
    checked.assert_failed("the Kubernetes version is recorded: could not read");
    assert_eq!(checked.report()["kubernetes_version"], "could not read");

    let mut cluster = Cluster::clean();
    cluster.unreadable = vec!["node.json"];
    let checked = check("node-unreadable", &cluster);
    checked.assert_failed(&format!(
        "the node image of {NODE} is recorded: could not read"
    ));
    assert_eq!(checked.report()["node_image"], "could not read");
}

#[test]
fn kindnet_with_network_policy_off_fails() {
    let mut cluster = Cluster::clean();
    cluster.kindnet_pod["spec"]["containers"][0]["args"] = json!(["--network-policy=false"]);
    let checked = check("kindnet-off", &cluster);
    checked.assert_failed(
        "network policy is not enforced: kindnet, off by flag (--network-policy=false)",
    );
    assert_eq!(
        checked.report()["enforcement"],
        "off by flag (--network-policy=false)"
    );

    // The agent says it skipped its policy controller.
    let mut cluster = Cluster::clean();
    cluster
        .kindnet_log
        .push_str("I1008 01:34:19.1 1 main.go:261] Error creating network policy controller: no nftables, skipping network policies\n");
    check("kindnet-skipped", &cluster).assert_failed(
        "network policy is not enforced: kindnet, default-on (kindnetd v20260528-9350166c, kind v0.32.0), but kindnet-9qv4m logged that it skipped network policies",
    );
}

#[test]
fn the_flag_or_the_pinned_default_settles_enforcement_and_the_log_is_only_a_fallback() {
    // The kubelet rotates kindnet's log, on switchboard-demo after about a week, and its start
    // lines go with it. The flag or the pinned kindnetd's default still settles it.
    let rotated = "I1008 01:35:29.003313       1 main.go:320] Handling node\n";
    let default_on = "default-on (kindnetd v20260528-9350166c, kind v0.32.0)";
    let mut cluster = Cluster::clean();
    cluster.kindnet_log = rotated.to_owned();
    let checked = check("enforcement-default-log-rotated", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert!(
        checked.passed(&format!(
            "network policy is enforced: kindnet, {default_on}"
        )),
        "{}",
        checked.run.transcript()
    );
    assert_eq!(checked.report()["enforcement"], default_on);
    assert_eq!(checked.report()["kind_version"], "kind v0.32.0");

    let mut cluster = Cluster::clean();
    cluster.unreadable.push("kindnet.log");
    let checked = check("enforcement-default-log-unread", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert_eq!(
        checked.report()["enforcement"],
        format!("{default_on}; its log could not be read, and is only a fallback")
    );

    let mut cluster = Cluster::clean();
    cluster.kindnet_pod["spec"]["containers"][0]["args"] = json!(["--network-policy=true"]);
    cluster.kindnet_log = rotated.to_owned();
    let checked = check("enforcement-flag-log-rotated", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert_eq!(
        checked.report()["enforcement"],
        "on by flag (--network-policy=true)"
    );

    // Neither settles it: the log does, and the report says it was the fallback.
    let mut cluster = Cluster::clean();
    cluster.kindnet_pod["spec"]["containers"][0]["image"] =
        json!("docker.io/kindest/kindnetd:v20990101-0123abcd");
    let checked = check("enforcement-log-fallback", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert_eq!(
        checked.report()["enforcement"],
        "on by its log (the fallback: no flag, and the default of kindnetd v20990101-0123abcd is not known; kindnet-9qv4m logged its network policy controller starting)"
    );
    assert_eq!(checked.report()["kind_version"], "unknown");
    cluster.kindnet_log.push_str(
        "I1008 01:34:19.1 1 main.go:261] Error creating network policy controller: no nftables, skipping network policies\n",
    );
    check("enforcement-log-fallback-skipped", &cluster).assert_failed(
        "network policy is not enforced: kindnet, off by its log (the fallback: no flag, and the default of kindnetd v20990101-0123abcd is not known), but kindnet-9qv4m logged that it skipped network policies",
    );
}

#[test]
fn enforcement_that_cannot_be_read_fails() {
    let mut cases: Vec<(&str, Cluster, &str)> = Vec::new();

    // With no flag and a kindnetd whose default is not known, the log is the fallback, and it
    // settles nothing when its start lines are gone or it cannot be read.
    let unknown = || {
        let mut cluster = Cluster::clean();
        cluster.kindnet_pod["spec"]["containers"][0]["image"] =
            json!("docker.io/kindest/kindnetd:v20990101-0123abcd");
        cluster
    };
    let mut cluster = unknown();
    cluster.kindnet_log = "I1008 01:35:29.003313       1 main.go:320] Handling node\n".to_owned();
    cases.push((
        "unknown-tag-log-rotated",
        cluster,
        "network policy enforcement: could not read (pod kindnet-9qv4m sets no network-policy flag, and the default of kindnetd v20990101-0123abcd is not known, and the log of kindnet-9qv4m, the fallback, does not show its network policy controller starting)",
    ));
    let mut cluster = unknown();
    cluster.unreadable.push("kindnet.log");
    cases.push((
        "unknown-tag-log-unread",
        cluster,
        "network policy enforcement: could not read (pod kindnet-9qv4m sets no network-policy flag, and the default of kindnetd v20990101-0123abcd is not known, and the log of kindnet-9qv4m, the fallback, could not be read)",
    ));

    let mut cluster = Cluster::clean();
    cluster.kindnet_pod["spec"]["nodeName"] = json!("another-node");
    cases.push((
        "no-agent-on-node",
        cluster,
        "network policy enforcement: could not read (no running kindnet pod on node switchboard-demo-control-plane)",
    ));

    let mut cluster = Cluster::clean();
    cluster.kindnet_pod["spec"]["containers"][0]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "NETWORK_POLICY", "valueFrom": {"configMapKeyRef": {"name": "kindnet", "key": "policy"}}}));
    cases.push((
        "flag-from-elsewhere",
        cluster,
        "network policy enforcement: could not read (pod kindnet-9qv4m sets NETWORK_POLICY=<from elsewhere>)",
    ));

    let mut cluster = Cluster::clean();
    cluster.kindnet_log = String::new();
    cluster.daemonsets["items"][0] = json!({"metadata": {"name": "calico-node"}, "spec": {}});
    cases.push((
        "calico",
        cluster,
        "network policy enforcement: unknown for plugin calico; only kindnet's is read",
    ));

    let mut cluster = Cluster::clean();
    cluster.daemonsets = json!({"items": [{"metadata": {"name": "kube-proxy"}, "spec": {}}]});
    cases.push((
        "no-plugin",
        cluster,
        "network policy enforcement: unknown for plugin unknown; only kindnet's is read",
    ));

    for (name, cluster, text) in cases {
        let checked = check(&format!("enforcement-{name}"), &cluster);
        checked.assert_failed(text);
        assert!(
            ["could not read", "unknown"]
                .contains(&checked.report()["enforcement"].as_str().unwrap()),
            "{name}: {}",
            checked.report()["enforcement"]
        );
    }

    // The DaemonSets themselves cannot be read.
    let mut cluster = Cluster::clean();
    cluster.daemonsets = Value::Null;
    let checked = check("enforcement-no-daemonsets", &cluster);
    checked
        .assert_failed("network policy enforcement: could not read the DaemonSets in kube-system");
    assert_eq!(checked.report()["network_plugin"], "could not read");
    assert_eq!(checked.report()["enforcement"], "could not read");
}

#[test]
fn no_running_pod_fails_and_starts_nothing() {
    let mut cluster = Cluster::clean();
    cluster.pod["status"]["phase"] = json!("Pending");
    let checked = check("no-pod", &cluster);
    checked.assert_failed("a running pod matches app=agent in team-a: there is none");
    assert!(!checked.calls.iter().any(|call| call.contains(" debug ")));
    assert!(!checked.calls.iter().any(|call| call.contains(" create ")));
    assert_eq!(checked.report()["checks"].as_array().unwrap().len(), 1);
}

#[test]
fn a_probe_that_does_not_pass_fails() {
    for (name, log, exit, text) in [
        (
            "result-fail",
            "ROUTE mock-docs name http://mock-docs.mock-docs.svc.cluster.local:8080/mcp open\nRESULT: FAIL\n",
            1,
            "the probe passed: RESULT: FAIL (exit 1)",
        ),
        (
            "no-result",
            "ROUTE mock-docs name http://mock-docs.mock-docs.svc.cluster.local:8080/mcp refused\n",
            0,
            "the probe passed: its last line is not a RESULT line",
        ),
        (
            "pass-with-open-route",
            "ROUTE mock-docs address 10.244.0.7 open\nRESULT: PASS\n",
            0,
            "the probe passed: RESULT: PASS, but not every route was refused",
        ),
        (
            "pass-with-bad-exit",
            PASSING_PROBE,
            2,
            "the probe passed: RESULT: PASS, but it exited 2",
        ),
        (
            "no-route",
            "RESULT: PASS\n",
            0,
            "the probe passed: it tried no route",
        ),
        (
            "unparsed-route",
            "ROUTE mock-docs somehow 10.244.0.7 refused\nRESULT: PASS\n",
            0,
            "the probe passed: 1 ROUTE lines are not in the probe's format",
        ),
    ] {
        let mut cluster = Cluster::clean();
        cluster.probe_log = log.to_owned();
        cluster.probe_exit = exit;
        check(&format!("probe-{name}"), &cluster).assert_failed(text);
    }
}

#[test]
fn a_probe_that_never_ends_fails_within_the_wait() {
    let mut cluster = Cluster::clean();
    cluster.probe_running = true;
    let checked = check_with("probe-running", &cluster, 2, Duration::from_secs(30));
    checked.assert_failed("the probe ended within 2 s: route-probe-");
    assert!(
        checked.elapsed < Duration::from_secs(20),
        "{:?}",
        checked.elapsed
    );
    // It never read a log it had no reason to trust.
    assert!(!checked.calls.iter().any(|call| call.contains("logs pod/")));
    assert_eq!(checked.report()["probe_result"], Value::Null);
    // Each read while waiting may take only the time the wait has left.
    let timeouts = wait_timeouts(&checked);
    assert!(!timeouts.is_empty(), "{:?}", checked.calls);
    assert!(
        timeouts.iter().all(|seconds| (1..=2).contains(seconds)),
        "{timeouts:?}"
    );
}

/// The `--request-timeout` of each read of the pod while waiting for the probe, in seconds.
fn wait_timeouts(checked: &Checked) -> Vec<u32> {
    checked
        .calls
        .iter()
        .filter(|call| call.ends_with(" get pod agent-0 -n team-a -o json"))
        .map(|call| {
            let (_, after) = call.split_once("--request-timeout=").unwrap();
            after
                .split_once("s ")
                .unwrap()
                .0
                .parse()
                .unwrap_or_else(|_| panic!("{call}"))
        })
        .collect()
}

/// A read of the pod that answers only after the wait is over: the probe's end it reports was
/// not seen within the wait, so it does not count.
#[test]
fn a_probe_end_seen_after_the_wait_does_not_count() {
    let mut cluster = Cluster::clean();
    cluster.probe_pod_delay = Some(3);
    let checked = check_with("probe-late", &cluster, 1, Duration::from_secs(30));
    checked.assert_failed("the probe ended within 1 s: route-probe-");
    assert!(!checked.passed("the probe ended"));
    assert!(!checked.calls.iter().any(|call| call.contains("logs pod/")));
    assert_eq!(wait_timeouts(&checked), [1]);
}

/// The step requires one ROUTE line for each attempt the routes ask for: a probe that skipped
/// one, tried one it was not asked to, or reported one twice does not pass, whatever its RESULT.
#[test]
fn the_probe_must_report_each_attempt_the_routes_ask_for_once() {
    let name_line =
        "ROUTE mock-docs name http://mock-docs.mock-docs.svc.cluster.local:8080/mcp refused\n";
    let without = |line: &str| PASSING_PROBE.replace(line, "");
    let with =
        |line: &str| PASSING_PROBE.replace("RESULT: PASS\n", &format!("{line}RESULT: PASS\n"));
    for (name, log, text) in [
        (
            "missing-address",
            without("ROUTE mock-docs address 10.96.12.34 refused\n"),
            "missing mock-docs address 10.96.12.34",
        ),
        (
            "missing-name",
            without(name_line),
            "missing mock-docs name http://mock-docs.mock-docs.svc.cluster.local:8080/mcp",
        ),
        (
            "extra-address",
            with("ROUTE mock-docs address 10.0.0.9 refused\n"),
            "not asked for mock-docs address 10.0.0.9",
        ),
        (
            "extra-name",
            with("ROUTE metadata name http://169.254.169.254/latest/meta-data/ refused\n"),
            "not asked for metadata name http://169.254.169.254/latest/meta-data/",
        ),
        (
            "extra-row",
            with("ROUTE elsewhere address 10.0.0.9 refused\n"),
            "not asked for elsewhere address 10.0.0.9",
        ),
        (
            "repeated",
            with("ROUTE mock-docs address 10.244.0.7 refused\n"),
            "repeated mock-docs address 10.244.0.7",
        ),
    ] {
        let mut cluster = Cluster::clean();
        cluster.probe_log = log;
        let checked = check(&format!("route-set-{name}"), &cluster);
        checked.assert_failed(&format!(
            "the probe passed: one ROUTE line per attempt the routes ask for: {text}"
        ));
        assert!(!checked.passed("the probe passed"), "{name}");
    }

    // A `resolve` row's addresses are found in the pod: any address lines will do, but there
    // must be one.
    let routes = format!("{ROUTES}lookup\thttp://lookup.example/\tresolve\n");
    let mut cluster = Cluster::clean();
    cluster.routes = Some(routes.clone());
    cluster.probe_log = with("ROUTE lookup name http://lookup.example/ refused\n");
    check("route-set-resolve-missing", &cluster).assert_failed(
        "the probe passed: one ROUTE line per attempt the routes ask for: missing lookup address (resolved in the pod)",
    );
    let mut cluster = Cluster::clean();
    cluster.routes = Some(routes);
    cluster.probe_log = with(
        "ROUTE lookup name http://lookup.example/ refused\n\
         ROUTE lookup address 10.1.2.3 refused\n\
         ROUTE lookup address 10.1.2.4 refused\n",
    );
    let checked = check("route-set-resolve", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert!(checked.passed("the probe passed: every route refused (7 attempts, EXPECT=refused)"));
}

/// The rows the probe fails for their host fail here too, and the probe is not started: an
/// address-literal host that is not one of the row's addresses, which the probe would never
/// try, a bracketed host that is not an IPv6 literal, and a host of digits and dots that is not
/// an IPv4 literal, which curl would look up as a name (issue #86). Each probe log below
/// matches the routes, so only the row check stands between it and a PASS.
#[test]
fn rows_the_probe_would_fail_for_their_host_fail_before_it_starts() {
    let with =
        |lines: &str| PASSING_PROBE.replace("RESULT: PASS\n", &format!("{lines}RESULT: PASS\n"));
    for (name, row, line, text) in [
        (
            "elsewhere",
            "server\thttp://127.0.0.1:8000/mcp\t127.0.0.2\treject_ok\n",
            "ROUTE server address 127.0.0.2 refused\n",
            ": the host 127.0.0.1 of the URL is not one of its addresses: 127.0.0.2",
        ),
        (
            "ipv6-elsewhere",
            "server\thttp://[::1]:8000/mcp\t127.0.0.1\treject_ok\n",
            "ROUTE server address 127.0.0.1 refused\n",
            ": the host ::1 of the URL is not one of its addresses: 127.0.0.1",
        ),
        (
            "not-ipv6",
            "server\thttp://[not-ipv6]:8000/\t::1\treject_ok\n",
            "ROUTE server address ::1 refused\n",
            ": the URL has a bracketed host that is not an IPv6 address: http://[not-ipv6]:8000/",
        ),
        (
            "bracketed-ipv4",
            "server\thttp://[127.0.0.1]:8000/mcp\t127.0.0.1\treject_ok\n",
            "ROUTE server address 127.0.0.1 refused\n",
            ": the URL has a bracketed host that is not an IPv6 address: http://[127.0.0.1]:8000/mcp",
        ),
        (
            "not-ipv4-resolve",
            "server\thttp://10.0.0.256:8000/mcp\tresolve\treject_ok\n",
            "ROUTE server address 10.0.0.256 refused\n",
            ": the URL has a host of digits and dots that is not an IPv4 address: http://10.0.0.256:8000/mcp",
        ),
        (
            "leading-zero",
            "server\thttp://010.0.0.1:8000/mcp\t010.0.0.1\treject_ok\n",
            "ROUTE server address 010.0.0.1 refused\n",
            ": the URL has a host of digits and dots that is not an IPv4 address: http://010.0.0.1:8000/mcp",
        ),
    ] {
        let mut cluster = Cluster::clean();
        cluster.routes = Some(format!("{ROUTES}{row}"));
        cluster.probe_log = with(line);
        let checked = check(&format!("host-row-{name}"), &cluster);
        checked.assert_failed(text);
        assert!(
            checked.run.failed("the probe ran: row server of "),
            "{name}\n{}",
            checked.run.transcript()
        );
        assert!(
            !checked.calls.iter().any(|call| call.contains(" debug ")),
            "{name}: the probe was started\n{:?}",
            checked.calls
        );
    }

    // An address-literal host among the row's addresses, and an IPv6 one, are tried.
    let mut cluster = Cluster::clean();
    cluster.routes = Some(format!(
        "{ROUTES}v6\thttp://[::1]:8000/mcp\t::1\treject_ok\n\
         listed\thttp://127.0.0.1:8000/mcp\t127.0.0.2,127.0.0.1\n"
    ));
    cluster.probe_log = with(
        "ROUTE v6 address ::1 refused\n\
         ROUTE listed address 127.0.0.2 refused\n\
         ROUTE listed address 127.0.0.1 refused\n",
    );
    let checked = check("host-row-listed", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert!(checked.passed("the probe passed: every route refused (7 attempts, EXPECT=refused)"));

    // The kind run's routes file still loads.
    let mut cluster = Cluster::clean();
    cluster.routes = Some(read("deploy/route-check/routes/kind.tsv"));
    cluster.probe_log =
        PASSING_PROBE.replace("ROUTE metadata address 169.254.169.254 refused\n", "");
    let checked = check("host-row-kind", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert!(checked.passed("the probe passed: every route refused (3 attempts, EXPECT=refused)"));
}

/// The probe itself, deploy/route-check/probe.sh, run for `kubectl debug` with the variables the
/// step gives it: its lines are the ones the step reads, and it reaches the gateway with no
/// credential.
#[test]
fn the_step_reads_the_probes_own_lines() {
    let gateway = Recorder::start(401);
    let hole = dropped();
    let port = hole.rsplit(':').next().unwrap().trim_end_matches("/mcp");
    let routes = format!(
        "# the probe's own run\n\
         mock-docs\thttp://mock-docs.mock-docs.svc.cluster.local:{port}/mcp\t{{{{ADDR}}}}\n\
         resolved\thttp://hole.test:{port}/mcp\tresolve\n\
         literal\t{hole}\t127.0.0.1\treject_ok\n"
    );
    let mut cluster = Cluster::clean();
    cluster.cluster_ip = "127.0.0.1";
    cluster.endpoints = json!([]);
    cluster.routes = Some(routes.clone());
    cluster.gateway_url = Some(gateway.url.clone());
    cluster.run_probe =
        Some("mock-docs.mock-docs.svc.cluster.local 127.0.0.1\nhole.test 127.0.0.1\n".to_owned());
    cluster.dropped = vec![hole.clone()];
    let checked = check("probe-itself", &cluster);
    assert_eq!(checked.run.status, Some(0), "{}", checked.run.transcript());
    assert!(
        checked.passed("the probe passed: every route refused (5 attempts, EXPECT=refused)"),
        "{}",
        checked.run.transcript()
    );
    let lines: Vec<&str> = checked.report()["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| route["line"].as_str().unwrap())
        .collect();
    assert_eq!(
        lines,
        [
            format!(
                "ROUTE mock-docs name http://mock-docs.mock-docs.svc.cluster.local:{port}/mcp refused"
            ),
            "ROUTE mock-docs address 127.0.0.1 refused".to_owned(),
            format!("ROUTE resolved name http://hole.test:{port}/mcp refused"),
            "ROUTE resolved address 127.0.0.1 refused".to_owned(),
            "ROUTE literal address 127.0.0.1 refused".to_owned(),
        ]
    );
    let heads = gateway.heads();
    assert_eq!(heads.len(), 1);
    assert!(!heads[0].to_ascii_lowercase().contains("\nauthorization:"));

    // A route that answers: the probe fails, and so does the step.
    let server = Recorder::start(200);
    let mut cluster = Cluster::clean();
    cluster.routes = Some(format!("server\t{}\t127.0.0.1\n", server.url));
    cluster.gateway_url = Some(gateway.url.clone());
    cluster.run_probe = Some(String::new());
    let checked = check("probe-itself-open", &cluster);
    checked.assert_failed("the probe passed: RESULT: FAIL (exit 1)");
    assert_eq!(
        checked.report()["routes"][0]["line"],
        "ROUTE server address 127.0.0.1 open"
    );
}

/// Projected sources that are not a list of objects, which a real API server does not serve,
/// fail each check that reads them, never pass as no source (issue #64).
#[test]
fn projected_sources_that_cannot_be_read_fail() {
    for (name, projected) in [
        ("sources-string", json!({"sources": "mock-docs"})),
        ("source-string", json!({"sources": ["mock-docs"]})),
        ("projected-string", json!("mock-docs")),
    ] {
        let mut cluster = Cluster::clean();
        cluster.pod_spec()["volumes"][0]["projected"] = projected;
        let checked = check(&format!("projected-unparsed-{name}"), &cluster);
        for text in [
            "no Secret volume: could not read the pod's volumes",
            "no string in a token format: could not read which ConfigMaps the pod reads",
            "no projected token for a server's audience: could not read the pod's projected volumes",
        ] {
            checked.assert_failed(text);
        }
        for text in [
            "no Secret volume",
            "no string in a token format",
            "no projected token",
        ] {
            assert!(!checked.passed(text), "{name}: {text} passed");
        }
    }
}

/// EndpointSlice endpoints that are not a list of addresses fail the address read, never leave
/// the ClusterIP alone (issue #64).
#[test]
fn endpoints_that_cannot_be_read_fail() {
    fails_when_unparsed(
        "endpoints-unparsed",
        "endpointslices-mock-docs.json",
        &[
            r#"{"items": [{"endpoints": "10.244.0.7"}]}"#,
            r#"{"items": [{"endpoints": {"addresses": ["10.244.0.7"]}}]}"#,
            r#"{"items": [{"endpoints": [{"addresses": [7]}]}]}"#,
            // jq's `//` reads false as null, and `.[]` iterates an object's values.
            r#"{"items": [{"endpoints": false}]}"#,
            r#"{"items": [{"endpoints": [{"addresses": {"ip": "10.244.0.7"}}]}]}"#,
            r#"{"items": {"slice": {"endpoints": [{"addresses": ["10.244.0.7"]}]}}}"#,
        ],
        "the probe ran: could not read the servers' addresses",
    );
}

/// A version or node read of two JSON objects is not read, though jq would take the last
/// (issue #64).
#[test]
fn versions_read_as_more_than_one_object_fail() {
    fails_when_unparsed(
        "version-doubled",
        "version.json",
        &[
            "{\"serverVersion\": {\"gitVersion\": \"v1.36.1\"}}\n{\"serverVersion\": {\"gitVersion\": \"v1.36.1\"}}\n",
        ],
        "the Kubernetes version is recorded: could not read",
    );
    fails_when_unparsed(
        "node-doubled",
        "node.json",
        &[
            "{\"status\": {\"nodeInfo\": {\"osImage\": \"Debian\", \"kubeletVersion\": \"v1.36.1\", \"containerRuntimeVersion\": \"containerd://2.1.1\"}}}\n\
           {\"status\": {\"nodeInfo\": {\"osImage\": \"Debian\", \"kubeletVersion\": \"v1.36.1\", \"containerRuntimeVersion\": \"containerd://2.1.1\"}}}\n",
        ],
        &format!("the node image of {NODE} is recorded: could not read"),
    );
}

#[test]
fn it_refuses_to_run_without_a_server_audience_before_calling_anything() {
    require(&["bash"]);
    let dir = scratch("usage");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let kubectl = write(&bin, "kubectl", FAKE_KUBECTL);
    std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let routes = write(&dir, "routes.tsv", ROUTES);
    let output = Command::new("bash")
        .arg(repo().join("deploy/route-check/route-check.sh"))
        .args(["--kubeconfig", "k", "--context", CONTEXT])
        .args(["--namespace", "team-a", "--selector", "app=agent"])
        .args(["--gateway-ns", "switchboard", "--server-ns", "mock-docs"])
        .args(["--server-service", "mock-docs/mock-docs"])
        .arg("--routes")
        .arg(&routes)
        .args(["--gateway-url", GATEWAY_URL, "--probe-image", PROBE_IMAGE])
        .arg("--report")
        .arg(dir.join("report.json"))
        .args(["--environment", "kind"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("FAKE_DIR", &dir)
        .output()
        .unwrap();
    let run = Run::from(output);
    assert_eq!(run.status, Some(2), "{}", run.transcript());
    assert!(run.stderr.contains("--server-audience is required"));
    assert!(!dir.join("calls.log").exists());
    assert!(!dir.join("report.json").exists());
}

/// The YAML documents of `rbac.yaml`, each without its comment lines.
fn rbac_documents() -> Vec<String> {
    read("deploy/kind/route-check/rbac.yaml")
        .split("\n---\n")
        .map(|doc| {
            doc.lines()
                .filter(|line| !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect()
}

#[test]
fn the_operator_is_granted_only_what_it_needs() {
    let docs = rbac_documents();
    let kinds: Vec<&str> = docs
        .iter()
        .map(|doc| {
            doc.lines()
                .find_map(|line| line.strip_prefix("kind: "))
                .unwrap()
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "Namespace",
            "ServiceAccount",
            "ClusterRole",
            "ClusterRoleBinding",
            "Role",
            "RoleBinding",
            "Role",
            "RoleBinding"
        ]
    );
    let rules = |doc: &str| doc.split_once("rules:\n").expect("rules").1.to_owned();
    assert_eq!(
        rules(&docs[2]),
        "  - apiGroups: [\"\"]
    resources: [pods, pods/log, services, serviceaccounts, configmaps, nodes]
    verbs: [get, list]
  - apiGroups: [apps]
    resources: [daemonsets]
    verbs: [get, list]
  - apiGroups: [discovery.k8s.io]
    resources: [endpointslices]
    verbs: [get, list]
  - apiGroups: [authorization.k8s.io]
    resources: [subjectaccessreviews]
    verbs: [create]"
    );
    for (doc, namespace) in [(&docs[4], "team-a"), (&docs[6], "team-b")] {
        assert!(doc.contains(&format!(
            "metadata:\n  name: route-check-probe\n  namespace: {namespace}\n"
        )));
        assert_eq!(
            rules(doc),
            "  - apiGroups: [\"\"]
    resources: [pods/ephemeralcontainers]
    verbs: [patch]"
        );
    }
    // Every binding is for the operator alone, to the role beside it.
    for (doc, kind, role) in [
        (&docs[3], "ClusterRole", "route-check-operator"),
        (&docs[5], "Role", "route-check-probe"),
        (&docs[7], "Role", "route-check-probe"),
    ] {
        assert!(
            doc.ends_with(&format!(
                "roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: {kind}
  name: {role}
subjects:
  - kind: ServiceAccount
    name: operator
    namespace: route-check"
            )),
            "{doc}"
        );
    }
    assert!(docs[1].contains("  name: operator\n  namespace: route-check\n"));
    let text = docs.join("\n");
    for word in [
        "secrets",
        "exec",
        "impersonate",
        "escalate",
        "bind,",
        "\"*\"",
        "[*]",
        "update",
        "delete",
    ] {
        assert!(!text.contains(word), "rbac.yaml mentions {word}");
    }
    // The kind run applies it; the base does not.
    assert!(!read("deploy/kind/base/kustomization.yaml").contains("route-check"));
}
