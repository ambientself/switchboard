//! `deploy/demo/demo.sh` with fake `docker`, `kind` and `kubectl` that record every call. The
//! driver must refuse any cluster but `switchboard-demo` before calling anything, name its own
//! kubeconfig in every call, never pass on the caller's KUBECONFIG, and count every failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Run, repo, require, scratch, write};
use serde_json::{Value, json};

/// A directory of fake tools. Each appends one line per call to `calls.log`:
/// `<tool> KUBECONFIG=<value> <args...>`. `kind get clusters` lists switchboard-demo, `docker
/// version` prints an architecture, `docker image inspect` an image ID, `kubectl` fails, and
/// everything else succeeds silently.
fn fake_tools(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("calls.log");
    let script = |tool: &str, body: &str| {
        let path = write(
            &bin,
            tool,
            &format!(
                "#!/bin/sh\nprintf '%s KUBECONFIG=%s %s\\n' {tool} \"${{KUBECONFIG:-}}\" \"$*\" >> '{}'\n{body}\n",
                log.display()
            ),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script(
        "kind",
        "if [ \"$1 $2\" = 'get clusters' ]; then echo switchboard-demo; fi\nexit 0",
    );
    script(
        "docker",
        "if [ \"$1\" = version ]; then echo arm64; fi\nif [ \"$1 $2\" = 'image inspect' ]; then echo sha256:0123456789abcdef0123; fi\nexit 0",
    );
    script(
        "kubectl",
        "echo 'fake kubectl: no cluster here' >&2\nexit 1",
    );
    bin
}

/// Runs demo.sh with `args`, the fake tools first on PATH, and `extra` in the environment.
fn demo(name: &str, args: &[&str], extra: &[(&str, &str)]) -> (Run, Vec<String>) {
    require(&["bash", "jq", "awk"]);
    let dir = scratch(name);
    let bin = fake_tools(&dir);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new("bash");
    command
        .arg(repo().join("deploy/demo/demo.sh"))
        .args(args)
        .env("PATH", path)
        .env_remove("SWITCHBOARD_DEMO_CLUSTER");
    for (key, value) in extra {
        command.env(key, value);
    }
    let run = Run::from(command.output().unwrap());
    let calls = std::fs::read_to_string(dir.join("calls.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    (run, calls)
}

/// The demo's own kubeconfig, as the script spells it.
fn own_kubeconfig() -> String {
    let root = repo().canonicalize().unwrap();
    format!("{}/.demo/kubeconfig", root.display())
}

#[test]
fn it_refuses_any_cluster_but_its_own_before_calling_anything() {
    for cluster in ["otto-dev", "other-cluster"] {
        for args in [
            &["kind"][..],
            &["compose"][..],
            &["down", "kind"][..],
            &["down", "all"][..],
        ] {
            let (run, calls) = demo(cluster, args, &[("SWITCHBOARD_DEMO_CLUSTER", cluster)]);
            assert_eq!(run.status, Some(2), "{args:?}: {}", run.transcript());
            assert!(
                run.stderr
                    .contains(&format!("refusing to touch the cluster {cluster}")),
                "{}",
                run.transcript()
            );
            assert!(
                calls.is_empty(),
                "demo.sh {args:?} called tools for {cluster}: {calls:?}"
            );
        }
    }
    // Naming its own cluster is the same as naming none.
    let (run, calls) = demo(
        "own-cluster",
        &["down", "kind"],
        &[("SWITCHBOARD_DEMO_CLUSTER", "switchboard-demo")],
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        calls,
        [format!(
            "kind KUBECONFIG= delete cluster --name switchboard-demo --kubeconfig {}",
            own_kubeconfig()
        )]
    );
}

#[test]
fn every_cluster_call_names_the_demos_own_kubeconfig() {
    let (run, calls) = demo(
        "kubeconfig",
        &["kind"],
        &[("KUBECONFIG", "/should/never/be/used")],
    );
    // The fake kubectl fails on its first call, so the run stops there and reports it.
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.stdout
            .contains("FAIL step 'the cluster's issuer and keys"),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .lines()
            .last()
            .unwrap_or_default()
            .starts_with("RESULT: FAIL ("),
        "{}",
        run.transcript()
    );

    let own = own_kubeconfig();
    let kubectl: Vec<&String> = calls.iter().filter(|c| c.starts_with("kubectl ")).collect();
    assert!(!kubectl.is_empty(), "kubectl was never called: {calls:?}");
    for call in &kubectl {
        assert!(
            call.contains(&format!(
                "--kubeconfig {own} --context kind-switchboard-demo"
            )),
            "{call}"
        );
    }
    let kind_cluster_calls: Vec<&String> = calls
        .iter()
        .filter(|c| {
            c.starts_with("kind ")
                && (c.contains(" export ") || c.contains(" create ") || c.contains(" delete "))
        })
        .collect();
    assert!(!kind_cluster_calls.is_empty(), "{calls:?}");
    for call in kind_cluster_calls {
        assert!(call.contains(&format!("--kubeconfig {own}")), "{call}");
        assert!(call.contains("--name switchboard-demo"), "{call}");
    }
    for call in &calls {
        assert!(
            call.contains(" KUBECONFIG= "),
            "the caller's KUBECONFIG reached a tool: {call}"
        );
    }
}

#[test]
fn down_takes_down_only_what_it_names() {
    let own = own_kubeconfig();
    let root = repo().canonicalize().unwrap();
    let compose = format!(
        "docker KUBECONFIG= compose -f {}/deploy/compose/compose.yaml --profile demo down -v --remove-orphans",
        root.display()
    );
    let cluster =
        format!("kind KUBECONFIG= delete cluster --name switchboard-demo --kubeconfig {own}");
    for (what, expected) in [
        ("compose", vec![compose.clone()]),
        ("kind", vec![cluster.clone()]),
        ("all", vec![compose.clone(), cluster.clone()]),
    ] {
        let (run, calls) = demo(
            &format!("down-{what}"),
            &["down", what],
            &[("KUBECONFIG", "/should/never/be/used")],
        );
        assert_eq!(run.status, Some(0), "{what}: {}", run.transcript());
        assert_eq!(calls, expected, "down {what}");
    }
}

#[test]
fn down_without_naming_what_is_refused() {
    for args in [&["down"][..], &["down", "everything"][..]] {
        let (run, calls) = demo("down-unnamed", args, &[]);
        assert_eq!(run.status, Some(2), "{args:?}: {}", run.transcript());
        assert!(
            run.stderr.contains("down compose|kind|all"),
            "{}",
            run.transcript()
        );
        assert!(calls.is_empty(), "{args:?}: {calls:?}");
    }
}

#[test]
fn an_unknown_mode_is_refused() {
    let (run, calls) = demo("usage", &["deploy"], &[]);
    assert_eq!(run.status, Some(2), "{}", run.transcript());
    assert!(calls.is_empty(), "{calls:?}");
}

/// Sources demo.sh, which defines its functions and runs nothing, then runs `body`.
fn sourced(body: &str) -> Run {
    require(&["bash", "awk"]);
    let script = format!(
        "source '{}'\n{body}\n",
        repo().join("deploy/demo/demo.sh").display()
    );
    Run::from(Command::new("bash").arg("-c").arg(script).output().unwrap())
}

#[test]
fn a_finished_run_with_every_check_passing_passes() {
    let run = sourced("tally_workload w 0 'PASS one\nPASS two'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: PASS (2/2)"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_fail_line_fails_the_run() {
    let run = sourced("tally_workload w 1 'PASS one\nFAIL two'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: FAIL (1 of 2 failed)"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_that_exits_non_zero_without_a_fail_line_fails_the_run() {
    let run = sourced("tally_workload w 3 'PASS one'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload exited 3 without a FAIL line"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_that_exits_zero_despite_a_fail_line_fails_the_run() {
    let run = sourced("tally_workload w 0 'FAIL one'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload exited 0 despite 1 FAIL lines"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_that_checked_nothing_fails_the_run() {
    let run = sourced("tally_workload w 0 'no checks here'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload ran no checks"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_run_that_stopped_early_fails_even_with_every_check_passing() {
    let run = sourced("CURRENT_STEP=deploy\npass one\nresult 1");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("step 'deploy' could not complete (exit 1)"),
        "{}",
        run.transcript()
    );
    let run = sourced("pass one\nresult 0");
    assert_eq!(
        run.status,
        Some(1),
        "an unfinished run passed\n{}",
        run.transcript()
    );
}

#[test]
fn the_server_bearer_check_admits_only_the_gateways_credential() {
    let sha = "35078c7e636169b1ad9e5a04af03cb483f59535baaf71232f48d8a6181a93bd4";
    // Lines as mock-docs writes them: one per request, with `accepted` and the bearer's prefix.
    let good = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#;
    let refused = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"aaaaaaaaaaaa","accepted":false}"#;
    let health_check = r#"{"event":"request","http_method":"GET","path":"/mcp","bearer_sha256":null,"accepted":false}"#;
    let accepted_other = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"bbbbbbbbbbbb","accepted":true}"#;
    let logs = |lines: &[&str]| lines.join("\n");

    let run = sourced(&format!(
        "check_server_bearers '{}' {sha} 2 accepted\nFINISHED=1\nresult 0",
        logs(&[good, health_check, good, refused])
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());

    let run = sourced(&format!(
        "check_server_bearers '{}' {sha} 2 all\nFINISHED=1\nresult 0",
        logs(&[good, good, refused])
    ));
    assert!(
        run.failed("mock-docs never received any bearer but the gateway's"),
        "{}",
        run.transcript()
    );

    let run = sourced(&format!(
        "check_server_bearers '{}' {sha} 2 accepted\nFINISHED=1\nresult 0",
        logs(&[good, good, accepted_other])
    ));
    assert!(
        run.failed("mock-docs accepted no other bearer"),
        "{}",
        run.transcript()
    );

    // One fewer than the calls the gateway allowed, or one more: a denied call reached the
    // server, or the log is short.
    for lines in [&[good][..], &[good, good, good][..]] {
        let run = sourced(&format!(
            "check_server_bearers '{}' {sha} 2 accepted\nFINISHED=1\nresult 0",
            logs(lines)
        ));
        assert!(
            run.failed("mock-docs accepted the gateway's credential on exactly the 2 calls"),
            "{}",
            run.transcript()
        );
    }
}

/// The calls a function of workload.sh expects the gateway to allow, before and inside its
/// `DIRECT_URL` block: one per `expect_allowed` of a call.
fn allowed_calls(script: &str, function: &str) -> (usize, usize) {
    let start = script
        .find(&format!("\n{function}() {{\n"))
        .unwrap_or_else(|| panic!("workload.sh has no {function}()"));
    let body = &script[start..];
    let body = &body[..body.find("\n}\n").expect("the function ends")];
    let (before, inside) = body
        .split_once("  if [ -n \"${DIRECT_URL:-}\" ]; then\n")
        .unwrap_or((body, ""));
    let count = |text: &str| text.matches("expect_allowed \"$(call ").count();
    (count(before), count(inside))
}

#[test]
fn the_server_bearer_checks_expect_exactly_the_calls_each_run_allows() {
    // Each allowed call is one request mock-docs accepts. Both runs have two teams. Compose
    // runs `full` without DIRECT_URL. kind runs `before-policy`, then `full` with DIRECT_URL,
    // which adds the same pod's read after its direct call.
    let workload = common::read("deploy/demo/workload.sh");
    let (full, full_direct) = allowed_calls(&workload, "full");
    let (before_policy, _) = allowed_calls(&workload, "before_policy");
    assert_eq!((full, full_direct, before_policy), (2, 1, 1));
    let compose = 2 * full;
    let kind = 2 * (before_policy + full + full_direct);
    assert_eq!((compose, kind), (4, 8));

    // In kind each before-policy Job makes one direct call to mock-docs with the workload's own
    // token, which the server refuses; after the policy no direct call reaches it.
    let before_policy_body = workload
        .split_once("\nbefore_policy() {\n")
        .expect("workload.sh has before_policy()")
        .1;
    let before_policy_body = &before_policy_body[..before_policy_body.find("\n}\n").unwrap()];
    assert_eq!(
        before_policy_body.matches(" \"$DIRECT_URL\" \\\n").count(),
        1
    );
    assert!(before_policy_body.contains("    -H \"Authorization: Bearer $TOKEN\""));

    let driver = common::read("deploy/demo/demo.sh");
    let probes = driver.matches(" mock-workload before-policy\n").count();
    assert_eq!(probes, 2);
    let compose_call = format!(
        "  check_server_bearers \"$(mock_docs_log)\" \\\n    \"$(cat \"$ROOT/deploy/compose/dummy-credentials/docs-credential.sha256\")\" {compose} all\n"
    );
    let kind_call = format!(
        "  check_server_callers \"$(mock_docs_log)\" \"$KIND_GATEWAY_SUBJECT\" {kind} {probes} \"$OPEN_ATTEMPTS\"\n"
    );
    for call in [compose_call, kind_call] {
        assert_eq!(driver.matches(&call).count(), 1, "{call}");
    }
    // Compose's is the only bearer check, and kind's the only caller check.
    assert_eq!(driver.matches("  check_server_bearers \"").count(), 1);
    assert_eq!(driver.matches("  check_server_callers \"").count(), 1);
}

/// A line of mock-docs in its JWT mode: one request, accepted with `caller` or refused for
/// `refusal`.
fn jwt_line(accepted: bool, caller: Option<&str>, refusal: Option<&str>) -> String {
    json!({
        "event": "request",
        "http_method": "POST",
        "path": "/mcp",
        "bearer_sha256": "35078c7e6361",
        "accepted": accepted,
        "caller": caller,
        "refusal": refusal,
    })
    .to_string()
}

/// Runs check_server_callers on `lines` for the gateway's subject, 8 calls, 2 refusals and 3
/// open attempts of the route check's probe.
fn check_callers(lines: &[String]) -> Run {
    sourced(&format!(
        "check_server_callers '{}' \"$KIND_GATEWAY_SUBJECT\" 8 2 3\nFINISHED=1\nresult 0",
        lines.join("\n")
    ))
}

#[test]
fn the_server_caller_check_admits_only_the_gateways_identity() {
    let gateway = jwt_line(
        true,
        Some("system:serviceaccount:switchboard:gateway"),
        None,
    );
    let direct = jwt_line(false, None, Some("wrong_audience"));
    // The route check's probe before the policy sends no credential.
    let mut probe = jwt_line(false, None, Some("no_bearer"));
    probe = probe.replace("\"35078c7e6361\"", "null");
    let boot =
        r#"{"event":"boot","mode":"jwt","subject":"system:serviceaccount:switchboard:gateway"}"#;
    let run_of = |gateway_calls: usize, extra: &[String]| {
        let mut lines = vec![boot.to_owned(), direct.clone(), direct.clone()];
        lines.extend(std::iter::repeat_n(probe.clone(), 3));
        lines.extend(std::iter::repeat_n(gateway.clone(), gateway_calls));
        lines.extend_from_slice(extra);
        check_callers(&lines)
    };

    let run = run_of(8, &[]);
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(run.lines("PASS ").len(), 5, "{}", run.transcript());

    // A request with no bearer that the probe's open attempts do not explain.
    let run = run_of(8, std::slice::from_ref(&probe));
    assert!(
        run.failed("mock-docs refused the route check's 3 open attempts before the policy"),
        "{}",
        run.transcript()
    );
    assert!(
        run.failed("mock-docs refused nothing else"),
        "{}",
        run.transcript()
    );

    // A second caller from the trusted issuer, and a token accepted with no caller at all, as
    // the static mode logs it.
    let other = jwt_line(
        true,
        Some("system:serviceaccount:team-a:mock-workload"),
        None,
    );
    let fake_gateway = jwt_line(
        true,
        Some("system:serviceaccount:switchboard:gateway x"),
        None,
    );
    let static_line = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#;
    for extra in [other, fake_gateway, static_line.to_owned()] {
        let run = run_of(8, std::slice::from_ref(&extra));
        assert!(
            run.failed("mock-docs accepted no other caller, and no token without one"),
            "{extra}\n{}",
            run.transcript()
        );
    }

    // One fewer than the calls the gateway allowed, or one more.
    for calls in [7, 9] {
        let run = run_of(calls, &[]);
        assert!(
            run.failed("on exactly the 8 calls the gateway allowed"),
            "{calls}\n{}",
            run.transcript()
        );
    }

    // A refusal the direct calls do not explain, or a direct call refused for another reason.
    let run = run_of(8, &[jwt_line(false, None, Some("wrong_subject"))]);
    assert!(
        run.failed("mock-docs refused nothing else"),
        "{}",
        run.transcript()
    );
    let mut lines = vec![direct.clone(), jwt_line(false, None, Some("expired"))];
    lines.extend(std::iter::repeat_n(gateway.clone(), 8));
    let run = check_callers(&lines);
    assert!(
        run.failed("mock-docs refused the 2 direct calls' tokens as meant for another audience"),
        "{}",
        run.transcript()
    );
}

#[test]
fn the_kind_identity_failure_count_reads_only_this_runs_gateway_log() {
    // A run on an existing cluster may reuse the gateway's pod, whose whole log still holds an
    // earlier run's identity failures.
    let driver = common::read("deploy/demo/demo.sh");
    assert!(driver.contains(
        "  gateway_logs=$(k -n switchboard logs --since-time \"$LOG_SINCE\" \"pod/$GATEWAY_POD\")\n"
    ));
    assert_eq!(driver.matches("gateway_logs=").count(), 1);
}

/// A fake `k` for gateway_pod: the gateway's Deployment at revision 2, the ReplicaSets of
/// revisions 1 and 2, and the pods of revision 2's, one of them on its way out.
const GATEWAY_ROLLOUT: &str = r#"k() {
  case "$*" in
    "-n switchboard get deploy/gateway -o jsonpath="*) echo 2 ;;
    "-n switchboard get replicasets -l app=gateway -o json")
      echo '{"items": [
        {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "1"}, "labels": {"app": "gateway", "pod-template-hash": "aaa"}}},
        {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "2"}, "labels": {"app": "gateway", "pod-template-hash": "bbb"}}}]}' ;;
    "-n switchboard get pods -l app=gateway,pod-template-hash=bbb -o json")
      echo '{"items": [
        {"metadata": {"name": "gateway-bbb-old", "deletionTimestamp": "2026-10-10T00:00:00Z"}, "status": {"phase": "Running"}},
        {"metadata": {"name": "gateway-bbb-new"}, "status": {"phase": "Running"}}]}' ;;
    *) echo "unexpected: k $*" >&2; return 1 ;;
  esac
}"#;

#[test]
fn the_kind_boot_lines_are_read_from_the_current_replica_sets_pod() {
    // After a rollout the previous pod can still be running out its grace period, and `logs
    // deploy/gateway` may pick it: its boot lines are the previous build's.
    require(&["jq"]);
    let run = sourced(&format!(
        "{GATEWAY_ROLLOUT}\ngateway_pod\necho \"pod=$GATEWAY_POD\""
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout.contains("pod=gateway-bbb-new\n"),
        "{}",
        run.transcript()
    );

    // No ReplicaSet of the Deployment's revision, or no running pod of it: no pod to read.
    for (case, body) in [
        (
            "no-revision",
            GATEWAY_ROLLOUT.replace("echo 2 ;;", "echo 3 ;;"),
        ),
        (
            "no-pod",
            GATEWAY_ROLLOUT.replace(
                "\"name\": \"gateway-bbb-new\"",
                "\"name\": \"gateway-bbb-new\", \"deletionTimestamp\": \"x\"",
            ),
        ),
    ] {
        let run = sourced(&format!("{body}\ngateway_pod && echo \"pod=$GATEWAY_POD\""));
        assert_ne!(run.status, Some(0), "{case}: {}", run.transcript());
        assert!(!run.stdout.contains("pod="), "{case}: {}", run.transcript());
    }

    // The kind run reads that pod's log for the boot lines, and never the Deployment's.
    let driver = common::read("deploy/demo/demo.sh");
    let found = driver
        .find("\n  gateway_pod\n")
        .expect("kind_run finds the gateway's pod");
    let boot = driver
        .find("\n  check_boot \"$(k -n switchboard logs \"pod/$GATEWAY_POD\")\"\n")
        .expect("kind_run reads the boot lines from that pod");
    assert!(found < boot);
    assert!(!driver.contains("logs deploy/gateway"));
}

#[test]
fn the_server_bearer_checks_count_only_this_runs_requests() {
    // A second run without `down` reuses mock-docs, whose whole log still holds the first run's
    // two accepted calls. The fakes print the whole log unless asked for lines from the mark.
    let sha = "35078c7e636169b1ad9e5a04af03cb483f59535baaf71232f48d8a6181a93bd4";
    let good = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#;
    let mark = "2026-10-08T10:00:00.123456Z";
    let this_run = [good, good].join("\n");
    let whole = [good, good, good, good].join("\n");
    for (mode, flag, fake) in [("compose", "--since", "dc"), ("kind", "--since-time", "k")] {
        let run = sourced(&format!(
            "{fake}() {{ case \" $* \" in *' {flag} {mark} '*) printf '%s\\n' '{this_run}' ;; *) printf '%s\\n' '{whole}' ;; esac; }}\n\
             MODE={mode}\nLOG_SINCE={mark}\n\
             check_server_bearers \"$(mock_docs_log)\" {sha} 2 accepted\nFINISHED=1\nresult 0"
        ));
        assert_eq!(run.status, Some(0), "{mode}: {}", run.transcript());
    }

    // The mark is the run's start, read once from Postgres with the audit rows' mark.
    let run = sourced(
        "psql_superuser() { echo '1791451200.123456 2026-10-08T10:00:00.123456Z'; }\nmark_start\necho \"since=$SINCE log=$LOG_SINCE\"",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout
            .contains("since=1791451200.123456 log=2026-10-08T10:00:00.123456Z"),
        "{}",
        run.transcript()
    );
}

#[test]
fn the_outage_step_counts_only_requests_mock_docs_accepted() {
    // The health checks run every 2 s and carry no bearer; were they counted, the count before
    // and after the outage would differ whatever the gateway did.
    require(&["jq"]);
    let lines = [
        r#"{"event":"request","http_method":"GET","path":"/mcp","bearer_sha256":null,"accepted":false}"#,
        r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#,
        r#"{"event":"boot","listen":"0.0.0.0:8080"}"#,
        r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"aaaaaaaaaaaa","accepted":false}"#,
        r#"{"event":"request","http_method":"GET","path":"/mcp","bearer_sha256":null,"accepted":false}"#,
        r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#,
    ];
    let run = sourced(&format!(
        "dc() {{ printf '%s\\n' '{}'; }}\nmock_docs_requests",
        lines.join("\n")
    ));
    assert_eq!(run.stdout.trim(), "2", "{}", run.transcript());
}

#[test]
fn a_compose_rerun_keeps_the_registry_directory_the_gateway_mounted() {
    // A rerun without `down` can reuse the gateway's container, whose bind mount holds the
    // directory it started with, as a shell holds its working directory: replacing the
    // directory would hide every later swap from it. The subshell stands in for the mount.
    let dir = scratch("compose-registry");
    let run = sourced(&format!(
        "DEMO_DIR='{}'\ncompose_registry\n\
         (cd \"$DEMO_DIR/compose-registry\" && echo withdrawn > registry.toml && compose_registry \\\n  \
         && cmp -s registry.toml \"$ROOT/deploy/compose/config/registry/registry.toml\" && echo seen-by-the-mount)",
        dir.display()
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout.contains("seen-by-the-mount"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_kind_run_tags_the_image_with_its_own_id() {
    let run = sourced(
        "docker() { case \"$1 $2\" in 'image inspect') echo sha256:90d73467ace7aabbccdd ;; *) echo \"docker $*\" ;; esac; }\nrun_image\necho \"tag=$IMG_RUN\"",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout
            .contains("docker tag switchboard-demo:dev switchboard-demo:90d73467ace7"),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains("tag=switchboard-demo:90d73467ace7"),
        "{}",
        run.transcript()
    );

    // Without an image ID there is no tag to deploy, and the run must stop.
    for answer in ["", "sha256:not-hex"] {
        let run = sourced(&format!(
            "docker() {{ echo '{answer}'; }}\nrun_image && echo \"tag=$IMG_RUN\""
        ));
        assert_ne!(run.status, Some(0), "{answer:?}: {}", run.transcript());
        assert!(
            !run.stdout.contains("tag="),
            "{answer:?}: {}",
            run.transcript()
        );
    }
}

#[test]
fn a_kind_run_deploys_every_pod_of_the_demo_image_on_its_own_tag() {
    // What kustomize renders: two pods on the demo image, one on Postgres.
    let rendered = "      - image: switchboard-demo:dev\n      - image: postgres:17-alpine\n          image: switchboard-demo:dev\n";
    let run = sourced(&format!(
        "k() {{ case \"$1\" in kustomize) printf '%s' '{rendered}' ;; apply) echo \"applied: $*\"; cat ;; esac; }}\nIMG_RUN=switchboard-demo:90d73467ace7\napply_base"
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout.contains("applied: apply -f -"),
        "{}",
        run.transcript()
    );
    assert_eq!(
        run.stdout
            .matches("image: switchboard-demo:90d73467ace7\n")
            .count(),
        2,
        "{}",
        run.transcript()
    );
    assert!(
        !run.stdout.contains("switchboard-demo:dev"),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains("image: postgres:17-alpine\n"),
        "{}",
        run.transcript()
    );
}

/// A call row as `row_resources_json` reads it.
fn row(
    team: &str,
    decision: &str,
    reason: Option<&str>,
    sentence: &str,
    resources: Value,
) -> Value {
    json!({
        "kind": "call", "team": team, "tool": "docs__read_document", "decision": decision,
        "reason": reason,
        "sentence": if sentence.is_empty() { Value::Null } else { json!(sentence) },
        "resources": resources, "revision": "demo-1", "listed": null, "omitted": null,
    })
}

/// A list row as `row_resources_json` reads it: no tool, decision or resources.
fn list_row(team: &str, revision: &str, listed: &[&str]) -> Value {
    json!({
        "kind": "list", "team": team, "tool": null, "decision": null, "reason": null,
        "sentence": null, "resources": null, "revision": revision, "listed": listed,
        "omitted": 0,
    })
}

const BOTH_TOOLS: [&str; 2] = ["docs__list_documents", "docs__read_document"];

fn project(name: &str) -> Value {
    json!([{"system": "docs", "kind": "project", "identifier": name}])
}

/// The rows a run of the demo writes, each recording what its call named.
fn demo_rows() -> Vec<Value> {
    let none_named = "Tool `docs__read_document` reaches resources the gateway must check, and this call named none of them, so it cannot be allowed. Name the resource the call is for.";
    let outside = |name: &str| {
        format!(
            "Tool `docs__read_document` names docs project `{name}`, which is outside what workload `w` may reach. Name only resources within that limit."
        )
    };
    vec![
        row("team-a", "allow", None, "", project("atlas")),
        row(
            "team-a",
            "deny",
            Some("resource_outside_limit"),
            &outside("borealis"),
            project("borealis"),
        ),
        row(
            "team-a",
            "deny",
            Some("resource_outside_limit"),
            none_named,
            json!([]),
        ),
        row("team-b", "allow", None, "", project("borealis")),
        row(
            "team-b",
            "deny",
            Some("resource_outside_limit"),
            &outside("atlas"),
            project("atlas"),
        ),
        row(
            "team-b",
            "deny",
            Some("resource_outside_limit"),
            none_named,
            json!([]),
        ),
        // The call to the withdrawn tool, which the gateway no longer knows.
        row(
            "team-a",
            "deny",
            Some("unknown_tool"),
            "Tool `docs__read_document` is not available on surface `docs`.",
            json!("unknown"),
        ),
        // Each team's list, and team-a's after the withdrawal, under the next revision.
        list_row("team-a", "demo-1", &BOTH_TOOLS),
        list_row("team-b", "demo-1", &BOTH_TOOLS),
        list_row("team-a", "demo-2", &["docs__list_documents"]),
    ]
}

/// Runs check_row_resources on `rows`, given as the text psql would print.
fn check_rows(name: &str, rows: &str) -> Run {
    require(&["jq"]);
    let file = write(&scratch(name), "rows.json", rows);
    sourced(&format!(
        "check_row_resources \"$(cat '{}')\"\nFINISHED=1\nresult 0",
        file.display()
    ))
}

const ROWS_CHECK: &str = "audit: every row records the resources its call named";

#[test]
fn each_row_must_record_what_its_call_named() {
    let run = check_rows("rows-good", &Value::from(demo_rows()).to_string());
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout
            .contains(&format!("PASS {ROWS_CHECK} (10 rows: 7 calls, 3 lists)")),
        "{}",
        run.transcript()
    );

    let wrong = |position: usize, resources: Value| {
        let mut rows = demo_rows();
        rows[position]["resources"] = resources;
        Value::from(rows).to_string()
    };
    for (case, rows) in [
        // The unknown tool's call named a project; recording none says it named nothing.
        ("unknown-as-none", wrong(6, json!([]))),
        ("allow-names-other", wrong(0, project("borealis"))),
        ("deny-names-own", wrong(1, project("atlas"))),
        ("none-named-names-one", wrong(2, project("atlas"))),
        ("named-as-unknown", wrong(3, json!("unknown"))),
        // A list names no resources.
        ("list-names-resources", wrong(7, project("atlas"))),
        ("list-names-none", wrong(8, json!([]))),
    ] {
        let run = check_rows(case, &rows);
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(run.failed(ROWS_CHECK), "{case}: {}", run.transcript());
        assert!(
            run.stdout.contains("    wrong: "),
            "{case}: {}",
            run.transcript()
        );
    }

    // A row no call of the demo makes cannot be judged, and fails.
    let mut rows = demo_rows();
    rows.push(row(
        "team-a",
        "deny",
        Some("classification_not_permitted"),
        "x",
        json!([]),
    ));
    let run = check_rows("rows-unexpected", &Value::from(rows).to_string());
    assert!(run.failed(ROWS_CHECK), "{}", run.transcript());

    // Nor can a row of a kind the demo does not write, or of no kind.
    for (case, kind) in [
        ("rows-other-kind", json!("other")),
        ("rows-no-kind", Value::Null),
    ] {
        let mut rows = demo_rows();
        rows[0]["kind"] = kind;
        let run = check_rows(case, &Value::from(rows).to_string());
        assert!(run.failed(ROWS_CHECK), "{case}: {}", run.transcript());
    }

    // No rows, or no JSON, checks nothing and fails.
    for (case, rows) in [
        ("rows-empty", "[]"),
        ("rows-none", ""),
        ("rows-not-json", "(0 rows)"),
    ] {
        let run = check_rows(case, rows);
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(run.failed(ROWS_CHECK), "{case}: {}", run.transcript());
    }
}

/// Runs check_list_rows on `rows`, given as the text psql would print, expecting `expected`.
fn check_lists(name: &str, rows: &str, expected: usize) -> Run {
    require(&["jq"]);
    let file = write(&scratch(name), "rows.json", rows);
    sourced(&format!(
        "check_list_rows \"$(cat '{}')\" {expected}\nFINISHED=1\nresult 0",
        file.display()
    ))
}

const LISTS_COUNTED: &str = "audit: one list row for each of the workloads'";
const LISTS_NAMED: &str = "audit: each list row names the tools its caller was shown";

#[test]
fn each_list_row_is_one_of_the_workloads_lists() {
    let rows = Value::from(demo_rows()).to_string();
    let run = check_lists("lists-good", &rows, 3);
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout
            .contains(&format!("PASS {LISTS_COUNTED} 3 tools/list calls")),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(&format!("PASS {LISTS_NAMED}")),
        "{}",
        run.transcript()
    );

    // One list more or less than the workloads made fails the count.
    for expected in [2, 4] {
        let run = check_lists("lists-count", &rows, expected);
        assert_eq!(run.status, Some(1), "{expected}: {}", run.transcript());
        assert!(
            run.failed(LISTS_COUNTED),
            "{expected}: {}",
            run.transcript()
        );
    }

    let wrong = |position: usize, field: &str, value: Value| {
        let mut rows = demo_rows();
        rows[position][field] = value;
        Value::from(rows).to_string()
    };
    for (case, rows) in [
        // The withdrawn tool listed after the withdrawal, or missing before it.
        ("withdrawn-listed", wrong(9, "listed", json!(BOTH_TOOLS))),
        (
            "read-missing",
            wrong(7, "listed", json!(["docs__list_documents"])),
        ),
        ("nothing-listed", wrong(8, "listed", json!([]))),
        ("listed-null", wrong(8, "listed", Value::Null)),
        ("tools-omitted", wrong(7, "omitted", json!(1))),
        ("other-team", wrong(7, "team", json!("team-c"))),
        ("no-team", wrong(7, "team", Value::Null)),
        ("unknown-revision", wrong(7, "revision", json!("demo-3"))),
    ] {
        let run = check_lists(case, &rows, 3);
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(run.failed(LISTS_NAMED), "{case}: {}", run.transcript());
        assert!(
            run.stdout.contains("    wrong: "),
            "{case}: {}",
            run.transcript()
        );
    }

    // The order a row lists its tools in does not matter.
    let run = check_lists(
        "lists-reordered",
        &wrong(
            7,
            "listed",
            json!(["docs__read_document", "docs__list_documents"]),
        ),
        3,
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());

    // No JSON checks nothing and fails.
    for (case, rows) in [("lists-none", ""), ("lists-not-json", "(0 rows)")] {
        let run = check_lists(case, rows, 3);
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(run.failed(LISTS_COUNTED), "{case}: {}", run.transcript());
    }
}

/// Runs `body` with `k` answering every `auth can-i` with `answer` and every SubjectAccessReview
/// with `allowed`. Returns the run, each can-i asked and each review's body.
fn with_can_i(
    name: &str,
    answer: &str,
    allowed: &str,
    body: &str,
) -> (Run, Vec<String>, Vec<Value>) {
    let log = scratch(name).join("calls.log");
    let run = sourced(&format!(
        "k() {{ case \"$1\" in\n  \
           create) printf 'review %s\\n' \"$(cat)\" >> '{log}'; echo {allowed} ;;\n  \
           *) echo \"k $*\" >> '{log}'; echo {answer} ;;\n\
         esac; }}\n{body}\nFINISHED=1\nresult 0",
        log = log.display()
    ));
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let mut asks = Vec::new();
    let mut reviews = Vec::new();
    for line in text.lines() {
        match line.strip_prefix("review ") {
            Some(review) => reviews.push(serde_json::from_str(review).unwrap()),
            None => asks.push(line.to_owned()),
        }
    }
    (run, asks, reviews)
}

/// What the operator checks asked of a team's workload before they read permissions.tsv
/// (#47's kind demo checks), as `kubectl auth can-i` arguments. Each must still be asked.
fn operator_asks(team: &str) -> Vec<String> {
    let mut asks = Vec::new();
    // Reading a secret or the gateway's configuration: list and watch return the data too.
    for verb in ["get", "list", "watch"] {
        asks.push(format!("{verb} secrets -n switchboard"));
        asks.push(format!("{verb} secrets -n mock-docs"));
        asks.push(format!("{verb} configmaps -n switchboard"));
    }
    // Across the cluster: the node proxy, impersonating a user or a group, and the cluster's
    // roles and bindings.
    for verb in ["create", "get"] {
        asks.push(format!("{verb} nodes --subresource=proxy"));
    }
    for resource in ["users", "groups"] {
        asks.push(format!("impersonate {resource}"));
    }
    for verb in ["bind", "escalate"] {
        asks.push(format!("{verb} clusterroles.rbac.authorization.k8s.io"));
    }
    asks.push("create clusterrolebindings.rbac.authorization.k8s.io".to_owned());
    // In mock-docs, the gateway's namespace and the team's own.
    for ns in ["mock-docs", "switchboard", team] {
        asks.push(format!("create pods -n {ns}"));
        asks.push(format!(
            "create serviceaccounts --subresource=token -n {ns}"
        ));
        asks.push(format!("impersonate serviceaccounts -n {ns}"));
        // The API server's routes, whose traffic network policy does not see.
        for verb in ["create", "get"] {
            for route in [
                "pods --subresource=exec",
                "pods --subresource=attach",
                "pods --subresource=portforward",
                "pods --subresource=proxy",
                "services --subresource=proxy",
            ] {
                asks.push(format!("{verb} {route} -n {ns}"));
            }
        }
        for verb in ["patch", "update"] {
            asks.push(format!(
                "{verb} pods --subresource=ephemeralcontainers -n {ns}"
            ));
        }
        for verb in ["bind", "escalate"] {
            asks.push(format!("{verb} roles.rbac.authorization.k8s.io -n {ns}"));
        }
        asks.push(format!(
            "create rolebindings.rbac.authorization.k8s.io -n {ns}"
        ));
        // The controllers that start pods.
        for resource in [
            "deployments.apps",
            "replicasets.apps",
            "statefulsets.apps",
            "daemonsets.apps",
            "jobs.batch",
            "cronjobs.batch",
        ] {
            for verb in ["create", "update", "patch"] {
                asks.push(format!("{verb} {resource} -n {ns}"));
            }
        }
    }
    asks
}

/// The review sar_no asks for `team`'s workload.
fn review(team: &str, resource: &str, subresource: &str, namespace: &str) -> Value {
    let mut review = json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": format!("system:serviceaccount:{team}:mock-workload"),
            "groups": [
                "system:serviceaccounts",
                format!("system:serviceaccounts:{team}"),
                "system:authenticated",
            ],
            "resourceAttributes": {
                "verb": "impersonate",
                "group": "authentication.k8s.io",
                "resource": resource,
                "subresource": subresource,
            },
        },
    });
    if !namespace.is_empty() {
        review["spec"]["resourceAttributes"]["namespace"] = json!(namespace);
    }
    review
}

/// What the operator checks must ask of `team`'s workload: every row of
/// deploy/route-check/permissions.tsv, read here on its own. A `namespaced` row is asked in
/// mock-docs, the gateway's namespace, the team's own and across the cluster; a `cluster` row
/// across the cluster only. Impersonating a UID or an extra is a review; the rest are can-i
/// arguments. Returns the can-i arguments and the reviews.
fn listed_asks(team: &str) -> (Vec<String>, Vec<Value>) {
    let mut asks = Vec::new();
    let mut reviews = Vec::new();
    for line in common::read("deploy/route-check/permissions.tsv").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let row: Vec<&str> = line.split('\t').collect();
        let [verb, resource, subresource, scope] = row[..] else {
            panic!("permissions.tsv: {line:?}");
        };
        let wheres: &[&str] = match scope {
            "namespaced" => &["mock-docs", "switchboard", team, "all"],
            "cluster" => &[""],
            _ => panic!("permissions.tsv: {line:?}"),
        };
        for place in wheres {
            if let ("impersonate", Some((name, "authentication.k8s.io"))) =
                (verb, resource.split_once('.'))
            {
                let subresource = if subresource == "-" { "" } else { subresource };
                let namespace = if *place == "all" { "" } else { place };
                reviews.push(review(team, name, subresource, namespace));
                continue;
            }
            let mut ask = format!("{verb} {resource}");
            if subresource != "-" {
                ask.push_str(&format!(" --subresource={subresource}"));
            }
            // Across the cluster is a can-i with no namespace, which asks in the kubeconfig's
            // namespace and counts its RoleBindings as well as ClusterRoleBindings.
            match *place {
                "" | "all" => {}
                namespace => ask.push_str(&format!(" -n {namespace}")),
            }
            asks.push(ask);
        }
    }
    (asks, reviews)
}

#[test]
fn the_operator_checks_ask_every_row_of_the_route_checks_list_for_both_teams() {
    let (run, asks, reviews) = with_can_i("can-i-no", "no", "false", "operator_checks");
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    let mut expected = Vec::new();
    let mut expected_reviews = Vec::new();
    for team in ["team-a", "team-b"] {
        let (team_asks, team_reviews) = listed_asks(team);
        for ask in &team_asks {
            let check = format!("PASS {team}'s workload may not: {ask}");
            assert!(
                run.stdout.lines().any(|line| line == check),
                "{check}\n{}",
                run.transcript()
            );
            expected.push(format!(
                "k auth can-i {ask} --as=system:serviceaccount:{team}:mock-workload"
            ));
        }
        // Every ask the operator checks made before they read the list is still made, as it
        // was made.
        for ask in operator_asks(team) {
            assert!(team_asks.contains(&ask), "{team}: no longer asked: {ask}");
        }
        // Impersonating a UID or an extra, which can-i cannot name, by SubjectAccessReview: the
        // group, resource and subresource the API server checks, for the user and groups `--as`
        // gives the team's ServiceAccount.
        for (named, resource, subresource) in [
            ("uids", "uids", ""),
            ("userextras/scopes", "userextras", "scopes"),
        ] {
            let check = format!(
                "PASS {team}'s workload may not: impersonate authentication.k8s.io/{named}"
            );
            assert!(
                run.stdout.lines().any(|line| line == check),
                "{check}\n{}",
                run.transcript()
            );
            assert!(team_reviews.contains(&review(team, resource, subresource, "")));
        }
        expected_reviews.extend(team_reviews);
    }
    // Exactly these, and each once: 43 namespaced rows asked four ways and 8 cluster rows, 178
    // asks and 2 reviews per team.
    let mut called = asks.clone();
    called.sort();
    expected.sort();
    assert_eq!(called, expected, "{}", run.transcript());
    assert_eq!(called.len(), 2 * 178);
    assert_eq!(reviews, expected_reviews, "{}", run.transcript());
    assert_eq!(run.lines("PASS ").len(), 2 * 180, "{}", run.transcript());

    // A yes, or no answer at all, fails the check.
    for (answer, allowed) in [("yes", "true"), ("''", "''")] {
        let (run, _, _) = with_can_i("can-i-answer", answer, allowed, "operator_checks");
        assert_eq!(run.status, Some(1), "{answer}: {}", run.transcript());
        for check in [
            "team-b's workload may not: create services --subresource=proxy -n mock-docs",
            "team-b's workload may not: create cronjobs.batch -n team-b",
            "team-b's workload may not: impersonate authentication.k8s.io/userextras/scopes",
        ] {
            assert!(run.failed(check), "{answer}: {check}\n{}", run.transcript());
        }
    }
}

#[test]
fn a_can_i_about_a_resource_the_api_does_not_serve_fails() {
    // can-i still answers no, about a core resource of the whole name: a no that means nothing.
    let run = sourced(
        "k() { echo \"Warning: the server doesn't have a resource type 'uids'\" >&2; echo no; }\n\
         can_i_no team-a impersonate uids\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("team-a's workload may not: impersonate uids (got 'a resource the API does not serve: Warning:"),
        "{}",
        run.transcript()
    );
    // Its warning about a cluster-wide resource asked in a namespace changes nothing.
    let run = sourced(
        "k() { echo \"Warning: resource 'nodes' is not namespace scoped\" >&2; echo no; }\n\
         can_i_no team-a get nodes --subresource=proxy\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
}

#[test]
fn each_team_has_its_own_direct_call_before_the_policy() {
    let run = sourced(
        "kind_workload() { echo \"workload label=[$1] namespace=$2 cronjob=$3 mode=$4\"; }\nbefore_policy_probes",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.lines("workload "),
        [
            "workload label=[team-a before policy] namespace=team-a cronjob=mock-workload mode=before-policy",
            "workload label=[team-b before policy] namespace=team-b cronjob=mock-workload mode=before-policy",
        ],
        "{}",
        run.transcript()
    );
    // The kind run makes them before it applies the network policy.
    let driver = common::read("deploy/demo/demo.sh");
    let probes = driver
        .find("\n  before_policy_probes\n")
        .expect("kind_run makes the probes");
    let policy = driver
        .find("\n  k apply -k \"$ROOT/deploy/kind/policy\"\n")
        .expect("kind_run applies the policy");
    assert!(probes < policy);
}

#[test]
fn a_new_job_keeps_its_templates_environment_and_takes_the_mode() {
    // The before-policy Job reads its team's project through the gateway, so it needs the
    // template's OWN_PROJECT.
    require(&["jq"]);
    let cronjob = json!({
        "metadata": {"namespace": "team-a"},
        "spec": {"jobTemplate": {
            "metadata": {"labels": {"app": "mock-workload"}},
            "spec": {"backoffLimit": 0, "template": {"spec": {"containers": [{
                "name": "workload",
                "args": ["full"],
                "env": [{"name": "OWN_PROJECT", "value": "atlas"}],
            }]}}},
        }},
    });
    // start_job discards what apply prints, so the fake shows what it was given on stderr.
    let run = sourced(&format!(
        "k() {{ case \"$*\" in '-n team-a get cronjob mock-workload -o json') echo '{cronjob}' ;; 'apply -f -') cat >&2 ;; esac; }}\n\
         start_job team-a mock-workload before-policy"
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    let applied: Value = serde_json::from_str(&run.stderr)
        .unwrap_or_else(|error| panic!("{error}\n{}", run.transcript()));
    assert_eq!(applied["kind"], "Job", "{applied}");
    assert_eq!(applied["metadata"]["namespace"], "team-a", "{applied}");
    let container = &applied["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(container["args"], json!(["before-policy"]), "{applied}");
    assert_eq!(
        container["env"],
        json!([{"name": "OWN_PROJECT", "value": "atlas"}]),
        "{applied}"
    );
}

#[test]
fn a_permission_query_kubectl_cannot_answer_fails_with_its_message_and_the_run_goes_on() {
    // kubectl itself fails: it cannot reach the cluster, or may not impersonate. The answer is
    // neither yes nor no, and the check says what kubectl said; the run does not stop there.
    require(&["jq"]);
    let run = sourced(
        "k() { echo 'error: You must be logged in to the server (Unauthorized)' >&2; return 1; }\n\
         can_i_no team-a get secrets -n mock-docs\n\
         sar_no team-a impersonate authentication.k8s.io uids\n\
         pass 'the run went on'\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    for check in [
        "team-a's workload may not: get secrets -n mock-docs (got 'no answer (kubectl exit 1): error: You must be logged in to the server (Unauthorized)",
        "team-a's workload may not: impersonate authentication.k8s.io/uids (got 'no answer (kubectl exit 1): error: You must be logged in to the server (Unauthorized)",
    ] {
        assert!(run.failed(check), "{check}\n{}", run.transcript());
    }
    assert!(
        run.stdout.contains("PASS the run went on\n"),
        "{}",
        run.transcript()
    );
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: FAIL (2 of 3 failed)"),
        "{}",
        run.transcript()
    );
}

/// A fake route-check.sh: it saves its arguments, one per line, to `args`, prints the lines in
/// `$FAKE_OUTPUT`, writes `$FAKE_REPORT` to its --report file, and exits `$FAKE_STATUS`.
const FAKE_ROUTE_CHECK: &str = r#"#!/bin/sh
dir=$(dirname "$0")
for arg do printf '%s\n' "$arg"; done >"$dir/args"
while [ $# -gt 0 ]; do
  case $1 in --report) report=$2 ;; esac
  shift
done
printf '%s\n' "$FAKE_OUTPUT"
[ -z "${FAKE_REPORT:-}" ] || printf '%s\n' "$FAKE_REPORT" >"$report"
exit "${FAKE_STATUS:-0}"
"#;

/// Runs `body` with ROUTE_CHECK set to the fake, DEMO_DIR to a scratch directory, and the
/// environment `env`. Returns the run and the fake's arguments.
fn with_route_check(name: &str, env: &[(&str, &str)], body: &str) -> (Run, Vec<String>) {
    require(&["jq"]);
    let dir = scratch(name);
    let fake = write(&dir, "route-check.sh", FAKE_ROUTE_CHECK);
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = Command::new("bash");
    command.arg("-c").arg(format!(
        "source '{}'\nROUTE_CHECK='{}'\nDEMO_DIR='{}'\nIMG_RUN=switchboard-demo:90d73467ace7\n{body}\n",
        repo().join("deploy/demo/demo.sh").display(),
        fake.display(),
        dir.display()
    ));
    for (key, value) in env {
        command.env(key, value);
    }
    let run = Run::from(command.output().unwrap());
    let args = std::fs::read_to_string(dir.join("args"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    (run, args)
}

#[test]
fn the_route_check_runs_as_its_operator_against_the_idle_pod() {
    let (run, args) = with_route_check(
        "route-check-args",
        &[("FAKE_OUTPUT", "PASS one\nPASS two\n\nRESULT: PASS (2/2)")],
        "route_check team-b refused mock-workload-idle-1\necho \"report=$ROUTE_REPORT\"\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: PASS (2/2)"),
        "{}",
        run.transcript()
    );
    let own = own_kubeconfig();
    let report = args[args.iter().position(|arg| arg == "--report").unwrap() + 1].clone();
    assert!(
        report.contains("/route-check-team-b-") && report.ends_with("Z.json"),
        "{report}"
    );
    assert!(
        run.stdout.contains(&format!("report={report}\n")),
        "{}",
        run.transcript()
    );
    let root = repo().canonicalize().unwrap();
    let want = [
        "--kubeconfig",
        &own,
        "--context",
        "kind-switchboard-demo",
        "--as",
        "system:serviceaccount:route-check:operator",
        "--namespace",
        "team-b",
        "--selector",
        "app=mock-workload,job-name=mock-workload-idle-1",
        "--gateway-ns",
        "switchboard",
        "--server-ns",
        "mock-docs",
        "--server-service",
        "mock-docs/mock-docs",
        "--server-audience",
        "mock-docs",
        "--routes",
        &format!("{}/deploy/route-check/routes/kind.tsv", root.display()),
        "--gateway-url",
        "http://gateway.switchboard.svc.cluster.local:8080/mcp/docs",
        "--expect",
        "refused",
        "--probe-image",
        "switchboard-demo:90d73467ace7",
        "--report",
        &report,
        "--environment",
        "first slice, kind",
    ];
    assert_eq!(args, want);

    // The control before the policy expects every route open, and keeps its report apart.
    let (run, args) = with_route_check(
        "route-check-open",
        &[("FAKE_OUTPUT", "PASS one")],
        "route_check team-a open mock-workload-idle-2\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    let at = args.iter().position(|arg| arg == "--expect").unwrap();
    assert_eq!(args[at + 1], "open");
    let at = args.iter().position(|arg| arg == "--report").unwrap();
    assert!(
        args[at + 1].contains("/route-check-team-a-open-"),
        "{args:?}"
    );
}

#[test]
fn a_route_check_fail_fails_the_run() {
    for (case, output, status) in [
        (
            "fail-line",
            "PASS one\nFAIL the probe passed: RESULT: FAIL",
            "1",
        ),
        // A FAIL with exit 0, or a non-zero exit with no FAIL, is caught too.
        (
            "fail-exit-0",
            "PASS one\nFAIL the probe passed: RESULT: FAIL",
            "0",
        ),
        ("exit-without-fail", "PASS one", "1"),
    ] {
        let (run, _) = with_route_check(
            case,
            &[("FAKE_OUTPUT", output), ("FAKE_STATUS", status)],
            "pass before\nroute_check team-a refused mock-workload-idle-1\nFINISHED=1\nresult 0",
        );
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(
            run.stdout
                .lines()
                .last()
                .unwrap_or_default()
                .starts_with("RESULT: FAIL ("),
            "{case}: {}",
            run.transcript()
        );
    }
}

#[test]
fn the_route_check_before_the_policy_counts_its_open_attempts() {
    // Each open attempt is a request mock-docs refused for carrying no bearer; the server
    // check counts them.
    let report = json!({"routes": [
        {"row": "mock-docs", "by": "name", "result": "open"},
        {"row": "mock-docs", "by": "address", "result": "open"},
        {"row": "mock-docs", "by": "address", "result": "open"},
    ]})
    .to_string();
    let stubs = "can_i_no_as() { echo \"can-i as $1: ${*:3}\"; }\n\
                 start_idle() { JOB=$1-idle-job; echo \"start_idle $1\"; }\n\
                 stop_idle() { echo \"stop_idle $*\"; }\n";
    let (run, args) = with_route_check(
        "route-check-before",
        &[("FAKE_OUTPUT", "PASS one"), ("FAKE_REPORT", &report)],
        &format!("{stubs}route_checks_before_policy\necho \"open=$OPEN_ATTEMPTS\""),
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(run.stdout.contains("open=3\n"), "{}", run.transcript());
    let at = args.iter().position(|arg| arg == "--selector").unwrap();
    assert_eq!(args[at + 1], "app=mock-workload,job-name=team-a-idle-job");
    // The operator's own access is checked first, and the idle Job is deleted after.
    let lines: Vec<&str> = run
        .stdout
        .lines()
        .filter(|line| line.starts_with("can-i as ") || line.contains("_idle "))
        .collect();
    assert_eq!(
        lines,
        [
            "can-i as system:serviceaccount:route-check:operator: get secrets -n mock-docs",
            "can-i as system:serviceaccount:route-check:operator: create pods --subresource=exec -n team-a",
            "can-i as system:serviceaccount:route-check:operator: create pods -n team-a",
            "can-i as system:serviceaccount:route-check:operator: patch pods --subresource=ephemeralcontainers -n mock-docs",
            "start_idle team-a",
            "stop_idle team-a team-a-idle-job",
        ],
        "{}",
        run.transcript()
    );

    // A report that records no open attempt is a FAIL.
    let (run, _) = with_route_check(
        "route-check-before-none",
        &[("FAKE_OUTPUT", "PASS one")],
        &format!("{stubs}route_checks_before_policy\nFINISHED=1\nresult 0"),
    );
    assert!(
        run.failed("the route check before the policy found routes open"),
        "{}",
        run.transcript()
    );
}

#[test]
fn after_the_policy_each_team_gets_a_new_pod_and_ten_seconds_before_its_route_check() {
    let report = json!({"network_plugin": "kindnet", "kind_version": "kind v0.32.0", "routes": []})
        .to_string();
    let (run, _) = with_route_check(
        "route-check-after",
        &[("FAKE_OUTPUT", "PASS one"), ("FAKE_REPORT", &report)],
        "start_idle() { JOB=$1-idle-job; echo \"step start_idle $1\"; }\n\
         stop_idle() { echo \"step stop_idle $*\"; }\n\
         sleep() { echo \"step sleep $*\"; }\n\
         route_check() { echo \"step route_check $*\"; ROUTE_REPORT=$DEMO_DIR/report.json; printf '%s' \"$FAKE_REPORT\" >\"$ROUTE_REPORT\"; }\n\
         route_checks_after_policy\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.lines("step "),
        [
            "step start_idle team-a",
            "step start_idle team-b",
            "step sleep 10",
            "step route_check team-a refused team-a-idle-job",
            "step route_check team-b refused team-b-idle-job",
            "step stop_idle team-a team-a-idle-job",
            "step stop_idle team-b team-b-idle-job",
        ],
        "{}",
        run.transcript()
    );
    for team in ["team-a", "team-b"] {
        for check in [
            format!("PASS the route check's report for {team} records the network plugin"),
            format!(
                "PASS the route check's report for {team} records the kind version (kind v0.32.0)"
            ),
        ] {
            assert!(
                run.stdout.lines().any(|line| line == check),
                "{check}\n{}",
                run.transcript()
            );
        }
    }

    // A report with no kind version, or none at all, fails.
    let report = json!({"network_plugin": "kindnet", "kind_version": "unknown"}).to_string();
    let (run, _) = with_route_check(
        "route-check-report",
        &[("FAKE_REPORT", &report)],
        "printf '%s' \"$FAKE_REPORT\" >\"$DEMO_DIR/r.json\"\ncheck_route_report team-a \"$DEMO_DIR/r.json\"\n\
         check_route_report team-b \"$DEMO_DIR/missing.json\"\nFINISHED=1\nresult 0",
    );
    for check in [
        "the route check's report for team-a records the kind version (got 'unknown')",
        "the route check's report for team-b records the network plugin (got '', want 'kindnet')",
    ] {
        assert!(run.failed(check), "{check}\n{}", run.transcript());
    }
}

#[test]
fn the_kind_run_checks_the_routes_open_before_the_policy_and_refused_after_it() {
    let driver = common::read("deploy/demo/demo.sh");
    let at = |text: &str| {
        let found: Vec<_> = driver.match_indices(text).collect();
        assert_eq!(found.len(), 1, "{text:?} in demo.sh: {}", found.len());
        found[0].0
    };
    let rbac = at("\n  k apply -f \"$ROOT/deploy/kind/route-check/rbac.yaml\"\n");
    let probes = at("\n  before_policy_probes\n");
    let open = at("\n  route_checks_before_policy\n");
    let policy = at("\n  k apply -k \"$ROOT/deploy/kind/policy\"\n  sleep 10\n");
    let refused = at("\n  route_checks_after_policy\n");
    let server = at("\n  check_server_callers \"$(mock_docs_log)\"");
    assert!(
        rbac < probes && probes < open && open < policy && policy < refused && refused < server
    );
    // The control expects every route open; the check after the policy, refused.
    assert_eq!(
        driver
            .matches("  route_check team-a open \"$job\"\n")
            .count(),
        1
    );
    assert_eq!(
        driver
            .matches("    route_check \"$team\" refused \"${jobs[$i]}\"\n")
            .count(),
        1
    );
    assert_eq!(driver.matches("\n  route_check ").count(), 1);
}
