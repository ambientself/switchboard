//! `deploy/demo/demo.sh` with fake `docker`, `kind` and `kubectl` that record every call. The
//! driver must refuse any cluster but `switchboard-demo` before calling anything, name its own
//! kubeconfig in every call, never pass on the caller's KUBECONFIG, and count every failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Run, read, repo, require, scratch, write};
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
    let run = sourced(
        "tally_workload w 0 'PASS one\nPASS two\nRESULT: PASS (2/2)'\nFINISHED=1\nresult 0",
    );
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
    let run = sourced(
        "tally_workload w 1 'PASS one\nFAIL two\nRESULT: FAIL (1 of 2 failed)'\nFINISHED=1\nresult 0",
    );
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
    let run = sourced("tally_workload w 3 'PASS one\nRESULT: PASS (1/1)'\nFINISHED=1\nresult 0");
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload exited 3 without a FAIL line"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_that_exits_zero_despite_a_fail_line_fails_the_run() {
    let run = sourced(
        "tally_workload w 0 'FAIL one\nRESULT: FAIL (1 of 1 failed)'\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload exited 0 despite 1 FAIL lines"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workload_that_checked_nothing_fails_the_run() {
    // Its RESULT counts the zero lines read, and it exits 0: only the missing checks fail it.
    let run = sourced(
        "tally_workload w 0 'no checks here\nRESULT: FAIL (0 of 0 failed)'\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert!(
        run.failed("w: the workload ran no checks (exit 0)"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_workloads_last_result_line_must_count_the_lines_tallied() {
    // The last RESULT line, not the last line: `dc run --rm` may print after it. route-check.sh
    // shows its probe's own RESULT indented, which is not a RESULT line of its own.
    let run = sourced(
        "tally_workload w 0 'PASS one\n    RESULT: PASS\nPASS two\n\nRESULT: PASS (2/2)\nContainer removed'\nFINISHED=1\nresult 0",
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: PASS (2/2)"),
        "{}",
        run.transcript()
    );

    for (case, output, status, failure) in [
        // A log cut short: its RESULT counts more checks than were read.
        (
            "short",
            "PASS one\nPASS two\nRESULT: PASS (3/3)",
            "0",
            "w: the workload's RESULT counts 3 checks, but 2 PASS and FAIL lines were read (RESULT: PASS (3/3))",
        ),
        (
            "short-fail",
            "PASS one\nFAIL two\nRESULT: FAIL (1 of 3 failed)",
            "1",
            "w: the workload's RESULT counts 3 checks, but 2 PASS and FAIL lines were read",
        ),
        (
            "more-lines",
            "PASS one\nPASS two\nRESULT: PASS (1/1)",
            "0",
            "w: the workload's RESULT counts 1 checks, but 2 PASS and FAIL lines were read",
        ),
        (
            "no-result",
            "PASS one\nPASS two",
            "0",
            "w: the workload printed no RESULT line (exit 0)",
        ),
        (
            "no-count",
            "PASS one\nRESULT: PASS",
            "0",
            "w: the workload's RESULT counts no number of checks, but 1 PASS and FAIL lines were read",
        ),
    ] {
        let run = sourced(&format!(
            "tally_workload w {status} '{output}'\nFINISHED=1\nresult 0"
        ));
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        assert!(run.failed(failure), "{case}: {}", run.transcript());
    }
}

#[test]
fn a_kind_workload_log_that_cannot_be_read_fails_the_run() {
    // kubectl can print part of a Job's log and then fail. What it printed is not the run's
    // log, even when it reads as a run that passed.
    let fake = |status: u8| {
        format!(
            "start_job() {{ JOB=$2-$3-1; }}\nwait_job() {{ JOB_STATUS=0; }}\n\
             k() {{ case \"$*\" in\n\
               '-n team-a logs job/mock-workload-full-1') printf 'PASS one\\nPASS two\\nRESULT: PASS (2/2)\\n'; return {status} ;;\n\
               *) echo \"unexpected: k $*\" >&2; return 2 ;;\n\
             esac; }}\n\
             kind_workload 'team-a workload' team-a mock-workload full\nFINISHED=1\nresult 0"
        )
    };
    let run = sourced(&fake(1));
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert_eq!(
        run.lines("FAIL "),
        ["FAIL could not read team-a workload's log (job team-a/mock-workload-full-1) (exit 1)"],
        "{}",
        run.transcript()
    );
    assert!(run.lines("PASS ").is_empty(), "{}", run.transcript());

    // The same log, read: it passes.
    let run = sourced(&fake(0));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some("RESULT: PASS (2/2)"),
        "{}",
        run.transcript()
    );
}

/// The text of the step of demo.sh's function `function` whose title starts with `title`, up to
/// the next step or the function's end.
fn step_text(driver: &str, function: &str, title: &str) -> String {
    let body = function_body(driver, function);
    let start = body
        .find(&format!("\n  step \"{title}"))
        .unwrap_or_else(|| panic!("{function} has no step {title:?}"));
    let rest = &body[start + 1..];
    let end = rest[1..].find("\n  step ").map_or(rest.len(), |at| at + 1);
    rest[..end].to_owned()
}

#[test]
fn a_log_or_metrics_read_that_fails_fails_as_that() {
    // Each read the runs check: the gateway's boot lines, mock-docs' log and the gateway's
    // metrics, in each run. The fake prints a boot line that would pass the boot check, then
    // fails. The step fails once, as a read that failed, and checks nothing from what it read.
    let driver = common::read("deploy/demo/demo.sh");
    let boot = r#"{"event":"boot","identity":"enforce","audit":"postgres"}"#;
    for (function, mode, fake, title, read) in [
        (
            "compose_run",
            "compose",
            "dc",
            "the gateway's boot lines",
            "the gateway's log (exit 1)",
        ),
        (
            "compose_run",
            "compose",
            "dc",
            "the server never saw",
            "mock-docs' log (exit 1)",
        ),
        (
            "compose_run",
            "compose",
            "dc",
            "the gateway's metrics",
            "the gateway's metrics (exit 1)",
        ),
        (
            "kind_run",
            "kind",
            "k",
            "the gateway's boot lines",
            "the gateway's log (pod gateway-1) (exit 1)",
        ),
        (
            "kind_run",
            "kind",
            "k",
            "mock-docs accepted only",
            "mock-docs' log (exit 1)",
        ),
        (
            "kind_run",
            "kind",
            "k",
            "the gateway's metrics",
            "the gateway's metrics (pod gateway-1) (exit 1)",
        ),
    ] {
        let step = step_text(&driver, function, title);
        let run = sourced(&format!(
            "GATEWAY_POD=gateway-1\ngateway_pod() {{ GATEWAY_POD=gateway-1; }}\naudit_rows() {{ :; }}\n\
             MODE={mode}\nLOG_SINCE=2026-10-08T10:00:00.123456Z\nOPEN_ATTEMPTS=1\n\
             {fake}() {{ printf '%s\\n' '{boot}'; return 1; }}\n{step}\nFINISHED=1\nresult 0"
        ));
        assert_eq!(
            run.status,
            Some(1),
            "{function} {title}: {}",
            run.transcript()
        );
        assert_eq!(
            run.lines("FAIL "),
            [format!("FAIL could not read {read}")],
            "{function} {title}: {}",
            run.transcript()
        );
        assert!(
            run.lines("PASS ").is_empty(),
            "{function} {title}: {}",
            run.transcript()
        );
    }
    // No read is passed on unchecked.
    for unchecked in [
        "\"$(mock_docs_log)\"",
        "\"$(dc logs",
        "\"$(k -n \"$ns\" logs",
        "\"$(k -n switchboard logs \"pod/",
        "\"$(dc exec -T gateway curl",
        "\"$(k -n switchboard exec",
    ] {
        assert!(!driver.contains(unchecked), "{unchecked}");
    }
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

/// The SHA-256s of the Compose entries' dummy credentials, docs-team-a's and docs-team-b's.
const SHA_A: &str = "88a0f2ba13fc3cc8cc886b3b543f88c828ba61e0f4c1109c510837e569bb23d9";
const SHA_B: &str = "d20bf481167cefe6c02813ea8c9886c2059292650bf5816a02843ab973eb19e3";

#[test]
fn the_compose_entries_digests_are_their_credentials() {
    for (entry, sha) in [("docs-team-a", SHA_A), ("docs-team-b", SHA_B)] {
        assert_eq!(
            common::read(&format!(
                "deploy/compose/dummy-credentials/{entry}-credential.sha256"
            ))
            .trim(),
            sha
        );
    }
}

/// A line of mock-docs in its static mode: one request with a bearer whose SHA-256 starts with
/// `prefix`, accepted or not.
fn static_line(prefix: &str, accepted: bool) -> String {
    json!({"event": "request", "http_method": "POST", "path": "/mcp",
           "bearer_sha256": prefix, "accepted": accepted})
    .to_string()
}

#[test]
fn the_server_bearer_check_admits_only_the_gateways_credentials() {
    // Lines as mock-docs writes them: one per request, with `accepted` and the bearer's prefix.
    let team_a = static_line("88a0f2ba13fc", true);
    let team_b = static_line("d20bf481167c", true);
    let refused = static_line("aaaaaaaaaaaa", false);
    let health_check = r#"{"event":"request","http_method":"GET","path":"/mcp","bearer_sha256":null,"accepted":false}"#.to_owned();
    let accepted_other = static_line("bbbbbbbbbbbb", true);
    let check = |lines: &[&String], calls: usize, scope: &str| {
        let logs: Vec<&str> = lines.iter().map(|line| line.as_str()).collect();
        sourced(&format!(
            "check_server_bearers '{}' \"{SHA_A} {SHA_B}\" {calls} {scope}\nFINISHED=1\nresult 0",
            logs.join("\n")
        ))
    };

    let run = check(&[&team_a, &health_check, &team_b, &refused], 2, "accepted");
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    // Either entry's credential counts as the gateway's.
    let run = check(&[&team_a, &team_a, &team_b, &team_b], 4, "all");
    assert_eq!(run.status, Some(0), "{}", run.transcript());

    let run = check(&[&team_a, &team_b, &refused], 2, "all");
    assert!(
        run.failed("mock-docs never received any bearer but the gateway's"),
        "{}",
        run.transcript()
    );

    let run = check(&[&team_a, &team_b, &accepted_other], 2, "accepted");
    assert!(
        run.failed("mock-docs accepted no other bearer"),
        "{}",
        run.transcript()
    );

    // One fewer than the calls the gateway allowed, or one more: a denied call reached the
    // server, or the log is short.
    for lines in [&[&team_a][..], &[&team_a, &team_b, &team_b][..]] {
        let run = check(lines, 2, "accepted");
        assert!(
            run.failed("mock-docs accepted the gateway's credentials on exactly the 2 calls"),
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
    // Each team's share of the calls, which check_server_entries expects under its own entry.
    let (compose_each, kind_each) = (compose / 2, kind / 2);
    let compose_call = format!(
        "  if fetch \"mock-docs' log\" mock_docs_log; then\n    check_server_bearers \"$FETCHED\" \"$(entry_sha team-a) $(entry_sha team-b)\" {compose} all\n    check_server_entries \"$FETCHED\" {compose_each} \"team-a=$(entry_sha team-a)\" \"team-b=$(entry_sha team-b)\"\n"
    );
    let kind_call = format!(
        "  if fetch \"mock-docs' log\" mock_docs_log; then\n    check_server_callers \"$FETCHED\" \"$KIND_ENTRY_SUBJECTS\" {kind} {probes} \"$OPEN_ATTEMPTS\"\n    check_server_entries \"$FETCHED\" {kind_each} \"team-a=${{KIND_ENTRY_SUBJECTS%% *}}\" \"team-b=${{KIND_ENTRY_SUBJECTS##* }}\"\n"
    );
    for call in [compose_call, kind_call] {
        assert_eq!(driver.matches(&call).count(), 1, "{call}");
    }
    // Compose's is the only bearer check, kind's the only caller check, and each run has one
    // entry check.
    assert_eq!(driver.matches("  check_server_bearers \"").count(), 1);
    assert_eq!(driver.matches("  check_server_callers \"").count(), 1);
    assert_eq!(driver.matches("  check_server_entries \"").count(), 2);
    // The Compose digests are the entries' credentials' files, team by team.
    let run = sourced("echo \"$(entry_sha team-a) $(entry_sha team-b)\"");
    assert_eq!(
        run.stdout.trim(),
        format!("{SHA_A} {SHA_B}"),
        "{}",
        run.transcript()
    );
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

/// Runs check_server_callers on `lines` for the entries' subjects, 8 calls, 2 refusals and 3
/// open attempts of the route check's probe.
fn check_callers(lines: &[String]) -> Run {
    sourced(&format!(
        "check_server_callers '{}' \"$KIND_ENTRY_SUBJECTS\" 8 2 3\nFINISHED=1\nresult 0",
        lines.join("\n")
    ))
}

/// The kind entries' ServiceAccounts, as mock-docs logs the verified caller.
const SUBJECT_A: &str = "system:serviceaccount:switchboard:docs-team-a";
const SUBJECT_B: &str = "system:serviceaccount:switchboard:docs-team-b";

#[test]
fn the_server_caller_check_admits_only_the_entries_identities() {
    let team_a = jwt_line(true, Some(SUBJECT_A), None);
    let team_b = jwt_line(true, Some(SUBJECT_B), None);
    let direct = jwt_line(false, None, Some("wrong_audience"));
    // The route check's probe before the policy sends no credential.
    let mut probe = jwt_line(false, None, Some("no_bearer"));
    probe = probe.replace("\"35078c7e6361\"", "null");
    let boot =
        r#"{"event":"boot","mode":"jwt","subject":"system:serviceaccount:switchboard:gateway"}"#;
    let run_of = |gateway_calls: usize, extra: &[String]| {
        let mut lines = vec![boot.to_owned(), direct.clone(), direct.clone()];
        lines.extend(std::iter::repeat_n(probe.clone(), 3));
        // Half under each entry's identity, team-a's first.
        lines.extend(std::iter::repeat_n(
            team_a.clone(),
            gateway_calls.div_ceil(2),
        ));
        lines.extend(std::iter::repeat_n(team_b.clone(), gateway_calls / 2));
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

    // Another caller from the trusted issuer, the gateway's own ServiceAccount among them, and a
    // token accepted with no caller at all, as the static mode logs it.
    let other = jwt_line(
        true,
        Some("system:serviceaccount:team-a:mock-workload"),
        None,
    );
    let gateway = jwt_line(
        true,
        Some("system:serviceaccount:switchboard:gateway"),
        None,
    );
    let fake_entry = jwt_line(true, Some(&format!("{SUBJECT_A} x")), None);
    let static_line = r#"{"event":"request","http_method":"POST","path":"/mcp","bearer_sha256":"35078c7e6361","accepted":true}"#;
    for extra in [other, gateway, fake_entry, static_line.to_owned()] {
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
    lines.extend(std::iter::repeat_n(team_a.clone(), 8));
    let run = check_callers(&lines);
    assert!(
        run.failed("mock-docs refused the 2 direct calls' tokens as meant for another audience"),
        "{}",
        run.transcript()
    );
}

/// A tools/call line of mock-docs, accepted under `identity` and naming `project`: in the JWT
/// mode when `identity` is a subject, as its verified caller, and in the static mode otherwise,
/// as its bearer's prefix. `refused` marks a project mock-docs refused for that identity.
fn call_line(identity: &str, project: &str, refused: bool) -> String {
    let mut line = json!({"event": "request", "http_method": "POST", "path": "/mcp",
        "accepted": true, "rpc_method": "tools/call", "rpc_id": 1,
        "tool": "read_document", "project": project, "document": "plan"});
    if identity.starts_with("system:") {
        line["bearer_sha256"] = json!("0123456789ab");
        line["caller"] = json!(identity);
        line["refusal"] = Value::Null;
    } else {
        line["bearer_sha256"] = json!(identity);
    }
    if refused {
        line["refused"] = json!("project");
    }
    line.to_string()
}

#[test]
fn the_server_entry_check_holds_each_team_to_its_own_entrys_identity_and_project() {
    // In Compose an entry's identity is its credential's SHA-256, logged as a prefix; in kind its
    // ServiceAccount, logged as the verified caller.
    for (who, a, b) in [
        (
            format!("\"team-a={SHA_A}\" \"team-b={SHA_B}\""),
            &SHA_A[..12],
            &SHA_B[..12],
        ),
        (
            "\"team-a=${KIND_ENTRY_SUBJECTS%% *}\" \"team-b=${KIND_ENTRY_SUBJECTS##* }\""
                .to_owned(),
            SUBJECT_A,
            SUBJECT_B,
        ),
    ] {
        let run_of = |lines: &[String]| {
            sourced(&format!(
                "check_server_entries '{}' 2 {who}\nFINISHED=1\nresult 0",
                lines.join("\n")
            ))
        };
        let good = [
            call_line(a, "atlas", false),
            call_line(a, "atlas", false),
            call_line(b, "borealis", false),
            call_line(b, "borealis", false),
        ];
        // A request that is not a tools/call, or was not accepted, is not counted.
        let mut lines = good.to_vec();
        lines.push(
            json!({"event": "request", "accepted": true, "rpc_method": "ping", "bearer_sha256": a, "caller": a})
                .to_string(),
        );
        lines.push(
            json!({"event": "request", "accepted": false, "rpc_method": "tools/call", "bearer_sha256": a, "project": "borealis"})
                .to_string(),
        );
        let run = run_of(&lines);
        assert_eq!(run.status, Some(0), "{who}: {}", run.transcript());
        assert_eq!(run.lines("PASS ").len(), 4, "{}", run.transcript());

        // Team B's call under team A's entry: one too many under A's, one too few under B's,
        // and one under A's for B's project.
        let mut swapped = good.to_vec();
        swapped[3] = call_line(a, "borealis", false);
        let run = run_of(&swapped);
        assert!(
            run.failed(
                "mock-docs answered team-b's 2 allowed calls under team-b's own entry's identity"
            ),
            "{who}: {}",
            run.transcript()
        );
        assert!(
            run.failed("no call under team-a's entry's identity named another project"),
            "{who}: {}",
            run.transcript()
        );

        // A call under team A's entry that mock-docs refused for its project.
        let mut refused = good.to_vec();
        refused[1] = call_line(a, "atlas", true);
        let run = run_of(&refused);
        assert!(
            run.failed("mock-docs answered team-a's 2 allowed calls under team-a's own entry's identity, each for atlas"),
            "{who}: {}",
            run.transcript()
        );
        assert!(
            run.failed("no call under team-a's entry's identity named another project"),
            "{who}: {}",
            run.transcript()
        );

        // One call fewer under team B's entry: the log is short, or an allowed call went
        // elsewhere.
        let run = run_of(&good[..3]);
        assert!(
            run.failed("mock-docs answered team-b's 2 allowed calls"),
            "{who}: {}",
            run.transcript()
        );
    }
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
        .find("\n  if fetch \"the gateway's log (pod $GATEWAY_POD)\" k -n switchboard logs \"pod/$GATEWAY_POD\"; then\n    check_boot \"$FETCHED\"\n")
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
    let rendered = "      - image: switchboard-demo:dev\n      - image: postgres:17.11-alpine\n          image: switchboard-demo:dev\n";
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
        run.stdout.contains("image: postgres:17.11-alpine\n"),
        "{}",
        run.transcript()
    );
}

/// What kustomize renders of the Postgres Deployment, as far as apply_base reads it.
const POSTGRES_RENDERED: &str = "  template:\n    metadata:\n      annotations:\n        switchboard.io/image-digest: set-by-demo-sh\n    spec:\n      containers:\n        - image: postgres:17.11-alpine\n";

/// apply_base's output for the Postgres Deployment, with `POSTGRES_IMAGE` set to `postgres`, or
/// left as demo.sh sets it when `None`.
fn applied_postgres(postgres: Option<&str>) -> String {
    let set = postgres
        .map(|image| format!("POSTGRES_IMAGE='{image}'\n"))
        .unwrap_or_default();
    let run = sourced(&format!(
        "k() {{ case \"$1\" in kustomize) printf '%s' '{POSTGRES_RENDERED}' ;; apply) cat ;; esac; }}\n{set}apply_base"
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    run.stdout
}

#[test]
fn a_new_postgres_digest_under_the_same_tag_changes_its_pod_template() {
    // The kind manifest names Postgres's tag alone. The digest goes on the pod template as an
    // annotation, so a bump that changes only the digest still changes the template, and
    // Kubernetes replaces the pod.
    let (a, b) = ("a".repeat(64), "b".repeat(64));
    let before = applied_postgres(Some(&format!("postgres:17.11-alpine@sha256:{a}")));
    let after = applied_postgres(Some(&format!("postgres:17.11-alpine@sha256:{b}")));
    assert!(
        before.contains(&format!(
            "      annotations:\n        switchboard.io/image-digest: sha256:{a}\n"
        )),
        "{before}"
    );
    assert!(
        after.contains(&format!(
            "      annotations:\n        switchboard.io/image-digest: sha256:{b}\n"
        )),
        "{after}"
    );
    assert!(after.contains("image: postgres:17.11-alpine\n"), "{after}");
    assert_ne!(before, after);

    // A run puts its own pin on the template.
    let driver = read("deploy/demo/demo.sh");
    let script = only_line(&driver, "POSTGRES_IMAGE=", "demo.sh");
    let (_, digest) = pinned(script, "demo.sh's POSTGRES_IMAGE");
    let applied = applied_postgres(None);
    assert!(
        applied.contains(&format!("switchboard.io/image-digest: sha256:{digest}\n")),
        "{applied}"
    );
}

/// A Docker image store, as check_postgres_image's reads of the pinned Postgres image see it.
struct Store {
    name: &'static str,
    /// What `docker image inspect --platform linux/arm64 --format '{{.Id}}'` prints.
    id: String,
    /// The manifest.json `docker save --platform linux/arm64` writes, or `None` when the save
    /// fails.
    saved: Option<String>,
}

/// The pinned image's config digest, the ID the node gives the image it runs.
fn postgres_config() -> String {
    format!("sha256:{}", "c".repeat(64))
}

/// Docker's containerd image store: an image's ID is its manifest's digest, and a save keeps the
/// pulled manifest, layers and config.
fn containerd_store() -> Store {
    Store {
        name: "containerd",
        id: format!("sha256:{}", "8".repeat(64)),
        saved: Some(format!(
            r#"[{{"Config":"blobs/sha256/{}","RepoTags":null,"Layers":["blobs/sha256/{}"]}}]"#,
            "c".repeat(64),
            "f".repeat(64)
        )),
    }
}

/// Docker's classic image store: an image's ID is its config's digest, and a save writes a
/// manifest of its own over uncompressed layers. Before Docker 25 the archive named the config
/// `<hex>.json`.
fn classic_stores() -> [Store; 2] {
    let id = postgres_config();
    [
        Store {
            name: "classic",
            id: id.clone(),
            saved: Some(format!(
                r#"[{{"Config":"blobs/sha256/{}","RepoTags":null,"Layers":["blobs/sha256/{}"]}}]"#,
                "c".repeat(64),
                "a".repeat(64)
            )),
        },
        Store {
            name: "classic before Docker 25",
            id,
            saved: Some(format!(
                r#"[{{"Config":"{}.json","RepoTags":null,"Layers":["{}/layer.tar"]}}]"#,
                "c".repeat(64),
                "b".repeat(64)
            )),
        },
    ]
}

/// What crictl lists for the Postgres container when it runs the image with ID `image`.
fn postgres_container(image: &str) -> String {
    format!(
        r#"{{"containers":[{{"id":"{}","imageRef":"{image}","state":"CONTAINER_RUNNING"}}]}}"#,
        "e".repeat(64)
    )
}

/// Runs check_postgres_image against fakes: `pods` is what kubectl lists for the Postgres pods
/// (a node and a container ID per line, as printf reads it), `store` the Docker image store the
/// pinned image is saved from, and `running` what crictl on that node lists for the container
/// (empty when crictl fails).
fn postgres_image_check(pods: &str, store: &Store, running: &str) -> Run {
    require(&["jq", "tar"]);
    let dir = scratch("postgres-image");
    let save = match &store.saved {
        Some(manifest) => {
            write(&dir, "manifest.json", manifest);
            format!(
                "[ \"$3 $4\" = \"linux/arm64 $POSTGRES_IMAGE\" ] && tar -cf - -C '{}' manifest.json",
                dir.display()
            )
        }
        None => "return 1".to_string(),
    };
    sourced(&format!(
        "k() {{ echo \"kubectl $*\" >&2; printf '{pods}'; }}\n\
         docker() {{\n\
           echo \"docker $*\" >&2\n\
           case \"$1 $2\" in\n\
             'version --format') echo arm64 ;;\n\
             'image inspect') [ \"$3 $4\" = '--platform linux/arm64' ] && printf '%s' '{id}' ;;\n\
             'save --platform') {save} ;;\n\
             'exec kind-node') [ -n '{running}' ] && printf '%s' '{running}' ;;\n\
             *) return 1 ;;\n\
           esac\n\
         }}\n\
         PASSES=0 FAILS=0\ncheck_postgres_image\necho \"passes=$PASSES fails=$FAILS\"",
        id = store.id,
    ))
}

#[test]
fn the_kind_run_fails_unless_postgres_runs_the_pinned_digest() {
    let container = "e".repeat(64);
    let pod = format!("kind-node containerd://{container}\\n");
    let config = postgres_config();
    let other = format!("sha256:{}", "d".repeat(64));
    let driver = read("deploy/demo/demo.sh");
    let pin = only_line(&driver, "POSTGRES_IMAGE=", "demo.sh");

    // Whichever store saved it, the check reads the config's digest of the pinned image for this
    // platform, and passes when the pod's container runs the image with that ID: the ID Docker
    // gives the image is the manifest's digest on one store and the config's on the other.
    let [classic, classic_old] = classic_stores();
    for store in [containerd_store(), classic, classic_old] {
        let run = postgres_image_check(&pod, &store, &postgres_container(&config));
        assert!(
            run.stdout.contains("PASS Postgres runs the pinned digest"),
            "{}: {}",
            store.name,
            run.transcript()
        );
        assert!(
            run.stdout.contains("passes=1 fails=0"),
            "{}: {}",
            store.name,
            run.transcript()
        );
        // It saved the pinned image for this platform, asked for the Postgres pods, and listed
        // the pod's container on the pod's node.
        assert!(
            run.stderr
                .contains(&format!("docker save --platform linux/arm64 {pin}\n")),
            "{}: {}",
            store.name,
            run.transcript()
        );
        assert!(
            run.stderr
                .contains("kubectl -n switchboard get pods -l app=postgres"),
            "{}: {}",
            store.name,
            run.transcript()
        );
        assert!(
            run.stderr.contains(&format!(
                "docker exec kind-node crictl ps -o json --id {container}\n"
            )),
            "{}: {}",
            store.name,
            run.transcript()
        );

        // The pod runs another image: the old pod, after a bump that did not replace it.
        let run = postgres_image_check(&pod, &store, &postgres_container(&other));
        assert!(
            run.stdout.contains("FAIL Postgres runs the pinned digest"),
            "{}: {}",
            store.name,
            run.transcript()
        );
        assert!(
            run.stdout.contains("passes=0 fails=1"),
            "{}: {}",
            store.name,
            run.transcript()
        );
    }

    // Nothing to compare fails too: no pod, two pods, a pod with no container yet, a container
    // the node does not list, no config for this platform, and neither read, where only the
    // check that the config was read stops two empty reads from agreeing.
    let unsaved = || Store {
        saved: None,
        ..containerd_store()
    };
    for (pods, store, running) in [
        (
            String::new(),
            containerd_store(),
            postgres_container(&config),
        ),
        (
            format!("{pod}{pod}"),
            containerd_store(),
            postgres_container(&config),
        ),
        (
            "kind-node \\n".to_string(),
            containerd_store(),
            postgres_container(&config),
        ),
        (
            pod.clone(),
            containerd_store(),
            r#"{"containers":[]}"#.to_string(),
        ),
        (pod.clone(), unsaved(), postgres_container(&config)),
        (pod.clone(), unsaved(), String::new()),
    ] {
        let run = postgres_image_check(&pods, &store, &running);
        assert!(
            run.stdout.contains("passes=0 fails=1"),
            "{pods:?} {:?} {running:?}: {}",
            store.saved,
            run.transcript()
        );
    }
}

#[test]
fn the_kind_run_checks_the_postgres_digest_after_its_rollout() {
    let driver = read("deploy/demo/demo.sh");
    assert!(
        driver.contains(
            "  k -n switchboard rollout status deploy/postgres --timeout=120s\n  check_postgres_image\n"
        ),
        "kind_run does not check Postgres's digest once its rollout is done"
    );
}

/// The one line of `text` that starts, after its indentation, with `prefix`, without the prefix.
fn only_line<'a>(text: &'a str, prefix: &str, what: &str) -> &'a str {
    let found: Vec<&str> = text
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(prefix))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{what}: expected one `{prefix}` line, found {found:?}"
    );
    found[0].trim_end()
}

/// Splits `name:tag@sha256:<digest>` at the digest, failing unless there is a tag and the digest
/// is 64 hex digits.
fn pinned<'a>(reference: &'a str, what: &str) -> (&'a str, &'a str) {
    let (tagged, digest) = reference
        .split_once("@sha256:")
        .unwrap_or_else(|| panic!("{what} is not pinned by digest: {reference}"));
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "{what} has no sha256 digest: {reference}"
    );
    assert!(
        tagged.contains(':'),
        "{what} names a digest with no tag: {reference}"
    );
    (tagged, digest)
}

#[test]
fn the_demo_images_are_pinned_by_tag_and_digest() {
    // Postgres: Compose names demo.sh's reference exactly. The kind manifest names its tag, and
    // demo.sh loads the pinned digest into the cluster under that tag (load_images).
    let driver = read("deploy/demo/demo.sh");
    let script = only_line(&driver, "POSTGRES_IMAGE=", "demo.sh");
    let (script_tag, _) = pinned(script, "demo.sh's POSTGRES_IMAGE");
    let compose = read("deploy/compose/compose.yaml");
    let compose = only_line(&compose, "image: postgres:", "compose.yaml");
    assert_eq!(
        format!("postgres:{compose}"),
        script,
        "Compose and demo.sh name different Postgres images"
    );
    let manifest = read("deploy/kind/base/postgres.yaml");
    let manifest = only_line(&manifest, "image: postgres:", "the kind manifest");
    assert_eq!(
        format!("postgres:{manifest}"),
        script_tag,
        "the kind manifest names another tag than the one demo.sh loads"
    );
    let dir = scratch("load-images");
    let run = sourced(&format!(
        "docker() {{ echo \"docker $*\"; }}\nkind() {{ echo \"kind $*\"; }}\nDEMO_DIR='{}'\nIMG_RUN=switchboard-demo:90d73467ace7\nload_images",
        dir.display()
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert!(
        run.stdout
            .contains(&format!("docker tag {script} {script_tag}\n")),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .lines()
            .any(|line| line.starts_with("docker save ")
                && line.ends_with(&format!(" switchboard-demo:90d73467ace7 {script_tag}"))),
        "{}",
        run.transcript()
    );

    // The Dockerfile: the frontend and both base images, and the rust tag is the toolchain's.
    let dockerfile = read("deploy/Dockerfile");
    let syntax = only_line(&dockerfile, "# syntax=", "the Dockerfile");
    pinned(syntax, "the Dockerfile's frontend");
    let from: Vec<&str> = dockerfile
        .lines()
        .filter_map(|line| line.strip_prefix("FROM "))
        .collect();
    assert_eq!(from.len(), 2, "the Dockerfile's stages: {from:?}");
    for line in &from {
        let image = line.split_whitespace().next().unwrap_or_default();
        pinned(image, "a Dockerfile base image");
    }
    let toolchain = read("rust-toolchain.toml");
    let channel = only_line(&toolchain, "channel = ", "rust-toolchain.toml").trim_matches('"');
    assert!(
        from[0].starts_with(&format!("rust:{channel}-slim-trixie@")),
        "the build stage is not rust-toolchain.toml's channel {channel}: {}",
        from[0]
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
        "kind": "call", "team": team, "tool": format!("docs-{team}__read_document"),
        "decision": decision, "reason": reason,
        "sentence": if sentence.is_empty() { Value::Null } else { json!(sentence) },
        "resources": resources, "revision": "demo-3", "listed": null, "omitted": null,
    })
}

/// A list row as `row_resources_json` reads it: no tool, decision or resources.
fn list_row(team: &str, revision: &str, listed: &[impl AsRef<str>]) -> Value {
    let listed: Vec<&str> = listed.iter().map(AsRef::as_ref).collect();
    json!({
        "kind": "list", "team": team, "tool": null, "decision": null, "reason": null,
        "sentence": null, "resources": null, "revision": revision, "listed": listed,
        "omitted": 0,
    })
}

/// The tools `team`'s surface serves: its own entry's two.
fn both_tools(team: &str) -> [String; 2] {
    [
        format!("docs-{team}__list_documents"),
        format!("docs-{team}__read_document"),
    ]
}

fn project(name: &str) -> Value {
    json!([{"system": "docs", "kind": "project", "identifier": name}])
}

/// The rows a run of the demo writes, each recording what its call named.
fn demo_rows() -> Vec<Value> {
    let none_named = "Tool `docs-team-a__read_document` reaches resources the gateway must check, and this call named none of them, so it cannot be allowed. Name the resource the call is for.";
    let outside = |name: &str| {
        format!(
            "Tool `docs-team-a__read_document` names docs project `{name}`, which is outside what workload `w` may reach. Name only resources within that limit."
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
            "Tool `docs-team-a__read_document` is not available on surface `docs-team-a`.",
            json!("unknown"),
        ),
        // Each team's list, and team-a's after the withdrawal, under the next revision.
        list_row("team-a", "demo-3", &both_tools("team-a")),
        list_row("team-b", "demo-3", &both_tools("team-b")),
        list_row("team-a", "demo-4", &["docs-team-a__list_documents"]),
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
        (
            "withdrawn-listed",
            wrong(9, "listed", json!(both_tools("team-a"))),
        ),
        (
            "read-missing",
            wrong(7, "listed", json!(["docs-team-a__list_documents"])),
        ),
        // A team shown the other team's entry's tools.
        (
            "other-teams-tools",
            wrong(7, "listed", json!(both_tools("team-b"))),
        ),
        ("nothing-listed", wrong(8, "listed", json!([]))),
        ("listed-null", wrong(8, "listed", Value::Null)),
        ("tools-omitted", wrong(7, "omitted", json!(1))),
        ("other-team", wrong(7, "team", json!("team-c"))),
        ("no-team", wrong(7, "team", Value::Null)),
        ("unknown-revision", wrong(7, "revision", json!("demo-1"))),
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
            json!(["docs-team-a__read_document", "docs-team-a__list_documents"]),
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
/// with `allowed`, and serving a cluster whose RBAC objects bind nothing to the workloads.
/// Returns the run, each can-i asked and each review's body.
fn with_can_i(
    name: &str,
    answer: &str,
    allowed: &str,
    body: &str,
) -> (Run, Vec<String>, Vec<Value>) {
    let (run, asks, reviews, _) = with_rbac(name, answer, allowed, body, &[]);
    (run, asks, reviews)
}

/// The RBAC lists `k` serves, by the file name `with_rbac` reads them from: the Roles and
/// RoleBindings are those of every namespace.
const RBAC_LISTS: [&str; 4] = [
    "clusterroles",
    "clusterrolebindings",
    "roles",
    "rolebindings",
];

/// As `with_can_i`, with `k get` serving each RBAC list from `rbac` by name (see `RBAC_LISTS`),
/// or an empty list; a name given as None is not served, so its read fails. `get roles -A` and
/// `get rolebindings -A` are served the whole list, and `-n NS` its items in NS. Returns the
/// RBAC reads too, as `get ...`.
fn with_rbac(
    name: &str,
    answer: &str,
    allowed: &str,
    body: &str,
    rbac: &[(&str, Option<&str>)],
) -> (Run, Vec<String>, Vec<Value>, Vec<String>) {
    require(&["jq"]);
    let dir = scratch(name);
    let log = dir.join("calls.log");
    for list in RBAC_LISTS {
        let given = rbac.iter().find(|(name, _)| *name == list).map(|(_, v)| *v);
        match given {
            Some(None) => {}
            Some(Some(contents)) => {
                write(&dir, &format!("{list}.json"), contents);
            }
            None => {
                write(
                    &dir,
                    &format!("{list}.json"),
                    r#"{"apiVersion": "v1", "kind": "List", "items": []}"#,
                );
            }
        }
    }
    let run = sourced(&format!(
        "k() {{ case \"$1\" in\n  \
           create) printf 'review %s\\n' \"$(cat)\" >> '{log}'; echo {allowed} ;;\n  \
           get) echo \"$*\" >> '{log}'; case \"$2 $3\" in\n    \
             'clusterroles -o' | 'clusterrolebindings -o' | 'roles -A' | 'rolebindings -A') cat '{dir}'/\"$2.json\" ;;\n    \
             'roles -n' | 'rolebindings -n') jq --arg ns \"$4\" '.items |= map(select(.metadata.namespace == $ns))' '{dir}'/\"$2.json\" ;;\n    \
             *) return 1 ;;\n  \
           esac ;;\n  \
           *) echo \"k $*\" >> '{log}'; echo {answer} ;;\n\
         esac; }}\n{body}\nFINISHED=1\nresult 0",
        log = log.display(),
        dir = dir.display()
    ));
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let mut asks = Vec::new();
    let mut reviews = Vec::new();
    let mut reads = Vec::new();
    for line in text.lines() {
        if line.starts_with("get ") {
            reads.push(line.to_owned());
            continue;
        }
        match line.strip_prefix("review ") {
            Some(review) => reviews.push(serde_json::from_str(review).unwrap()),
            None => asks.push(line.to_owned()),
        }
    }
    (run, asks, reviews, reads)
}

/// What the operator checks asked of a team's workload before they read permissions.tsv
/// (#47's kind demo checks), and #60's updating and patching of bindings, as `kubectl auth
/// can-i` arguments. Each must still be asked.
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
    for verb in ["create", "update", "patch"] {
        asks.push(format!(
            "{verb} clusterrolebindings.rbac.authorization.k8s.io"
        ));
    }
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
        for verb in ["create", "update", "patch"] {
            asks.push(format!(
                "{verb} rolebindings.rbac.authorization.k8s.io -n {ns}"
            ));
        }
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
    // Exactly these, and each once: 45 namespaced rows asked four ways and 10 cluster rows, 188
    // asks and 2 reviews per team; then one RBAC check per row, 55 per team.
    let mut called = asks.clone();
    called.sort();
    expected.sort();
    assert_eq!(called, expected, "{}", run.transcript());
    assert_eq!(called.len(), 2 * 188);
    assert_eq!(reviews, expected_reviews, "{}", run.transcript());
    assert_eq!(
        run.lines("PASS ").len(),
        2 * (190 + 55),
        "{}",
        run.transcript()
    );

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

/// The rows of deploy/route-check/permissions.tsv, as the operator checks name them.
fn permission_rows() -> Vec<String> {
    common::read("deploy/route-check/permissions.tsv")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let row: Vec<&str> = line.split('\t').collect();
            match row[2] {
                "-" => format!("{} {}", row[0], row[1]),
                sub => format!("{} {}/{sub}", row[0], row[1]),
            }
        })
        .collect()
}

#[test]
fn the_operator_checks_read_the_rbac_rules_bound_to_each_team() {
    let (run, _, _, mut reads) = with_rbac("rbac-clean", "no", "false", "operator_checks", &[]);
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    // One check per row and team, with rbac-match.jq, over the RoleBindings of every namespace.
    for team in ["team-a", "team-b"] {
        for row in permission_rows() {
            let check = format!(
                "PASS {team}'s workload is bound to no RBAC rule for: {row}, whatever its resourceNames ("
            );
            assert!(
                run.stdout.lines().any(|line| line.starts_with(&check)),
                "{check}\n{}",
                run.transcript()
            );
        }
        assert!(
            run.stdout.contains(&format!(
                "PASS {team}'s workload is bound to no RBAC rule for: get secrets, whatever its resourceNames (RoleBindings in every namespace, and ClusterRoleBindings)\n"
            )),
            "{}",
            run.transcript()
        );
    }
    // Each list is read once, with the demo's own access.
    reads.sort();
    assert_eq!(
        reads,
        [
            "get clusterrolebindings -o json",
            "get clusterroles -o json",
            "get rolebindings -A -o json",
            "get roles -A -o json",
        ]
    );
    // demo.sh and route-check.sh run the one matcher.
    let driver = common::read("deploy/demo/demo.sh");
    assert!(driver.contains("RBAC_MATCH=$ROOT/deploy/route-check/rbac-match.jq\n"));
    assert!(driver.contains("-f \"$RBAC_MATCH\""));
    let route_check = common::read("deploy/route-check/route-check.sh");
    assert!(route_check.contains("RBAC_MATCH=$HERE/rbac-match.jq\n"));
    assert!(route_check.contains("-f \"$RBAC_MATCH\""));
}

#[test]
fn a_grant_limited_by_resource_names_fails_the_operator_checks_for_its_team() {
    // A RoleBinding in the gateway's namespace lets team-b's workload mint a token for the
    // gateway's ServiceAccount, and only that one. can-i and the reviews answer no; the rules
    // show it.
    let clusterroles = r#"{"items": [{"metadata": {"name": "mint"}, "rules": [
        {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"], "resourceNames": ["gateway"]}
    ]}]}"#;
    let bindings = r#"{"items": [{"metadata": {"name": "mint", "namespace": "switchboard"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "mint"},
        "subjects": [{"kind": "ServiceAccount", "name": "mock-workload", "namespace": "team-b"}]}]}"#;
    let (run, _, _, _) = with_rbac(
        "rbac-names",
        "no",
        "false",
        "operator_checks",
        &[
            ("clusterroles", Some(clusterroles)),
            ("rolebindings", Some(bindings)),
        ],
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert_eq!(
        run.lines("FAIL "),
        [
            "FAIL team-b's workload is bound to no RBAC rule for: create serviceaccounts/token, whatever its resourceNames (RoleBinding switchboard/mint binds ClusterRole mint to ServiceAccount team-b/mock-workload, for resourceNames gateway)"
        ],
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains(
        "PASS team-b's workload may not: create serviceaccounts --subresource=token -n switchboard\n"
    ));
    assert!(run.stdout.contains(
        "PASS team-a's workload is bound to no RBAC rule for: create serviceaccounts/token, whatever its resourceNames ("
    ));

    // The same grant to every authenticated user fails both teams.
    let everyone = bindings.replace(
        r#"{"kind": "ServiceAccount", "name": "mock-workload", "namespace": "team-b"}"#,
        r#"{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "system:authenticated"}"#,
    );
    let (run, _, _, _) = with_rbac(
        "rbac-names-everyone",
        "no",
        "false",
        "operator_checks",
        &[
            ("clusterroles", Some(clusterroles)),
            ("rolebindings", Some(&everyone)),
        ],
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    for team in ["team-a", "team-b"] {
        assert!(
            run.failed(&format!("{team}'s workload is bound to no RBAC rule for: create serviceaccounts/token, whatever its resourceNames (RoleBinding switchboard/mint binds ClusterRole mint to Group system:authenticated, for resourceNames gateway)")),
            "{team}\n{}",
            run.transcript()
        );
    }
}

#[test]
fn a_grant_outside_a_teams_three_namespaces_fails_the_operator_checks() {
    // can-i and the reviews ask in mock-docs, switchboard and the team's own namespace, and
    // across the cluster, where only ClusterRoleBindings (and default's RoleBindings, for can-i)
    // count. A RoleBinding in kube-system, or in the other team's namespace, is seen by none.
    let roles = r#"{"items": [
        {"metadata": {"name": "mint", "namespace": "kube-system"}, "rules": [
            {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"], "resourceNames": ["clusterrole-aggregation-controller"]}
        ]},
        {"metadata": {"name": "read-credential", "namespace": "team-b"}, "rules": [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["team-b-credential"]}
        ]}
    ]}"#;
    for (name, bindings, want) in [
        (
            "kube-system",
            r#"{"items": [{"metadata": {"name": "mint", "namespace": "kube-system"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "mint"},
                "subjects": [{"kind": "ServiceAccount", "name": "mock-workload", "namespace": "team-a"}]}]}"#,
            "FAIL team-a's workload is bound to no RBAC rule for: create serviceaccounts/token, whatever its resourceNames (RoleBinding kube-system/mint binds Role mint to ServiceAccount team-a/mock-workload, for resourceNames clusterrole-aggregation-controller)",
        ),
        (
            "other-team",
            r#"{"items": [{"metadata": {"name": "read-credential", "namespace": "team-b"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "read-credential"},
                "subjects": [{"kind": "ServiceAccount", "name": "mock-workload", "namespace": "team-a"}]}]}"#,
            "FAIL team-a's workload is bound to no RBAC rule for: get secrets, whatever its resourceNames (RoleBinding team-b/read-credential binds Role read-credential to ServiceAccount team-a/mock-workload, for resourceNames team-b-credential)",
        ),
    ] {
        let (run, _, _, _) = with_rbac(
            &format!("rbac-elsewhere-{name}"),
            "no",
            "false",
            "operator_checks",
            &[("roles", Some(roles)), ("rolebindings", Some(bindings))],
        );
        assert_eq!(run.status, Some(1), "{name}: {}", run.transcript());
        // team-a's alone; every can-i and review answered no.
        assert_eq!(run.lines("FAIL "), [want], "{name}: {}", run.transcript());
    }
}

#[test]
fn rbac_lists_the_operator_checks_cannot_read_fail() {
    for (name, rbac, want) in [
        (
            "unread",
            vec![("rolebindings", None)],
            vec![
                "operator checks: the RBAC rules bound to each team's workload (could not read the rolebindings in every namespace)",
            ],
        ),
        (
            "not-json",
            vec![("clusterroles", Some("{\"items\": ["))],
            vec![
                "operator checks: the RBAC rules bound to each team's workload (could not read the clusterroles)",
            ],
        ),
        (
            "shape",
            vec![(
                "clusterroles",
                Some(
                    r#"{"items": [{"metadata": {"name": "odd"}, "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": "get"}]}]}"#,
                ),
            )],
            vec![
                "team-a's workload is bound to no RBAC rule for a row of",
                "team-b's workload is bound to no RBAC rule for a row of",
                "could not read ClusterRole odd: verbs: not a list of strings",
            ],
        ),
    ] {
        let (run, _, _, _) = with_rbac(
            &format!("rbac-{name}"),
            "no",
            "false",
            "operator_checks",
            &rbac,
        );
        assert_eq!(run.status, Some(1), "{name}: {}", run.transcript());
        for text in want {
            assert!(run.failed(text), "{name}: {text}\n{}", run.transcript());
        }
        assert!(
            !run.stdout
                .contains("PASS team-a's workload is bound to no RBAC rule"),
            "{name}: {}",
            run.transcript()
        );
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
        "http://gateway.switchboard.svc.cluster.local:8080/mcp/docs-team-b",
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
        &[("FAKE_OUTPUT", "PASS one\n\nRESULT: PASS (1/1)")],
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
    // Each output ends in a RESULT line that counts its lines, so the run fails on the line or
    // the exit status alone, not on a missing or short RESULT.
    let label = "route check in team-a, every route refused";
    for (case, output, status, message, last) in [
        (
            "fail-line",
            "PASS one\nFAIL the probe passed: RESULT: FAIL\nRESULT: FAIL (1 of 2 failed)",
            "1",
            None,
            "RESULT: FAIL (1 of 3 failed)",
        ),
        // A FAIL with exit 0, or a non-zero exit with no FAIL, is caught too.
        (
            "fail-exit-0",
            "PASS one\nFAIL the probe passed: RESULT: FAIL\nRESULT: FAIL (1 of 2 failed)",
            "0",
            Some("the workload exited 0 despite 1 FAIL lines"),
            "RESULT: FAIL (2 of 4 failed)",
        ),
        (
            "exit-without-fail",
            "PASS one\nRESULT: PASS (1/1)",
            "1",
            Some("the workload exited 1 without a FAIL line"),
            "RESULT: FAIL (1 of 3 failed)",
        ),
    ] {
        let (run, _) = with_route_check(
            case,
            &[("FAKE_OUTPUT", output), ("FAKE_STATUS", status)],
            "pass before\nroute_check team-a refused mock-workload-idle-1\nFINISHED=1\nresult 0",
        );
        assert_eq!(run.status, Some(1), "{case}: {}", run.transcript());
        match message {
            Some(message) => assert!(
                run.failed(&format!("{label}: {message}")),
                "{case}: {}",
                run.transcript()
            ),
            None => assert!(!run.failed(label), "{case}: {}", run.transcript()),
        }
        assert_eq!(
            run.stdout.lines().last(),
            Some(last),
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
        &[
            ("FAKE_OUTPUT", "PASS one\n\nRESULT: PASS (1/1)"),
            ("FAKE_REPORT", &report),
        ],
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
        &[("FAKE_OUTPUT", "PASS one\n\nRESULT: PASS (1/1)")],
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
    let server = at("\n    check_server_callers \"$FETCHED\"");
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

/// What a gateway answers on `GET /metrics` after a run: the values given, and the rest as a
/// run with no failures leaves them.
fn metrics_text(begin_failures: &str, answers: &str, open_rows: Option<&str>) -> String {
    let mut text = String::from(
        "# HELP switchboard_telemetry_events_total Telemetry events emitted.\n\
         # TYPE switchboard_telemetry_events_total counter\n\
         switchboard_telemetry_events_total{event=\"ping\"} 0\n\
         # TYPE switchboard_telemetry_dropped_total counter\n\
         switchboard_telemetry_dropped_total 0\n\
         # TYPE switchboard_audit_begin_failures_total counter\n",
    );
    for (cause, count) in [
        ("budget_exceeded", "0"),
        ("pool_timeout", begin_failures),
        ("database_error", "0"),
        ("value_refused", "0"),
    ] {
        text.push_str(&format!(
            "switchboard_audit_begin_failures_total{{cause=\"{cause}\"}} {count}\n"
        ));
    }
    text.push_str(&format!(
        "# TYPE switchboard_audit_failure_answers_total counter\n\
         switchboard_audit_failure_answers_total {answers}\n\
         # TYPE switchboard_audit_open_rows gauge\n"
    ));
    if let Some(open) = open_rows {
        text.push_str(&format!("switchboard_audit_open_rows {open}\n"));
    }
    text
}

/// check_metrics run on `text`, with `outage` as its first argument, to its RESULT.
fn check_metrics(outage: &str, text: &str) -> Run {
    sourced(&format!(
        "check_metrics {outage} '{text}'\nFINISHED=1\nresult 0",
        text = text.replace('\'', "'\\''")
    ))
}

#[test]
fn the_metrics_check_counts_the_outage_and_bounds_the_open_rows() {
    let passed = check_metrics("outage", &metrics_text("1", "1", Some("1")));
    assert_eq!(passed.status, Some(0), "{}", passed.transcript());
    assert_eq!(passed.lines("PASS ").len(), 4, "{}", passed.transcript());
    assert!(
        passed
            .stdout
            .contains("    switchboard_audit_failure_answers_total 1\n"),
        "the samples are shown:\n{}",
        passed.transcript()
    );

    let uncounted = check_metrics("outage", &metrics_text("0", "1", Some("0")));
    assert_eq!(uncounted.status, Some(1), "{}", uncounted.transcript());
    assert!(
        uncounted.failed("refused call counted as a begin failure (got 0, want at least 1)"),
        "{}",
        uncounted.transcript()
    );
    let unanswered = check_metrics("outage", &metrics_text("2", "0", Some("0")));
    assert!(
        unanswered.failed("counted as an audit-failure answer (got 0, want at least 1)"),
        "{}",
        unanswered.transcript()
    );

    let open = check_metrics("none", &metrics_text("0", "0", Some("2")));
    assert_eq!(open.status, Some(1), "{}", open.transcript());
    assert!(
        open.failed("found at most one row open (got 2, want at most 1)"),
        "{}",
        open.transcript()
    );
    let outage_open = check_metrics("outage", &metrics_text("1", "1", Some("2")));
    assert!(
        outage_open.failed("found at most the database outage's refused call's row open (got 2"),
        "{}",
        outage_open.transcript()
    );
    // A poll that never succeeded leaves no sample, which is not a count.
    let unpolled = check_metrics("none", &metrics_text("0", "0", None));
    assert!(
        unpolled.failed("found at most one row open (got '', want a number of at most 1)"),
        "{}",
        unpolled.transcript()
    );

    // Without the outage, only telemetry dropped and the open rows are checked, and nothing
    // speaks of an outage the run did not have.
    let kind = check_metrics("none", &metrics_text("0", "0", Some("0")));
    assert_eq!(kind.status, Some(0), "{}", kind.transcript());
    assert_eq!(kind.lines("PASS ").len(), 2, "{}", kind.transcript());
    assert!(!kind.stdout.contains("outage"), "{}", kind.transcript());

    // A gateway that answered nothing fails every check.
    let silent = check_metrics("outage", "");
    assert_eq!(silent.status, Some(1), "{}", silent.transcript());
    assert_eq!(silent.lines("FAIL ").len(), 4, "{}", silent.transcript());
    assert!(
        silent.failed("telemetry dropped is exported (got ''"),
        "{}",
        silent.transcript()
    );
}

/// The body of the function `name` in demo.sh.
fn function_body(driver: &str, name: &str) -> String {
    driver
        .split_once(&format!("\n{name}() {{\n"))
        .unwrap_or_else(|| panic!("no function {name}"))
        .1
        .split_once("\n}\n")
        .unwrap()
        .0
        .to_owned()
}

#[test]
fn each_run_reads_the_metrics_inside_the_gateways_container_after_its_workloads() {
    let driver = common::read("deploy/demo/demo.sh");
    let compose = function_body(&driver, "compose_run");
    let reading = "  if fetch \"the gateway's metrics\" dc exec -T gateway curl -sS --fail http://127.0.0.1:9090/metrics; then\n    check_metrics outage \"$FETCHED\"\n";
    assert!(compose.contains(reading), "{compose}");
    // After the outage step, whose refused call it counts.
    assert!(compose.find("dc unpause postgres").unwrap() < compose.find(reading).unwrap());

    let kind = function_body(&driver, "kind_run");
    let reading = "  if fetch \"the gateway's metrics (pod $GATEWAY_POD)\" k -n switchboard exec \"pod/$GATEWAY_POD\" -c gateway -- \\\n    curl -sS --fail http://localhost:9090/metrics; then\n    check_metrics none \"$FETCHED\"\n";
    assert!(kind.contains(reading), "{kind}");
    assert!(kind.find("team-a and team-b workloads").unwrap() < kind.find(reading).unwrap());
    assert_eq!(driver.matches("\n    check_metrics ").count(), 2);
}

// --- The token writer (deploy/demo/token-writer.sh) ------------------------------------------

/// The token writer's own API token in the tests. A dummy.
const API_TOKEN: &str = "dummy-api-token-for-the-token-writer-tests";

/// The token the fake API server issues for `account`. A dummy.
fn issued(account: &str) -> String {
    format!("dummy-issued-token-for-{account}")
}

/// A scratch directory for the token writer: `bin/curl`, a fake API server that records its
/// arguments and the headers it read from standard input, and answers as `FAKE_API` says
/// (`ok`, `fail`, `no-token` or `ok-but-<account>-fails`); `api/token` and `api/ca.crt`; and an
/// empty `tokens` directory.
fn token_writer_dir(name: &str) -> PathBuf {
    let dir = scratch(name);
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(dir.join("api")).unwrap();
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    write(&dir.join("api"), "token", &format!("{API_TOKEN}\n"));
    write(
        &dir.join("api"),
        "ca.crt",
        "dummy CA, never read by the fake\n",
    );
    // The last argument is the URL; the TokenRequest is the argument after --data-binary.
    let curl = write(
        &bin,
        "curl",
        &format!(
            r#"#!/bin/sh
log='{log}'
printf 'ARGS' >> "$log"; for arg in "$@"; do printf ' [%s]' "$arg" >> "$log"; done; echo >> "$log"
printf 'STDIN %s\n' "$(cat)" >> "$log"
for arg in "$@"; do url=$arg; done
account=${{url%/token}}; account=${{account##*/}}
case "$FAKE_API" in
  fail) echo 'curl: (22) The requested URL returned error: 403' >&2; exit 22 ;;
  no-token) echo '{{"kind":"TokenRequest","status":{{}}}}'; exit 0 ;;
  ok-but-*-fails) if [ "$account-fails" = "${{FAKE_API#ok-but-}}" ]; then exit 7; fi ;;
esac
printf '{{"kind":"TokenRequest","status":{{"token":"dummy-issued-token-for-%s","expirationTimestamp":"2026-10-11T00:10:00Z"}}}}\n' "$account"
"#,
            log = dir.join("curl.log").display()
        ),
    );
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// Runs `token-writer.sh once` in `dir` with the fake API server answering `api`, and `env`
/// over the kind manifest's settings.
fn token_writer(dir: &Path, api: &str, env: &[(&str, &str)]) -> Run {
    require(&["sh", "jq"]);
    let path = format!(
        "{}:{}",
        dir.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new("sh");
    command
        .arg(repo().join("deploy/demo/token-writer.sh"))
        .arg("once")
        .env_clear()
        .env("PATH", path)
        .env("FAKE_API", api)
        .env("TOKEN_SERVICE_ACCOUNTS", "docs-team-a docs-team-b")
        .env("TOKEN_NAMESPACE", "switchboard")
        .env("TOKEN_AUDIENCE", "mock-docs")
        .env("TOKEN_EXPIRATION_SECONDS", "600")
        .env("TOKEN_REFRESH_SECONDS", "300")
        .env("TOKEN_RETRY_SECONDS", "5")
        .env("TOKEN_DIR", dir.join("tokens"))
        .env("API_SERVER", "https://kubernetes.default.svc")
        .env("API_TOKEN_FILE", dir.join("api/token"))
        .env("API_CA_FILE", dir.join("api/ca.crt"));
    for (key, value) in env {
        command.env(key, value);
    }
    Run::from(command.output().unwrap())
}

/// What the fake API server recorded: each call's arguments and the headers it read.
fn api_calls(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("curl.log")).unwrap_or_default()
}

fn token_file(dir: &Path, account: &str) -> Option<String> {
    std::fs::read_to_string(dir.join("tokens").join(account)).ok()
}

#[test]
fn the_token_writer_writes_each_entrys_token_for_the_servers_audience() {
    let dir = token_writer_dir("token-writer-ok");
    let run = token_writer(&dir, "ok", &[]);
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    for account in ["docs-team-a", "docs-team-b"] {
        assert_eq!(
            token_file(&dir, account),
            Some(format!("{}\n", issued(account))),
            "{}",
            run.transcript()
        );
    }
    // Nothing is left beside the tokens.
    let mut names: Vec<String> = std::fs::read_dir(dir.join("tokens"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["docs-team-a", "docs-team-b"]);

    // Each request is a TokenRequest for the server's audience and the expiration, to the
    // account's token subresource, over TLS checked against the cluster's CA.
    let calls = api_calls(&dir);
    let args: Vec<&str> = calls
        .lines()
        .filter(|line| line.starts_with("ARGS"))
        .collect();
    assert_eq!(args.len(), 2, "{calls}");
    let body = r#"[{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"audiences":["mock-docs"],"expirationSeconds":600}}]"#;
    for (line, account) in args.iter().zip(["docs-team-a", "docs-team-b"]) {
        assert!(
            line.contains(&format!(" [--data-binary] {body} ")),
            "{line}"
        );
        assert!(
            line.ends_with(&format!(
                " [https://kubernetes.default.svc/api/v1/namespaces/switchboard/serviceaccounts/{account}/token]"
            )),
            "{line}"
        );
        assert!(
            line.contains(&format!(
                " [--cacert] [{}] ",
                dir.join("api/ca.crt").display()
            )),
            "{line}"
        );
        assert!(line.contains(" [--fail] "), "{line}");
    }
    // The API token goes on standard input as the header, never on a command line.
    assert!(!args.iter().any(|line| line.contains(API_TOKEN)), "{calls}");
    assert_eq!(
        calls
            .matches(&format!("STDIN Authorization: Bearer {API_TOKEN}\n"))
            .count(),
        2,
        "{calls}"
    );
}

#[test]
fn the_token_writer_never_prints_a_token() {
    for api in ["ok", "fail", "no-token"] {
        let dir = token_writer_dir(&format!("token-writer-quiet-{api}"));
        let run = token_writer(&dir, api, &[]);
        let printed = format!("{}{}", run.stdout, run.stderr);
        for secret in [
            API_TOKEN.to_owned(),
            issued("docs-team-a"),
            issued("docs-team-b"),
        ] {
            assert!(!printed.contains(&secret), "{api}: {}", run.transcript());
        }
        // It says what it did for each account all the same.
        assert_eq!(
            printed.matches("token-writer: docs-team-").count(),
            2,
            "{api}: {}",
            run.transcript()
        );
    }
}

#[test]
fn a_token_the_writer_cannot_get_leaves_the_previous_one_in_place() {
    for api in ["fail", "no-token"] {
        let dir = token_writer_dir(&format!("token-writer-keeps-{api}"));
        for account in ["docs-team-a", "docs-team-b"] {
            write(&dir.join("tokens"), account, "previous-token\n");
        }
        let run = token_writer(&dir, api, &[]);
        assert_eq!(run.status, Some(1), "{api}: {}", run.transcript());
        for account in ["docs-team-a", "docs-team-b"] {
            assert_eq!(
                token_file(&dir, account).as_deref(),
                Some("previous-token\n"),
                "{api}: {}",
                run.transcript()
            );
            assert!(
                run.stdout.contains(&format!("token-writer: {account}: "))
                    && run.stdout.contains("keeping the previous token"),
                "{api}: {}",
                run.transcript()
            );
        }
        assert!(!dir.join("tokens/.docs-team-a.next").exists());
    }

    // One account failing does not stop the other's.
    let dir = token_writer_dir("token-writer-one-fails");
    write(&dir.join("tokens"), "docs-team-a", "previous-token\n");
    let run = token_writer(&dir, "ok-but-docs-team-a-fails", &[]);
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    assert_eq!(
        token_file(&dir, "docs-team-a").as_deref(),
        Some("previous-token\n")
    );
    assert_eq!(
        token_file(&dir, "docs-team-b"),
        Some(format!("{}\n", issued("docs-team-b")))
    );
}

#[test]
fn the_token_writer_refuses_a_bad_configuration_before_asking() {
    for (name, value) in [
        ("TOKEN_SERVICE_ACCOUNTS", ""),
        ("TOKEN_SERVICE_ACCOUNTS", "docs-team-a ../gateway"),
        ("TOKEN_AUDIENCE", ""),
        ("TOKEN_EXPIRATION_SECONDS", "ten minutes"),
        ("TOKEN_EXPIRATION_SECONDS", "60"),
        ("TOKEN_REFRESH_SECONDS", "600"),
        ("TOKEN_RETRY_SECONDS", "0"),
        ("TOKEN_DIR", "/no/such/directory"),
        ("API_SERVER", "http://kubernetes.default.svc"),
        ("API_CA_FILE", ""),
    ] {
        let dir = token_writer_dir("token-writer-bad");
        let run = token_writer(&dir, "ok", &[(name, value)]);
        assert_eq!(run.status, Some(2), "{name}={value}: {}", run.transcript());
        assert!(
            run.stderr.contains("token-writer: bad configuration: "),
            "{name}={value}: {}",
            run.transcript()
        );
        assert_eq!(api_calls(&dir), "", "{name}={value}");
    }
}

/// The kind manifest runs the token writer with the settings the tests above use, and the image
/// carries it.
#[test]
fn the_kind_gateway_pod_runs_the_token_writer_the_tests_run() {
    let gateway = common::read("deploy/kind/base/gateway.yaml");
    for line in [
        "          command: [\"token-writer.sh\"]\n",
        "            - {name: TOKEN_SERVICE_ACCOUNTS, value: \"docs-team-a docs-team-b\"}\n",
        "            - {name: TOKEN_NAMESPACE, value: switchboard}\n",
        "            - {name: TOKEN_AUDIENCE, value: mock-docs}\n",
        "            - {name: TOKEN_EXPIRATION_SECONDS, value: \"600\"}\n",
        "            - {name: TOKEN_REFRESH_SECONDS, value: \"300\"}\n",
        "            - {name: TOKEN_RETRY_SECONDS, value: \"5\"}\n",
        "            - {name: TOKEN_DIR, value: /var/run/switchboard/tokens}\n",
        "            - {name: API_SERVER, value: \"https://kubernetes.default.svc\"}\n",
    ] {
        assert_eq!(gateway.matches(line).count(), 1, "{line}");
    }
    let dockerfile = common::read("deploy/Dockerfile");
    assert!(dockerfile.contains(
        "\nCOPY deploy/demo/workload.sh deploy/demo/migrate.sh deploy/demo/token-writer.sh /usr/local/bin/\n"
    ));
}

#[test]
fn the_gateways_token_grant_must_name_only_the_entries() {
    // A fake `k` answering can-i as RBAC would for gateway-tokens.yaml, or as it would with
    // the grant widened to every ServiceAccount.
    let fake = |widened: bool| {
        format!(
            "k() {{ case \"$*\" in\n  *serviceaccounts/docs-team-a\\ *|*serviceaccounts/docs-team-b\\ *) echo yes ;;\n  *) {} ;;\n esac; }}\n",
            if widened {
                "echo yes"
            } else {
                "echo no; return 1"
            }
        )
    };
    let run = sourced(&format!(
        "{}token_grants\nFINISHED=1\nresult 0",
        fake(false)
    ));
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(run.lines("PASS ").len(), 6, "{}", run.transcript());
    let run = sourced(&format!("{}token_grants\nFINISHED=1\nresult 0", fake(true)));
    assert_eq!(run.lines("FAIL ").len(), 4, "{}", run.transcript());
    assert!(
        run.failed(
            "the gateway may not: create serviceaccounts --subresource=token -n switchboard"
        ),
        "{}",
        run.transcript()
    );
}
