//! `deploy/demo/demo.sh` with fake `docker`, `kind` and `kubectl` that record every call. The
//! driver must refuse the cluster `otto-dev` before calling anything, name its own kubeconfig
//! in every call, never pass on the caller's KUBECONFIG, and count every failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Run, repo, require, scratch, write};

/// A directory of fake tools. Each appends one line per call to `calls.log`:
/// `<tool> KUBECONFIG=<value> <args...>`. `kind get clusters` lists switchboard-demo, `docker
/// version` prints an architecture, `kubectl` fails, and everything else succeeds silently.
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
        "if [ \"$1\" = version ]; then echo arm64; fi\nexit 0",
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
fn it_refuses_otto_dev_before_calling_anything() {
    for mode in ["kind", "compose", "down"] {
        let (run, calls) = demo(
            "otto-dev",
            &[mode],
            &[("SWITCHBOARD_DEMO_CLUSTER", "otto-dev")],
        );
        assert_eq!(run.status, Some(2), "{}", run.transcript());
        assert!(
            run.stderr
                .contains("refusing to touch the cluster otto-dev"),
            "{}",
            run.transcript()
        );
        assert!(
            calls.is_empty(),
            "demo.sh {mode} called tools for otto-dev: {calls:?}"
        );
    }
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
fn down_deletes_only_the_demo_cluster_through_its_own_kubeconfig() {
    let (run, calls) = demo(
        "down",
        &["down"],
        &[("KUBECONFIG", "/should/never/be/used")],
    );
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    let own = own_kubeconfig();
    let root = repo().canonicalize().unwrap();
    assert_eq!(
        calls,
        vec![
            format!(
                "docker KUBECONFIG= compose -f {}/deploy/compose/compose.yaml --profile demo down -v --remove-orphans",
                root.display()
            ),
            format!("kind KUBECONFIG= delete cluster --name switchboard-demo --kubeconfig {own}"),
        ]
    );
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
    let good = r#"{"status":200,"bearer_sha256":"35078c7e6361"}"#;
    let refused = r#"{"status":401,"bearer_sha256":"aaaaaaaaaaaa"}"#;
    let accepted_other = r#"{"status":200,"bearer_sha256":"bbbbbbbbbbbb"}"#;
    let logs = |lines: &[&str]| lines.join("\n");

    let run = sourced(&format!(
        "check_server_bearers '{}' {sha} 2 accepted\nFINISHED=1\nresult 0",
        logs(&[good, good, refused])
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

    let run = sourced(&format!(
        "check_server_bearers '{}' {sha} 2 accepted\nFINISHED=1\nresult 0",
        logs(&[good])
    ));
    assert!(
        run.failed("mock-docs accepted the gateway's credential"),
        "{}",
        run.transcript()
    );
}
