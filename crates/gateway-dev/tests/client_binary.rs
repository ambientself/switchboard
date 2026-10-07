//! `switchboard-client` as a process, against a fixture gateway running in this test: it runs
//! the script for the caller and era asked for, with the token and URL from the tokens file,
//! and its exit status says whether every answer was as expected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gateway_dev::client::{caller_name, other_document};
use gateway_dev::start_fixture_gateway;
use gateway_dev::tokens::write_tokens;
use gateway_testkit::Caller;
use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_switchboard-client");

/// A fresh directory under the system's temporary directory for one test.
fn scratch(test: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("gateway-dev-client-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// Runs the binary with `arguments` off the test's runtime, so the gateway keeps serving.
async fn run(arguments: Vec<String>) -> (Option<i32>, String, String) {
    let output: Output = tokio::task::spawn_blocking(move || {
        Command::new(BINARY)
            .args(&arguments)
            .env_remove("RUST_LOG")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn tokens_argument(path: &Path) -> Vec<String> {
    vec!["--tokens".to_owned(), path.display().to_string()]
}

#[tokio::test]
async fn each_caller_runs_its_script_in_the_era_asked_for() {
    let gateway = start_fixture_gateway().await.unwrap();
    let directory = scratch("callers");
    let tokens = directory.join("tokens.json");
    write_tokens(&tokens, &gateway).unwrap();
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&tokens).unwrap()).unwrap();

    let mut runs = 0;
    for (caller, spelled) in [
        (Caller::TeamA, "team-a"),
        (Caller::TeamB, "team_b"),
        (Caller::UserInGroupG, "user"),
    ] {
        for (era, version, other_era) in [
            ("legacy", "2025-06-18", "modern"),
            ("modern", "2026-07-28", "legacy"),
        ] {
            let mut arguments = tokens_argument(&tokens);
            arguments.extend(["--caller", spelled, "--era", era].map(str::to_owned));
            let (code, stdout, stderr) = run(arguments).await;
            assert_eq!(code, Some(0), "{spelled} {era}:\n{stdout}\n{stderr}");
            runs += 1;

            let name = caller_name(caller);
            assert!(
                stdout.contains(&format!("=== {era} ({version}), as {name}: ")),
                "{stdout}"
            );
            assert!(!stdout.contains(&format!("=== {other_era}")), "{stdout}");
            assert!(
                stdout.contains(&format!(
                    "read {}, which they do not",
                    other_document(caller)
                )),
                "{stdout}"
            );
            assert!(!stdout.contains("!! expected"), "{stdout}");
            let token = document[name].as_str().unwrap();
            assert!(!stdout.contains(token), "the token was printed");

            // The calls were made as this caller: the latest row is the denial of the other
            // document, under this caller's profile.
            let rows = gateway.store().rows();
            assert_eq!(rows.len(), runs * 2);
            let denied = rows.last().unwrap();
            assert!(
                denied
                    .sentence
                    .as_deref()
                    .unwrap()
                    .contains(other_document(caller)),
                "{denied:?}"
            );
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn by_default_it_runs_both_eras_as_team_a_on_the_url_the_file_names() {
    let gateway = start_fixture_gateway().await.unwrap();
    let directory = scratch("defaults");
    let tokens = directory.join("tokens.json");
    write_tokens(&tokens, &gateway).unwrap();

    let (code, stdout, stderr) = run(tokens_argument(&tokens)).await;
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    for marker in [
        "=== legacy (2025-06-18), as team_a: initialize",
        "=== modern (2026-07-28), as team_a: server/discover",
        "/mcp/fixture-read",
        "< 202 Accepted",
    ] {
        assert!(stdout.contains(marker), "missing {marker:?}:\n{stdout}");
    }
    assert_eq!(gateway.store().rows().len(), 4);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn an_answer_that_is_not_as_expected_exits_1() {
    let gateway = start_fixture_gateway().await.unwrap();
    let directory = scratch("unexpected");
    let tokens = directory.join("tokens.json");
    write_tokens(&tokens, &gateway).unwrap();

    // A surface the policy does not have: every call is denied, including the caller's own
    // document, which the script expects to read.
    let mut arguments = tokens_argument(&tokens);
    arguments.extend(["--era", "modern", "--url"].map(str::to_owned));
    arguments.push(gateway.url("no-such-surface"));
    let (code, stdout, stderr) = run(arguments).await;
    assert_eq!(code, Some(1), "{stdout}\n{stderr}");
    assert!(stdout.contains("!! expected a tool result"), "{stdout}");
    assert!(stderr.contains("not as expected"), "{stderr}");
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn a_missing_tokens_file_exits_1_and_usage_errors_exit_2() {
    let directory = scratch("missing");
    let (code, _, stderr) = run(tokens_argument(&directory.join("tokens.json"))).await;
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("cannot read the tokens file"), "{stderr}");

    for arguments in [
        &["--caller"][..],
        &["--caller", "team-c"],
        &["--era", "2024-11-05"],
        &["--url"],
        &["--verbose"],
    ] {
        let (code, _, stderr) = run(arguments.iter().map(|a| (*a).to_owned()).collect()).await;
        assert_eq!(code, Some(2), "{arguments:?}");
        assert!(stderr.contains("usage: switchboard-client"), "{stderr}");
    }
    let (code, stdout, _) = run(vec!["--help".to_owned()]).await;
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("usage: switchboard-client"));
}
