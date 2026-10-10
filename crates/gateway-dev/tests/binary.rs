//! `switchboard-dev` as a process: `--once` runs the scripted client in both eras against
//! itself, prints every exchange and audit row, writes the tokens file and exits 0.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_switchboard-dev");

#[test]
fn once_runs_the_script_in_both_eras_and_prints_answers_and_rows() {
    let directory = std::env::temp_dir().join(format!("gateway-dev-binary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let tokens = directory.join("tokens.json");
    let output = Command::new(BINARY)
        .args(["--once", "--port", "0", "--tokens"])
        .arg(&tokens)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{:?}\n{stdout}\n{stderr}",
        output.status
    );

    for marker in [
        "=== legacy (2025-06-18), as team_a: initialize",
        "=== legacy (2025-06-18), as team_a: the initialized notification",
        "=== modern (2026-07-28), as team_a: server/discover",
        "=== modern (2026-07-28), as team_a: read team-b-notes",
        "< 202 Accepted",
        "< 401 Unauthorized",
        "audit: 4 rows, 2 allowed (2 completed) and 2 denied",
    ] {
        assert!(stdout.contains(marker), "missing {marker:?}:\n{stdout}");
    }
    assert!(!stdout.contains("!! expected"), "{stdout}");

    let audit: Vec<Value> = stdout
        .lines()
        .filter(|line| line.starts_with("{\"audit\""))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let events: Vec<&str> = audit
        .iter()
        .map(|line| line["audit"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "listed", "begun", "finished", "begun", "listed", "begun", "finished", "begun"
        ],
        "{stdout}"
    );

    let document: Value = serde_json::from_str(&std::fs::read_to_string(&tokens).unwrap()).unwrap();
    let token = document["team_a"].as_str().unwrap();
    assert!(!stdout.contains(token), "a token was printed");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn usage_errors_exit_2_and_help_exits_0() {
    for arguments in [
        &["--port"][..],
        &["--port", "eighty"],
        &["--verbose"],
        &["--tokens"],
    ] {
        let output = Command::new(BINARY).args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("usage: switchboard-dev"), "{stderr}");
    }
    let output = Command::new(BINARY).arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("usage: switchboard-dev")
    );
}
