//! `switchboard-client`: the scripted client, against a gateway that is already running.
//!
//! ```text
//! switchboard-client [--caller team-a|team-b|user] [--era legacy|modern|both]
//!                    [--url URL] [--tokens PATH]
//! ```
//!
//! It reads the caller's token from the tokens file `switchboard-dev` writes (default
//! `target/switchboard-dev/tokens.json` in the workspace) and runs the script for that caller
//! in each era asked for, printing every request and answer:
//!
//! - **legacy** (2025-06-18): `initialize`, `notifications/initialized`, `tools/list`, a read
//!   of the caller's own document and a read of another team's;
//! - **modern** (2026-07-28): `server/discover`, `tools/list` and the same two reads.
//!
//! The defaults are team A, both eras, and the `fixture-read` endpoint the tokens file names.
//! The token itself is never printed.
//!
//! Exit status: 0 when every answer was what its step expected; 1 when the tokens file could
//! not be read, a request went unanswered, or an answer was not as expected; 2 for a usage
//! error.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use gateway_dev::client::{Client, caller_name, caller_named, era_named, script};
use gateway_dev::tokens::{self, read_token};
use gateway_mcp::Era;
use gateway_testkit::{Caller, SURFACE_READ};

const USAGE: &str = "usage: switchboard-client [--caller team-a|team-b|user] \
                     [--era legacy|modern|both] [--url URL] [--tokens PATH]";

struct Arguments {
    caller: Caller,
    eras: Vec<Era>,
    url: Option<String>,
    tokens: PathBuf,
}

fn arguments() -> Result<Arguments, String> {
    let mut parsed = Arguments {
        caller: Caller::TeamA,
        eras: vec![Era::Legacy, Era::Modern],
        url: None,
        tokens: tokens::default_path(),
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = |what: &str| {
            arguments
                .next()
                .ok_or_else(|| format!("{argument} needs {what}"))
        };
        match argument.as_str() {
            "--caller" => {
                let name = value("a caller")?;
                parsed.caller =
                    caller_named(&name).ok_or_else(|| format!("`{name}` is not a caller"))?;
            }
            "--era" => {
                let name = value("an era")?;
                parsed.eras = match name.as_str() {
                    "both" => vec![Era::Legacy, Era::Modern],
                    _ => vec![era_named(&name).ok_or_else(|| format!("`{name}` is not an era"))?],
                };
            }
            "--url" => parsed.url = Some(value("a URL")?),
            "--tokens" => parsed.tokens = value("a path")?.into(),
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown argument `{argument}`")),
        }
    }
    Ok(parsed)
}

fn fail(what: &str) -> ExitCode {
    eprintln!("switchboard-client: {what}");
    ExitCode::from(1)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments = match arguments() {
        Ok(arguments) => arguments,
        Err(problem) if problem.is_empty() => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(problem) => {
            eprintln!("switchboard-client: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let caller = arguments.caller;
    let (token, listed_url) = match read_token(&arguments.tokens, caller, SURFACE_READ) {
        Ok(read) => read,
        Err(error) => {
            return fail(&format!(
                "{error} (`{}`; is switchboard-dev running?)",
                arguments.tokens.display()
            ));
        }
    };
    let Some(url) = arguments.url.or(listed_url) else {
        return fail("the tokens file names no URL; pass --url");
    };
    let client = match Client::new(url, caller_name(caller), token) {
        Ok(client) => client,
        Err(error) => return fail(&format!("cannot make the client: {error}")),
    };

    let mut out = io::stdout();
    let mut as_expected = true;
    for era in arguments.eras {
        if let Err(error) = client.run(&script(era, caller), &mut out).await {
            let _ = out.flush();
            eprintln!("switchboard-client: {error}");
            as_expected = false;
        }
    }
    let _ = out.flush();
    if as_expected {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
