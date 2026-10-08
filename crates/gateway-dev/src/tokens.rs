//! The tokens file: a token for each fixture caller, for a client outside the process.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use gateway_testkit::{Caller, DEFAULT_MAX_LIFETIME, SURFACE_ALL, SURFACE_READ};
use serde_json::{Value, json};
use thiserror::Error;

use crate::client::caller_name;
use crate::start::FixtureGateway;

/// How long a token in the tokens file lives, in seconds: the most the fixture's issuers allow.
pub const TOKEN_LIFETIME_SECS: u64 = DEFAULT_MAX_LIFETIME;

/// How often `switchboard-dev` writes the tokens file again: half a token's lifetime, so a
/// token read from the file always has at least half an hour left.
pub const REMINT_EVERY: Duration = Duration::from_secs(TOKEN_LIFETIME_SECS / 2);

/// What the tokens file says: a fresh token for each fixture caller, when they expire, and the
/// endpoint of each surface.
///
/// ```json
/// {"note": "...", "expires_at": 1800003600,
///  "team_a": "eyJ...", "team_b": "eyJ...", "user": "eyJ...",
///  "urls": {"fixture-read": "http://127.0.0.1:8471/mcp/fixture-read", "fixture-all": "..."}}
/// ```
pub fn tokens_document(gateway: &FixtureGateway) -> Value {
    let issued_at = gateway
        .clock()
        .now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut document = json!({
        "note": "Development tokens signed by switchboard-dev's in-process issuers, whose keys \
                 exist only while it runs. They are not credentials for anything else.",
        "issued_at": issued_at,
        "expires_at": issued_at + TOKEN_LIFETIME_SECS,
        "urls": {
            SURFACE_READ: gateway.url(SURFACE_READ),
            SURFACE_ALL: gateway.url(SURFACE_ALL),
        },
    });
    for caller in [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG] {
        let token = gateway
            .token_builder(caller)
            .lifetime(TOKEN_LIFETIME_SECS)
            .build();
        document[caller_name(caller)] = json!(token);
    }
    document
}

/// Where `switchboard-dev` writes the tokens file and `switchboard-client` reads it unless told
/// otherwise: `target/switchboard-dev/tokens.json` in the workspace these binaries were built
/// from.
pub fn default_path() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.ancestors().nth(2).unwrap_or(manifest);
    workspace.join("target/switchboard-dev/tokens.json")
}

/// Why a token could not be read from a tokens file.
#[derive(Debug, Error)]
pub enum ReadError {
    /// The file could not be read.
    #[error("cannot read the tokens file: {0}")]
    Io(#[from] io::Error),
    /// The file is not JSON.
    #[error("the tokens file is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The file has no token for the caller.
    #[error("the tokens file has no token for {0}")]
    NoToken(&'static str),
}

/// The token for `caller` in the tokens file at `path`, and the file's endpoint for `surface`,
/// if it names one.
pub fn read_token(
    path: &Path,
    caller: Caller,
    surface: &str,
) -> Result<(String, Option<String>), ReadError> {
    let document: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let name = caller_name(caller);
    let token = document[name]
        .as_str()
        .ok_or(ReadError::NoToken(name))?
        .to_owned();
    let url = document["urls"][surface].as_str().map(str::to_owned);
    Ok((token, url))
}

/// Writes [`tokens_document`] to `path`, creating its directory.
///
/// The file is written beside `path` and renamed over it, so a reader never sees half a file.
/// On Unix only its owner may read it.
pub fn write_tokens(path: &Path, gateway: &FixtureGateway) -> io::Result<()> {
    if let Some(directory) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(directory)?;
    }
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = Path::new(&partial);
    let mut file = fs::File::create(partial)?;
    // Before a token is written: a file left by an earlier run keeps its mode otherwise.
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let mut text = serde_json::to_string_pretty(&tokens_document(gateway))?;
    text.push('\n');
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(partial, path)
}
