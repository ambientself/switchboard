//! Configuration, from environment variables.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::tools::{DEFAULT_TOOLS, ToolName, parse_tool_list};

/// Where the MCP endpoint listens unless `MOCK_DOCS_LISTEN` says otherwise.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
/// How long `slow-doc` takes unless `MOCK_DOCS_SLOW_MS` says otherwise.
pub const DEFAULT_SLOW: Duration = Duration::from_secs(10);
/// How many hex digits of a bearer's SHA-256 each log line carries.
pub const LOGGED_PREFIX_HEX: usize = 12;

/// The variable naming the file that holds the one accepted bearer credential.
pub const TOKEN_FILE_VAR: &str = "MOCK_DOCS_TOKEN_FILE";
/// The variable holding the hex SHA-256 of the one accepted bearer credential.
pub const TOKEN_SHA256_VAR: &str = "MOCK_DOCS_TOKEN_SHA256";
/// The variable naming a file that holds the hex SHA-256 of the one accepted bearer
/// credential, so a deployment can hand the server a secret file holding only the hash.
pub const TOKEN_SHA256_FILE_VAR: &str = "MOCK_DOCS_TOKEN_SHA256_FILE";
/// The variable holding the MCP endpoint's listen address.
pub const LISTEN_VAR: &str = "MOCK_DOCS_LISTEN";
/// The variable holding the admin endpoint's listen address. Unset, there is no admin endpoint.
pub const ADMIN_LISTEN_VAR: &str = "MOCK_DOCS_ADMIN_LISTEN";
/// The variable holding the comma-separated tools offered at start.
pub const TOOLS_VAR: &str = "MOCK_DOCS_TOOLS";
/// The variable holding `slow-doc`'s delay in milliseconds.
pub const SLOW_MS_VAR: &str = "MOCK_DOCS_SLOW_MS";

/// The one bearer credential the server accepts, held only as its SHA-256.
#[derive(Clone, PartialEq, Eq)]
pub struct AcceptedCredential {
    digest: [u8; 32],
}

impl AcceptedCredential {
    /// Accepts exactly `token`.
    pub fn token(token: &str) -> Self {
        Self {
            digest: sha256(token),
        }
    }

    /// Accepts the token whose SHA-256 is `hex` (64 hex digits, either case).
    pub fn sha256_hex(hex: &str) -> Result<Self, ConfigError> {
        decode_digest(hex.trim())
            .map(|digest| Self { digest })
            .ok_or(ConfigError::BadDigest)
    }

    /// Whether `token` is the accepted credential.
    pub fn accepts(&self, token: &str) -> bool {
        let received = sha256(token);
        // Compares every byte, so the time taken does not say how much of a guess was right.
        received
            .iter()
            .zip(self.digest.iter())
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
    }

    /// The logged prefix of the accepted credential's SHA-256, for comparing with request logs.
    pub fn logged_prefix(&self) -> String {
        logged_prefix(&self.digest)
    }
}

impl fmt::Debug for AcceptedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AcceptedCredential({}…)", self.logged_prefix())
    }
}

/// What the server does: which credential it accepts, what it offers and how slow `slow-doc` is.
#[derive(Clone, Debug)]
pub struct Config {
    /// The one bearer credential accepted. Every other request gets a 401.
    pub accepted: AcceptedCredential,
    /// The tools offered at start, in the order `tools/list` gives them.
    pub tools: Vec<ToolName>,
    /// How long `slow-doc` takes to answer.
    pub slow: Duration,
}

impl Config {
    /// A server accepting `accepted`, offering the default tools, with the default delay.
    pub fn new(accepted: AcceptedCredential) -> Self {
        Self {
            accepted,
            tools: DEFAULT_TOOLS.to_vec(),
            slow: DEFAULT_SLOW,
        }
    }
}

/// Everything the binary reads from its environment.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Where the MCP endpoint, `POST /mcp`, listens.
    pub listen: SocketAddr,
    /// Where the admin endpoint listens, if it is enabled.
    pub admin_listen: Option<SocketAddr>,
    /// The server's configuration.
    pub config: Config,
}

impl Settings {
    /// Reads the settings through `var`, which returns a variable's value or `None` if it is
    /// unset. Exactly one of [`TOKEN_FILE_VAR`], [`TOKEN_SHA256_VAR`] and
    /// [`TOKEN_SHA256_FILE_VAR`] must be set; anything missing, contradictory or unreadable is
    /// an error, and the server does not start.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let accepted = match (
            var(TOKEN_FILE_VAR),
            var(TOKEN_SHA256_VAR),
            var(TOKEN_SHA256_FILE_VAR),
        ) {
            (Some(path), None, None) => read_token_file(Path::new(&path))?,
            (None, Some(hex), None) => AcceptedCredential::sha256_hex(&hex)?,
            (None, None, Some(path)) => read_digest_file(Path::new(&path))?,
            (None, None, None) => return Err(ConfigError::NoCredential),
            _ => return Err(ConfigError::TwoCredentials),
        };
        let listen = address(
            LISTEN_VAR,
            var(LISTEN_VAR).as_deref().unwrap_or(DEFAULT_LISTEN),
        )?;
        let admin_listen = var(ADMIN_LISTEN_VAR)
            .map(|value| address(ADMIN_LISTEN_VAR, &value))
            .transpose()?;
        let tools = match var(TOOLS_VAR) {
            Some(list) => parse_tool_list(&list).map_err(ConfigError::Tools)?,
            None => DEFAULT_TOOLS.to_vec(),
        };
        let slow = match var(SLOW_MS_VAR) {
            Some(value) => Duration::from_millis(
                value
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError::BadNumber(SLOW_MS_VAR))?,
            ),
            None => DEFAULT_SLOW,
        };
        Ok(Self {
            listen,
            admin_listen,
            config: Config {
                accepted,
                tools,
                slow,
            },
        })
    }
}

/// Why the settings were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Neither credential variable is set.
    NoCredential,
    /// Both credential variables are set, so which one counts is unclear.
    TwoCredentials,
    /// The token file could not be read.
    TokenFile(String),
    /// The token file holds nothing but whitespace.
    EmptyToken,
    /// The SHA-256 is not 64 hex digits.
    BadDigest,
    /// An address does not parse.
    BadAddress(&'static str),
    /// A number does not parse.
    BadNumber(&'static str),
    /// The tool list names an unknown tool or one tool twice.
    Tools(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCredential => write!(
                formatter,
                "set one of {TOKEN_FILE_VAR}, {TOKEN_SHA256_VAR} and {TOKEN_SHA256_FILE_VAR}: \
                 the server accepts one credential"
            ),
            Self::TwoCredentials => write!(
                formatter,
                "set only one of {TOKEN_FILE_VAR}, {TOKEN_SHA256_VAR} and {TOKEN_SHA256_FILE_VAR}"
            ),
            Self::TokenFile(reason) => {
                write!(formatter, "cannot read {TOKEN_FILE_VAR}: {reason}")
            }
            Self::EmptyToken => write!(formatter, "the file in {TOKEN_FILE_VAR} is empty"),
            Self::BadDigest => write!(
                formatter,
                "{TOKEN_SHA256_VAR} must be 64 hex digits, the SHA-256 of the token"
            ),
            Self::BadAddress(var) => write!(formatter, "{var} is not an address like 0.0.0.0:8080"),
            Self::BadNumber(var) => write!(formatter, "{var} is not a whole number"),
            Self::Tools(reason) => write!(formatter, "{TOOLS_VAR}: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn read_token_file(path: &Path) -> Result<AcceptedCredential, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| ConfigError::TokenFile(error.to_string()))?;
    // A secret file usually ends in a newline that is not part of the token.
    let token = text.trim();
    if token.is_empty() {
        return Err(ConfigError::EmptyToken);
    }
    Ok(AcceptedCredential::token(token))
}

fn read_digest_file(path: &Path) -> Result<AcceptedCredential, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| ConfigError::TokenFile(error.to_string()))?;
    AcceptedCredential::sha256_hex(&text)
}

fn address(var: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::BadAddress(var))
}

pub(crate) fn sha256(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub(crate) fn logged_prefix(digest: &[u8; 32]) -> String {
    let mut hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.truncate(LOGGED_PREFIX_HEX);
    hex
}

fn decode_digest(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, [high, low]) in digest.iter_mut().zip(pairs) {
        let high = char::from(*high).to_digit(16)?;
        let low = char::from(*low).to_digit(16)?;
        *slot = u8::try_from(high * 16 + low).ok()?;
    }
    Some(digest)
}
