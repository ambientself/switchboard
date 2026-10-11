//! Configuration, from environment variables.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::documents::PROJECTS;
use crate::jwt::JwtVerifier;
use crate::tools::{DEFAULT_TOOLS, ToolName, parse_tool_list};

/// Where the MCP endpoint listens unless `MOCK_DOCS_LISTEN` says otherwise.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
/// How long `slow-doc` takes unless `MOCK_DOCS_SLOW_MS` says otherwise.
pub const DEFAULT_SLOW: Duration = Duration::from_secs(10);
/// How many hex digits of a bearer's SHA-256 each log line carries.
pub const LOGGED_PREFIX_HEX: usize = 12;

/// The variable naming the file that holds the one accepted bearer credential. It may name
/// every project.
pub const TOKEN_FILE_VAR: &str = "MOCK_DOCS_TOKEN_FILE";
/// The variable holding the hex SHA-256 of the one accepted bearer credential. It may name
/// every project.
pub const TOKEN_SHA256_VAR: &str = "MOCK_DOCS_TOKEN_SHA256";
/// The variable naming a file that holds the hex SHA-256 of each accepted bearer credential,
/// so a deployment can hand the server a secret file holding only hashes. Each line is a
/// digest, alone or followed by a space and the comma-separated projects that credential may
/// name: `<hex> atlas,borealis`. A digest alone may name every project, so a file holding one
/// digest reads as it always has.
pub const TOKEN_SHA256_FILE_VAR: &str = "MOCK_DOCS_TOKEN_SHA256_FILE";
/// The variable holding the issuer a JWT must name, in the JWT mode.
pub const JWT_ISSUER_VAR: &str = "MOCK_DOCS_JWT_ISSUER";
/// The variable holding the audience a JWT must name, in the JWT mode.
pub const JWT_AUDIENCE_VAR: &str = "MOCK_DOCS_JWT_AUDIENCE";
/// The variable holding the one subject accepted in the JWT mode, such as
/// `system:serviceaccount:switchboard:gateway`. It may name every project.
pub const JWT_SUBJECT_VAR: &str = "MOCK_DOCS_JWT_SUBJECT";
/// The variable holding the subjects accepted in the JWT mode, in place of [`JWT_SUBJECT_VAR`],
/// each with the projects it may name: `<subject>=<project>[,<project>]`, entries separated by
/// `;`, as in `system:serviceaccount:team-a:agent=atlas;system:serviceaccount:team-b:agent=borealis`.
pub const JWT_SUBJECTS_VAR: &str = "MOCK_DOCS_JWT_SUBJECTS";
/// The variable naming the file that holds the JWK set a JWT must be signed by, in the shape a
/// Kubernetes API server's `/openid/v1/jwks` returns.
pub const JWKS_FILE_VAR: &str = "MOCK_DOCS_JWKS_FILE";
/// The JWT mode's variables. All four are set together, or none is; [`JWT_SUBJECTS_VAR`] may
/// stand in for [`JWT_SUBJECT_VAR`].
pub const JWT_VARS: [&str; 4] = [
    JWT_ISSUER_VAR,
    JWT_AUDIENCE_VAR,
    JWT_SUBJECT_VAR,
    JWKS_FILE_VAR,
];
/// The static mode's variables. At most one is set.
pub const STATIC_VARS: [&str; 3] = [TOKEN_FILE_VAR, TOKEN_SHA256_VAR, TOKEN_SHA256_FILE_VAR];
/// The variable holding the MCP endpoint's listen address.
pub const LISTEN_VAR: &str = "MOCK_DOCS_LISTEN";
/// The variable holding the admin endpoint's listen address. Unset, there is no admin endpoint.
/// An address other than loopback needs [`ADMIN_TOKEN_SHA256_FILE_VAR`] too.
pub const ADMIN_LISTEN_VAR: &str = "MOCK_DOCS_ADMIN_LISTEN";
/// The variable naming a file that holds the hex SHA-256 of the admin credential: the one bearer
/// the admin endpoint accepts, in place of every caller's. It must differ from each caller's.
pub const ADMIN_TOKEN_SHA256_FILE_VAR: &str = "MOCK_DOCS_ADMIN_TOKEN_SHA256_FILE";
/// The variable holding the comma-separated tools offered at start.
pub const TOOLS_VAR: &str = "MOCK_DOCS_TOOLS";
/// The variable holding `slow-doc`'s delay in milliseconds.
pub const SLOW_MS_VAR: &str = "MOCK_DOCS_SLOW_MS";
/// The variables that need a value when set: each is refused if it holds only whitespace,
/// rather than read as unset. [`TOOLS_VAR`] is not one of them: empty, it offers no tools.
pub const VALUED_VARS: [&str; 12] = [
    TOKEN_FILE_VAR,
    TOKEN_SHA256_VAR,
    TOKEN_SHA256_FILE_VAR,
    JWT_ISSUER_VAR,
    JWT_AUDIENCE_VAR,
    JWT_SUBJECT_VAR,
    JWT_SUBJECTS_VAR,
    JWKS_FILE_VAR,
    LISTEN_VAR,
    ADMIN_LISTEN_VAR,
    ADMIN_TOKEN_SHA256_FILE_VAR,
    SLOW_MS_VAR,
];

/// The projects a caller may name in a tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Projects {
    /// Every project: the one credential of the variables that name a single one.
    Every,
    /// Only these. A call naming any other gets a 403.
    Only(BTreeSet<String>),
}

impl Projects {
    /// Only `projects`.
    pub fn only<'a>(projects: impl IntoIterator<Item = &'a str>) -> Self {
        Self::Only(projects.into_iter().map(str::to_owned).collect())
    }

    /// Whether a call may name `project`.
    pub fn allows(&self, project: &str) -> bool {
        match self {
            Self::Every => true,
            Self::Only(projects) => projects.contains(project),
        }
    }

    /// As log lines and the admin endpoint show it: `"every"`, or the projects in order.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Every => serde_json::json!("every"),
            Self::Only(projects) => serde_json::json!(projects),
        }
    }
}

/// Reads a comma-separated list of projects, as [`named_projects`] takes them.
pub fn parse_projects(list: &str) -> Result<Projects, String> {
    named_projects(list.split(',').map(str::trim))
}

/// The projects `names`. Each must be one the server holds and named once, and there must be at
/// least one.
pub fn named_projects<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Projects, String> {
    let mut projects = BTreeSet::new();
    for project in names {
        if project.is_empty() {
            return Err("a project name is empty".to_owned());
        }
        if !PROJECTS.contains(&project) {
            return Err(format!(
                "there is no project `{project}`; the projects are {}",
                PROJECTS.join(", ")
            ));
        }
        if !projects.insert(project.to_owned()) {
            return Err(format!("project `{project}` is named twice"));
        }
    }
    if projects.is_empty() {
        return Err("no project is named".to_owned());
    }
    Ok(Projects::Only(projects))
}

/// A bearer credential the server accepts, held only as its SHA-256, and the projects it may
/// name.
#[derive(Clone, PartialEq, Eq)]
pub struct AcceptedCredential {
    digest: [u8; 32],
    projects: Projects,
}

impl AcceptedCredential {
    /// Accepts exactly `token`, for every project.
    pub fn token(token: &str) -> Self {
        Self {
            digest: sha256(token),
            projects: Projects::Every,
        }
    }

    /// Accepts the token whose SHA-256 is `hex` (64 hex digits, either case), for every project.
    pub fn sha256_hex(hex: &str) -> Result<Self, ConfigError> {
        decode_digest(hex.trim())
            .map(|digest| Self {
                digest,
                projects: Projects::Every,
            })
            .ok_or(ConfigError::BadDigest)
    }

    /// The same credential, limited to `projects`.
    pub fn limited_to(self, projects: Projects) -> Self {
        Self { projects, ..self }
    }

    /// The projects this credential may name at start.
    pub fn projects(&self) -> &Projects {
        &self.projects
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

    /// Whether `other` accepts the same token, whatever projects each may name.
    pub fn same_token(&self, other: &Self) -> bool {
        self.digest == other.digest
    }

    /// The logged prefix of the accepted credential's SHA-256, for comparing with request logs.
    /// It also names the credential on the admin endpoint.
    pub fn logged_prefix(&self) -> String {
        logged_prefix(&self.digest)
    }

    /// Reads the static mode's variables through `var`: exactly one must be set.
    fn from_vars(var: &impl Fn(&str) -> Option<String>) -> Result<Vec<Self>, ConfigError> {
        let accepted = match (
            var(TOKEN_FILE_VAR),
            var(TOKEN_SHA256_VAR),
            var(TOKEN_SHA256_FILE_VAR),
        ) {
            (Some(path), None, None) => vec![read_token_file(Path::new(&path))?],
            (None, Some(hex), None) => vec![AcceptedCredential::sha256_hex(&hex)?],
            (None, None, Some(path)) => read_digest_file(Path::new(&path))?,
            (None, None, None) => return Err(ConfigError::NoCredential),
            _ => return Err(ConfigError::TwoCredentials),
        };
        Ok(accepted)
    }
}

impl fmt::Debug for AcceptedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "AcceptedCredential({}…, {:?})",
            self.logged_prefix(),
            self.projects
        )
    }
}

/// What the server accepts: static bearer credentials, or the signed tokens of some subjects.
#[derive(Clone, Debug)]
pub enum Credential {
    /// The static mode: bearer credentials, each held as its SHA-256.
    Static(Vec<AcceptedCredential>),
    /// The JWT mode: tokens from one issuer, for one audience, about one of some subjects.
    Jwt(JwtVerifier),
}

impl Credential {
    /// Each accepted caller's name and the projects it may name at start. A caller is named by
    /// its subject in the JWT mode and by its digest's logged prefix in the static mode.
    pub fn callers(&self) -> BTreeMap<String, Projects> {
        match self {
            Self::Static(accepted) => accepted
                .iter()
                .map(|accepted| (accepted.logged_prefix(), accepted.projects.clone()))
                .collect(),
            Self::Jwt(verifier) => verifier.subjects().clone(),
        }
    }
}

impl From<AcceptedCredential> for Credential {
    fn from(accepted: AcceptedCredential) -> Self {
        Self::Static(vec![accepted])
    }
}

impl From<Vec<AcceptedCredential>> for Credential {
    fn from(accepted: Vec<AcceptedCredential>) -> Self {
        Self::Static(accepted)
    }
}

impl From<JwtVerifier> for Credential {
    fn from(verifier: JwtVerifier) -> Self {
        Self::Jwt(verifier)
    }
}

/// What the server does: which credential it accepts, what it offers and how slow `slow-doc` is.
#[derive(Clone, Debug)]
pub struct Config {
    /// What is accepted. Every other request gets a 401.
    pub accepted: Credential,
    /// The tools offered at start, in the order `tools/list` gives them.
    pub tools: Vec<ToolName>,
    /// How long `slow-doc` takes to answer.
    pub slow: Duration,
    /// The one credential the admin endpoint accepts, in place of every caller's; its projects
    /// mean nothing. `None`: the admin endpoint accepts the callers, as `POST /mcp` does, and
    /// the binary serves it only on loopback, where no caller can reach it.
    pub admin: Option<AcceptedCredential>,
}

impl Config {
    /// A server accepting `accepted`, offering the default tools, with the default delay.
    pub fn new(accepted: impl Into<Credential>) -> Self {
        Self {
            accepted: accepted.into(),
            tools: DEFAULT_TOOLS.to_vec(),
            slow: DEFAULT_SLOW,
            admin: None,
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
    /// unset. The server runs in one of two modes. In the static mode exactly one of
    /// [`TOKEN_FILE_VAR`], [`TOKEN_SHA256_VAR`] and [`TOKEN_SHA256_FILE_VAR`] is set. In the
    /// JWT mode all four of [`JWT_VARS`] are set, or [`JWT_SUBJECTS_VAR`] in place of
    /// [`JWT_SUBJECT_VAR`], and none of the static ones. Anything missing, blank, contradictory
    /// or unreadable is an error, and the server does not start. So is an admin endpoint on an
    /// address other than loopback without an admin credential, since the callers could reach
    /// it and widen their own projects.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        if let Some(blank) = VALUED_VARS
            .into_iter()
            .find(|name| var(name).is_some_and(|value| value.trim().is_empty()))
        {
            return Err(ConfigError::Blank(blank));
        }
        let jwt_set = JWT_VARS
            .iter()
            .chain([&JWT_SUBJECTS_VAR])
            .any(|name| var(name).is_some());
        let static_set = STATIC_VARS.iter().any(|name| var(name).is_some());
        let accepted = match (jwt_set, static_set) {
            (true, true) => return Err(ConfigError::StaticAndJwt),
            (true, false) => Credential::Jwt(read_jwt(&var)?),
            (false, _) => Credential::Static(AcceptedCredential::from_vars(&var)?),
        };
        let listen = address(
            LISTEN_VAR,
            var(LISTEN_VAR).as_deref().unwrap_or(DEFAULT_LISTEN),
        )?;
        let admin_listen = var(ADMIN_LISTEN_VAR)
            .map(|value| address(ADMIN_LISTEN_VAR, &value))
            .transpose()?;
        let admin = var(ADMIN_TOKEN_SHA256_FILE_VAR)
            .map(|path| read_admin_digest(Path::new(&path)))
            .transpose()?;
        match (admin_listen, &admin) {
            (None, Some(_)) => return Err(ConfigError::AdminCredentialUnused),
            (Some(address), None) if !address.ip().is_loopback() => {
                return Err(ConfigError::AdminNotLoopback(address));
            }
            _ => {}
        }
        if let (Some(admin), Credential::Static(callers)) = (&admin, &accepted)
            && callers.iter().any(|caller| caller.same_token(admin))
        {
            return Err(ConfigError::AdminIsACaller);
        }
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
                admin,
            },
        })
    }
}

/// Why the settings were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No credential variable is set, static or JWT.
    NoCredential,
    /// Two static credential variables are set, so which one counts is unclear.
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
    /// A static credential variable and a JWT variable are both set.
    StaticAndJwt,
    /// Some of the JWT variables are set but not this one.
    JwtIncomplete(&'static str),
    /// The JWK set file could not be read, or does not hold a set of RS256 keys.
    Jwks(String),
    /// Both [`JWT_SUBJECT_VAR`] and [`JWT_SUBJECTS_VAR`] are set.
    SubjectAndSubjects,
    /// [`JWT_SUBJECTS_VAR`] is malformed, names a subject twice or names an unknown project.
    JwtSubjects(String),
    /// A line of the digest file is malformed, repeats a digest or names an unknown project.
    DigestFile(String),
    /// A variable that needs a value is set, but holds only whitespace.
    Blank(&'static str),
    /// The admin credential's file cannot be read or does not hold one SHA-256.
    AdminCredential(String),
    /// The admin credential is set, but there is no admin endpoint to use it.
    AdminCredentialUnused,
    /// The admin endpoint listens on an address other than loopback with no admin credential.
    AdminNotLoopback(SocketAddr),
    /// The admin credential is also a caller's.
    AdminIsACaller,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCredential => write!(
                formatter,
                "set one of {TOKEN_FILE_VAR}, {TOKEN_SHA256_VAR} and {TOKEN_SHA256_FILE_VAR}, \
                 or all of {}: the server accepts one credential",
                JWT_VARS.join(", ")
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
            Self::StaticAndJwt => write!(
                formatter,
                "set either a static credential ({}) or the JWT settings ({}), not both",
                STATIC_VARS.join(", "),
                JWT_VARS.join(", ")
            ),
            Self::JwtIncomplete(var) => write!(
                formatter,
                "{var} is missing: the JWT mode needs all of {}, \
                 or {JWT_SUBJECTS_VAR} in place of {JWT_SUBJECT_VAR}",
                JWT_VARS.join(", ")
            ),
            Self::Jwks(reason) => write!(formatter, "{JWKS_FILE_VAR}: {reason}"),
            Self::SubjectAndSubjects => write!(
                formatter,
                "set either {JWT_SUBJECT_VAR} or {JWT_SUBJECTS_VAR}, not both"
            ),
            Self::JwtSubjects(reason) => write!(formatter, "{JWT_SUBJECTS_VAR}: {reason}"),
            Self::DigestFile(reason) => write!(formatter, "{TOKEN_SHA256_FILE_VAR}: {reason}"),
            Self::Blank(var) => write!(
                formatter,
                "{var} is set but blank: give it a value, or leave it unset"
            ),
            Self::AdminCredential(reason) => {
                write!(formatter, "{ADMIN_TOKEN_SHA256_FILE_VAR}: {reason}")
            }
            Self::AdminCredentialUnused => write!(
                formatter,
                "{ADMIN_TOKEN_SHA256_FILE_VAR} is set without {ADMIN_LISTEN_VAR}: \
                 there is no admin endpoint to use it"
            ),
            Self::AdminNotLoopback(address) => write!(
                formatter,
                "{ADMIN_LISTEN_VAR} is {address}, which callers could reach: \
                 set {ADMIN_TOKEN_SHA256_FILE_VAR} too, or listen on loopback"
            ),
            Self::AdminIsACaller => write!(
                formatter,
                "the admin credential in {ADMIN_TOKEN_SHA256_FILE_VAR} is also a caller's: \
                 give the admin endpoint a credential of its own"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

fn read_jwt(var: &impl Fn(&str) -> Option<String>) -> Result<JwtVerifier, ConfigError> {
    // A blank variable was refused before this, so each here is set or unset.
    let set = |name| var(name).map(|value| value.trim().to_owned());
    let [issuer, audience, subject, jwks_file] =
        JWT_VARS.map(|name| set(name).ok_or(ConfigError::JwtIncomplete(name)));
    let (issuer, audience) = (issuer?, audience?);
    let subjects = match (subject, set(JWT_SUBJECTS_VAR)) {
        (Ok(_), Some(_)) => return Err(ConfigError::SubjectAndSubjects),
        (Ok(subject), None) => BTreeMap::from([(subject, Projects::Every)]),
        (Err(_), Some(subjects)) => parse_subjects(&subjects).map_err(ConfigError::JwtSubjects)?,
        (Err(missing), None) => return Err(missing),
    };
    let jwks_file = jwks_file?;
    let jwks = std::fs::read_to_string(&jwks_file)
        .map_err(|error| ConfigError::Jwks(format!("cannot read {jwks_file}: {error}")))?;
    JwtVerifier::with_subjects(&issuer, &audience, subjects, &jwks).map_err(ConfigError::Jwks)
}

/// Reads [`JWT_SUBJECTS_VAR`]: `<subject>=<project>[,<project>]` entries separated by `;`.
/// Space around each part is ignored, and so is an empty entry, such as after a last `;`.
fn parse_subjects(value: &str) -> Result<BTreeMap<String, Projects>, String> {
    let mut subjects = BTreeMap::new();
    for entry in value
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (subject, projects) = entry
            .split_once('=')
            .ok_or_else(|| format!("`{entry}` is not <subject>=<project>[,<project>]"))?;
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(format!("`{entry}` names no subject"));
        }
        let projects = parse_projects(projects).map_err(|reason| format!("{subject}: {reason}"))?;
        if subjects.insert(subject.to_owned(), projects).is_some() {
            return Err(format!("subject `{subject}` is named twice"));
        }
    }
    if subjects.is_empty() {
        return Err("names no subject".to_owned());
    }
    Ok(subjects)
}

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

/// Reads the digest file: one credential per line, a digest alone or followed by a space and
/// its projects. Empty lines are skipped. No two lines may share a logged prefix, since that
/// prefix names the credential on the admin endpoint; the same digest twice is refused so.
fn read_digest_file(path: &Path) -> Result<Vec<AcceptedCredential>, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|error| ConfigError::TokenFile(error.to_string()))?;
    let mut accepted: Vec<AcceptedCredential> = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let credential = match line.split_once(char::is_whitespace) {
            None => AcceptedCredential::sha256_hex(line)?,
            Some((hex, projects)) => AcceptedCredential::sha256_hex(hex)?
                .limited_to(parse_projects(projects.trim()).map_err(ConfigError::DigestFile)?),
        };
        let prefix = credential.logged_prefix();
        if accepted.iter().any(|other| other.logged_prefix() == prefix) {
            return Err(ConfigError::DigestFile(format!(
                "the digest {prefix}… is given twice"
            )));
        }
        accepted.push(credential);
    }
    if accepted.is_empty() {
        return Err(ConfigError::BadDigest);
    }
    Ok(accepted)
}

/// Reads the admin credential's file: one SHA-256 in hex, and nothing else.
fn read_admin_digest(path: &Path) -> Result<AcceptedCredential, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::AdminCredential(format!("cannot read it: {error}")))?;
    AcceptedCredential::sha256_hex(&text).map_err(|_| {
        ConfigError::AdminCredential(
            "the file must hold 64 hex digits, the SHA-256 of the admin token".to_owned(),
        )
    })
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
