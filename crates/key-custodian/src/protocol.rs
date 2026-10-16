//! What goes over the custodian's socket: one request and one answer per connection, each one
//! line of JSON.
//!
//! A request names the team, the tool, the repositories, the permission set and the policy
//! revision the call was decided under (see [`TokenRequest::revision`]). The answer is a token and when it expires, a refusal
//! with its reason, or a failure to get a token from GitHub. The reasons are closed sets, so the
//! client can turn each into an error kind and the custodian can count each.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use gateway_core::{PolicyRevision, TeamId, ToolName};
use gateway_registry::Access;
use serde::{Deserialize, Serialize};

/// The most repositories one token may name. GitHub refuses more in one installation token, so
/// a larger request is refused here, never cut short (design section 9).
pub const MAX_REPOSITORIES: usize = 500;

/// The most bytes a request line may hold, newline included. 500 repositories of the longest
/// names GitHub allows fit in well under half of it.
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// The most bytes an answer line may hold, newline included.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The most permissions one request may name. GitHub has fewer than this.
pub const MAX_PERMISSIONS: usize = 64;

/// The longest team name, or base of a revision (see [`base_revision`]), a request may carry.
/// A derived revision's withdrawn tools are bounded only by [`MAX_REQUEST_BYTES`].
pub const MAX_NAME_BYTES: usize = 256;

/// A request for one installation token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// The team the call was decided for.
    pub team: TeamId,
    /// The tool being called.
    pub tool: ToolName,
    /// The repositories the token is for, each `owner/name` as GitHub writes it: at least one,
    /// at most [`MAX_REPOSITORIES`], none twice. Only a reach report's request, for
    /// `metadata: read` alone, may name none (see [`crate::policy`]).
    pub repositories: Vec<String>,
    /// The permissions the token is for, each at its level: at least one.
    pub permissions: BTreeMap<String, Access>,
    /// The policy revision the call was decided under, as the gateway's decision names it:
    /// the registry's revision, or, while the gateway has withdrawn tools, the revision it
    /// derived from that, `{base}+withdrawn:{names}`. The custodian checks the base.
    pub revision: PolicyRevision,
}

/// The base of `revision`: the part before its first `+`, or all of it if it has none. The
/// registry loader refuses a `+` in a revision, so a revision the gateway derived by withdrawing
/// tools, `{base}+withdrawn:{names}` (decision 0013), has the registry's revision as its base.
pub fn base_revision(revision: &PolicyRevision) -> &str {
    let revision = revision.as_str();
    revision.split_once('+').map_or(revision, |(base, _)| base)
}

impl TokenRequest {
    /// Why the request is malformed, if it is: a name too long, a repository not written
    /// `owner/name`, a repository named twice, or a permission that is not a permission name.
    /// The counts and the policy are checked after this, by the custodian.
    pub fn malformed(&self) -> Option<String> {
        if self.team.as_str().is_empty() || self.team.as_str().len() > MAX_NAME_BYTES {
            return Some("the team is empty or too long".into());
        }
        let base = base_revision(&self.revision);
        if base.is_empty() || base.len() > MAX_NAME_BYTES {
            return Some("the revision's base is empty or too long".into());
        }
        let mut seen = BTreeSet::new();
        for repository in &self.repositories {
            if split_repository(repository).is_none() {
                return Some(format!(
                    "`{}` is not a repository written owner/name",
                    bounded(repository)
                ));
            }
            if !seen.insert(repository.as_str()) {
                return Some(format!("repository `{repository}` is named twice"));
            }
        }
        if self.permissions.len() > MAX_PERMISSIONS {
            return Some(format!(
                "the request names more than {MAX_PERMISSIONS} permissions"
            ));
        }
        if let Some(name) = self.permissions.keys().find(|name| !permission_name(name)) {
            return Some(format!("`{}` is not a permission name", bounded(name)));
        }
        None
    }
}

/// The first 64 bytes of `text`, at a character boundary, for a message about it.
fn bounded(text: &str) -> &str {
    let mut end = text.len().min(64);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A permission name as GitHub writes one: lowercase ASCII letters and underscores.
fn permission_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

/// `owner/name` split in two, if it is a repository as GitHub writes one: an account of 1 to
/// 39 ASCII letters, digits and hyphens, and a name of 1 to 100 ASCII letters, digits, `.`,
/// `_` and `-`, other than `.` and `..`.
pub fn split_repository(repository: &str) -> Option<(&str, &str)> {
    let (owner, name) = repository.split_once('/')?;
    let owner_ok = (1..=39).contains(&owner.len())
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    let name_ok = (1..=100).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    (owner_ok && name_ok).then_some((owner, name))
}

/// A token's text. Its `Debug` and `Display` never show it; [`Secret::expose`] does.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a token's text.
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The token's text, to put in an `Authorization` header.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The custodian's answer to one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Answer {
    /// A token, narrowed to exactly the repositories and permissions asked for.
    Issued {
        /// The token.
        token: Secret,
        /// When it stops being usable, in seconds since the Unix epoch: no later than GitHub's
        /// own expiry, and the custodian revokes it then if that is sooner.
        expires_at: u64,
    },
    /// The custodian refused the request: no token was asked of GitHub.
    Refused {
        /// Why.
        reason: Refusal,
        /// A sentence for the operator.
        message: String,
    },
    /// The request passed the custodian's checks, and GitHub did not give a token for it.
    Failed {
        /// Why.
        reason: Failure,
        /// A sentence for the operator.
        message: String,
    },
}

/// Why the custodian refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The connecting process is not the one the custodian serves. Nothing it sent was read.
    Peer,
    /// The request is not one line of JSON of the expected shape, or is malformed.
    Malformed,
    /// The request was decided under a policy revision whose base is not the custodian's
    /// revision.
    StaleRevision,
    /// The team has no limits in the custodian's copy of policy.
    UnknownTeam,
    /// No connector entry the custodian serves states the tool's permission set.
    UnknownTool,
    /// The request names no repository, which GitHub reads as every repository, and is not a
    /// reach report's request for `metadata: read` alone (see [`crate::policy`]).
    NoRepositories,
    /// The request names more than [`MAX_REPOSITORIES`] repositories.
    TooManyRepositories,
    /// A repository is on an account other than the installation's.
    OtherAccount,
    /// A repository is outside the team's limit.
    RepositoryOutsideLimit,
    /// The request names no permission, which GitHub reads as every permission.
    NoPermissions,
    /// A permission is outside the tool's stated set, or above its level there.
    PermissionOutsideTool,
    /// The team has made too many requests: try again later.
    RateLimited,
}

impl Refusal {
    /// Every refusal, for the counters.
    pub const ALL: [Refusal; 12] = [
        Refusal::Peer,
        Refusal::Malformed,
        Refusal::StaleRevision,
        Refusal::UnknownTeam,
        Refusal::UnknownTool,
        Refusal::NoRepositories,
        Refusal::TooManyRepositories,
        Refusal::OtherAccount,
        Refusal::RepositoryOutsideLimit,
        Refusal::NoPermissions,
        Refusal::PermissionOutsideTool,
        Refusal::RateLimited,
    ];

    /// The reason as the wire, the record and the counters write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Peer => "peer",
            Refusal::Malformed => "malformed",
            Refusal::StaleRevision => "stale_revision",
            Refusal::UnknownTeam => "unknown_team",
            Refusal::UnknownTool => "unknown_tool",
            Refusal::NoRepositories => "no_repositories",
            Refusal::TooManyRepositories => "too_many_repositories",
            Refusal::OtherAccount => "other_account",
            Refusal::RepositoryOutsideLimit => "repository_outside_limit",
            Refusal::NoPermissions => "no_permissions",
            Refusal::PermissionOutsideTool => "permission_outside_tool",
            Refusal::RateLimited => "rate_limited",
        }
    }
}

/// Why GitHub gave no token for a request the custodian accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    /// GitHub refused: it answered 401, 403, 404 or 422.
    VendorRefused,
    /// GitHub answered with another status, or an answer the custodian could not read.
    VendorFailed,
    /// GitHub did not answer within the custodian's deadline.
    VendorTimeout,
    /// GitHub issued a token broader than asked for. The custodian revoked it and handed out
    /// nothing.
    Widened,
}

impl Failure {
    /// Every failure, for the counters.
    pub const ALL: [Failure; 4] = [
        Failure::VendorRefused,
        Failure::VendorFailed,
        Failure::VendorTimeout,
        Failure::Widened,
    ];

    /// The reason as the wire, the record and the counters write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Failure::VendorRefused => "vendor_refused",
            Failure::VendorFailed => "vendor_failed",
            Failure::VendorTimeout => "vendor_timeout",
            Failure::Widened => "widened",
        }
    }
}
