//! The built-in GitHub connector (design sections 9 and 13; #12): gateway code that calls
//! GitHub's REST API itself, in the gateway's own process.
//!
//! It holds no GitHub key. For every call it asks the key custodian for an installation token,
//! through [`key_custodian::CustodianClient`], and uses that token for that call alone. The
//! request names:
//!
//! - the team the call was decided for, the caller's proved team;
//! - the tool;
//! - the repositories, narrowed as the tool's connector entry says (decision 0011, section 1):
//!   `limit`, the caller's limit as the snapshot the call was decided under holds it, which is
//!   how Otto's tokens are narrowed today, its GitHub repositories on the configured
//!   organization; or `call`, the one repository the call names. An entry narrowed `none` is
//!   refused when the connector is built: GitHub tokens are always narrowed;
//! - the permission set the entry states in the registry's `[[connectors]]`;
//! - the policy revision the call was decided under ([`ToolCall::policy_revision`]).
//!
//! The custodian checks the request against its own copy of policy. A refusal comes back as an
//! `error` of the kind `custodian_refusal`, and GitHub's refusal to issue the token as
//! `vendor_refusal`.
//!
//! Before anything is asked of the custodian or of GitHub, each call is checked as Otto's
//! gateway checks it (docs/otto-baseline.md):
//!
//! - its arguments are parsed into the tool's own types, and a malformed one (a missing
//!   argument, a number below 1, a path with a `..` segment, a name outside GitHub's character
//!   set) is an `error` of the kind `invalid_arguments`;
//! - its owner must be the one organization the deployment configures; a call naming another
//!   is `refused`, with the sentence the caller reads on its row;
//! - its repository must be within the caller's limit, which the gateway's check 6 has already
//!   decided from the call's resources: each tool's resource adapter names the repository
//!   `owner/repo`, exactly as a limit holds it.
//!
//! [`tools`] has three of the read tools this connector serves, `github__get_file`,
//! `github__get_pr` and `github__get_issue`, each with the definition its approval in the
//! registry must hash to. Each bounds its result and tags it as external evidence, as Otto's
//! gateway does. None checks its own scope: each is declared from its arguments, so its row
//! records the repository it reached.
//!
//! [`search`] has the fourth, `github__search`, which is declared `checks_own_scope`
//! (decision 0011): which repositories a search reaches is known only once GitHub answers. It
//! builds its query as Otto's gateway does, withholds every result from a repository outside
//! the caller's limit, and reports the repositories its results came from as the resources
//! the call reached, which its row records when it finishes.
//!
//! GitHub's errors are told apart: a 404, which GitHub also answers for a repository the token
//! cannot see; a 403, the kind `vendor_refusal`; and its rate limit. A token never appears in
//! an error, a log line or a result: [`key_custodian::Token`] shows nothing of itself, the
//! `Authorization` header is marked sensitive, and no sentence the connector writes quotes
//! GitHub's answer.
//!
//! The gateway wraps the connector in its in-process bound, a deadline and a result size bound,
//! and its rate quotas (`gateway::bound`), as it does every connector in its own process.

#![forbid(unsafe_code)]

mod api;
mod connector;
#[cfg(feature = "test-support")]
pub mod fake;
pub mod search;
pub mod tools;

pub use api::{ApiError, MAX_ANSWER_BYTES};
pub use connector::{DEFAULT_CUSTODIAN_DEADLINE, GitHubConnector, GitHubSettings, SettingsError};
pub use tools::{Definition, definitions};

#[cfg(doc)]
use gateway_core::ToolCall;

/// The system of every GitHub resource and connector entry.
pub const SYSTEM: &str = "github";

/// The kind of a GitHub repository in a limit and in a call's resources.
pub const REPOSITORY: &str = "repository";
