//! The connector: one call, from its arguments to its result.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use gateway_core::{
    BoxFuture, ConnectorName, ErrorKind, Narrowing, PrincipalKind, TeamId, ToolCall, ToolOutcome,
};
use gateway_registry::{Access, BuiltInEntry};
use hyper::StatusCode;
use key_custodian::{CustodianClient, Token, TokenRequest};
use serde_json::{Value, json};
use thiserror::Error;

use crate::api::{Answered, Api, ApiError};
use crate::tools::{self, Call};
use crate::{REPOSITORY, SYSTEM};

/// How long the connector waits for the key custodian's answer unless configured otherwise.
pub const DEFAULT_CUSTODIAN_DEADLINE: Duration = Duration::from_secs(5);

/// Where the connector finds GitHub and the key custodian: the deployment file's `[github]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubSettings {
    /// The one organization every call must name as its owner.
    pub organization: String,
    /// GitHub's REST API base URL, such as `https://api.github.com`.
    pub api_url: String,
    /// The CAs trusted for an `https` API URL: the only ones.
    pub ca_file: Option<PathBuf>,
    /// The key custodian's socket.
    pub custodian_socket: PathBuf,
    /// How long the custodian has to answer each token request.
    pub custodian_deadline: Duration,
    /// The hosts GitHub's job log redirects may point to, each a URL with a scheme, a host and
    /// a port, if not the scheme's own, and nothing else, held to the same rules and the same
    /// CA file as `api_url`. A redirect to any other is refused, and with none every one is.
    pub job_log_hosts: Vec<String>,
}

/// Why the connector could not be built.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettingsError {
    /// The organization is not a GitHub account name.
    #[error("`{0}` is not a GitHub organization name")]
    Organization(String),
    /// The API URL or its CA file was refused.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// A GitHub entry that serves approved tools is not narrowed: GitHub tokens are always
    /// narrowed, to the caller's limit or to the call's repository.
    #[error(
        "connector `{0}` says its credential is narrowed \"none\"; the GitHub connector narrows \
         every token, so declare \"limit\" or \"call\""
    )]
    NotNarrowed(ConnectorName),
    /// A job log host was refused.
    #[error("the job log host `{0}` was refused: {1}")]
    JobLogHost(String, ApiError),
    /// An entry serves a tool whose permission set it does not hold, so the key custodian
    /// would refuse every token the tool asks for.
    #[error(
        "connector `{entry}` serves `{tool}`, which asks for `{permission}: read`, and the entry \
         does not state it"
    )]
    PermissionNotStated {
        /// The entry.
        entry: ConnectorName,
        /// The tool.
        tool: String,
        /// The permission the entry does not state.
        permission: String,
    },
}

/// What one entry's tokens are asked for with.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryCredential {
    narrowing: Narrowing,
    permissions: BTreeMap<String, Access>,
}

/// The GitHub connector. See the [crate documentation](crate).
pub struct GitHubConnector {
    organization: String,
    api: Api,
    custodian: CustodianClient,
    entries: BTreeMap<ConnectorName, EntryCredential>,
    job_log_hosts: Vec<Api>,
}

impl std::fmt::Debug for GitHubConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubConnector")
            .field("organization", &self.organization)
            .field("api", &self.api)
            .field("entries", &self.entries.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl GitHubConnector {
    /// A connector for `settings`, serving the tools of `entries`, the registry's built-in
    /// entries of system `github`. Each entry's permission set and narrowing are read now:
    /// the gateway refuses a registry version that changes them while it runs. An entry that
    /// declares no credential serves no approved tool, and is not served.
    pub fn new<'a>(
        settings: &GitHubSettings,
        entries: impl IntoIterator<Item = &'a BuiltInEntry>,
    ) -> Result<Self, SettingsError> {
        let organization = &settings.organization;
        let account = (1..=39).contains(&organization.len())
            && organization
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !account {
            return Err(SettingsError::Organization(organization.clone()));
        }
        let api = Api::new(&settings.api_url, settings.ca_file.as_deref())?;
        let mut served = BTreeMap::new();
        for entry in entries {
            let Some(declaration) = &entry.declaration else {
                continue;
            };
            if declaration.narrowing == Narrowing::None {
                return Err(SettingsError::NotNarrowed(entry.name.clone()));
            }
            crate::reads::check_entry(entry)?;
            served.insert(
                entry.name.clone(),
                EntryCredential {
                    narrowing: declaration.narrowing,
                    permissions: entry.permissions.clone(),
                },
            );
        }
        let job_log_hosts = settings
            .job_log_hosts
            .iter()
            .map(|host| {
                Api::new(host, settings.ca_file.as_deref())
                    .map_err(|error| SettingsError::JobLogHost(host.clone(), error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            organization: organization.clone(),
            api,
            job_log_hosts,
            custodian: CustodianClient::new(
                settings.custodian_socket.clone(),
                settings.custodian_deadline,
            ),
            entries: served,
        })
    }

    /// The sentence for a call naming an owner other than the configured organization: Otto's.
    pub fn other_organization(&self, owner: &str) -> String {
        format!(
            "owner {owner:?} is not this gateway's configured org {:?}",
            self.organization
        )
    }

    async fn call(&self, call: ToolCall) -> ToolOutcome {
        let tool = call.tool().name.clone();
        let Some(parsed) = tools::parse(tool.as_str(), call.arguments()) else {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!("the GitHub connector does not serve `{tool}`"),
            );
        };
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        // One organization, before anything is asked of anyone (docs/otto-baseline.md).
        if parsed.owner() != self.organization {
            return ToolOutcome::Refused(self.other_organization(parsed.owner()));
        }
        let Some(entry) = self.entries.get(&call.tool().connector) else {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "the GitHub connector does not serve connector entry `{}`",
                    call.tool().connector
                ),
            );
        };
        let team = match &call.call().caller.principal.get().kind {
            PrincipalKind::Workload { team, .. } => team.clone(),
            PrincipalKind::User { .. } => {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    "the GitHub connector serves a team's workloads only: a token is asked for \
                     the caller's team, and a person has none",
                );
            }
        };
        let repositories = match self.repositories(&call, entry, &parsed) {
            Ok(repositories) => repositories,
            Err(outcome) => return outcome,
        };
        let request = TokenRequest {
            team,
            tool: tool.clone(),
            repositories,
            permissions: entry.permissions.clone(),
            revision: call.policy_revision().clone(),
        };
        // The newer reads ask for their own permission sets, within the entry's.
        if let Call::Read(read) = &parsed {
            return crate::reads::run(self, &parsed, read, request).await;
        }
        let token = match self.token(&request).await {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        self.read(&parsed, token.expose()).await
    }

    /// A token from the key custodian for `request`, or the outcome for the call when there
    /// is none.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn token(&self, request: &TokenRequest) -> Result<Token, ToolOutcome> {
        match self.custodian.token(request).await {
            Ok(token) => Ok(token),
            Err(error) => {
                let kind = error.error_kind();
                let tool = &request.tool;
                tracing::warn!(%tool, %error, "the key custodian gave no GitHub token");
                Err(ToolOutcome::error(
                    kind,
                    custodian_sentence(&request.team, kind),
                ))
            }
        }
    }

    /// The API clients of the hosts a job log redirect may point to.
    pub(crate) fn job_log_hosts(&self) -> &[Api] {
        &self.job_log_hosts
    }

    /// The API client.
    pub(crate) fn api(&self) -> &Api {
        &self.api
    }

    /// The repositories a call's token is asked for, as its entry narrows it.
    #[allow(clippy::result_large_err)]
    fn repositories(
        &self,
        call: &ToolCall,
        entry: &EntryCredential,
        parsed: &Call,
    ) -> Result<Vec<String>, ToolOutcome> {
        match entry.narrowing {
            Narrowing::Call => Ok(vec![format!("{}/{}", parsed.owner(), parsed.repo())]),
            Narrowing::Limit => {
                let Some(limit) = call.caller_limit() else {
                    return Err(ToolOutcome::error(
                        ErrorKind::Other,
                        "the call's decision carried no limit to narrow its token to",
                    ));
                };
                let prefix = format!("{}/", self.organization);
                let repositories: BTreeSet<&str> = limit
                    .iter()
                    .filter(|resource| resource.system == SYSTEM && resource.kind == REPOSITORY)
                    .map(|resource| resource.identifier.as_str())
                    .filter(|identifier| identifier.starts_with(&prefix))
                    .collect();
                Ok(repositories.into_iter().map(str::to_owned).collect())
            }
            Narrowing::None => Err(ToolOutcome::error(
                ErrorKind::Other,
                "the GitHub connector narrows every token, and this entry says not to",
            )),
        }
    }

    async fn read(&self, call: &Call, token: &str) -> ToolOutcome {
        match call {
            Call::File {
                path, reference, ..
            } => {
                let target = tools::file_path(call, path, reference.as_deref());
                let answer = match self.get(&target, token, "file", call).await {
                    Ok(answer) => answer,
                    Err(outcome) => return outcome,
                };
                match tools::file_result(path, reference.as_deref(), &answer) {
                    Ok(result) => ToolOutcome::Ok(result),
                    Err(why) => ToolOutcome::error(ErrorKind::Other, why),
                }
            }
            Call::Pr { number, .. } => {
                let base = tools::repo_path(call);
                let pr = match self
                    .get(
                        &format!("{base}/pulls/{number}"),
                        token,
                        "pull request",
                        call,
                    )
                    .await
                {
                    Ok(pr) => pr,
                    Err(outcome) => return outcome,
                };
                let comments = match self
                    .get(
                        &format!("{base}/issues/{number}/comments{}", tools::comments_query()),
                        token,
                        "pull request's comments",
                        call,
                    )
                    .await
                {
                    Ok(comments) => comments,
                    Err(outcome) => return outcome,
                };
                let Some((kept, more)) = tools::comments(&comments) else {
                    return unreadable();
                };
                ToolOutcome::Ok(json!({
                    "pr": tools::pr_fields(&pr),
                    "comments": kept,
                    "commentsTruncated": more,
                    "provenance": tools::provenance(tools::GET_PR),
                }))
            }
            Call::Issue { number, .. } => {
                let base = tools::repo_path(call);
                let issue = match self
                    .get(&format!("{base}/issues/{number}"), token, "issue", call)
                    .await
                {
                    Ok(issue) => issue,
                    Err(outcome) => return outcome,
                };
                if issue.get("pull_request").is_some_and(|pr| !pr.is_null()) {
                    return ToolOutcome::Ok(json!({
                        "isPullRequest": true,
                        "number": number,
                        "note": format!(
                            "#{number} is a pull request, not an issue; read it with {}",
                            tools::GET_PR
                        ),
                        "provenance": tools::provenance(tools::GET_ISSUE),
                    }));
                }
                let comments = match self
                    .get(
                        &format!("{base}/issues/{number}/comments{}", tools::comments_query()),
                        token,
                        "issue's comments",
                        call,
                    )
                    .await
                {
                    Ok(comments) => comments,
                    Err(outcome) => return outcome,
                };
                let Some((kept, more)) = tools::comments(&comments) else {
                    return unreadable();
                };
                let mut result = json!({
                    "issue": tools::issue_fields(&issue),
                    "comments": kept,
                    "commentsTruncated": more,
                    "provenance": tools::provenance(tools::GET_ISSUE),
                });
                if more {
                    let count = issue
                        .get("comments")
                        .and_then(Value::as_u64)
                        .map_or_else(|| "more".to_owned(), |count| count.to_string());
                    result["commentsTruncationNote"] = Value::String(format!(
                        "showing the first {} of {count} comments, oldest first; the newest are \
                         not shown",
                        tools::MAX_COMMENTS
                    ));
                }
                ToolOutcome::Ok(result)
            }
            Call::Read(_) => ToolOutcome::error(
                ErrorKind::Other,
                "the newer GitHub reads ask for their own tokens",
            ),
        }
    }

    /// GitHub's JSON answer to `GET target`, or the outcome for the call when there is none.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn get(
        &self,
        target: &str,
        token: &str,
        what: &str,
        call: &Call,
    ) -> Result<Value, ToolOutcome> {
        match self.api.get(target, token).await {
            Answered::Json(value) => Ok(value),
            other => Err(vendor_error(other, what, call)),
        }
    }

    /// GitHub's JSON answer to `GET target`, `None` for a 404, or the outcome for the call when
    /// there is neither: for what a repository may or may not have.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn get_if_found(
        &self,
        target: &str,
        token: &str,
        what: &str,
        call: &Call,
    ) -> Result<Option<Value>, ToolOutcome> {
        match self.api.get(target, token).await {
            Answered::Json(value) => Ok(Some(value)),
            Answered::Status {
                status,
                rate_limited: false,
            } if status == StatusCode::NOT_FOUND => Ok(None),
            other => Err(vendor_error(other, what, call)),
        }
    }
}

/// The outcome for a call when GitHub gave no JSON answer to a request for `what`. A 404, which
/// GitHub also answers for a repository the token cannot see, and the rate limit are `other`;
/// a 403 is `vendor_refusal`. No sentence quotes GitHub's answer.
pub(crate) fn vendor_error(answered: Answered, what: &str, call: &Call) -> ToolOutcome {
    match answered {
        Answered::Json(_) | Answered::Unreadable => unreadable(),
        Answered::Unreachable => ToolOutcome::error(
            ErrorKind::Other,
            "GitHub could not be reached, or its answer could not be read in full",
        ),
        Answered::Status {
            status,
            rate_limited: true,
        } => ToolOutcome::error(
            ErrorKind::Other,
            format!(
                "GitHub's rate limit for this App's installation is used up (HTTP {}); try again \
                 later",
                status.as_u16()
            ),
        ),
        Answered::Status { status, .. } if status == StatusCode::NOT_FOUND => ToolOutcome::error(
            ErrorKind::Other,
            format!(
                "GitHub found no {what} there in {}/{}, or the token cannot see the repository \
                 (HTTP 404)",
                call.owner(),
                call.repo()
            ),
        ),
        Answered::Status { status, .. } if status == StatusCode::FORBIDDEN => ToolOutcome::error(
            ErrorKind::VendorRefusal,
            format!(
                "GitHub refused to show the {what} in {}/{} to this App (HTTP 403)",
                call.owner(),
                call.repo()
            ),
        ),
        Answered::Status { status, .. } => ToolOutcome::error(
            ErrorKind::Other,
            format!("GitHub answered HTTP {}", status.as_u16()),
        ),
    }
}

pub(crate) fn unreadable() -> ToolOutcome {
    ToolOutcome::error(ErrorKind::Other, "GitHub's answer could not be read")
}

/// The caller's sentence when no token came back. The custodian's own sentence goes to the
/// log, not the caller.
fn custodian_sentence(team: &TeamId, kind: ErrorKind) -> String {
    match kind {
        ErrorKind::CustodianRefusal => format!(
            "the key custodian refused a GitHub token for team {team:?} for this call, so nothing \
             was sent to GitHub"
        ),
        ErrorKind::VendorRefusal => {
            "GitHub refused to issue a token for this call, so nothing was read".to_owned()
        }
        _ => "no GitHub token could be had for this call, so nothing was read".to_owned(),
    }
}

impl gateway_core::Connector for GitHubConnector {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(self.call(call))
    }
}
