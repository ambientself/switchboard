//! The connector: one call, from its arguments to its result.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use gateway_core::{
    BoxFuture, ConnectorName, ErrorKind, Narrowing, PrincipalKind, ReceiptAttribution, Resource,
    TeamId, ToolCall, ToolOutcome,
};
use gateway_registry::{Access, BuiltInEntry};
use hyper::StatusCode;
use key_custodian::{CustodianClient, Token, TokenRequest};
use serde_json::{Value, json};
use thiserror::Error;

use crate::api::{Answered, Api, ApiError};
use crate::report;
use crate::search;
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
    /// The App's own login, such as `my-app[bot]`, which GitHub names as the author of every
    /// pull request the App opens. `github__amend_change` needs it, and refuses a pull request
    /// opened by anyone else; with it, a lookup by marker finds only pull requests the App
    /// opened. `None` when the deployment gives none.
    pub bot_login: Option<String>,
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
    /// narrowed, to the caller's limit or to the call's repository, except a reach report's
    /// (see [`crate::report`]).
    #[error(
        "connector `{0}` says its credential is narrowed \"none\"; the GitHub connector narrows \
         every token but a reach report's, so declare \"limit\" or \"call\""
    )]
    NotNarrowed(ConnectorName),
    /// The bot login is not a GitHub login, with `[bot]` after it or not.
    #[error(
        "`{0}` is not a GitHub login: 1 to 39 letters, digits and hyphens, with \"[bot]\" after \
         it or not"
    )]
    BotLogin(String),
    /// A job log host was refused.
    #[error("the job log host `{0}` was refused: {1}")]
    JobLogHost(String, ApiError),
    /// An entry serves a write tool and is not narrowed `call`: a write's token is for the one
    /// repository its call names, never the caller's whole limit.
    #[error(
        "connector `{entry}` serves `{tool}`, which writes, and is not narrowed \"call\"; a \
         write's token is narrowed to the one repository its call names"
    )]
    WriteNotNarrowedToTheCall {
        /// The entry.
        entry: ConnectorName,
        /// The tool.
        tool: String,
    },
    /// An entry serves a write tool whose permission set it does not hold, at the level the
    /// tool asks for, so the key custodian would refuse every token the tool asks for.
    #[error(
        "connector `{entry}` serves `{tool}`, which asks for `{permission}`, and the entry does \
         not state it"
    )]
    WritePermissionNotStated {
        /// The entry.
        entry: ConnectorName,
        /// The tool.
        tool: String,
        /// The permission and level the entry does not state, such as `pull_requests: write`.
        permission: String,
    },
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
    /// Whether the entry is a reach report's, which serves only the report's tool.
    reports_reach: bool,
}

/// The GitHub connector. See the [crate documentation](crate).
pub struct GitHubConnector {
    organization: String,
    api: Api,
    custodian: CustodianClient,
    entries: BTreeMap<ConnectorName, EntryCredential>,
    job_log_hosts: Vec<Api>,
    bot_login: Option<String>,
    /// The gateway's receipts, once its store has connected: see
    /// [`read_receipts_from`](GitHubConnector::read_receipts_from).
    receipts: OnceLock<Arc<dyn ReceiptAttribution>>,
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
        if let Some(login) = &settings.bot_login
            && !bot_login(login)
        {
            return Err(SettingsError::BotLogin(login.clone()));
        }
        let api = Api::new(&settings.api_url, settings.ca_file.as_deref())?;
        let mut served = BTreeMap::new();
        for entry in entries {
            let Some(declaration) = &entry.declaration else {
                continue;
            };
            if declaration.narrowing == Narrowing::None && !entry.reports_reach {
                return Err(SettingsError::NotNarrowed(entry.name.clone()));
            }
            crate::reads::check_entry(entry)?;
            crate::writes::check_entry(entry, declaration.narrowing)?;
            served.insert(
                entry.name.clone(),
                EntryCredential {
                    narrowing: declaration.narrowing,
                    permissions: entry.permissions.clone(),
                    reports_reach: entry.reports_reach,
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
            bot_login: settings.bot_login.clone(),
            receipts: OnceLock::new(),
        })
    }

    /// Gives the connector the gateway's receipts to read, once the gateway's receipt store has
    /// connected, which is after the connector is built. The proposal tools read them to tell a
    /// pull request the gateway opened for the caller ([`crate::proposals`]), and send nothing
    /// until they are given. Given once; a second is passed over.
    pub fn read_receipts_from(&self, receipts: Arc<dyn ReceiptAttribution>) {
        let _ = self.receipts.set(receipts);
    }

    /// The gateway's receipts, once given.
    pub(crate) fn receipts(&self) -> Option<Arc<dyn ReceiptAttribution>> {
        self.receipts.get().cloned()
    }

    /// The App's own login, if the deployment gives it.
    pub(crate) fn bot_login(&self) -> Option<&str> {
        self.bot_login.as_deref()
    }

    /// The sentence for a call naming an owner other than the configured organization: Otto's.
    pub fn other_organization(&self, owner: &str) -> String {
        format!(
            "owner {owner:?} is not this gateway's configured org {:?}",
            self.organization
        )
    }

    /// The one organization every call must name as its owner.
    pub(crate) fn organization(&self) -> &str {
        &self.organization
    }

    /// How `entry`'s tokens are narrowed, if the connector was built with it.
    pub(crate) fn narrowing(&self, entry: &ConnectorName) -> Option<Narrowing> {
        self.entries.get(entry).map(|entry| entry.narrowing)
    }

    async fn call(&self, call: ToolCall) -> ToolOutcome {
        let tool = call.tool().name.clone();
        if tool.as_str() == report::LIST_INSTALLATION_REPOSITORIES {
            return self.report(&call).await;
        }
        if tool.as_str() == crate::create_pr::CREATE_PR {
            return self.create_pr(&call).await;
        }
        if tool.as_str() == crate::proposals::PROPOSE_CHANGE {
            return self.propose_change(&call).await;
        }
        if tool.as_str() == crate::proposals::AMEND_CHANGE {
            return self.amend_change(&call).await;
        }
        if tool.as_str() == search::SEARCH {
            return self.search(&call).await;
        }
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
            return not_served(&call);
        };
        let repositories = match self.repositories(&call, entry, &parsed) {
            Ok(repositories) => repositories,
            Err(outcome) => return outcome,
        };
        let request = match self.request(&call, entry, repositories) {
            Ok(request) => request,
            Err(outcome) => return outcome,
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

    /// The token request for `call`, for the caller's team, narrowed to `repositories`, with
    /// `entry`'s permissions and the call's revision; or the outcome for the call when there is
    /// none.
    #[allow(clippy::result_large_err)]
    fn request(
        &self,
        call: &ToolCall,
        entry: &EntryCredential,
        repositories: Vec<String>,
    ) -> Result<TokenRequest, ToolOutcome> {
        let team = match &call.call().caller.principal.get().kind {
            PrincipalKind::Workload { team, .. } => team.clone(),
            PrincipalKind::User { .. } => {
                return Err(ToolOutcome::error(
                    ErrorKind::Other,
                    "the GitHub connector serves a team's workloads only: a token is asked for \
                     the caller's team, and a person has none",
                ));
            }
        };
        Ok(TokenRequest {
            team,
            tool: call.tool().name.clone(),
            repositories,
            permissions: entry.permissions.clone(),
            revision: call.policy_revision().clone(),
        })
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

    /// The reach report's call (see [`crate::report`]): served only on an entry declared a
    /// reach report, with no arguments, and a token asked for with no repositories and
    /// `metadata: read` alone, which the key custodian gives a reach report's tool and no other.
    async fn report(&self, call: &ToolCall) -> ToolOutcome {
        let tool = call.tool().name.clone();
        if call
            .arguments()
            .as_object()
            .is_none_or(|arguments| !arguments.is_empty())
        {
            return ToolOutcome::error(
                ErrorKind::InvalidArguments,
                format!("`{tool}` takes no arguments"),
            );
        }
        let reporting = self
            .entries
            .get(&call.tool().connector)
            .is_some_and(|entry| entry.reports_reach);
        if !reporting {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "the GitHub connector serves `{tool}` only on an entry the registry declares \
                     a reach report, and `{}` is not one",
                    call.tool().connector
                ),
            );
        }
        let PrincipalKind::Workload { team, .. } = &call.call().caller.principal.get().kind else {
            return ToolOutcome::error(
                ErrorKind::Other,
                "the GitHub connector serves a team's workloads only: a token is asked for the \
                 caller's team, and a person has none",
            );
        };
        // The revision the call was decided under, as every token request carries it.
        let revision = call.policy_revision().clone();
        let request = TokenRequest {
            team: team.clone(),
            tool: tool.clone(),
            repositories: Vec::new(),
            permissions: BTreeMap::from([(report::REPORT_PERMISSION.to_owned(), Access::Read)]),
            revision,
        };
        let token = match self.custodian.token(&request).await {
            Ok(token) => token,
            Err(error) => {
                let kind = error.error_kind();
                tracing::warn!(%tool, %error, "the key custodian gave no GitHub token");
                return ToolOutcome::error(kind, custodian_sentence(&request.team, kind));
            }
        };
        report::read(&self.api, token.expose()).await
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
                    return Err(no_limit());
                };
                Ok(self.limit_repositories(limit))
            }
            Narrowing::None => Err(ToolOutcome::error(
                ErrorKind::Other,
                "the GitHub connector narrows every token, and this entry says not to",
            )),
        }
    }

    /// The repositories of the configured organization in the caller's `limit`, each once, for
    /// a token narrowed to the limit.
    fn limit_repositories(&self, limit: &[Resource]) -> Vec<String> {
        let prefix = format!("{}/", self.organization);
        let repositories: BTreeSet<&str> = limit
            .iter()
            .filter(|resource| resource.system == SYSTEM && resource.kind == REPOSITORY)
            .map(|resource| resource.identifier.as_str())
            .filter(|identifier| identifier.starts_with(&prefix))
            .collect();
        repositories.into_iter().map(str::to_owned).collect()
    }

    /// `github__search`, which checks its own scope: see [`search`].
    async fn search(&self, call: &ToolCall) -> ToolOutcome {
        let query = match search::parse(call.arguments()) {
            Ok(query) => query,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        // One organization, before anything is asked of anyone (docs/otto-baseline.md).
        if let Some(other) = search::other_account(&query, &self.organization) {
            return ToolOutcome::Refused(self.other_organization(other));
        }
        let Some(entry) = self.entries.get(&call.tool().connector) else {
            return not_served(call);
        };
        // A search is held to the caller's limit by filtering its results, so it runs only
        // under an entry narrowed to the limit, whose calls carry it.
        let Some(limit) = call.caller_limit() else {
            return no_limit();
        };
        let repositories = self.limit_repositories(limit);
        if repositories.is_empty() {
            return ToolOutcome::Refused(format!(
                "the caller's limit holds no repository of this gateway's configured org {:?}, \
                 so there is nothing it may search",
                self.organization
            ));
        }
        let request = match self.request(call, entry, repositories) {
            Ok(request) => request,
            Err(outcome) => return outcome,
        };
        let token = match self.token(&request).await {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        let scoped = search::scoped(&query, &self.organization);
        let answer = match self.api.get(&search::target(&scoped), token.expose()).await {
            Answered::Json(answer) => answer,
            Answered::Unreadable => return unreadable(),
            Answered::Unreachable => return unreachable(),
            Answered::Status {
                status,
                rate_limited: true,
            } => return rate_limited(status),
            Answered::Status { status, .. } if status == StatusCode::UNPROCESSABLE_ENTITY => {
                return ToolOutcome::error(
                    ErrorKind::InvalidArguments,
                    "GitHub could not run the query as written (HTTP 422); check its search \
                     syntax",
                );
            }
            Answered::Status { status, .. } if status == StatusCode::FORBIDDEN => {
                return ToolOutcome::error(
                    ErrorKind::VendorRefusal,
                    "GitHub refused the search to this App (HTTP 403)",
                );
            }
            Answered::Status { status, .. } => {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    format!("GitHub answered HTTP {}", status.as_u16()),
                );
            }
        };
        let filter = search::limit_filter(limit, &self.organization);
        match search::result(&answer, &scoped, &filter) {
            Some((result, reached)) => ToolOutcome::Reached(result, reached),
            None => unreadable(),
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
        Answered::Unreachable => unreachable(),
        Answered::Status {
            status,
            rate_limited: true,
        } => rate_limited(status),
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

fn unreachable() -> ToolOutcome {
    ToolOutcome::error(
        ErrorKind::Other,
        "GitHub could not be reached, or its answer could not be read in full",
    )
}

fn rate_limited(status: StatusCode) -> ToolOutcome {
    ToolOutcome::error(
        ErrorKind::Other,
        format!(
            "GitHub's rate limit for this App's installation is used up (HTTP {}); try again \
             later",
            status.as_u16()
        ),
    )
}

fn no_limit() -> ToolOutcome {
    ToolOutcome::error(
        ErrorKind::Other,
        "the call's decision carried no limit to narrow its token to",
    )
}

fn not_served(call: &ToolCall) -> ToolOutcome {
    ToolOutcome::error(
        ErrorKind::Other,
        format!(
            "the GitHub connector does not serve connector entry `{}`",
            call.tool().connector
        ),
    )
}

/// The caller's sentence when no token came back. The custodian's own sentence goes to the
/// log, not the caller.
/// Whether `login` is a GitHub login, 1 to 39 ASCII letters, digits and hyphens, with `[bot]`
/// after it or not, as GitHub names an App's own account.
fn bot_login(login: &str) -> bool {
    let account = login.strip_suffix("[bot]").unwrap_or(login);
    (1..=39).contains(&account.len())
        && account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn custodian_sentence(team: &TeamId, kind: ErrorKind) -> String {
    match kind {
        ErrorKind::CustodianRefusal => format!(
            "the key custodian refused a GitHub token for team {team:?} for this call, so nothing \
             was sent to GitHub"
        ),
        ErrorKind::VendorRefusal => {
            "GitHub refused to issue a token for this call, so nothing was sent to GitHub"
                .to_owned()
        }
        _ => "no GitHub token could be had for this call, so nothing was sent to GitHub".to_owned(),
    }
}

impl gateway_core::Connector for GitHubConnector {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(self.call(call))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use gateway_core::{Classification, CredentialMode};
    use gateway_registry::EntryDeclaration;

    use super::*;

    fn settings(organization: &str) -> GitHubSettings {
        GitHubSettings {
            organization: organization.into(),
            api_url: "http://127.0.0.1:9".into(),
            ca_file: None,
            custodian_socket: PathBuf::from("/nonexistent/custodian.sock"),
            custodian_deadline: DEFAULT_CUSTODIAN_DEADLINE,
            job_log_hosts: Vec::new(),
            bot_login: None,
        }
    }

    fn entry(narrowing: Narrowing, reports_reach: bool) -> BuiltInEntry {
        BuiltInEntry {
            name: "github-read".into(),
            system: SYSTEM.into(),
            permissions: BTreeMap::from([("contents".to_owned(), Access::Read)]),
            tools: BTreeSet::new(),
            declaration: Some(EntryDeclaration {
                credential: CredentialMode::TeamServiceIdentity,
                principal: "app".into(),
                narrowing,
                permits: Classification::Read,
                reach: BTreeSet::new(),
            }),
            reports_reach,
            reach_report: None,
        }
    }

    /// GitHub tokens are always narrowed, to the caller's limit or the call's repository: an
    /// entry narrowed `none` is refused when the connector is built, except a reach report's,
    /// whose one token is the installation-wide exception.
    #[test]
    fn an_entry_narrowed_none_is_refused_unless_it_reports_reach() {
        let refused =
            GitHubConnector::new(&settings("example-org"), [&entry(Narrowing::None, false)])
                .unwrap_err();
        assert_eq!(refused, SettingsError::NotNarrowed("github-read".into()));
        for (narrowing, reports_reach) in [
            (Narrowing::None, true),
            (Narrowing::Limit, false),
            (Narrowing::Call, false),
        ] {
            GitHubConnector::new(&settings("example-org"), [&entry(narrowing, reports_reach)])
                .unwrap();
        }
        // An entry that declares no credential serves no approved tool, and is not checked.
        let mut undeclared = entry(Narrowing::None, false);
        undeclared.declaration = None;
        GitHubConnector::new(&settings("example-org"), [&undeclared]).unwrap();
    }

    /// An entry serving `github__create_pr` must be narrowed `call` and state `contents` and
    /// `pull_requests: write`, or the connector refuses to be built, naming the entry.
    #[test]
    fn an_entry_serving_a_write_is_narrowed_to_the_call_and_states_its_permissions() {
        let writing = |narrowing: Narrowing, permissions: &[(&str, Access)]| {
            let mut entry = entry(narrowing, false);
            entry.name = "github-write".into();
            entry.tools = BTreeSet::from([crate::create_pr::CREATE_PR.parse().unwrap()]);
            entry.permissions = permissions
                .iter()
                .map(|(permission, access)| ((*permission).to_owned(), *access))
                .collect();
            entry
        };
        let stated = [
            ("contents", Access::Write),
            ("pull_requests", Access::Write),
        ];
        GitHubConnector::new(
            &settings("example-org"),
            [&writing(Narrowing::Call, &stated)],
        )
        .unwrap();
        let narrowed = GitHubConnector::new(
            &settings("example-org"),
            [&writing(Narrowing::Limit, &stated)],
        )
        .unwrap_err();
        assert_eq!(
            narrowed,
            SettingsError::WriteNotNarrowedToTheCall {
                entry: "github-write".into(),
                tool: crate::create_pr::CREATE_PR.into(),
            }
        );
        assert!(
            narrowed.to_string().contains("`github-write`"),
            "{narrowed}"
        );
        for (permissions, missing) in [
            (
                vec![("contents", Access::Write), ("pull_requests", Access::Read)],
                "pull_requests: write",
            ),
            (vec![("pull_requests", Access::Write)], "contents: read"),
        ] {
            let refused = GitHubConnector::new(
                &settings("example-org"),
                [&writing(Narrowing::Call, &permissions)],
            )
            .unwrap_err();
            assert_eq!(
                refused,
                SettingsError::WritePermissionNotStated {
                    entry: "github-write".into(),
                    tool: crate::create_pr::CREATE_PR.into(),
                    permission: missing.into(),
                }
            );
        }
    }

    /// An entry serving `github__propose_change` or `github__amend_change` must be narrowed
    /// `call` and state `contents: write` and `pull_requests: write`: its git writes need the
    /// one, and its pull request's the other.
    #[test]
    fn an_entry_serving_a_proposal_states_both_writes_and_is_narrowed_to_the_call() {
        for tool in [
            crate::proposals::PROPOSE_CHANGE,
            crate::proposals::AMEND_CHANGE,
        ] {
            let writing = |narrowing: Narrowing, permissions: &[(&str, Access)]| {
                let mut entry = entry(narrowing, false);
                entry.name = "github-write".into();
                entry.tools = BTreeSet::from([tool.parse().unwrap()]);
                entry.permissions = permissions
                    .iter()
                    .map(|(permission, access)| ((*permission).to_owned(), *access))
                    .collect();
                entry
            };
            let stated = [
                ("contents", Access::Write),
                ("pull_requests", Access::Write),
            ];
            GitHubConnector::new(
                &settings("example-org"),
                [&writing(Narrowing::Call, &stated)],
            )
            .unwrap();
            assert_eq!(
                GitHubConnector::new(
                    &settings("example-org"),
                    [&writing(Narrowing::Limit, &stated)],
                )
                .unwrap_err(),
                SettingsError::WriteNotNarrowedToTheCall {
                    entry: "github-write".into(),
                    tool: tool.into(),
                }
            );
            for (permissions, missing) in [
                (
                    vec![("contents", Access::Read), ("pull_requests", Access::Write)],
                    "contents: write",
                ),
                (
                    vec![("contents", Access::Write), ("pull_requests", Access::Read)],
                    "pull_requests: write",
                ),
            ] {
                assert_eq!(
                    GitHubConnector::new(
                        &settings("example-org"),
                        [&writing(Narrowing::Call, &permissions)],
                    )
                    .unwrap_err(),
                    SettingsError::WritePermissionNotStated {
                        entry: "github-write".into(),
                        tool: tool.into(),
                        permission: missing.into(),
                    }
                );
            }
        }
    }

    /// The bot login is a GitHub login, with `[bot]` after it or not.
    #[test]
    fn the_bot_login_is_a_github_login() {
        let with = |login: &str| GitHubSettings {
            bot_login: Some(login.to_owned()),
            ..settings("example-org")
        };
        let long = "a".repeat(40);
        for refused in [
            "",
            "[bot]",
            "my app[bot]",
            "my_app",
            "app[bot] ",
            "a[bot][bot]",
            long.as_str(),
        ] {
            assert_eq!(
                GitHubConnector::new(&with(refused), []).unwrap_err(),
                SettingsError::BotLogin(refused.to_owned())
            );
        }
        let longest = format!("{}[bot]", "a".repeat(39));
        for accepted in ["switchboard-app[bot]", "octocat", longest.as_str()] {
            GitHubConnector::new(&with(accepted), []).unwrap();
        }
    }

    /// The organization is a GitHub account name: 1 to 39 letters, digits and hyphens.
    #[test]
    fn the_organization_is_an_account_name() {
        let long = "a".repeat(40);
        for refused in ["", "example/org", "example_org", long.as_str()] {
            assert_eq!(
                GitHubConnector::new(&settings(refused), []).unwrap_err(),
                SettingsError::Organization(refused.to_owned())
            );
        }
        let longest = "a".repeat(39);
        for accepted in ["example-org", "E", longest.as_str()] {
            GitHubConnector::new(&settings(accepted), []).unwrap();
        }
    }
}
