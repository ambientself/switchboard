//! The GitHub connector's lookup by marker (decision 0009, "Reconciliation"; #12): how
//! reconciliation settles the `unknown` receipt of a GitHub write by finding what it made.
//!
//! A lookup is not a tool call: it writes no audit row, and sends nothing but reads. It asks
//! the key custodian for a token for the team the receipt recorded, the receipt's tool, the
//! receipt's target repository alone and `pull_requests: read` alone ([`LOOKUP_PERMISSION`]),
//! under the policy revision in force. With it, it reads the repository's pull requests, of
//! every state, the most recently updated first, [`PULLS_PER_PAGE`] a page, at most
//! [`MAX_LOOKUP_PAGES`] pages:
//! `GET /repos/{owner}/{repo}/pulls?state=all&sort=updated&direction=desc&per_page=100&page=N`.
//!
//! - The first pull request whose body has a line exactly equal to the receipt's marker
//!   ([`crate::writes::marker`]) is the effect: `found`, with the reference `pull/<number>`. A
//!   line, not a substring, and never a branch name or anything else the caller chose: no
//!   caller can write the marker, since a call whose text holds its prefix is refused. The
//!   marker is the line of a pull request `github__create_pr` or `github__propose_change`
//!   opened, or the line `github__amend_change` added to one.
//! - With the App's own login configured (`[github] bot_login`), only a pull request GitHub
//!   says that login opened is looked at: a person who copies a draft's description, marker
//!   and all, into a pull request of their own makes nothing a lookup finds.
//! - Nothing found is `not_found`, never authoritative: GitHub does not document the list as
//!   complete and current, and a pull request updated by others since may sit past the pages
//!   read. So a lookup never settles a receipt `not_performed`; one never found goes to a
//!   person once its attempts are used up.
//! - A receipt with no team, a target that is not one repository of the configured
//!   organization, the custodian's refusal, and any error or answer that cannot be read are
//!   `failed`.
//!
//! A receipt of `github__pr_comment` is looked for among the repository's comments instead,
//! with the same token, by the same rule: see [`crate::pr_comment`].

use std::collections::BTreeMap;

use gateway_core::{BoxFuture, Lookup, LookupAnswer, LookupRequest, VendorReference};
use gateway_registry::Access;
use key_custodian::TokenRequest;
use serde_json::Value;

use crate::api::Answered;
use crate::connector::GitHubConnector;
use crate::writes;
use crate::{REPOSITORY, SYSTEM};

/// The one permission a lookup's token is asked for, at `read`.
pub const LOOKUP_PERMISSION: &str = "pull_requests";

/// How many pull requests a lookup reads a page.
pub const PULLS_PER_PAGE: usize = 100;

/// The most pages a lookup reads.
pub const MAX_LOOKUP_PAGES: usize = 3;

impl GitHubConnector {
    async fn look_up(&self, request: LookupRequest<'_>) -> LookupAnswer {
        let Some(team) = request.team else {
            tracing::warn!(
                receipt = request.marker.as_str(),
                "a GitHub lookup has no team to ask for a token for"
            );
            return LookupAnswer::Failed;
        };
        let target = request.target;
        let repository = target.identifier.as_str();
        let in_organization = target.system == SYSTEM
            && target.kind == REPOSITORY
            && repository.split_once('/').is_some_and(|(owner, repo)| {
                owner == self.organization()
                    && !repo.is_empty()
                    && repo.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                    && repo != "."
                    && repo != ".."
            });
        if !in_organization {
            return LookupAnswer::Failed;
        }
        let token = TokenRequest {
            team: team.clone(),
            tool: request.tool.clone(),
            repositories: vec![repository.to_owned()],
            permissions: BTreeMap::from([(LOOKUP_PERMISSION.to_owned(), Access::Read)]),
            revision: request.revision.clone(),
        };
        let Ok(token) = self.token(&token).await else {
            return LookupAnswer::Failed;
        };
        if request.tool.as_str() == crate::pr_comment::PR_COMMENT {
            return self
                .find_comment(request.marker, repository, token.expose())
                .await;
        }
        let marker = writes::marker(request.marker);
        for page in 1..=MAX_LOOKUP_PAGES {
            let path = format!(
                "/repos/{repository}/pulls?state=all&sort=updated&direction=desc&per_page=\
                 {PULLS_PER_PAGE}&page={page}"
            );
            let Answered::Json(Value::Array(pulls)) = self.api().get(&path, token.expose()).await
            else {
                return LookupAnswer::Failed;
            };
            if let Some(found) = pulls
                .iter()
                .find(|pull| opened_by(pull, self.bot_login()) && marked(pull, &marker))
            {
                return match found.get("number").and_then(Value::as_u64) {
                    Some(number) => LookupAnswer::Found {
                        reference: VendorReference::new(format!("pull/{number}")),
                    },
                    None => LookupAnswer::Failed,
                };
            }
            if pulls.len() < PULLS_PER_PAGE {
                break;
            }
        }
        LookupAnswer::NotFound {
            authoritative: false,
        }
    }
}

/// Whether `pull` was opened by `bot_login`, as GitHub names its author; any pull request when
/// no bot login is configured.
fn opened_by(pull: &Value, bot_login: Option<&str>) -> bool {
    bot_login.is_none_or(|login| pull.pointer("/user/login").and_then(Value::as_str) == Some(login))
}

/// Whether `pull`'s body, or a comment's, has a line exactly equal to `marker`.
pub(crate) fn marked(pull: &Value, marker: &str) -> bool {
    pull.get("body")
        .and_then(Value::as_str)
        .is_some_and(|body| body.lines().any(|line| line == marker))
}

impl Lookup for GitHubConnector {
    fn look<'a>(&'a self, request: LookupRequest<'a>) -> BoxFuture<'a, LookupAnswer> {
        Box::pin(self.look_up(request))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn only_a_line_exactly_equal_to_the_marker_is_found() {
        let marker = "<!-- switchboard-receipt: r1 -->";
        for body in [
            marker.to_owned(),
            format!("Why.\n\n{marker}"),
            format!("Why.\r\n\r\n{marker}\r\n"),
            format!("{marker}\nmore"),
        ] {
            assert!(marked(&json!({ "body": body }), marker), "{body:?}");
        }
        for body in [
            format!("see {marker}"),
            format!("{marker} "),
            "<!-- switchboard-receipt: r10 -->".to_owned(),
            "<!-- switchboard-receipt: r -->".to_owned(),
            String::new(),
        ] {
            assert!(!marked(&json!({ "body": body }), marker), "{body:?}");
        }
        assert!(!marked(&json!({ "body": null }), marker));
        assert!(!marked(&json!({}), marker));
    }

    #[test]
    fn with_a_bot_login_only_its_pull_requests_are_looked_at() {
        let app = json!({"user": {"login": "switchboard-app[bot]"}});
        let person = json!({"user": {"login": "switchboard-app"}});
        assert!(opened_by(&app, Some("switchboard-app[bot]")));
        assert!(!opened_by(&person, Some("switchboard-app[bot]")));
        assert!(!opened_by(&json!({}), Some("switchboard-app[bot]")));
        assert!(opened_by(&person, None));
        assert!(opened_by(&json!({}), None));
    }
}
