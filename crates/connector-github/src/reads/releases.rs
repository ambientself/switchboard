//! `github__list_releases`: a repository's releases and tags, two lists of at most thirty, each
//! said to be cut, with no release notes. As Otto's gateway does, the releases are read on a
//! token for `contents` and the tags on one for `metadata`.

use gateway_core::ToolOutcome;
use key_custodian::TokenRequest;
use serde_json::{Value, json};

use super::{RELEASES_PERMISSIONS, TAGS_PERMISSIONS, at, string_or_null, token};
use crate::connector::{GitHubConnector, unreadable};
use crate::tools::{self, Call};

/// How many releases a result holds.
pub const MAX_RELEASES: usize = 30;

/// How many tags a result holds.
pub const MAX_TAGS: usize = 30;

fn release_fields(release: &Value) -> Value {
    json!({
        "tagName": at(release, "/tag_name"),
        "name": at(release, "/name"),
        "url": at(release, "/html_url"),
        "publishedAt": at(release, "/published_at"),
        "draft": at(release, "/draft"),
        "prerelease": at(release, "/prerelease"),
    })
}

fn tag_fields(tag: &Value) -> Value {
    json!({
        "name": at(tag, "/name"),
        "commitSha": string_or_null(tag, "/commit/sha"),
    })
}

/// The releases and tags, each on its own token from `request`.
#[allow(clippy::result_large_err)]
pub(super) async fn read(
    connector: &GitHubConnector,
    call: &Call,
    request: &TokenRequest,
) -> Result<Value, ToolOutcome> {
    let base = tools::repo_path(call);
    let releases_token = token(connector, request, RELEASES_PERMISSIONS).await?;
    let releases = connector
        .get(
            &format!("{base}/releases?per_page={}", MAX_RELEASES + 1),
            releases_token.expose(),
            "releases",
            call,
        )
        .await?;
    drop(releases_token);
    let releases = releases.as_array().ok_or_else(unreadable)?;
    let tags_token = token(connector, request, TAGS_PERMISSIONS).await?;
    let tags = connector
        .get(
            &format!("{base}/tags?per_page={}", MAX_TAGS + 1),
            tags_token.expose(),
            "tags",
            call,
        )
        .await?;
    let tags = tags.as_array().ok_or_else(unreadable)?;
    let kept_releases: Vec<Value> = releases
        .iter()
        .take(MAX_RELEASES)
        .map(release_fields)
        .collect();
    let kept_tags: Vec<Value> = tags.iter().take(MAX_TAGS).map(tag_fields).collect();
    Ok(json!({
        "releasesTruncated": releases.len() > kept_releases.len(),
        "releases": kept_releases,
        "tagsTruncated": tags.len() > kept_tags.len(),
        "tags": kept_tags,
        "provenance": tools::provenance(super::LIST_RELEASES),
    }))
}
