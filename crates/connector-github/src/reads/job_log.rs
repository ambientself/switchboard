//! `github__get_job_log`: a GitHub Actions job's log.
//!
//! GitHub answers a log request with a redirect to a signed URL on its blob storage. The
//! connector follows it only to a host the deployment pins (`[github] job_log_hosts`): the
//! redirect's scheme, host and port must be one of theirs, and the log is then asked of that
//! host's own client, at the redirect's path and query, so no request can reach any other.
//! A redirect anywhere else is `refused` before any request is made to it, with a sentence
//! naming its scheme, host and port and never its path or query, which carry the signature. A
//! log served without a redirect is an `error` whose body is not read, and so is no log.
//!
//! The log host is sent no token and no GitHub header. At most [`MAX_LOG_READ_BYTES`] of the
//! log are read, and the last [`MAX_LOG_BYTES`] kept: a failing job's errors are near its end.
//! The result says when it was cut.

use gateway_core::{ErrorKind, ToolOutcome};
use hyper::{StatusCode, Uri};
use serde_json::{Value, json};

use crate::api::{Answered, Api, Located, Tail};
use crate::connector::{GitHubConnector, vendor_error};
use crate::tools::{self, Call};

/// The most of a log a result holds, in bytes: its end.
pub const MAX_LOG_BYTES: usize = 64 * 1024;

/// The most of a log that is read, in bytes.
pub const MAX_LOG_READ_BYTES: usize = 32 * 1024 * 1024;

/// A URL's scheme, host and port, the port filled in from the scheme when not given.
fn origin(uri: &Uri) -> Option<(String, String, u16)> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;
    // A user name or password in the authority is never a log host's.
    if authority.as_str().contains('@') {
        return None;
    }
    let port = match (uri.port_u16(), scheme.as_str()) {
        (Some(port), _) => port,
        (None, "https") => 443,
        (None, "http") => 80,
        _ => return None,
    };
    Some((scheme, authority.host().to_ascii_lowercase(), port))
}

/// The pinned host `location` points to, and the path and query to ask it for; `None` when it
/// points to no pinned host.
fn pinned<'a>(hosts: &'a [Api], location: &Uri) -> Option<(&'a Api, String)> {
    let wanted = origin(location)?;
    let host = hosts.iter().find(|host| {
        host.base()
            .parse::<Uri>()
            .ok()
            .and_then(|base| origin(&base))
            .is_some_and(|base| base == wanted)
    })?;
    let path = location
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |path| path.as_str().to_owned());
    Some((host, path))
}

/// The sentence for a redirect that is not followed: its scheme, host and port only.
fn refusal(job: u64, location: &Uri) -> String {
    let named = match (location.scheme_str(), location.authority()) {
        (Some(scheme), Some(authority)) => {
            let host = authority.as_str().rsplit('@').next().unwrap_or_default();
            format!("{scheme}://{host}")
        }
        _ => "a target that is not an absolute URL".to_owned(),
    };
    format!(
        "GitHub's redirect for job {job}'s log points to {named}, which is not a job log host \
         this gateway pins, so it will not be followed"
    )
}

/// The log of job `job`.
#[allow(clippy::result_large_err)]
pub(super) async fn read(
    connector: &GitHubConnector,
    call: &Call,
    job: u64,
    token: &str,
) -> Result<Value, ToolOutcome> {
    let target = format!("{}/actions/jobs/{job}/logs", tools::repo_path(call));
    let location = match connector.api().get_location(&target, token).await {
        Located::Redirect(location) => location,
        Located::Direct(status) => {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "GitHub answered the request for job {job}'s log with HTTP {} and no \
                     redirect; a log is read only from the job log host GitHub redirects to",
                    status.as_u16()
                ),
            ));
        }
        Located::Answered(Answered::Status {
            status,
            rate_limited: false,
        }) if status == StatusCode::NOT_FOUND => {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "GitHub has no log for this job: job {job} in {}/{}, or the token cannot see \
                     the repository (HTTP 404)",
                    call.owner(),
                    call.repo()
                ),
            ));
        }
        Located::Answered(other) => return Err(vendor_error(other, "job's log", call)),
    };
    let Ok(location) = location.parse::<Uri>() else {
        return Err(ToolOutcome::Refused(format!(
            "GitHub's redirect for job {job}'s log is not a URL, so it will not be followed"
        )));
    };
    let Some((host, path)) = pinned(connector.job_log_hosts(), &location) else {
        return Err(ToolOutcome::Refused(refusal(job, &location)));
    };
    match host
        .get_tail(&path, MAX_LOG_BYTES, MAX_LOG_READ_BYTES)
        .await
    {
        Tail::Text { tail, cut, stopped } => {
            // A cut may fall inside a character: start at the next whole one.
            let start = if cut {
                tail.iter()
                    .position(|byte| (byte & 0b1100_0000) != 0b1000_0000)
                    .unwrap_or(tail.len())
            } else {
                0
            };
            let text = String::from_utf8_lossy(&tail[start..]).into_owned();
            let mut log = json!({
                "jobId": job,
                "text": text,
                "truncated": cut,
            });
            if cut {
                log["truncationNote"] = Value::String(if stopped {
                    format!(
                        "reading stopped after {} MiB; showing the last 64 KiB of what was read, \
                         and the end of the log is not shown",
                        MAX_LOG_READ_BYTES / (1024 * 1024)
                    )
                } else {
                    "showing the last 64 KiB of the log; earlier lines are not shown".to_owned()
                });
            }
            Ok(json!({"log": log, "provenance": tools::provenance(super::GET_JOB_LOG)}))
        }
        Tail::Status(status) => Err(ToolOutcome::error(
            ErrorKind::Other,
            format!(
                "the job log host answered HTTP {} for job {job}'s log",
                status.as_u16()
            ),
        )),
        Tail::Unreachable => Err(ToolOutcome::error(
            ErrorKind::Other,
            "the job log host could not be reached, or the log could not be read",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn uri(text: &str) -> Uri {
        text.parse().unwrap()
    }

    #[test]
    fn an_origin_is_its_scheme_host_and_port() {
        assert_eq!(
            origin(&uri("https://Logs.Example.test/a?sig=x")),
            Some(("https".into(), "logs.example.test".into(), 443))
        );
        assert_eq!(
            origin(&uri("https://logs.example.test:443/a")),
            origin(&uri("https://logs.example.test/b"))
        );
        assert_ne!(
            origin(&uri("https://logs.example.test:8443/a")),
            origin(&uri("https://logs.example.test/a"))
        );
        assert_ne!(
            origin(&uri("http://logs.example.test/a")),
            origin(&uri("https://logs.example.test/a"))
        );
        assert_eq!(origin(&uri("https://user@logs.example.test/a")), None);
        assert_eq!(origin(&uri("/relative")), None);
    }

    #[test]
    fn a_refusal_names_no_path_or_query() {
        let sentence = refusal(7, &uri("https://other.example.test:8443/logs/7?sig=secret"));
        assert!(
            sentence.contains("https://other.example.test:8443"),
            "{sentence}"
        );
        assert!(!sentence.contains("sig"), "{sentence}");
        assert!(!sentence.contains("/logs/"), "{sentence}");
        let sentence = refusal(7, &uri("https://user:pw@other.example.test/x"));
        assert!(!sentence.contains("pw"), "{sentence}");
    }
}
