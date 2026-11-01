//! The reach report's tool (decision 0011, section 4; #193):
//! `github__list_installation_repositories`, which reads GitHub's own report of the
//! repositories the App's installation reaches, for the drift pass to compare with each GitHub
//! entry's recorded reach.
//!
//! GitHub reports an installation's repositories at `GET /installation/repositories`, and lists
//! to a token only the repositories that token can see. Every token the other tools use is
//! narrowed to a team's repositories or the call's one, so none of them can read the whole list.
//! This tool's token is the key custodian's one stated exception: asked for with no
//! repositories, so for the whole installation, and for `metadata: read` alone, the permission
//! every GitHub token carries and the least that lists the repositories. The custodian gives it
//! only to a tool served by an entry the registry declares `reports_reach = true`, and the
//! registry holds such an entry to that job: narrowed `none`, `read`, served only on
//! `registry-reach`, to one named principal, the registry's own identity. The connector serves
//! this tool only on such an entry, and serves no other tool on one ([`crate::served`]).
//!
//! It takes no arguments. It reads every page, [`PER_PAGE`] repositories a page, up to
//! [`MAX_REPORT_PAGES`]. An installation on more repositories than that is an error, never a
//! list read in part: a repository on a page not read would look dropped. So is a page GitHub
//! answers that is not a list of repositories with their full names, or a list that does not
//! reach the total GitHub says it has. The result is the full names, `owner/name`, sorted, as
//! `repositories`, with `totalCount` and the `provenance` every result of this connector
//! carries.

use std::collections::BTreeSet;

use gateway_core::{Classification, ErrorKind, ToolOutcome};
use gateway_registry::{Assurance, StatedResources};
use serde_json::{Value, json};

use crate::api::{Answered, Api};
use crate::tools::{self, Definition};

/// The tool's exposed name.
pub const LIST_INSTALLATION_REPOSITORIES: &str = "github__list_installation_repositories";

/// The one permission its token is asked for.
pub const REPORT_PERMISSION: &str = "metadata";

/// How many repositories it asks GitHub for on each page: GitHub's most.
pub const PER_PAGE: usize = 100;

/// The most pages it reads: 1,000 repositories.
pub const MAX_REPORT_PAGES: usize = 10;

/// The tool's definition, as its approval in the registry must hash to it.
pub fn definition() -> Definition {
    Definition {
        name: LIST_INSTALLATION_REPOSITORIES,
        description: "Lists every repository the GitHub App's installation reaches, as GitHub \
                      reports it, for the registry's reach check to compare with each GitHub \
                      entry's recorded reach. It takes no arguments and reads no content.",
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        // It reads only the names of the installation's repositories, nothing a limit applies
        // to, for the registry alone, on the one surface the registry's loader allows it.
        assurance: Assurance {
            classification: Classification::Read,
            resources: StatedResources::NoResources,
        },
    }
}

/// Reads the installation's repositories with `token`, every page, and gives them as the
/// tool's result.
pub(crate) async fn read(api: &Api, token: &str) -> ToolOutcome {
    let mut repositories = BTreeSet::new();
    for page in 1..=MAX_REPORT_PAGES {
        let target = format!("/installation/repositories?per_page={PER_PAGE}&page={page}");
        let answer = match api.get(&target, token).await {
            Answered::Json(answer) => answer,
            Answered::Unreadable => return failed("GitHub's report could not be read"),
            Answered::Unreachable => {
                return failed(
                    "GitHub could not be reached, or its report could not be read in full",
                );
            }
            Answered::Status {
                status,
                rate_limited: true,
            } => {
                return failed(&format!(
                    "GitHub's rate limit for this App's installation is used up (HTTP {}); try \
                     again later",
                    status.as_u16()
                ));
            }
            Answered::Status { status, .. } => {
                let kind = if status.as_u16() == 403 {
                    ErrorKind::VendorRefusal
                } else {
                    ErrorKind::Other
                };
                return ToolOutcome::error(
                    kind,
                    format!(
                        "GitHub answered HTTP {} to the report of the installation's repositories",
                        status.as_u16()
                    ),
                );
            }
        };
        let Some((total, names)) = names(&answer) else {
            return failed("GitHub's report is not a list of repositories with their full names");
        };
        let count = names.len();
        repositories.extend(names);
        let total_usize = usize::try_from(total).unwrap_or(usize::MAX);
        if repositories.len() >= total_usize || count < PER_PAGE {
            if repositories.len() != total_usize {
                return failed(&format!(
                    "GitHub's report lists {} repositories, and says the installation has {total}",
                    repositories.len()
                ));
            }
            return ToolOutcome::Ok(json!({
                "repositories": repositories,
                "totalCount": total,
                "provenance": tools::provenance(LIST_INSTALLATION_REPOSITORIES),
            }));
        }
    }
    failed(&format!(
        "the installation reaches more than {} repositories, more than the report reads; a list \
         read in part would show the rest as dropped",
        PER_PAGE * MAX_REPORT_PAGES
    ))
}

/// The total GitHub says the installation has, and the full names on one page of its report.
fn names(answer: &Value) -> Option<(u64, Vec<String>)> {
    let total = answer.get("total_count")?.as_u64()?;
    let names = answer
        .get("repositories")?
        .as_array()?
        .iter()
        .map(|repository| {
            repository
                .get("full_name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Option<Vec<String>>>()?;
    Some((total, names))
}

fn failed(why: &str) -> ToolOutcome {
    ToolOutcome::error(ErrorKind::Other, why)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_page_is_a_total_and_full_names() {
        let page = json!({
            "total_count": 2,
            "repository_selection": "all",
            "repositories": [{"full_name": "example-org/atlas"}, {"full_name": "example-org/b"}],
        });
        assert_eq!(
            names(&page),
            Some((
                2,
                vec!["example-org/atlas".to_owned(), "example-org/b".to_owned()]
            ))
        );
        for broken in [
            json!({"repositories": []}),
            json!({"total_count": 1, "repositories": [{"name": "atlas"}]}),
            json!({"total_count": 1, "repositories": "atlas"}),
            json!([]),
        ] {
            assert_eq!(names(&broken), None, "{broken}");
        }
    }

    /// An installation's report as a GitHub that lists `listed` repositories, `example-org/r0`
    /// on, says it has `total`, and answers each page of `per_page` as asked; with the pages
    /// asked for, in order.
    struct Installation {
        listed: usize,
        total: usize,
        asked: std::sync::Mutex<Vec<(usize, usize)>>,
    }

    impl Installation {
        fn page(&self, query: &str) -> String {
            let number = |name: &str| {
                query
                    .split('&')
                    .filter_map(|pair| pair.split_once('='))
                    .find(|(key, _)| *key == name)
                    .and_then(|(_, value)| value.parse::<usize>().ok())
                    .unwrap()
            };
            let (per_page, page) = (number("per_page"), number("page"));
            self.asked.lock().unwrap().push((per_page, page));
            let repositories: Vec<Value> = (0..self.listed)
                .skip((page - 1) * per_page)
                .take(per_page)
                .map(|index| json!({"full_name": format!("example-org/r{index}")}))
                .collect();
            json!({"total_count": self.total, "repositories": repositories}).to_string()
        }
    }

    /// What the report's tool reads from `installation`, and the pages it asked for.
    fn report(listed: usize, total: usize) -> (ToolOutcome, Vec<(usize, usize)>) {
        use std::sync::Arc;

        use axum::http::{StatusCode, Uri};

        let installation = Arc::new(Installation {
            listed,
            total,
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(async {
            let serving = installation.clone();
            let router = axum::Router::new().fallback(move |uri: Uri| {
                let serving = serving.clone();
                async move {
                    assert_eq!(uri.path(), "/installation/repositories");
                    (StatusCode::OK, serving.page(uri.query().unwrap_or("")))
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            let api = Api::new(&format!("http://{address}"), None).unwrap();
            read(&api, "token").await
        });
        let asked = installation.asked.lock().unwrap().clone();
        (outcome, asked)
    }

    fn listed(outcome: &ToolOutcome) -> (Vec<String>, u64) {
        let ToolOutcome::Ok(result) = outcome else {
            panic!("{outcome:?}");
        };
        let names = result["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect();
        (names, result["totalCount"].as_u64().unwrap())
    }

    fn failed(outcome: &ToolOutcome) -> String {
        match outcome {
            ToolOutcome::Error(kind, sentence) => {
                assert_eq!(*kind, ErrorKind::Other);
                sentence.clone()
            }
            other => panic!("{other:?}"),
        }
    }

    /// Every page is read, a hundred repositories at a time, until the list reaches GitHub's
    /// total, and no further.
    #[test]
    fn every_page_is_read_until_the_list_reaches_its_total() {
        let (outcome, asked) = report(250, 250);
        let (names, total) = listed(&outcome);
        assert_eq!(total, 250);
        assert_eq!(names.len(), 250);
        assert!(names.contains(&"example-org/r249".to_owned()));
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]), "sorted");
        assert_eq!(asked, [(100, 1), (100, 2), (100, 3)]);
        // Two full pages that reach the total ask for no third.
        let (outcome, asked) = report(200, 200);
        assert_eq!(listed(&outcome).0.len(), 200);
        assert_eq!(asked, [(100, 1), (100, 2)]);
        // An installation on no repository is one empty page.
        let (outcome, asked) = report(0, 0);
        assert_eq!(listed(&outcome), (Vec::new(), 0));
        assert_eq!(asked, [(100, 1)]);
    }

    /// A list that does not come to GitHub's total, short of it or past it, is an error, never a
    /// list read in part.
    #[test]
    fn a_list_that_does_not_come_to_its_total_is_an_error() {
        let (outcome, asked) = report(120, 150);
        assert_eq!(
            failed(&outcome),
            "GitHub's report lists 120 repositories, and says the installation has 150"
        );
        assert_eq!(asked, [(100, 1), (100, 2)]);
        let (outcome, _) = report(3, 2);
        assert_eq!(
            failed(&outcome),
            "GitHub's report lists 3 repositories, and says the installation has 2"
        );
    }

    /// An installation on more than 1,000 repositories is an error: ten pages are read and no
    /// more, since a repository on a page not read would look dropped.
    #[test]
    fn more_than_a_thousand_repositories_is_an_error() {
        let (outcome, asked) = report(1000, 1000);
        assert_eq!(listed(&outcome).0.len(), 1000);
        assert_eq!(asked.len(), 10);
        let (outcome, asked) = report(1001, 1001);
        assert_eq!(
            failed(&outcome),
            "the installation reaches more than 1000 repositories, more than the report reads; \
             a list read in part would show the rest as dropped"
        );
        assert_eq!(asked.len(), MAX_REPORT_PAGES);
        assert_eq!(asked.last(), Some(&(PER_PAGE, MAX_REPORT_PAGES)));
    }

    #[test]
    fn the_definition_takes_no_arguments() {
        let definition = definition();
        assert_eq!(definition.name, LIST_INSTALLATION_REPOSITORIES);
        assert_eq!(definition.input_schema["properties"], json!({}));
        assert_eq!(
            definition.input_schema["additionalProperties"],
            json!(false)
        );
        assert_eq!(
            definition.assurance,
            Assurance {
                classification: Classification::Read,
                resources: StatedResources::NoResources,
            }
        );
    }
}
