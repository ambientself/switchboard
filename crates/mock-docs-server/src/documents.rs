//! The seeded documents, keyed by project and document name together.

use std::collections::BTreeMap;

/// The projects the server is seeded with.
pub const PROJECTS: [&str; 2] = ["atlas", "borealis"];

/// The ordinary document every project holds.
pub const PLAN: &str = "plan";
/// Answers only after the configured delay (10 s unless told otherwise).
pub const SLOW_DOC: &str = "slow-doc";
/// Never answers. The connection stays open until the client gives up.
pub const HANG_DOC: &str = "hang-doc";
/// Answers with a JSON-RPC error, code [`FAIL_CODE`].
pub const FAIL_DOC: &str = "fail-doc";
/// Answers with a text of exactly [`HUGE_BYTES`] bytes.
pub const HUGE_DOC: &str = "huge-doc";

/// The JSON-RPC error code `fail-doc` answers with: the specification's internal error.
pub const FAIL_CODE: i64 = -32603;
/// The size of `huge-doc`'s text: 1 MiB.
pub const HUGE_BYTES: usize = 1 << 20;

/// What reading a document does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Content {
    Text(String),
    Slow,
    Hang,
    Fail,
    Huge,
}

/// Every document, keyed by `(project, document)`. A document name alone finds nothing: the same
/// name in two projects is two documents, and a name never reaches into another project.
#[derive(Clone, Debug)]
pub(crate) struct Documents(BTreeMap<(String, String), Content>);

impl Documents {
    pub(crate) fn seeded() -> Self {
        let mut documents = BTreeMap::new();
        for project in PROJECTS {
            let plan = format!(
                "The {project} plan. This text belongs to project {project} and to no other."
            );
            for (name, content) in [
                (PLAN, Content::Text(plan)),
                (SLOW_DOC, Content::Slow),
                (HANG_DOC, Content::Hang),
                (FAIL_DOC, Content::Fail),
                (HUGE_DOC, Content::Huge),
            ] {
                documents.insert((project.to_owned(), name.to_owned()), content);
            }
        }
        Self(documents)
    }

    /// The document `document` of project `project`, if that pair exists.
    pub(crate) fn get(&self, project: &str, document: &str) -> Option<&Content> {
        self.0.get(&(project.to_owned(), document.to_owned()))
    }

    /// The names of the documents in `project`, in order, or `None` for an unknown project.
    pub(crate) fn list(&self, project: &str) -> Option<Vec<&str>> {
        let names: Vec<&str> = self
            .0
            .keys()
            .filter(|(owner, _)| owner == project)
            .map(|(_, name)| name.as_str())
            .collect();
        (!names.is_empty()).then_some(names)
    }

    /// The names of the text documents in `project` whose text contains `query`, or `None` for
    /// an unknown project. The documents that misbehave have no text and never match.
    pub(crate) fn search(&self, project: &str, query: &str) -> Option<Vec<&str>> {
        let names = self.list(project)?;
        Some(
            names
                .into_iter()
                .filter(|name| {
                    matches!(self.get(project, name), Some(Content::Text(text)) if text.contains(query))
                })
                .collect(),
        )
    }
}
