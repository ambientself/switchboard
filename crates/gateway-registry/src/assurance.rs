//! What a built-in connector's own code gives for each tool it serves (decision 0011, section
//! 1), and how an approval's declarations are compared with it.
//!
//! A proxied tool's approval is the only statement there is of what the tool does, and rests on
//! its reviewer. A built-in tool is gateway code, so its connector states, from its own code,
//! what each tool is: its classification, and how the resources it reaches are known. The
//! gateway compares every built-in tool's approval with that statement at boot and on every
//! reload (`gateway::boot`), and refuses an approval that declares otherwise. Without it, an
//! approval could declare `checks_own_scope` or `no_resources` for a tool that checks nothing
//! while it runs: check 6 would allow a repository outside the caller's limit, and the row
//! would record no resources where decision 0011 says `unknown`.

use std::fmt;

use gateway_core::{Classification, ToolName};

use crate::adapter::ResourceSource;

/// How a built-in tool's resources are known, as its connector's code gives it, in the terms an
/// approval declares them (`resources` in `[[built_in_tools]]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatedResources {
    /// The tool reaches only what these structured arguments name, and checks nothing more
    /// while it runs: its approval is `from_arguments`, with exactly these sources.
    FromArguments(Vec<ResourceSource>),
    /// The tool reaches its entry's whole reach on every call: its approval is `as_reach`.
    AsReach,
    /// The tool checks its own scope while it runs, refusing what is outside the caller's
    /// limit, and reports what it reached when it finishes: its approval is
    /// `checks_own_scope`, and its row reads `unknown` until then.
    ChecksOwnScope,
    /// The tool reaches nothing a limit applies to: its approval is `no_resources`.
    NoResources,
}

impl fmt::Display for StatedResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromArguments(sources) => {
                f.write_str("`from_arguments`, reading ")?;
                for (index, source) in sources.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{} {} from `", source.system, source.kind)?;
                    if let Some(qualifier) = &source.qualified_by {
                        write!(f, "{qualifier}`/`")?;
                    }
                    write!(f, "{}`", source.from_argument)?;
                }
                if sources.is_empty() {
                    f.write_str("nothing")?;
                }
                Ok(())
            }
            Self::AsReach => f.write_str("`as_reach`"),
            Self::ChecksOwnScope => f.write_str("`checks_own_scope`"),
            Self::NoResources => f.write_str("`no_resources`"),
        }
    }
}

/// What one tool is, as its connector's code states it, or as its approval declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assurance {
    /// The tool's classification.
    pub classification: Classification,
    /// How the resources it reaches are known.
    pub resources: StatedResources,
}

impl Assurance {
    /// How `approved`, an approval's declarations, differs from this, the connector's own
    /// statement: a sentence such as "is approved as `checks_own_scope`, and its connector
    /// states `from_arguments`, reading github repository from `owner`/`repo`", or `None` when
    /// they agree. Sources are compared as a set: an approval may list them in any order.
    pub fn mismatch(&self, approved: &Assurance) -> Option<String> {
        if approved.classification != self.classification {
            return Some(format!(
                "is approved as `{}`, and its connector classifies it `{}`",
                approved.classification.as_str(),
                self.classification.as_str()
            ));
        }
        let agree = match (&self.resources, &approved.resources) {
            (StatedResources::FromArguments(stated), StatedResources::FromArguments(declared)) => {
                stated.len() == declared.len()
                    && stated.iter().all(|source| declared.contains(source))
                    && declared.iter().all(|source| stated.contains(source))
            }
            (stated, declared) => stated == declared,
        };
        (!agree).then(|| {
            format!(
                "is approved as {}, and its connector states {}",
                approved.resources, self.resources
            )
        })
    }
}

/// One tool a built-in connector serves on one of its entries, as its own code states it: the
/// SHA-256 its approval's `definition_sha256` must record, and what it is. The gateway refuses,
/// at boot and on every reload, an approval on that entry that differs from either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedTool {
    /// The tool's exposed name.
    pub name: ToolName,
    /// The SHA-256 of its definition, as [`definition_sha256`](crate::definition_sha256)
    /// computes it.
    pub definition_sha256: String,
    /// What the connector's code gives for it.
    pub assurance: Assurance,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> ResourceSource {
        ResourceSource {
            from_argument: "repo".into(),
            qualified_by: Some("owner".into()),
            system: "github".into(),
            kind: "repository".into(),
        }
    }

    fn read(resources: StatedResources) -> Assurance {
        Assurance {
            classification: Classification::Read,
            resources,
        }
    }

    #[test]
    fn an_approval_that_declares_what_the_connector_states_agrees() {
        let stated = read(StatedResources::FromArguments(vec![repository()]));
        assert_eq!(stated.mismatch(&stated.clone()), None);
        for resources in [
            StatedResources::AsReach,
            StatedResources::ChecksOwnScope,
            StatedResources::NoResources,
        ] {
            assert_eq!(read(resources.clone()).mismatch(&read(resources)), None);
        }
        // Sources in another order are the same sources.
        let other = ResourceSource {
            from_argument: "project".into(),
            qualified_by: None,
            system: "jira".into(),
            kind: "project".into(),
        };
        let both = read(StatedResources::FromArguments(vec![
            repository(),
            other.clone(),
        ]));
        let reversed = read(StatedResources::FromArguments(vec![other, repository()]));
        assert_eq!(both.mismatch(&reversed), None);
    }

    #[test]
    fn each_way_an_approval_can_declare_otherwise_is_a_mismatch() {
        let stated = read(StatedResources::FromArguments(vec![repository()]));
        assert_eq!(
            stated
                .mismatch(&read(StatedResources::ChecksOwnScope))
                .unwrap(),
            "is approved as `checks_own_scope`, and its connector states `from_arguments`, \
             reading github repository from `owner`/`repo`"
        );
        assert_eq!(
            stated
                .mismatch(&read(StatedResources::NoResources))
                .unwrap(),
            "is approved as `no_resources`, and its connector states `from_arguments`, reading \
             github repository from `owner`/`repo`"
        );
        assert!(stated.mismatch(&read(StatedResources::AsReach)).is_some());
        let unqualified = ResourceSource {
            qualified_by: None,
            ..repository()
        };
        assert_eq!(
            stated
                .mismatch(&read(StatedResources::FromArguments(vec![unqualified])))
                .unwrap(),
            "is approved as `from_arguments`, reading github repository from `repo`, and its \
             connector states `from_arguments`, reading github repository from `owner`/`repo`"
        );
        assert!(
            stated
                .mismatch(&read(StatedResources::FromArguments(vec![
                    repository(),
                    repository()
                ])))
                .is_some(),
            "a source twice is not the one source"
        );
        assert!(
            read(StatedResources::ChecksOwnScope)
                .mismatch(&read(StatedResources::NoResources))
                .is_some()
        );
        let proposed = Assurance {
            classification: Classification::Propose,
            ..stated.clone()
        };
        assert_eq!(
            stated.mismatch(&proposed).unwrap(),
            "is approved as `propose`, and its connector classifies it `read`"
        );
    }
}
