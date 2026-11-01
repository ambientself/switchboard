//! What every GitHub write tool shares (#12): the outcome of a write, the marker a lookup finds
//! it by, the receipt it sends under, the guards a proposal makes before any request, and the
//! check of an entry that serves one.
//!
//! # The outcome of a write
//!
//! A write's outcome turns on whether anything may have been sent (decision 0009, "Outcomes"),
//! and `Writes` keeps that for one call:
//!
//! - Everything refused or failed before the call's first write request may have been sent is
//!   `error` or `refused`, as for a read: an argument error, a refusal, the key custodian's
//!   refusal (`custodian_refusal`), a read that failed. Nothing took effect, and the receipt
//!   is settled `not_performed`.
//! - A definite refusal of the call's first write, any 3xx or 4xx, is `error` too: GitHub did
//!   nothing. A 403 that is not GitHub's rate limit is `vendor_refusal`, anything else `other`,
//!   and the sentence names the status, never GitHub's own text.
//! - Once a write may have been sent, every failure, and every answer that is not definite, is
//!   [`ToolOutcome::Unknown`]: a 5xx, an exchange broken off after its connection was made, a
//!   2xx that cannot be read, and any failure of a later request, a later write's definite
//!   refusal included. Its receipt is `unknown`, for reconciliation to settle by the marker.
//! - Success is [`ToolOutcome::Completed`] with GitHub's reference, `pull/<n>` for a pull
//!   request (`completed`). A 2xx whose number cannot be read is `unknown`, since something
//!   was made. A call whose answer shows it wrote nothing reports [`ToolOutcome::Ok`], with no
//!   reference.
//!
//! GitHub documents no idempotency key for these endpoints, and none is sent. A write is never
//! sent twice (`crate::api`).
//!
//! # The marker
//!
//! The connector attaches one line it controls to what it writes:
//! `<!-- switchboard-receipt: <receipt> -->`, the receipt being the call's audit row
//! ([`ToolCall::receipt`]). A lookup finds the effect by a line exactly equal to it, never by
//! anything the caller chose alone (decision 0009, "Reconciliation"). So a call whose own text
//! holds `switchboard-receipt`, in any case, is refused before any request: no caller can
//! write a marker, its own or another receipt's.
//!
//! # The guards
//!
//! A proposal tool guards, when it runs, against what would take effect without a person
//! acting (design section 8; decision 0011, section 6), with one predicate for each that every
//! write tool shares:
//!
//! - [`command_text`]: a text whose first word is one of [`ATLANTIS_COMMANDS`] (`atlantis`,
//!   `@atlantis` or `/atlantis`), in any case, after any leading whitespace and Unicode format
//!   characters, and with any format character in the word passed over: text Atlantis could
//!   read as a command. Otto refuses such a comment; this is broader than Otto's rule, so that
//!   no spelling Atlantis might take as its own name gets through.
//! - [`refused_path`]: Otto's four refused path groups, with Otto's sentences, in any case: a
//!   file named `AGENTS.md` in any directory and any path with a `.agents` segment, the
//!   instruction-authority group; any path under `.github/workflows/` and a file named
//!   `atlantis.yaml` or `atlantis.yml` anywhere, the automation group. `.github`,
//!   `.github/workflows` and `.agents` themselves are refused too, since a file there would
//!   replace the directory.

use gateway_core::audit::AuditRowId;
use gateway_core::{
    Classification, ConnectorName, ErrorKind, Narrowing, ToolCall, ToolOutcome, VendorReference,
};
use gateway_registry::{Access, BuiltInEntry};
use hyper::StatusCode;
use serde_json::Value;

use crate::api::{Api, WriteMethod, Wrote};
use crate::connector::SettingsError;
use crate::create_pr;
use crate::pr_comment;

/// The text every marker begins with, after `<!-- `. A call whose text holds it, in any case,
/// is refused.
pub const MARKER_PREFIX: &str = "switchboard-receipt";

/// The marker line for the receipt `receipt`, as the connector attaches it and a lookup finds
/// it: `<!-- switchboard-receipt: <receipt> -->`.
pub fn marker(receipt: &AuditRowId) -> String {
    format!("<!-- {MARKER_PREFIX}: {} -->", receipt.as_str())
}

/// Whether `text` holds [`MARKER_PREFIX`], in any case.
pub fn holds_marker(text: &str) -> bool {
    text.to_ascii_lowercase().contains(MARKER_PREFIX)
}

/// The first words Atlantis could read as a command addressed to it, compared in any case:
/// its own name, and the name as a mention or a slash command.
pub const ATLANTIS_COMMANDS: &[&str] = &["atlantis", "@atlantis", "/atlantis"];

/// Whether Atlantis could read `text` as a command: its first word is one of
/// [`ATLANTIS_COMMANDS`], in any case. Leading whitespace and Unicode format characters (a
/// zero-width space or joiner, a byte order mark, a direction mark) are passed over, and so is
/// any format character inside the word, which a reader does not see. Otto's rule for a comment
/// (docs/otto-baseline.md, "Scope refusals"), made broader.
pub fn command_text(text: &str) -> bool {
    let start = text.trim_start_matches(|c: char| c.is_whitespace() || format_character(c));
    let word: String = start
        .split(char::is_whitespace)
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !format_character(*c))
        .collect();
    ATLANTIS_COMMANDS
        .iter()
        .any(|command| word.eq_ignore_ascii_case(command))
}

/// Whether `c` is a Unicode format character (general category `Cf`), which takes no space
/// when shown: Unicode 16's list.
fn format_character(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// The sentence a proposal tool refuses command text in `field` with.
pub(crate) fn command_text_sentence(field: &str) -> String {
    format!(
        "the {field} begins with \"atlantis\", which Atlantis would read as a command; a proposal \
         may not carry one"
    )
}

/// The sentence a call whose `field` holds the marker's text is refused with.
pub(crate) fn marker_sentence(field: &str) -> String {
    format!(
        "the {field} holds \"{MARKER_PREFIX}\", which only the gateway writes, to mark what a \
         call made; take it out"
    )
}

/// The group a refused path is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathGroup {
    /// CI workflow files and Atlantis configuration: automation that acts without a person.
    Automation,
    /// `AGENTS.md` and `.agents/`: files an agent reads as instructions.
    InstructionAuthority,
}

/// A path a proposal may not change, its group, and Otto's sentence for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusedPath {
    /// The group.
    pub group: PathGroup,
    /// Otto's sentence.
    pub sentence: &'static str,
}

/// Whether `path`, a path in a repository, is one a proposal may not change, and why: see the
/// [module documentation](self). Compared in any case; empty and `.` segments are passed over.
pub fn refused_path(path: &str) -> Option<RefusedPath> {
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .map(str::to_ascii_lowercase)
        .collect();
    let last = segments.last()?;
    let workflows = RefusedPath {
        group: PathGroup::Automation,
        sentence: "paths under .github/workflows/ carry their own token permission",
    };
    if segments[0] == ".github" && segments.get(1).is_none_or(|second| second == "workflows") {
        return Some(workflows);
    }
    if last == "atlantis.yaml" || last == "atlantis.yml" {
        return Some(RefusedPath {
            group: PathGroup::Automation,
            sentence: "atlantis.yaml selects Atlantis project names",
        });
    }
    if last == "agents.md" {
        return Some(RefusedPath {
            group: PathGroup::InstructionAuthority,
            sentence: "AGENTS.md is an instruction-authority file",
        });
    }
    if segments.iter().any(|segment| segment == ".agents") {
        return Some(RefusedPath {
            group: PathGroup::InstructionAuthority,
            sentence: "paths under .agents/ are instruction-authority files",
        });
    }
    None
}

/// The receipt `call` sends under: its audit row, which the gateway reserved as its receipt.
/// Nothing is sent for a write tool approved as anything but what the connector states it is,
/// `write` for `github__pr_comment` and `propose` for every other, whatever its approval says,
/// or for a call that reserved no receipt: the outcome then is `error`, before the key
/// custodian is asked.
#[allow(clippy::result_large_err)]
pub(crate) fn receipt(call: &ToolCall) -> Result<&AuditRowId, ToolOutcome> {
    let tool = &call.tool().name;
    let classification = call.tool().classification;
    let stated = if tool.as_str() == pr_comment::PR_COMMENT {
        Classification::Write
    } else {
        Classification::Propose
    };
    if classification != stated {
        return Err(ToolOutcome::error(
            ErrorKind::Other,
            format!(
                "`{tool}` is approved as `{classification}`, and the GitHub connector sends it \
                 only as `{stated}`; nothing was sent"
            ),
        ));
    }
    call.receipt().ok_or_else(|| {
        ToolOutcome::error(
            ErrorKind::Other,
            format!("`{tool}` was given no receipt to mark what it makes with; nothing was sent"),
        )
    })
}

/// The permission set each write tool asks for, every permission at its level: the tool's own,
/// never its entry's whole set (#223). `None` for a tool that is not a write.
pub(crate) fn asked(tool: &str) -> Option<&'static [(&'static str, Access)]> {
    match tool {
        create_pr::CREATE_PR => Some(create_pr::PERMISSIONS),
        pr_comment::PR_COMMENT => Some(pr_comment::PERMISSIONS),
        _ => None,
    }
}

/// Refuses `entry`, narrowed `narrowing`, if it serves a write tool without being narrowed
/// `call`, or without stating every permission the tool asks for at its level or above. A
/// write's token is for the one repository the call names, never the caller's whole limit.
pub(crate) fn check_entry(entry: &BuiltInEntry, narrowing: Narrowing) -> Result<(), SettingsError> {
    for tool in &entry.tools {
        let Some(permissions) = asked(tool.as_str()) else {
            continue;
        };
        if narrowing != Narrowing::Call {
            return Err(SettingsError::WriteNotNarrowedToTheCall {
                entry: entry.name.clone(),
                tool: tool.as_str().to_owned(),
            });
        }
        for (permission, access) in permissions {
            if entry.permissions.get(*permission) < Some(access) {
                return Err(SettingsError::WritePermissionNotStated {
                    entry: entry.name.clone(),
                    tool: tool.as_str().to_owned(),
                    permission: format!("{permission}: {}", access.as_str()),
                });
            }
        }
    }
    Ok(())
}

/// Whether `entry` serves a write tool, and so registers the connector's lookup by marker.
pub fn serves_a_write(entry: &BuiltInEntry) -> bool {
    entry
        .tools
        .iter()
        .any(|tool| asked(tool.as_str()).is_some())
}

/// The sentence for a call of a write tool on an entry the connector was not built with, or
/// that is not narrowed to the call.
pub(crate) fn not_narrowed(connector: &ConnectorName) -> ToolOutcome {
    ToolOutcome::error(
        ErrorKind::Other,
        format!(
            "connector entry `{connector}` is not one the GitHub connector sends writes on: a \
             write's token is narrowed to the call's repository; nothing was sent"
        ),
    )
}

/// One call's writes, and whether any may have been sent: see the [module
/// documentation](self).
#[derive(Debug, Default)]
pub(crate) struct Writes {
    may_have_written: bool,
}

impl Writes {
    /// A call's writes, none sent yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The outcome of a call that failed with `failure` now: `failure` itself while no write
    /// may have been sent, and `unknown` once one may have been.
    pub(crate) fn failed(&self, failure: ToolOutcome) -> ToolOutcome {
        if self.may_have_written {
            ToolOutcome::Unknown
        } else {
            failure
        }
    }

    /// Sends one write, `method {path}` with `body` and `token`, and GitHub's JSON answer to a
    /// write it did; otherwise the call's outcome, by the rule in the [module
    /// documentation](self). `what` names what the write makes, such as "the pull request",
    /// in the sentence of a definite refusal.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn send(
        &mut self,
        api: &Api,
        method: WriteMethod,
        path: &str,
        body: &impl serde::Serialize,
        token: &str,
        what: &str,
    ) -> Result<Value, ToolOutcome> {
        match api.write(method, path, body, token).await {
            Wrote::Json(answer) => {
                self.may_have_written = true;
                Ok(answer)
            }
            Wrote::NoDefiniteAnswer => {
                self.may_have_written = true;
                Err(ToolOutcome::Unknown)
            }
            Wrote::NotSent => Err(self.failed(ToolOutcome::error(
                ErrorKind::Other,
                format!("GitHub could not be reached, so {what} was not sent and nothing was made"),
            ))),
            Wrote::Refused {
                status,
                rate_limited,
            } => Err(self.failed(refused(status, rate_limited, what))),
        }
    }
}

/// The outcome of GitHub's definite refusal of a call's first write, with `status`: `error`,
/// `vendor_refusal` for a 403 that is not its rate limit and `other` for anything else, with a
/// sentence that names the status and never GitHub's text.
fn refused(status: StatusCode, rate_limited: bool, what: &str) -> ToolOutcome {
    let code = status.as_u16();
    if rate_limited {
        return ToolOutcome::error(
            ErrorKind::Other,
            format!(
                "GitHub's rate limit for this App's installation is used up (HTTP {code}), so \
                 {what} was not made; try again later"
            ),
        );
    }
    if status == StatusCode::FORBIDDEN {
        return ToolOutcome::error(
            ErrorKind::VendorRefusal,
            format!("GitHub refused {what} to this App (HTTP 403), so nothing was made"),
        );
    }
    ToolOutcome::error(
        ErrorKind::Other,
        format!("GitHub refused {what} (HTTP {code}), so nothing was made"),
    )
}

/// A write GitHub did: `result` for the caller, with the reference `pull/<number>`, or
/// `unknown` when the number could not be read from its answer, since something was made.
pub(crate) fn completed(result: Value, number: Option<u64>) -> ToolOutcome {
    match number {
        Some(number) => {
            ToolOutcome::Completed(result, VendorReference::new(format!("pull/{number}")))
        }
        None => ToolOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_text_is_a_first_word_of_atlantis_in_any_case() {
        for command in [
            "atlantis apply",
            "Atlantis plan -p x",
            "  \n\tATLANTIS",
            "atlantis",
            "aTlAnTiS\nunlock",
            "/atlantis apply",
            "@atlantis plan",
            "@ATLANTIS",
            "\u{200B}atlantis apply",
            "\u{FEFF} \u{2060}\n@Atlantis unlock",
            "\u{00A0}\u{3000}atlantis plan",
            "atl\u{200D}antis apply",
            "atlantis\u{200B} apply",
        ] {
            assert!(command_text(command), "{command:?}");
        }
        for text in [
            "",
            "   ",
            "\u{200B}",
            "please run atlantis apply",
            "please run atlantis plan later",
            "atlantisapply",
            "atlantis-bot apply",
            "#atlantis apply",
            "//atlantis apply",
            "Adds a retry to the client.",
        ] {
            assert!(!command_text(text), "{text:?}");
        }
    }

    #[test]
    fn the_marker_is_one_line_carrying_the_receipt() {
        let receipt = AuditRowId::new("0190f5a2-7c3e-7d4e-9a1b-2c3d4e5f6a7b");
        assert_eq!(
            marker(&receipt),
            "<!-- switchboard-receipt: 0190f5a2-7c3e-7d4e-9a1b-2c3d4e5f6a7b -->"
        );
        assert!(holds_marker(&marker(&receipt)));
        for text in [
            "switchboard-receipt",
            "see <!-- SWITCHBOARD-RECEIPT: x -->",
            "Switchboard-Receipt",
        ] {
            assert!(holds_marker(text), "{text}");
        }
        for text in ["switchboard receipt", "switchboard-receip", "receipt"] {
            assert!(!holds_marker(text), "{text}");
        }
    }

    #[test]
    fn each_refused_path_group_in_any_case_and_at_any_depth() {
        let automation = |path: &str| {
            assert_eq!(
                refused_path(path).map(|refused| refused.group),
                Some(PathGroup::Automation),
                "{path}"
            );
        };
        let instructions = |path: &str| {
            assert_eq!(
                refused_path(path).map(|refused| refused.group),
                Some(PathGroup::InstructionAuthority),
                "{path}"
            );
        };
        for path in [
            ".github/workflows/ci.yml",
            ".GitHub/Workflows/deploy.yaml",
            ".github/workflows/nested/x.yml",
            ".github",
            ".github/workflows",
            ".GITHUB/WORKFLOWS",
            "./.github/workflows/ci.yml",
        ] {
            automation(path);
            assert_eq!(
                refused_path(path).unwrap().sentence,
                "paths under .github/workflows/ carry their own token permission"
            );
        }
        for path in ["atlantis.yaml", "infra/Atlantis.yml", "a/b/c/ATLANTIS.YAML"] {
            automation(path);
            assert_eq!(
                refused_path(path).unwrap().sentence,
                "atlantis.yaml selects Atlantis project names"
            );
        }
        for path in ["AGENTS.md", "docs/agents.md", "a/b/c/Agents.MD"] {
            instructions(path);
            assert_eq!(
                refused_path(path).unwrap().sentence,
                "AGENTS.md is an instruction-authority file"
            );
        }
        for path in [".agents", ".agents/rules.md", "sub/.Agents/x/y.txt"] {
            instructions(path);
            assert_eq!(
                refused_path(path).unwrap().sentence,
                "paths under .agents/ are instruction-authority files"
            );
        }
        for path in [
            "",
            "README.md",
            ".github/CODEOWNERS",
            ".github/actions/setup/action.yml",
            "docs/.github/workflows/x.yml",
            "src/workflows/ci.yml",
            "atlantis.yaml.bak",
            "AGENTS.md.txt",
            "my.agents/file",
            "main.tf",
        ] {
            assert_eq!(refused_path(path), None, "{path}");
        }
    }

    #[test]
    fn a_definite_refusal_names_its_status_and_is_a_vendor_refusal_only_for_a_403() {
        for (status, rate_limited, kind) in [
            (StatusCode::FORBIDDEN, false, ErrorKind::VendorRefusal),
            (StatusCode::FORBIDDEN, true, ErrorKind::Other),
            (StatusCode::TOO_MANY_REQUESTS, true, ErrorKind::Other),
            (StatusCode::NOT_FOUND, false, ErrorKind::Other),
            (StatusCode::UNPROCESSABLE_ENTITY, false, ErrorKind::Other),
            (StatusCode::MOVED_PERMANENTLY, false, ErrorKind::Other),
        ] {
            match refused(status, rate_limited, "the pull request") {
                ToolOutcome::Error(found, sentence) => {
                    assert_eq!(found, kind, "{status}");
                    assert!(
                        sentence.contains(&format!("HTTP {}", status.as_u16())),
                        "{sentence}"
                    );
                }
                other => panic!("{status}: {other:?}"),
            }
        }
    }

    #[test]
    fn once_a_write_may_have_been_sent_every_failure_is_unknown() {
        let failure = ToolOutcome::error(ErrorKind::Other, "it failed");
        let mut writes = Writes::new();
        assert_eq!(writes.failed(failure.clone()), failure);
        writes.may_have_written = true;
        assert_eq!(writes.failed(failure), ToolOutcome::Unknown);
        assert_eq!(completed(Value::Null, None), ToolOutcome::Unknown);
        assert_eq!(
            completed(Value::Null, Some(7)),
            ToolOutcome::Completed(Value::Null, VendorReference::new("pull/7"))
        );
    }
}
