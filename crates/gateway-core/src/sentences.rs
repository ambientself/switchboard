//! Every sentence the gateway refuses with, in one place.
//!
//! Each is a template with named `{placeholders}`. A refusal is a sentence a model can act on:
//! it says what disagreed, naming the tool, the surface or both teams, and what to do instead.
//! The text rendered here is both what the caller receives and what the audit record stores,
//! so the two cannot drift apart.
//!
//! The module is private. A denial's sentence leaves the crate only on a
//! [`Refusal`](crate::audit::Refusal), after its row is written; the audit-failure sentence only
//! through [`AuditFailure::sentence`](crate::audit::AuditFailure::sentence); and the identity
//! failure sentence, which no decision produces, is re-exported as
//! [`IDENTITY_FAILURE`](crate::IDENTITY_FAILURE).
//!
//! Every value put into a sentence passes through [`safe`]: control characters, non-ASCII,
//! backticks and backslashes are escaped and the length is capped, because some of these
//! values (the tool and surface a request names, a resource identifier) are chosen by the
//! caller.

use crate::classification::Classification;
use crate::decision::{DelegationProblem, Reason, ResourceProblem};
use crate::names::MAX_TOOL_NAME;
use crate::principal::{Principal, PrincipalKind};

/// The profile the context names is not in the snapshot.
const PROFILE_UNKNOWN: &str = "This gateway has no policy profile `{profile}`, so it cannot decide this call and has refused it. This is a fault in the gateway's configuration; report it to the gateway's operators.";

/// The tool is not approved anywhere, or not on this surface. One sentence for both, so a
/// caller cannot learn which tool names exist (decision 0007); the audit record keeps the two
/// kinds apart.
const TOOL_NOT_AVAILABLE: &str = "Tool `{tool}` is not available on surface `{surface}`. Call `tools/list` to see the tools this surface serves.";

/// The requested name is not a valid tool name. The name is shown escaped and cut short.
const INVALID_TOOL_NAME: &str = "The requested tool `{tool}` is not a valid tool name: a tool name is 1 to 64 ASCII letters, digits, `_` or `-`. Call `tools/list` to see the tools this surface serves.";

/// The principal may not use the surface.
const SURFACE_NOT_PERMITTED: &str = "Surface `{surface}` is not available to {principal}. Use a surface your team or groups are permitted to use.";

/// The delegation lists its tools, and not this one.
const TOOL_NOT_IN_DELEGATION: &str = "Tool `{tool}` is not among the tools this delegation permits. Call only the tools the delegation lists.";

/// The profile requires a delegation, and there was none.
const DELEGATION_MISSING: &str = "Profile `{profile}` requires a delegation saying whom this call acts for, and the call carried none. Present the delegation issued for this work.";

/// The delegation's team is not the principal's.
const DELEGATION_TEAM_MISMATCH: &str = "The delegation was issued for team `{delegated_team}`, but the caller is proved to belong to team `{proved_team}`. Present a delegation issued for team `{proved_team}`.";

/// A delegation was presented by a user, who has no team.
const DELEGATION_WITHOUT_TEAM: &str = "The delegation was issued for team `{delegated_team}`, but the caller is user `{subject}` from issuer `{issuer}`, who belongs to no team. Only a workload of the team a delegation was issued for may present it.";

/// The tool is destructive. Its own sentence, because no profile can change the answer.
const DESTRUCTIVE: &str = "Tool `{tool}` is classified `destructive`, and destructive tools are denied in every profile. Ask a person to make this change.";

/// The tool is a direct write. Its own sentence, because no profile can change the answer, and
/// because the caller can usually do what it wanted by proposing instead.
const DIRECT_WRITE: &str = "Tool `{tool}` is classified `write`: it changes something directly instead of proposing a change for a person to review, and direct writes are denied in every profile. Use a tool that proposes the change, or ask a person to make it.";

/// The profile does not permit the tool's classification.
const CLASSIFICATION_NOT_PERMITTED: &str = "Tool `{tool}` is classified `{classification}`, which profile `{profile}` does not permit. Choose a tool whose classification this profile permits.";

/// A named resource is outside the caller's limit.
const RESOURCE_OUTSIDE_LIMIT: &str = "Tool `{tool}` names {system} {kind} `{identifier}`, which is outside what {principal} may reach. Name only resources within that limit.";

/// The resources are unknown and the tool does not check its own scope.
const RESOURCES_UNKNOWN: &str = "Tool `{tool}` cannot say which resources this call names before it runs, and it does not check its own scope, so the call cannot be allowed. Call a tool that names the resources it touches.";

/// The tool declares its resources and the call named none.
const RESOURCES_NONE_NAMED: &str = "Tool `{tool}` reaches resources the gateway must check, and this call named none of them, so it cannot be allowed. Name the resource the call is for.";

/// How a workload is named inside another sentence.
const WORKLOAD: &str = "workload `{subject}` of team `{team}` from issuer `{issuer}`";

/// How a user is named inside another sentence.
const USER: &str = "user `{subject}` from issuer `{issuer}`";

/// The one sentence for every identity failure. Which check failed is logged for operators and
/// never returned, so a caller cannot learn which subjects exist or why a token was refused.
pub const IDENTITY_FAILURE: &str =
    "The gateway could not verify who is calling, so the call was refused.";

/// The sentence for a call refused because its audit row could not be written.
pub(crate) const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// The longest a value is rendered, in characters after escaping, before it is cut short.
pub(crate) const MAX_RENDERED: usize = 128;

/// Every complete-sentence template, for the tests that check them all.
#[cfg(test)]
const SENTENCES: [&str; 16] = [
    PROFILE_UNKNOWN,
    TOOL_NOT_AVAILABLE,
    INVALID_TOOL_NAME,
    SURFACE_NOT_PERMITTED,
    TOOL_NOT_IN_DELEGATION,
    DELEGATION_MISSING,
    DELEGATION_TEAM_MISMATCH,
    DELEGATION_WITHOUT_TEAM,
    DESTRUCTIVE,
    DIRECT_WRITE,
    CLASSIFICATION_NOT_PERMITTED,
    RESOURCE_OUTSIDE_LIMIT,
    RESOURCES_UNKNOWN,
    RESOURCES_NONE_NAMED,
    IDENTITY_FAILURE,
    AUDIT_FAILURE,
];

/// The sentence for `reason`.
pub(crate) fn render(reason: &Reason) -> String {
    use Piece::Text;
    let rendered = match reason {
        Reason::ProfileUnknown { profile } => {
            fill(PROFILE_UNKNOWN, &[("profile", Text(profile.as_str()))])
        }
        Reason::UnknownTool { tool, surface } => match tool.name() {
            Ok(name) => fill(
                TOOL_NOT_AVAILABLE,
                &[
                    ("tool", Text(name.as_str())),
                    ("surface", Text(surface.as_str())),
                ],
            ),
            Err(_) => fill(
                INVALID_TOOL_NAME,
                &[("tool", Piece::Capped(tool.as_str(), MAX_TOOL_NAME))],
            ),
        },
        Reason::ToolNotOnSurface { tool, surface } => fill(
            TOOL_NOT_AVAILABLE,
            &[
                ("tool", Text(tool.as_str())),
                ("surface", Text(surface.as_str())),
            ],
        ),
        Reason::SurfaceNotPermitted { surface, principal } => {
            let principal = describe(principal);
            fill(
                SURFACE_NOT_PERMITTED,
                &[
                    ("surface", Text(surface.as_str())),
                    ("principal", Piece::Rendered(&principal)),
                ],
            )
        }
        Reason::ToolNotInDelegation { tool } => {
            fill(TOOL_NOT_IN_DELEGATION, &[("tool", Text(tool.as_str()))])
        }
        Reason::DelegationDisagrees(DelegationProblem::Missing { profile }) => {
            fill(DELEGATION_MISSING, &[("profile", Text(profile.as_str()))])
        }
        Reason::DelegationDisagrees(DelegationProblem::TeamMismatch {
            proved_team,
            delegated_team,
        }) => fill(
            DELEGATION_TEAM_MISMATCH,
            &[
                ("proved_team", Text(proved_team.as_str())),
                ("delegated_team", Text(delegated_team.as_str())),
            ],
        ),
        Reason::DelegationDisagrees(DelegationProblem::PrincipalHasNoTeam {
            principal,
            delegated_team,
        }) => fill(
            DELEGATION_WITHOUT_TEAM,
            &[
                ("delegated_team", Text(delegated_team.as_str())),
                ("subject", Text(principal.subject.as_str())),
                ("issuer", Text(principal.issuer.as_str())),
            ],
        ),
        Reason::ClassificationNotPermitted {
            tool,
            classification: Classification::Destructive,
            ..
        } => fill(DESTRUCTIVE, &[("tool", Text(tool.as_str()))]),
        Reason::ClassificationNotPermitted {
            tool,
            classification: Classification::Write,
            ..
        } => fill(DIRECT_WRITE, &[("tool", Text(tool.as_str()))]),
        Reason::ClassificationNotPermitted {
            tool,
            classification,
            profile,
        } => fill(
            CLASSIFICATION_NOT_PERMITTED,
            &[
                ("tool", Text(tool.as_str())),
                ("classification", Text(classification.as_str())),
                ("profile", Text(profile.as_str())),
            ],
        ),
        Reason::ResourceOutsideLimit(ResourceProblem::Outside {
            tool,
            resource,
            principal,
        }) => {
            let principal = describe(principal);
            fill(
                RESOURCE_OUTSIDE_LIMIT,
                &[
                    ("tool", Text(tool.as_str())),
                    ("system", Text(&resource.system)),
                    ("kind", Text(&resource.kind)),
                    ("identifier", Text(&resource.identifier)),
                    ("principal", Piece::Rendered(&principal)),
                ],
            )
        }
        Reason::ResourceOutsideLimit(ResourceProblem::Unknown { tool }) => {
            fill(RESOURCES_UNKNOWN, &[("tool", Text(tool.as_str()))])
        }
        Reason::ResourceOutsideLimit(ResourceProblem::NoneNamed { tool }) => {
            fill(RESOURCES_NONE_NAMED, &[("tool", Text(tool.as_str()))])
        }
    };
    rendered.0
}

fn describe(principal: &Principal) -> Rendered {
    use Piece::Text;
    let id = &principal.id;
    match &principal.kind {
        PrincipalKind::Workload { team } => fill(
            WORKLOAD,
            &[
                ("subject", Text(id.subject.as_str())),
                ("team", Text(team.as_str())),
                ("issuer", Text(id.issuer.as_str())),
            ],
        ),
        PrincipalKind::User { .. } => fill(
            USER,
            &[
                ("subject", Text(id.subject.as_str())),
                ("issuer", Text(id.issuer.as_str())),
            ],
        ),
    }
}

/// Text already built by [`fill`], whose values were made safe when it was.
struct Rendered(String);

/// A value for a placeholder.
enum Piece<'a> {
    /// Untrusted text: made safe and capped at [`MAX_RENDERED`].
    Text(&'a str),
    /// Untrusted text: made safe and capped at the given length.
    Capped(&'a str, usize),
    /// A fragment [`fill`] already rendered, inserted as it is.
    Rendered(&'a Rendered),
}

/// `text` made safe to put inside a sentence or an audit column: printable ASCII stays as it
/// is, a backtick becomes `` \` `` so it cannot close a code span, a backslash becomes `\\`,
/// and anything else (newlines, other control characters, non-ASCII) is written as an escape:
/// `\n`, `\r`, `\t` or `\u{...}`. Because the backslash is escaped too, two different texts
/// never give the same result unless they were cut. The result is cut at `cap` characters and
/// marked with `…`, which cannot otherwise appear, since non-ASCII is escaped.
pub(crate) fn safe(text: &str, cap: usize) -> String {
    let mut out = String::new();
    let mut length = 0;
    for character in text.chars() {
        let piece: String = match character {
            '`' => "\\`".to_owned(),
            '\\' => "\\\\".to_owned(),
            ' ' => " ".to_owned(),
            c if c.is_ascii_graphic() => c.to_string(),
            c => c.escape_default().collect(),
        };
        let added = piece.chars().count();
        if length + added > cap {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        length += added;
    }
    out
}

/// Replaces each `{name}` in `template` with its value, in one pass over the template.
///
/// Values are copied in, never scanned, so a tool name that itself contains `{surface}`
/// cannot pull another value into the sentence. A placeholder with no value is left as it is,
/// where a test will see it.
fn fill(template: &str, values: &[(&str, Piece<'_>)]) -> Rendered {
    let mut sentence = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        sentence.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            rest = &rest[open..];
            break;
        };
        let name = &after[..close];
        match values.iter().find(|(key, _)| *key == name) {
            Some((_, Piece::Text(value))) => sentence.push_str(&safe(value, MAX_RENDERED)),
            Some((_, Piece::Capped(value, cap))) => sentence.push_str(&safe(value, *cap)),
            Some((_, Piece::Rendered(value))) => sentence.push_str(&value.0),
            None => sentence.push_str(&rest[open..open + close + 2]),
        }
        rest = &after[close + 1..];
    }
    sentence.push_str(rest);
    Rendered(sentence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(template: &str, values: &[(&str, &str)]) -> String {
        let pieces: Vec<(&str, Piece<'_>)> = values
            .iter()
            .map(|(key, value)| (*key, Piece::Text(value)))
            .collect();
        fill(template, &pieces).0
    }

    #[test]
    fn every_template_is_a_complete_sentence() {
        for template in SENTENCES {
            let first = template.chars().next();
            assert!(
                first.is_some_and(char::is_uppercase),
                "does not start with a capital: {template}"
            );
            assert!(
                template.ends_with('.'),
                "does not end with a full stop: {template}"
            );
            assert!(!template.contains("  "), "has a double space: {template}");
        }
    }

    /// Pinned as literal text: the constants are the thing under test, so comparing a constant
    /// with itself would prove nothing.
    #[test]
    fn the_two_fixed_sentences_say_what_they_should() {
        assert_eq!(
            IDENTITY_FAILURE,
            "The gateway could not verify who is calling, so the call was refused."
        );
        assert_eq!(
            AUDIT_FAILURE,
            "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later."
        );
        assert!(
            !IDENTITY_FAILURE.contains('{'),
            "the opaque sentence must not vary"
        );
    }

    #[test]
    fn fill_replaces_every_occurrence() {
        assert_eq!(
            text("{a} and {b}, then {a}.", &[("a", "x"), ("b", "y")]),
            "x and y, then x."
        );
    }

    #[test]
    fn fill_does_not_expand_placeholders_inside_values() {
        assert_eq!(
            text(TOOL_NOT_IN_DELEGATION, &[("tool", "{tool}")]),
            "Tool `{tool}` is not among the tools this delegation permits. Call only the tools the delegation lists."
        );
        assert_eq!(text("{a}{b}", &[("a", "{b}"), ("b", "z")]), "{b}z");
    }

    #[test]
    fn fill_leaves_an_unknown_or_unclosed_placeholder_visible() {
        assert_eq!(text("x {nope} y.", &[]), "x {nope} y.");
        assert_eq!(text("x {open", &[]), "x {open");
    }

    #[test]
    fn safe_escapes_what_is_not_printable_ascii() {
        assert_eq!(safe("org/repo-1_A.b", 64), "org/repo-1_A.b");
        assert_eq!(safe("a b", 64), "a b");
        assert_eq!(safe("a\nb", 64), "a\\nb");
        assert_eq!(safe("a\rb\tc\u{0}", 64), "a\\rb\\tc\\u{0}");
        assert_eq!(safe("a`b", 64), "a\\`b");
        assert_eq!(safe("caf\u{e9}", 64), "caf\\u{e9}");
        assert_eq!(safe("\u{202e}", 64), "\\u{202e}");
        assert_eq!(safe("a\\b", 64), "a\\\\b");
    }

    /// Texts that differ before escaping differ after it: a backslash is escaped, so a
    /// literal `\n` and a newline are told apart.
    #[test]
    fn safe_keeps_different_texts_different() {
        for (one, other) in [
            ("a\nb", "a\\nb"),
            ("a`b", "a\\`b"),
            ("\u{e9}", "\\u{e9}"),
            ("\\", "\\\\"),
        ] {
            assert_ne!(safe(one, 64), safe(other, 64), "{one:?} and {other:?}");
        }
    }

    #[test]
    fn safe_caps_the_length() {
        assert_eq!(safe("abcdef", 4), "abcd…");
        assert_eq!(safe("abcd", 4), "abcd");
        assert_eq!(safe("ab\ncd", 3), "ab…");
        let long = safe(&"x".repeat(10_000), MAX_RENDERED);
        assert_eq!(long.chars().count(), MAX_RENDERED + 1);
    }

    #[test]
    fn fill_makes_every_value_safe() {
        assert_eq!(text("`{a}`.", &[("a", "x\n`y")]), "`x\\n\\`y`.");
    }
}
