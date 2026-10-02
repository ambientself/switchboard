//! Every sentence the gateway refuses with, in one place.
//!
//! Each is a template with named `{placeholders}`. A refusal is a sentence a model can act on:
//! it says what disagreed, naming the tool, the surface or both teams, and what to do instead.
//! The text rendered here is both what the caller receives and what the audit record stores,
//! so the two cannot drift apart.
//!
//! Section 10 of the design names three families: named refusals from the decision function,
//! one opaque sentence for every identity failure, and a distinct one for an audit failure.

use crate::decision::{DelegationProblem, Reason, ResourceProblem};
use crate::principal::{Principal, PrincipalKind};

/// The tool is not approved on any surface.
pub const UNKNOWN_TOOL: &str = "Tool `{tool}` is not an approved tool. Call `tools/list` on surface `{surface}` to see the tools you may call.";

/// The tool is approved, but not on this surface.
pub const TOOL_NOT_ON_SURFACE: &str = "Tool `{tool}` is not served on surface `{surface}`. Call `tools/list` on surface `{surface}` to see the tools it serves.";

/// The principal may not use the surface.
pub const SURFACE_NOT_PERMITTED: &str = "Surface `{surface}` is not available to {principal}. Use a surface your team or groups are permitted to use.";

/// The delegation lists its tools, and not this one.
pub const TOOL_NOT_IN_DELEGATION: &str = "Tool `{tool}` is not among the tools this delegation permits. Call only the tools the delegation lists.";

/// The profile requires a delegation, and there was none.
pub const DELEGATION_MISSING: &str = "Profile `{profile}` requires a delegation saying whom this call acts for, and the call carried none. Present the delegation issued for this work.";

/// The delegation's team is not the principal's.
pub const DELEGATION_TEAM_MISMATCH: &str = "The delegation was issued for team `{delegated_team}`, but the caller is proved to belong to team `{proved_team}`. Present a delegation issued for team `{proved_team}`.";

/// A delegation was presented by a user, who has no team.
pub const DELEGATION_WITHOUT_TEAM: &str = "The delegation was issued for team `{delegated_team}`, but the caller is user `{subject}` from issuer `{issuer}`, who belongs to no team. Only a workload of the team a delegation was issued for may present it.";

/// The tool is destructive. Its own sentence, because no profile can change the answer.
pub const DESTRUCTIVE: &str = "Tool `{tool}` is classified `destructive`, and destructive tools are denied in every profile. Ask a person to make this change.";

/// The profile does not permit the tool's classification.
pub const CLASSIFICATION_NOT_PERMITTED: &str = "Tool `{tool}` is classified `{classification}`, which profile `{profile}` does not permit. Choose a tool whose classification this profile permits.";

/// A named resource is outside the caller's limit.
pub const RESOURCE_OUTSIDE_LIMIT: &str = "Tool `{tool}` names {system} {kind} `{identifier}`, which is outside what {principal} may reach. Name only resources within that limit.";

/// The resources are unknown and the tool does not check its own scope.
pub const RESOURCES_UNKNOWN: &str = "Tool `{tool}` cannot say which resources this call names before it runs, and it does not check its own scope, so the call cannot be allowed. Call a tool that names the resources it touches.";

/// How a workload is named inside another sentence.
pub const WORKLOAD: &str = "workload `{subject}` of team `{team}` from issuer `{issuer}`";

/// How a user is named inside another sentence.
pub const USER: &str = "user `{subject}` from issuer `{issuer}`";

/// The one sentence for every identity failure. Which check failed is logged for operators and
/// never returned, so a caller cannot learn which subjects exist or why a token was refused.
pub const IDENTITY_FAILURE: &str =
    "The gateway could not verify who is calling, so the call was refused.";

/// The sentence for a call refused because its audit row could not be written.
pub const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// Every complete-sentence template, for tests that check them all.
pub const SENTENCES: [&str; 13] = [
    UNKNOWN_TOOL,
    TOOL_NOT_ON_SURFACE,
    SURFACE_NOT_PERMITTED,
    TOOL_NOT_IN_DELEGATION,
    DELEGATION_MISSING,
    DELEGATION_TEAM_MISMATCH,
    DELEGATION_WITHOUT_TEAM,
    DESTRUCTIVE,
    CLASSIFICATION_NOT_PERMITTED,
    RESOURCE_OUTSIDE_LIMIT,
    RESOURCES_UNKNOWN,
    IDENTITY_FAILURE,
    AUDIT_FAILURE,
];

/// The sentence for `reason`.
pub(crate) fn render(reason: &Reason) -> String {
    match reason {
        Reason::UnknownTool { tool, surface } => fill(
            UNKNOWN_TOOL,
            &[("tool", tool.as_str()), ("surface", surface.as_str())],
        ),
        Reason::ToolNotOnSurface { tool, surface } => fill(
            TOOL_NOT_ON_SURFACE,
            &[("tool", tool.as_str()), ("surface", surface.as_str())],
        ),
        Reason::SurfaceNotPermitted { surface, principal } => fill(
            SURFACE_NOT_PERMITTED,
            &[
                ("surface", surface.as_str()),
                ("principal", &describe(principal)),
            ],
        ),
        Reason::ToolNotInDelegation { tool } => {
            fill(TOOL_NOT_IN_DELEGATION, &[("tool", tool.as_str())])
        }
        Reason::DelegationDisagrees(DelegationProblem::Missing { profile }) => {
            fill(DELEGATION_MISSING, &[("profile", profile.as_str())])
        }
        Reason::DelegationDisagrees(DelegationProblem::TeamMismatch {
            proved_team,
            delegated_team,
        }) => fill(
            DELEGATION_TEAM_MISMATCH,
            &[
                ("proved_team", proved_team.as_str()),
                ("delegated_team", delegated_team.as_str()),
            ],
        ),
        Reason::DelegationDisagrees(DelegationProblem::PrincipalHasNoTeam {
            principal,
            delegated_team,
        }) => fill(
            DELEGATION_WITHOUT_TEAM,
            &[
                ("delegated_team", delegated_team.as_str()),
                ("subject", principal.subject.as_str()),
                ("issuer", principal.issuer.as_str()),
            ],
        ),
        Reason::ClassificationNotPermitted {
            tool,
            classification,
            profile,
        } => match classification {
            crate::Classification::Destructive => fill(DESTRUCTIVE, &[("tool", tool.as_str())]),
            _ => fill(
                CLASSIFICATION_NOT_PERMITTED,
                &[
                    ("tool", tool.as_str()),
                    ("classification", classification.as_str()),
                    ("profile", profile.as_str()),
                ],
            ),
        },
        Reason::ResourceOutsideLimit(ResourceProblem::Outside {
            tool,
            resource,
            principal,
        }) => fill(
            RESOURCE_OUTSIDE_LIMIT,
            &[
                ("tool", tool.as_str()),
                ("system", &resource.system),
                ("kind", &resource.kind),
                ("identifier", &resource.identifier),
                ("principal", &describe(principal)),
            ],
        ),
        Reason::ResourceOutsideLimit(ResourceProblem::Unknown { tool }) => {
            fill(RESOURCES_UNKNOWN, &[("tool", tool.as_str())])
        }
    }
}

fn describe(principal: &Principal) -> String {
    let id = &principal.id;
    match &principal.kind {
        PrincipalKind::Workload { team } => fill(
            WORKLOAD,
            &[
                ("subject", id.subject.as_str()),
                ("team", team.as_str()),
                ("issuer", id.issuer.as_str()),
            ],
        ),
        PrincipalKind::User { .. } => fill(
            USER,
            &[
                ("subject", id.subject.as_str()),
                ("issuer", id.issuer.as_str()),
            ],
        ),
    }
}

/// Replaces each `{name}` in `template` with its value, in one pass over the template.
///
/// Values are copied in, never scanned, so a tool name that itself contains `{surface}`
/// cannot pull another value into the sentence. A placeholder with no value is left as it is,
/// where a test will see it.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
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
            Some((_, value)) => sentence.push_str(value),
            None => sentence.push_str(&rest[open..open + close + 2]),
        }
        rest = &after[close + 1..];
    }
    sentence.push_str(rest);
    sentence
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_three_families_are_distinct() {
        let named: Vec<&str> = SENTENCES
            .iter()
            .copied()
            .filter(|s| *s != IDENTITY_FAILURE && *s != AUDIT_FAILURE)
            .collect();
        assert_ne!(IDENTITY_FAILURE, AUDIT_FAILURE);
        assert!(!named.contains(&IDENTITY_FAILURE));
        assert!(!named.contains(&AUDIT_FAILURE));
        assert!(
            !IDENTITY_FAILURE.contains('{'),
            "the opaque sentence must not vary"
        );
    }

    #[test]
    fn fill_replaces_every_occurrence() {
        assert_eq!(
            fill("{a} and {b}, then {a}.", &[("a", "x"), ("b", "y")]),
            "x and y, then x."
        );
    }

    #[test]
    fn fill_does_not_expand_placeholders_inside_values() {
        assert_eq!(
            fill(TOOL_NOT_IN_DELEGATION, &[("tool", "{tool}")]),
            "Tool `{tool}` is not among the tools this delegation permits. Call only the tools the delegation lists."
        );
        assert_eq!(fill("{a}{b}", &[("a", "{b}"), ("b", "z")]), "{b}z");
    }

    #[test]
    fn fill_leaves_an_unknown_or_unclosed_placeholder_visible() {
        assert_eq!(fill("x {nope} y.", &[]), "x {nope} y.");
        assert_eq!(fill("x {open", &[]), "x {open");
    }
}
