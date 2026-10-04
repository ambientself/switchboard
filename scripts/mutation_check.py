#!/usr/bin/env python3
"""Break each guard in the policy core, one at a time, and require the tests to notice.

    python3 scripts/mutation_check.py              # every mutation
    python3 scripts/mutation_check.py --list       # what would run
    python3 scripts/mutation_check.py --targets    # check every target still matches, no cargo
    python3 scripts/mutation_check.py ID [ID ...]  # only these

Each mutation is one or more exact text replacements in the crate's source. The script copies
the workspace into a temporary directory, checks that the unmutated copy passes, and then for
each mutation applies it to the copy, runs `cargo test --workspace --locked --no-fail-fast`,
and restores the copy. The working tree is never written to.

Verdicts, one line per mutation:

    CAUGHT      a test failed (the line names which), or, for a mutation marked as meaning to
                break the build, the library itself did not compile
    SURVIVED    every test passed: nothing watches this guard
    ERROR       the mutation's target text did not match exactly once, so the mutation is
                stale and was not run; it is never counted as caught
    NO-VERDICT  cargo failed without a test failing (a test target did not compile, a timeout):
                nothing was learned

The exit status is zero only if every mutation was caught. CI does not run this: it is one
full test run per mutation. Run it after changing a guard or the tests that watch one, and add
a mutation for every guard you add.

Needs Python 3.12 or later and nothing outside the standard library.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

if sys.version_info < (3, 12):
    sys.exit("mutation_check.py needs Python 3.12 or later")

ROOT = Path(__file__).resolve().parent.parent
CRATE = "crates/gateway-core/"
SRC = CRATE + "src/"
REGRESSIONS = CRATE + "tests/properties.proptest-regressions"
TIMEOUT_SECONDS = 1200


@dataclass(frozen=True)
class Edit:
    path: str
    old: str
    new: str


@dataclass(frozen=True)
class Mutation:
    id: str
    description: str
    edits: tuple[Edit, ...]
    # The intended effect is that the library itself does not compile. Only then does a build
    # failure count as caught; for every other mutation it is no verdict.
    breaks_build: bool = False


MUTATIONS: list[Mutation] = []


def mutate(id: str, description: str, path: str, old: str, new: str, *, breaks_build: bool = False) -> None:
    MUTATIONS.append(Mutation(id, description, (Edit(path, old, new),), breaks_build))


def mutate_all(id: str, description: str, *edits: tuple[str, str, str]) -> None:
    MUTATIONS.append(Mutation(id, description, tuple(Edit(*edit) for edit in edits)))


# --- The order of the checks --------------------------------------------------------------

CHECK = {
    0: "    let profile = profile_is_known(snapshot, &caller.profile)?;\n",
    1: "    surface_is_permitted(snapshot, caller, principal)?;\n",
    2: "    let tool = tool_is_approved_on_surface(snapshot, &caller.surface, tool)?;\n",
    3: "    delegation_agrees(caller, profile, principal)?;\n",
    4: "    delegation_lists_tool(caller.delegation.as_ref(), tool)?;\n",
    5: "    classification_is_permitted(profile, tool)?;\n",
    6: (
        "    if let Some(resources) = resources {\n"
        "        resources_are_within_limit(snapshot.limits(), principal, tool, resources)?;\n"
        "    }\n"
    ),
}
for first, second in [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6)]:
    mutate(
        f"order-swap-{first}-{second}",
        f"checks {first} and {second} run in the other order",
        SRC + "decision.rs",
        CHECK[first] + CHECK[second],
        CHECK[second] + CHECK[first],
    )
mutate(
    "order-swap-3-5",
    "check 5 runs before checks 3 and 4",
    SRC + "decision.rs",
    CHECK[3] + CHECK[4] + CHECK[5],
    CHECK[5] + CHECK[3] + CHECK[4],
)
for number in (1, 3, 4, 5, 6):
    mutate(f"check-{number}-removed", f"check {number} is not run", SRC + "decision.rs", CHECK[number], "")

# --- Check 0: the profile ------------------------------------------------------------------

mutate(
    "profile-unknown-falls-back",
    "a profile the snapshot does not hold falls back to the `otto` profile",
    SRC + "decision.rs",
    "        .profile(profile)\n        .ok_or_else(",
    '        .profile(profile)\n        .or_else(|| snapshot.profile(&ProfileName::new("otto")))\n        .ok_or_else(',
)

# --- Check 1: the surface ------------------------------------------------------------------

mutate(
    "surface-unknown-passes",
    "a surface that does not exist passes check 1",
    SRC + "decision.rs",
    "        Some(surface) if surface.permits(principal) => Ok(()),\n",
    "        Some(surface) if surface.permits(principal) => Ok(()),\n        None => Ok(()),\n",
)
RESTRICTION = "            PrincipalRestriction::Only(principals) => principals.contains(&principal.id),"
mutate(
    "surface-restriction-ignores-issuer",
    "a surface's principal restriction compares subjects only",
    SRC + "policy.rs",
    RESTRICTION,
    "            PrincipalRestriction::Only(principals) => principals.iter().any(|p| p.subject == principal.id.subject),",
)
mutate(
    "surface-restriction-ignored",
    "a surface's principal restriction admits everyone",
    SRC + "policy.rs",
    RESTRICTION,
    "            PrincipalRestriction::Only(_) => true,",
)
mutate(
    "surface-restriction-or",
    "a principal restriction admits on its own, without the allowlist",
    SRC + "policy.rs",
    "        by_team_or_group && by_principal",
    "        by_team_or_group || (matches!(self.principals, PrincipalRestriction::Only(_)) && by_principal)",
)
mutate(
    "surface-user-needs-every-group",
    "a user must be in every listed group",
    SRC + "policy.rs",
    "!self.groups.is_disjoint(groups)",
    "!groups.is_empty() && groups.is_subset(&self.groups)",
)
mutate(
    "surface-user-admitted-by-team-name",
    "a user whose group is named like a listed team is admitted",
    SRC + "policy.rs",
    "            PrincipalKind::User { groups } => !self.groups.is_disjoint(groups),",
    "            PrincipalKind::User { groups } => !self.groups.is_disjoint(groups) || groups.iter().any(|g| self.teams.contains(&TeamId::new(g.as_str()))),",
)
mutate(
    "surface-workload-admitted-by-group-name",
    "a workload whose team is named like a listed group is admitted",
    SRC + "policy.rs",
    "            PrincipalKind::Workload { team } => self.teams.contains(team),",
    "            PrincipalKind::Workload { team } => self.teams.contains(team) || self.groups.contains(&GroupId::new(team.as_str())),",
)

# --- Check 2: the tool ---------------------------------------------------------------------

mutate(
    "tool-on-any-surface",
    "a tool approved anywhere counts as approved on every surface",
    SRC + "policy.rs",
    "            .filter(|surface| surface.tools.contains(name))\n",
    "",
)
mutate(
    "tool-reasons-swapped",
    "unknown tool and tool not on this surface are recorded as each other",
    SRC + "decision.rs",
    "        Some(_) => Reason::ToolNotOnSurface {\n            tool: name,\n            surface: surface.clone(),\n        },\n        None => unknown(),",
    "        Some(_) => unknown(),\n        None => Reason::ToolNotOnSurface {\n            tool: name,\n            surface: surface.clone(),\n        },",
)
mutate(
    "denied-tool-resolved-off-surface",
    "a denial records the classification of a tool the surface does not serve",
    SRC + "decision.rs",
    "                .and_then(|name| snapshot.tool_on_surface(&call.caller.surface, &name))",
    "                .and_then(|name| snapshot.tool(&name))",
)
NAME_RULE = "                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');"
mutate(
    "tool-name-allows-dot",
    "a tool name may contain `.`",
    SRC + "names.rs",
    NAME_RULE,
    "                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.');",
)
mutate(
    "tool-name-allows-newline",
    "a tool name may contain a newline",
    SRC + "names.rs",
    NAME_RULE,
    "                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'\\n');",
)
mutate(
    "tool-name-65-characters",
    "a tool name may be 65 characters",
    SRC + "names.rs",
    "            && value.len() <= MAX_TOOL_NAME\n",
    "            && value.len() <= MAX_TOOL_NAME + 1\n",
)
mutate(
    "tool-name-may-be-empty",
    "a tool name may be empty",
    SRC + "names.rs",
    "        let valid = !value.is_empty()\n            && value.len()",
    "        let valid = value.len()",
)
mutate(
    "tool-name-unchecked-conversion",
    "a tool name can be made from any string without checking it",
    SRC + "names.rs",
    "impl std::str::FromStr for ToolName {",
    "impl From<&str> for ToolName {\n    fn from(value: &str) -> Self {\n        Self(value.to_owned())\n    }\n}\n\nimpl std::str::FromStr for ToolName {",
)

# --- Checks 3 and 4: the delegation --------------------------------------------------------

mutate(
    "delegation-missing-accepted",
    "a profile that requires a delegation accepts a call without one",
    SRC + "decision.rs",
    "        return if profile.requires_delegation {",
    "        return if false && profile.requires_delegation {",
)
mutate(
    "delegation-checked-only-if-required",
    "a delegation is ignored by check 3 where the profile does not require one",
    SRC + "decision.rs",
    "    let delegated_team = &delegation.get().team;\n",
    "    if !profile.requires_delegation {\n        return Ok(());\n    }\n    let delegated_team = &delegation.get().team;\n",
)
mutate(
    "delegation-from-user-accepted",
    "a user presenting a delegation passes check 3",
    SRC + "decision.rs",
    "        None => Err(Reason::DelegationDisagrees(\n            DelegationProblem::PrincipalHasNoTeam {",
    "        None if true => Ok(()),\n        None => Err(Reason::DelegationDisagrees(\n            DelegationProblem::PrincipalHasNoTeam {",
)
mutate(
    "delegation-empty-list-narrows-nothing",
    "a delegation that lists no tools narrows nothing",
    SRC + "decision.rs",
    "Some(permitted) if !permitted.contains(&tool.name)",
    "Some(permitted) if !permitted.is_empty() && !permitted.contains(&tool.name)",
)
mutate(
    "delegation-tools-may-be-omitted",
    "a delegation's tool list may be left out, and then narrows nothing",
    SRC + "principal.rs",
    '    #[serde(deserialize_with = "present")]\n    pub tools',
    "    #[serde(default)]\n    pub tools",
)

# --- Check 5: the classification -----------------------------------------------------------

mutate(
    "destructive-permitted-by-profile",
    "a destructive tool is allowed by a profile that lists destructive",
    SRC + "decision.rs",
    "    let permitted = tool.classification != Classification::Destructive\n        && profile",
    "    let permitted = profile",
)
CLASSIFICATION_MATCH = "            .find(|classification| classification.as_str() == value)"
for id, description, replacement in [
    ("classification-any-case", "a classification parses in any case", "classification.as_str().eq_ignore_ascii_case(value)"),
    ("classification-trimmed", "a classification parses with spaces around it", "classification.as_str() == value.trim()"),
    ("classification-prefix", "a classification parses from anything starting with it", "value.starts_with(classification.as_str())"),
]:
    mutate(id, description, SRC + "classification.rs", CLASSIFICATION_MATCH, f"            .find(|classification| {replacement})")
mutate(
    "classification-unknown-is-read",
    "an unrecognized classification parses as read",
    SRC + "classification.rs",
    "            .ok_or_else(|| UnrecognizedClassification(value.to_owned()))",
    "            .or(Some(Classification::Read))\n            .ok_or_else(|| UnrecognizedClassification(value.to_owned()))",
)
mutate(
    "classification-empty-is-write",
    "an empty classification parses as write",
    SRC + "classification.rs",
    "        Classification::ALL\n            .into_iter()\n            .find(",
    "        if value.is_empty() {\n            return Ok(Classification::Write);\n        }\n        Classification::ALL\n            .into_iter()\n            .find(",
)
mutate_all(
    "classification-lenient-configuration",
    "configuration reads an unrecognized classification as read",
    (SRC + "classification.rs", "#[serde(try_from = \"String\", into = \"&'static str\")]", "#[serde(from = \"LenientClass\", into = \"&'static str\")]"),
    (
        SRC + "classification.rs",
        "impl fmt::Display for Classification {",
        "#[derive(Deserialize)]\n#[serde(transparent)]\nstruct LenientClass(String);\nimpl From<LenientClass> for Classification {\n    fn from(v: LenientClass) -> Self {\n        v.0.parse().unwrap_or(Classification::Read)\n    }\n}\nimpl fmt::Display for Classification {",
    ),
)
mutate(
    "classification-misnamed",
    "read is written as `reader`",
    SRC + "classification.rs",
    'Classification::Read => "read",',
    'Classification::Read => "reader",',
)

# --- Check 6: the resources ----------------------------------------------------------------

NAMED_SCAN = "            match named\n                .iter()\n                .find("
mutate("resources-first-only", "check 6 looks only at the first named resource", SRC + "decision.rs", NAMED_SCAN,
       "            match named\n                .iter().take(1)\n                .find(")
mutate("resources-last-only", "check 6 looks only at the last named resource", SRC + "decision.rs", NAMED_SCAN,
       "            match named\n                .iter().rev().take(1)\n                .find(")
mutate("resources-reports-last", "check 6 reports the last resource outside the limit", SRC + "decision.rs", NAMED_SCAN,
       "            match named\n                .iter().rev()\n                .find(")
mutate(
    "resources-unknown-allowed-when-declared",
    "unknown resources are allowed for a tool that declares its resources",
    SRC + "decision.rs",
    "        (Resources::Unknown, ResourceDeclaration::ChecksOwnScope) => return Ok(()),",
    "        (Resources::Unknown, ResourceDeclaration::ChecksOwnScope | ResourceDeclaration::Declared) => return Ok(()),",
)
mutate(
    "resources-unknown-allowed-when-none",
    "unknown resources are allowed for a tool that reaches none",
    SRC + "decision.rs",
    "        (Resources::Unknown, ResourceDeclaration::ChecksOwnScope) => return Ok(()),",
    "        (Resources::Unknown, ResourceDeclaration::ChecksOwnScope | ResourceDeclaration::NoResources) => return Ok(()),",
)
mutate(
    "resources-none-named-allowed",
    "a tool that declares its resources is allowed when the call names none",
    SRC + "decision.rs",
    "                None if named.is_empty() && declaration == ResourceDeclaration::Declared => {",
    "                None if false && named.is_empty() && declaration == ResourceDeclaration::Declared => {",
)
mutate(
    "resources-skipped-for-users",
    "check 6 is skipped for users",
    SRC + "decision.rs",
    "    let problem = match (resources, tool.resources) {",
    "    if matches!(principal.kind, crate::principal::PrincipalKind::User { .. }) {\n        return Ok(());\n    }\n    let problem = match (resources, tool.resources) {",
)
TEAM_LIMIT = ".is_some_and(|allowed| allowed.contains(resource)),"
USER_LIMIT = ".is_some_and(|allowed| allowed.contains(resource))\n            }),"
FIELDS = ["system", "kind", "identifier"]
for field in FIELDS:
    same = " && ".join(f"r.{other} == resource.{other}" for other in FIELDS if other != field)
    mutate(f"limit-team-ignores-{field}", f"a team limit ignores {field}", SRC + "policy.rs", TEAM_LIMIT,
           f".is_some_and(|allowed| allowed.iter().any(|r| {same})),")
    mutate(f"limit-user-ignores-{field}", f"a group limit ignores {field}", SRC + "policy.rs", USER_LIMIT,
           f".is_some_and(|allowed| allowed.iter().any(|r| {same}))\n            }}),")
SAME_SYSTEM_KIND = "r.system == resource.system && r.kind == resource.kind"
mutate("limit-team-identifier-any-case", "a team limit matches identifiers in any case", SRC + "policy.rs", TEAM_LIMIT,
       f".is_some_and(|allowed| allowed.iter().any(|r| {SAME_SYSTEM_KIND} && r.identifier.eq_ignore_ascii_case(&resource.identifier))),")
mutate("limit-team-identifier-prefix", "a team limit matches identifiers that start with it", SRC + "policy.rs", TEAM_LIMIT,
       f".is_some_and(|allowed| allowed.iter().any(|r| {SAME_SYSTEM_KIND} && resource.identifier.starts_with(&r.identifier))),")
mutate("limit-user-identifier-any-case", "a group limit matches identifiers in any case", SRC + "policy.rs", USER_LIMIT,
       f".is_some_and(|allowed| allowed.iter().any(|r| {SAME_SYSTEM_KIND} && r.identifier.eq_ignore_ascii_case(&resource.identifier)))\n            }}),")
mutate("limit-user-identifier-prefix", "a group limit matches identifiers that start with it", SRC + "policy.rs", USER_LIMIT,
       f".is_some_and(|allowed| allowed.iter().any(|r| {SAME_SYSTEM_KIND} && resource.identifier.starts_with(&r.identifier)))\n            }}),")
mutate("limit-user-needs-every-group", "a user's resource must be in every group's limit", SRC + "policy.rs",
       "PrincipalKind::User { groups } => groups.iter().any(|group| {", "PrincipalKind::User { groups } => groups.iter().all(|group| {")
mutate("limit-user-falls-back-to-team", "a user's group falls back to the limit of a team with its name", SRC + "policy.rs",
       "self.groups\n                    .get(group)", "self.groups\n                    .get(group).or_else(|| self.teams.get(&TeamId::new(group.as_str())))")
mutate("limit-team-falls-back-to-group", "a workload's team falls back to the limit of a group with its name", SRC + "policy.rs",
       ".teams\n                .get(team)", ".teams\n                .get(team).or_else(|| self.groups.get(&GroupId::new(team.as_str())))")

# --- tools/list ----------------------------------------------------------------------------

LIST = "        .filter_map(|tool| check(snapshot, caller, &tool.clone().into(), None).ok())"
mutate("list-ignores-delegation", "tools/list ignores the delegation", SRC + "decision.rs", LIST,
       "        .filter_map(|tool| check(snapshot, &CallerContext { delegation: None, ..caller.clone() }, &tool.clone().into(), None).ok())")
mutate("list-checks-empty-resources", "tools/list decides with an empty resource list instead of none", SRC + "decision.rs", LIST,
       "        .filter_map(|tool| check(snapshot, caller, &tool.clone().into(), Some(&Resources::Named(Vec::new()))).ok())")

# --- The snapshot --------------------------------------------------------------------------

mutate("snapshot-duplicate-tool", "a tool approved twice is accepted", SRC + "policy.rs",
       "return Err(SnapshotError::DuplicateTool(previous.name));", "let _ = previous;")
mutate("snapshot-duplicate-surface", "a surface defined twice is accepted", SRC + "policy.rs",
       "return Err(SnapshotError::DuplicateSurface(previous.name));", "let _ = previous;")
mutate("snapshot-duplicate-profile", "a profile defined twice is accepted", SRC + "policy.rs",
       "return Err(SnapshotError::DuplicateProfile(previous.name));", "let _ = previous;")
mutate("snapshot-unapproved-tool", "a surface may serve an unapproved tool", SRC + "policy.rs",
       "find(|tool| !tools.contains_key(*tool))", "find(|tool| false && !tools.contains_key(*tool))")
for struct in ("Surface", "ApprovedTool"):
    mutate(f"unknown-fields-{struct}", f"{struct} accepts unknown fields", SRC + "policy.rs",
           f"#[serde(deny_unknown_fields)]\npub struct {struct} {{", f"pub struct {struct} {{")
mutate("unknown-fields-AuditRecord", "AuditRecord accepts unknown fields", SRC + "audit.rs",
       "#[serde(deny_unknown_fields)]\npub struct AuditRecord {", "pub struct AuditRecord {")
mutate_all(
    "surface-restriction-default",
    "a surface with no principal restriction written reads as unrestricted",
    (SRC + "policy.rs", "    pub principals: PrincipalRestriction,", '    #[serde(default = "unrestricted")]\n    pub principals: PrincipalRestriction,'),
    (SRC + "policy.rs", "impl Surface {", "fn unrestricted() -> PrincipalRestriction {\n    PrincipalRestriction::AnyInTeamsAndGroups\n}\n\nimpl Surface {"),
)
mutate_all(
    "tool-resources-default",
    "a tool with no resource declaration written reads as checking its own scope",
    (SRC + "policy.rs", "    pub resources: ResourceDeclaration,", '    #[serde(default = "self_checked")]\n    pub resources: ResourceDeclaration,'),
    (SRC + "policy.rs", "impl Surface {", "fn self_checked() -> ResourceDeclaration {\n    ResourceDeclaration::ChecksOwnScope\n}\n\nimpl Surface {"),
)

# --- Principals and proof ------------------------------------------------------------------

mutate_all(
    "principal-id-ignores-issuer",
    "principal identifiers compare, order and hash by subject alone",
    (SRC + "principal.rs", "#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\npub struct PrincipalId {",
     "#[derive(Clone, Debug, Serialize, Deserialize)]\npub struct PrincipalId {"),
    (SRC + "principal.rs", "/// What kind of caller a principal is, and the facts that come with that kind.",
     "impl PartialEq for PrincipalId {\n    fn eq(&self, o: &Self) -> bool {\n        self.subject == o.subject\n    }\n}\nimpl Eq for PrincipalId {}\n"
     "impl PartialOrd for PrincipalId {\n    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {\n        Some(self.cmp(o))\n    }\n}\n"
     "impl Ord for PrincipalId {\n    fn cmp(&self, o: &Self) -> std::cmp::Ordering {\n        self.subject.cmp(&o.subject)\n    }\n}\n"
     "impl std::hash::Hash for PrincipalId {\n    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {\n        self.subject.hash(h)\n    }\n}\n"
     "/// What kind of caller a principal is, and the facts that come with that kind."),
)
mutate_all(
    "principal-ignores-issuer",
    "principals compare by subject and kind alone",
    (SRC + "principal.rs", "#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\npub struct Principal {",
     "#[derive(Clone, Debug, Serialize, Deserialize)]\npub struct Principal {"),
    (SRC + "principal.rs", "impl Principal {\n",
     "impl PartialEq for Principal {\n    fn eq(&self, o: &Self) -> bool {\n        self.id.subject == o.id.subject && self.kind == o.kind\n    }\n}\nimpl Eq for Principal {}\nimpl Principal {\n"),
)
mutate("proved-field-public", "a proved value can be built from outside", SRC + "proof.rs",
       "pub struct Proved<T>(T);", "pub struct Proved<T>(pub T);")
mutate("proved-constructor", "a proved value has a public constructor", SRC + "proof.rs",
       "impl<T> Proved<T> {\n", "impl<T> Proved<T> {\n    /// Broken on purpose.\n    pub fn new(value: T) -> Self {\n        Self(value)\n    }\n\n")
mutate("proved-from-claimed", "a claimed value converts into a proved one", SRC + "proof.rs",
       "impl<T: Provable> Proved<T> {", "impl<T: Provable> From<Claimed<T>> for Proved<T> {\n    fn from(c: Claimed<T>) -> Self {\n        Proved(c.0)\n    }\n}\n\nimpl<T: Provable> Proved<T> {")
mutate("proved-deserialize", "a proved value can be read from JSON", SRC + "proof.rs",
       "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct Proved<T>(T);", "#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]\n#[serde(transparent)]\npub struct Proved<T>(T);")
mutate_all(
    "provable-team",
    "a verifier may prove a bare team",
    (SRC + "proof.rs", "    impl Sealed for crate::principal::Delegation {}", "    impl Sealed for crate::principal::Delegation {}\n    impl Sealed for crate::names::TeamId {}"),
    (SRC + "proof.rs", "impl Provable for Delegation {}", "impl Provable for Delegation {}\nimpl Provable for crate::names::TeamId {}"),
)

# --- The audited path ----------------------------------------------------------------------

mutate("decision-clone", "a decision can be copied", SRC + "decision.rs",
       "#[derive(Debug, PartialEq, Eq)]\npub struct Decision {", "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct Decision {")
mutate("decision-fields-public", "a decision can be built without deciding", SRC + "decision.rs",
       "pub struct Decision {\n    call: CallContext,\n    verdict: Verdict,\n    policy_revision: PolicyRevision,",
       "pub struct Decision {\n    pub call: CallContext,\n    pub verdict: Verdict,\n    pub policy_revision: PolicyRevision,")
mutate("decision-revision-constant", "a decision records a fixed revision", SRC + "decision.rs",
       "policy_revision: snapshot.revision().clone(),", 'policy_revision: PolicyRevision::new("x"),')
mutate("sentence-public", "a denial's sentence can be rendered without its row", SRC + "decision.rs",
       "    pub(crate) fn sentence(&self) -> String {", "    pub fn sentence(&self) -> String {")
mutate("guard-clone", "a guard can be copied", SRC + "audit.rs",
       "#[derive(Debug)]\npub struct AuditGuard {", "#[derive(Clone, Debug)]\npub struct AuditGuard {")
mutate("guard-fields-public", "a guard can be built by hand", SRC + "audit.rs",
       "pub struct AuditGuard {\n    row: AuditRowId,\n    call: CallContext,\n    tool: ApprovedTool,\n    arguments: serde_json::Value,",
       "pub struct AuditGuard {\n    pub row: AuditRowId,\n    pub call: CallContext,\n    pub tool: ApprovedTool,\n    pub arguments: serde_json::Value,")
mutate("guard-constructor", "a guard has a public constructor", SRC + "audit.rs",
       "impl AuditGuard {\n", "impl AuditGuard {\n    /// Broken on purpose.\n    pub fn new(row: AuditRowId, call: CallContext, tool: ApprovedTool) -> Self {\n        Self { row, call, tool, arguments: serde_json::Value::Null }\n    }\n\n")
mutate("refusal-fields-public", "a refusal can be built or rewritten by hand", SRC + "audit.rs",
       "pub struct Refusal {\n    row: AuditRowId,\n    reason: Reason,\n    sentence: String,",
       "pub struct Refusal {\n    pub row: AuditRowId,\n    pub reason: Reason,\n    pub sentence: String,")
mutate("ran-fields-public", "a run can be made up", SRC + "audit.rs",
       "pub struct Ran {\n    row: AuditRowId,\n    outcome: ToolOutcome,", "pub struct Ran {\n    pub row: AuditRowId,\n    pub outcome: ToolOutcome,")
mutate("row-completion-fields-public", "a store's finish can be called for any row", SRC + "audit.rs",
       "pub struct RowCompletion {\n    row: AuditRowId,\n    completion: Completion,", "pub struct RowCompletion {\n    pub row: AuditRowId,\n    pub completion: Completion,")
mutate("tool-call-constructor-public", "a connector can be called around the audited path", SRC + "connector.rs",
       "    pub(crate) fn new(call: CallContext", "    pub fn new(call: CallContext")
mutate("connector-run-without-call", "a connector runs without being handed the call", SRC + "connector.rs",
       "    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome>;", "    fn run(&self) -> BoxFuture<'_, ToolOutcome>;", breaks_build=True)
mutate("run-drops-arguments", "the connector is not given the call's arguments", SRC + "audit.rs",
       "connector.run(ToolCall::new(call, tool, arguments))", "connector.run(ToolCall::new(call, tool, serde_json::Value::Null))")
mutate(
    "guard-for-denied-tool",
    "begin hands out a guard for a denial whose tool the surface serves",
    SRC + "audit.rs",
    "        Decided::Deny {\n            reason, sentence, ..\n        } => Begun::Denied(Refusal {",
    "        Decided::Deny { tool: Some(tool), .. } => Begun::Allowed(AuditGuard {\n            row,\n            call,\n            tool,\n            arguments,\n        }),\n        Decided::Deny {\n            reason, sentence, ..\n        } => Begun::Denied(Refusal {",
)
mutate(
    "begin-failure-on-denial-swallowed",
    "a denial is answered even when its row could not be written",
    SRC + "audit.rs",
    "    let row = store\n        .begin(&record)\n        .await\n        .map_err(AuditFailure::from_store)?;",
    '    let row = match store.begin(&record).await {\n        Ok(row) => row,\n        Err(error) => match &decided {\n            Decided::Deny { .. } => AuditRowId::new("unwritten"),\n            Decided::Allow(_) => return Err(AuditFailure::from_store(error)),\n        },\n    };',
)
REFUSAL = "        } => Begun::Denied(Refusal {\n            row,\n            reason,\n            sentence,\n        }),"
mutate("refusal-sentence-truncated", "the caller's sentence is not the recorded one", SRC + "audit.rs", REFUSAL,
       "        } => Begun::Denied(Refusal {\n            row,\n            reason,\n            sentence: sentence.split('.').next().unwrap_or_default().to_owned(),\n        }),")
mutate("refusal-sentence-lowercased-for-delegation", "the caller's sentence differs for delegation denials", SRC + "audit.rs", REFUSAL,
       "        } => Begun::Denied(Refusal {\n            row,\n            sentence: if reason.kind() == ReasonKind::DelegationDisagrees { sentence.to_lowercase() } else { sentence },\n            reason,\n        }),")
RECORDED_SENTENCE = "            Some(sentence.clone()),\n        ),"
mutate("record-sentence-blank-for-unknown", "the row's sentence is blank when the tool is unknown", SRC + "audit.rs", RECORDED_SENTENCE,
       "            Some(if tool.is_none() { String::new() } else { sentence.clone() }),\n        ),")
mutate("record-sentence-missing-for-resources", "the row has no sentence for a resource denial", SRC + "audit.rs", RECORDED_SENTENCE,
       "            Some(sentence.clone()).filter(|_| reason.kind() != ReasonKind::ResourceOutsideLimit),\n        ),")
ALLOW_ROW = "        Decided::Allow(tool) => (Some(tool), DecisionKind::Allow, None, None),"
mutate("record-allow-has-sentence", "an allowed row carries a sentence", SRC + "audit.rs", ALLOW_ROW,
       '        Decided::Allow(tool) => (Some(tool), DecisionKind::Allow, None, Some(String::from("x"))),')
mutate("record-allow-has-reason", "an allowed row carries a reason", SRC + "audit.rs", ALLOW_ROW,
       "        Decided::Allow(tool) => (Some(tool), DecisionKind::Allow, Some(ReasonKind::UnknownTool), None),")
mutate("record-deny-as-allow", "a denied row is recorded as allowed", SRC + "audit.rs",
       "            DecisionKind::Deny,\n            Some(reason.kind()),", "            DecisionKind::Allow,\n            Some(reason.kind()),")
mutate("record-reason-wrong", "a resource denial is recorded as an unknown tool", SRC + "audit.rs",
       "            Some(reason.kind()),", "            Some(if reason.kind() == ReasonKind::ResourceOutsideLimit { ReasonKind::UnknownTool } else { reason.kind() }),")
mutate("record-denial-completed", "a denied row is written already completed", SRC + "audit.rs",
       "        completion: None,\n    };",
       "        completion: if decision == DecisionKind::Deny { Some(Completion { outcome: Outcome::Ok, latency_ms: 0 }) } else { None },\n    };")
for field, old, new in [
    ("deployment", "        deployment: call.caller.deployment.clone(),", '        deployment: "x".into(),'),
    ("profile", "        profile: call.caller.profile.clone(),", '        profile: "x".into(),'),
    ("connector", "        connector: tool.map(|tool| tool.connector.clone()),", "        connector: None,"),
    ("classification", "        classification: tool.map(|tool| tool.classification),", "        classification: None,"),
    ("resources", "        resources,\n        resources_omitted,", "        resources: { let _ = resources; Resources::Named(Vec::new()) },\n        resources_omitted,"),
    ("resources-omitted", "        resources_omitted,\n        decision,", "        resources_omitted: { let _ = resources_omitted; 0 },\n        decision,"),
    ("tool-use-id", "        tool_use_id: metadata.tool_use_id,", "        tool_use_id: None,"),
    ("claimed-team", "        claimed_team: metadata.claimed_team,", "        claimed_team: None,"),
    ("revision", "        policy_revision,\n        proved_principal", '        policy_revision: { let _ = policy_revision; PolicyRevision::new("x") },\n        proved_principal'),
    ("delegation-team", "            .map(|delegation| delegation.team().into()),", "            .map(|_| None).flatten(),"),
    ("acting-person", "            .map(|delegation| delegation.acting_person()),", "            .map(|_| None).flatten(),"),
    ("tool-unescaped", "        tool: sentences::safe(call.tool.as_str(), sentences::MAX_RENDERED),", "        tool: call.tool.as_str().to_owned(),"),
    ("surface-unescaped", "        surface: SurfaceName::new(sentences::safe(\n            call.caller.surface.as_str(),\n            sentences::MAX_RENDERED,\n        )),",
     "        surface: call.caller.surface.clone(),"),
    ("surface-constant", "        surface: SurfaceName::new(sentences::safe(\n            call.caller.surface.as_str(),", '        surface: SurfaceName::new(sentences::safe(\n            "x",'),
]:
    mutate(f"record-{field}", f"the row's {field} is wrong", SRC + "audit.rs", old, new)
for variant, renamed in [("Ok", "success"), ("Error", "failed")]:
    mutate(f"outcome-{variant.lower()}-renamed", f"the {variant} outcome is written as `{renamed}`", SRC + "audit.rs",
           f"    {variant},\n    /// The ", f"    #[serde(rename = \"{renamed}\")]\n    {variant},\n    /// The ")
mutate("outcome-refused-renamed", "the refused outcome is written as `rejected`", SRC + "audit.rs",
       "    Refused {\n        /// The connector's sentence", "    #[serde(rename = \"rejected\")]\n    Refused {\n        /// The connector's sentence")
for variant in ("Allow", "Deny"):
    mutate(f"decision-kind-{variant.lower()}-renamed", f"{variant} is written under another name", SRC + "audit.rs",
           f"    /// The call was {'allowed' if variant == 'Allow' else 'denied'}.\n    {variant},",
           f"    /// The call was {'allowed' if variant == 'Allow' else 'denied'}.\n    #[serde(rename = \"x\")]\n    {variant},")
mutate("latency-not-written", "latency is not serialized", SRC + "audit.rs",
       "    pub latency_ms: u64,", "    #[serde(skip)]\n    pub latency_ms: u64,")
RECORDED_TAKE = "        .take(MAX_RECORDED_RESOURCES)\n"
mutate("record-resources-uncapped", "the row records every resource a call names", SRC + "audit.rs", RECORDED_TAKE, "")
mutate("record-resources-cap-short", "the row records one resource fewer than it should", SRC + "audit.rs", RECORDED_TAKE,
       "        .take(MAX_RECORDED_RESOURCES - 1)\n")
mutate("record-resources-reordered", "the row records resources in reverse order", SRC + "audit.rs",
       "        .iter()\n" + RECORDED_TAKE, "        .iter()\n        .rev()\n" + RECORDED_TAKE)
mutate("record-resources-omitted-miscounted", "the row's omitted count is off by one", SRC + "audit.rs",
       "    let omitted = named.len().saturating_sub(MAX_RECORDED_RESOURCES);",
       "    let omitted = named.len().saturating_sub(MAX_RECORDED_RESOURCES - 1);")
mutate("record-resources-unknown-as-none", "unknown resources are recorded as an empty list", SRC + "audit.rs",
       "        return (Resources::Unknown, 0);", "        return (Resources::Named(Vec::new()), 0);")
for field in ("system", "kind", "identifier"):
    mutate(f"record-resource-{field}-unescaped", f"a recorded resource's {field} is not made safe", SRC + "audit.rs",
           f"            {field}: safe(&resource.{field}),", f"            {field}: resource.{field}.clone(),")
mutate("finish-ignores-outcome", "finish writes ok whatever happened", SRC + "audit.rs",
       "            outcome: recorded,\n            latency_ms,", "            outcome: { let _ = recorded; Outcome::Ok },\n            latency_ms,")
mutate("finish-ignores-latency", "finish writes a latency of zero", SRC + "audit.rs",
       "            outcome: recorded,\n            latency_ms,", "            outcome: recorded,\n            latency_ms: { let _ = latency_ms; 0 },")
mutate("finish-wrong-row", "finish completes row 0 whatever ran", SRC + "audit.rs",
       "    let completion = RowCompletion {\n        row,", '    let completion = RowCompletion {\n        row: { let _ = row; AuditRowId::new("0") },')
mutate("finish-error-swallowed", "a store error on finish is not reported", SRC + "audit.rs",
       "            failure: Some(AuditFailure::from_store(error)),", "            failure: { let _ = error; None },")
mutate("finish-refusal-unrecorded-answered", "a refusal that could not be recorded is still answered with its sentence", SRC + "audit.rs",
       "                Answer::Refused(_) => Answer::AuditFailed {\n                    sentence: sentences::AUDIT_FAILURE,\n                },\n",
       "")
mutate("finish-refusal-sentence-differs", "the refusal the caller reads is not the one recorded", SRC + "audit.rs",
       "            Answer::Refused(sentence),", "            Answer::Refused(sentence.to_uppercase()),")

# --- Sentences -----------------------------------------------------------------------------

SENTENCE_NAMES = [
    "PROFILE_UNKNOWN", "TOOL_NOT_AVAILABLE", "INVALID_TOOL_NAME", "SURFACE_NOT_PERMITTED",
    "TOOL_NOT_IN_DELEGATION", "DELEGATION_MISSING", "DELEGATION_TEAM_MISMATCH",
    "DELEGATION_WITHOUT_TEAM", "DESTRUCTIVE", "CLASSIFICATION_NOT_PERMITTED",
    "RESOURCE_OUTSIDE_LIMIT", "RESOURCES_UNKNOWN", "RESOURCES_NONE_NAMED", "WORKLOAD", "USER",
    "IDENTITY_FAILURE", "AUDIT_FAILURE",
]


def sentence_mutations(source: str) -> None:
    """For each sentence, one mutation that loses its first placeholder, or for a fixed
    sentence, its first word. Derived from the current text so that a reworded sentence is
    still mutated; a sentence that has disappeared is an ERROR, not a pass."""
    for name in SENTENCE_NAMES:
        match = re.search(rf'^(?:pub(?:\(crate\))? )?const {name}: &str =\s*"([^"]*)";', source, re.M)
        if match is None:
            mutate(f"sentence-{name}", f"sentence {name} is missing", SRC + "sentences.rs", f"const {name}: &str", "")
            continue
        text = match.group(1)
        placeholder = re.search(r"\{[a-z_]+\}", text)
        changed = text.replace(placeholder.group(0), "", 1) if placeholder else text.split(" ", 1)[-1]
        declaration = match.group(0)
        mutate(f"sentence-{name}", f"sentence {name} loses {placeholder.group(0) if placeholder else 'its first word'}",
               SRC + "sentences.rs", declaration, declaration.replace(f'"{text}"', f'"{changed}"'))


mutate("sentence-surfaces-differ", "tool not on this surface reads differently from an unknown tool", SRC + "sentences.rs",
       "        Reason::ToolNotOnSurface { tool, surface } => fill(\n            TOOL_NOT_AVAILABLE,",
       "        Reason::ToolNotOnSurface { tool, surface } => fill(\n            TOOL_NOT_IN_DELEGATION,")
mutate("sentence-system-kind-swapped", "the resource sentence swaps system and kind", SRC + "sentences.rs",
       '("system", Text(&resource.system)),\n                    ("kind", Text(&resource.kind)),',
       '("system", Text(&resource.kind)),\n                    ("kind", Text(&resource.system)),')
mutate("sentence-fill-rescans", "a value is scanned for placeholders", SRC + "sentences.rs",
       "            Some((_, Piece::Text(value))) => sentence.push_str(&safe(value, MAX_RENDERED)),",
       "            Some((_, Piece::Text(value))) => sentence.push_str(&fill(value, values).0),")
mutate("sentence-invalid-name-raw", "an invalid tool name is echoed as it was sent", SRC + "sentences.rs",
       '                &[("tool", Piece::Capped(tool.as_str(), MAX_TOOL_NAME))],', '                &[("tool", Piece::Rendered(&Rendered(tool.as_str().to_owned())))],')
mutate("safe-no-escape", "control characters are not escaped", SRC + "sentences.rs",
       "            c => c.escape_default().collect(),", "            c => c.to_string(),")
mutate("safe-backtick", "a backtick is not escaped", SRC + "sentences.rs",
       "            '`' => \"\\\\`\".to_owned(),", "            '`' => \"`\".to_owned(),")
mutate("safe-no-cap", "values are not cut short", SRC + "sentences.rs",
       "        if length + added > cap {", "        if false && length + added > cap {")

# --- The core's dependencies ---------------------------------------------------------------

# A new crate would change Cargo.lock, which `--locked` refuses before any test runs. Moving a
# dev-dependency into the core's own dependencies leaves the lock as it is.
mutate_all(
    "dependency-added",
    "the core gains a dependency outside the allowlist",
    (CRATE + "Cargo.toml", 'thiserror = "2"\n', 'thiserror = "2"\nproptest = "1"\n'),
    (CRATE + "Cargo.toml", '[dev-dependencies]\nproptest = "1"\n', "[dev-dependencies]\n"),
)


# --- Running -------------------------------------------------------------------------------


def copy_workspace(destination: Path) -> None:
    """Copies what git would see: tracked files and untracked ones that are not ignored, as they
    are in the working tree, so uncommitted changes are measured and build output is not."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    for relative in filter(None, listed.split("\0")):
        source = ROOT / relative
        if source.is_file():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def apply(mutation: Mutation, read) -> dict[str, str] | str:
    """The mutated contents of each file, or why the mutation does not apply."""
    contents: dict[str, str] = {}
    for edit in mutation.edits:
        text = contents.get(edit.path, read(edit.path))
        count = text.count(edit.old)
        if count != 1:
            return f"{edit.path}: target found {count} times, expected exactly once"
        contents[edit.path] = text.replace(edit.old, edit.new)
    return contents


def run_tests(workspace: Path, target: Path) -> tuple[int | None, str]:
    command = ["cargo", "test", "--workspace", "--locked", "--no-fail-fast"]
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_TERM_COLOR": "never"}
    try:
        result = subprocess.run(command, cwd=workspace, env=environment, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None, "timed out"
    return result.returncode, result.stdout + result.stderr


def verdict(mutation: Mutation, code: int | None, output: str) -> tuple[str, str]:
    if code is None:
        return "NO-VERDICT", "timed out"
    if code == 0:
        return "SURVIVED", "every test passed"
    failed = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED$", output, re.M)))
    trybuild = sorted(set(re.findall(r"^test (tests/compile-fail/\S+) \.\.\. (?:error|mismatch)$", output, re.M)))
    if failed:
        return "CAUGHT", ", ".join(failed + trybuild)
    broken = re.findall(r"could not compile `gateway-core` \(([^)]*)\)", output)
    if mutation.breaks_build and "lib" in broken:
        return "CAUGHT", "the library does not compile, as intended"
    if broken:
        return "NO-VERDICT", "did not compile: " + ", ".join(broken)
    lines = [line for line in output.splitlines() if line.startswith("error")]
    return "NO-VERDICT", "; ".join(lines[:2]) or f"cargo exited {code}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("only", nargs="*", help="run only these mutation ids")
    parser.add_argument("--list", action="store_true", help="list the mutations and exit")
    parser.add_argument("--targets", action="store_true", help="check every target matches exactly once, without cargo")
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace")
    arguments = parser.parse_args()

    sentence_mutations((ROOT / SRC / "sentences.rs").read_text())
    known = {mutation.id for mutation in MUTATIONS}
    if len(known) != len(MUTATIONS):
        sys.exit("two mutations share an id")
    if unknown := [id for id in arguments.only if id not in known]:
        sys.exit(f"no such mutation: {', '.join(unknown)}")
    selected = [mutation for mutation in MUTATIONS if not arguments.only or mutation.id in arguments.only]

    if arguments.list:
        for mutation in selected:
            print(f"{mutation.id:<48} {mutation.description}")
        return 0

    if arguments.targets:
        bad = 0
        for mutation in selected:
            applied = apply(mutation, lambda path: (ROOT / path).read_text())
            if isinstance(applied, str):
                bad += 1
                print(f"{'ERROR':<10} {mutation.id:<48} {applied}")
        print(f"{len(selected)} mutations: {len(selected) - bad} targets match, {bad} do not")
        return 1 if bad else 0

    scratch = Path(tempfile.mkdtemp(prefix="mutation-check-"))
    workspace, target = scratch / "workspace", scratch / "target"
    copy_workspace(workspace)
    print(f"workspace copy: {workspace}", flush=True)
    try:
        started = time.monotonic()
        code, output = run_tests(workspace, target)
        if code != 0:
            print(output[-4000:])
            print("the unmutated workspace does not pass its tests; nothing to measure against")
            return 2
        print(f"baseline passes ({time.monotonic() - started:.0f}s); {len(selected)} mutations to run", flush=True)

        pristine = {path: (workspace / path).read_text() for path in {edit.path for m in selected for edit in m.edits} | {REGRESSIONS}
                    if (workspace / path).exists()}
        counts = {"CAUGHT": 0, "SURVIVED": 0, "ERROR": 0, "NO-VERDICT": 0}
        for mutation in selected:
            applied = apply(mutation, lambda path: pristine[path])
            if isinstance(applied, str):
                status, detail = "ERROR", applied
            else:
                try:
                    for path, text in applied.items():
                        (workspace / path).write_text(text)
                    code, output = run_tests(workspace, target)
                    status, detail = verdict(mutation, code, output)
                finally:
                    # Written afresh, so every restored file is newer than the mutant's build
                    # and cargo cannot reuse it; the regression file is restored so that one
                    # mutation's saved cases do not change the next one's run.
                    for path, text in pristine.items():
                        (workspace / path).write_text(text)
                    shutil.rmtree(workspace / CRATE / "wip", ignore_errors=True)
            counts[status] += 1
            print(f"{status:<10} {mutation.id:<48} {detail}", flush=True)

        print(
            f"{len(selected)} mutations: {counts['CAUGHT']} caught, {counts['SURVIVED']} survived, "
            f"{counts['ERROR']} errors, {counts['NO-VERDICT']} without a verdict"
        )
        return 0 if counts["CAUGHT"] == len(selected) else 1
    finally:
        if arguments.keep:
            print(f"kept {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
