#!/usr/bin/env python3
"""Break each guard in the gateway crates, one at a time, and require the tests to notice.

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
IDENTITY = "crates/gateway-identity/"
IDENTITY_SRC = IDENTITY + "src/"
TESTKIT = "crates/gateway-testkit/"
TESTKIT_SRC = TESTKIT + "src/"
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
DELEGATION_LISTS = "        Some(delegation) if !delegation.get().tools.contains(&tool.name) => {"
mutate(
    "delegation-empty-list-narrows-nothing",
    "a delegation that lists no tools narrows nothing",
    SRC + "decision.rs",
    DELEGATION_LISTS,
    "        Some(delegation) if !delegation.get().tools.is_empty() && !delegation.get().tools.contains(&tool.name) => {",
)
mutate(
    "delegation-tools-may-be-omitted",
    "a delegation's tool list may be left out",
    SRC + "principal.rs",
    "    pub tools: BTreeSet<ToolName>,",
    "    #[serde(default)]\n    pub tools: BTreeSet<ToolName>,",
)
mutate_all(
    "delegation-null-tools-read-as-empty",
    "a delegation whose tool list is null reads as one that lists no tools",
    (
        SRC + "principal.rs",
        "    pub tools: BTreeSet<ToolName>,\n}",
        "    #[serde(deserialize_with = \"null_is_empty\")]\n    pub tools: BTreeSet<ToolName>,\n}\n\n"
        "fn null_is_empty<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<BTreeSet<ToolName>, D::Error> {\n"
        "    Ok(Option::<BTreeSet<ToolName>>::deserialize(deserializer)?.unwrap_or_default())\n}",
    ),
)

# --- Check 5: the classification -----------------------------------------------------------

DENIED_EVERYWHERE = "        Classification::Write | Classification::Destructive\n    );"
mutate(
    "destructive-permitted-by-profile",
    "a destructive tool is allowed by a profile that lists destructive",
    SRC + "decision.rs",
    DENIED_EVERYWHERE,
    "        Classification::Write\n    );",
)
mutate(
    "write-permitted-by-profile",
    "a direct write is allowed by a profile that lists write",
    SRC + "decision.rs",
    DENIED_EVERYWHERE,
    "        Classification::Destructive\n    );",
)
mutate(
    "propose-denied-everywhere",
    "a proposal is denied in every profile, like a direct write",
    SRC + "decision.rs",
    DENIED_EVERYWHERE,
    "        Classification::Propose | Classification::Write | Classification::Destructive\n    );",
)
PROFILE_LISTS = "    let permitted = !denied_everywhere && profile.classifications.contains(&tool.classification);"
for id, description, replacement in [
    (
        "profile-ignored",
        "a profile permits every classification not denied everywhere, whatever it lists",
        "!denied_everywhere",
    ),
    (
        "read-permitted-by-every-profile",
        "every profile permits a read, whether or not it lists `read`",
        "!denied_everywhere\n        && (tool.classification == Classification::Read\n            || profile.classifications.contains(&tool.classification))",
    ),
    (
        "profile-permits-lesser-classifications",
        "a profile permits every classification ordered at or below one it lists",
        "!denied_everywhere\n        && profile\n            .classifications\n            .iter()\n            .any(|listed| tool.classification <= *listed)",
    ),
    (
        "empty-profile-permits-everything",
        "a profile that lists no classification permits every one not denied everywhere",
        "!denied_everywhere\n        && (profile.classifications.is_empty()\n            || profile.classifications.contains(&tool.classification))",
    ),
]:
    mutate(id, description, SRC + "decision.rs", PROFILE_LISTS, f"    let permitted = {replacement};")
mutate(
    "classification-write-parses-as-propose",
    "`write` in configuration reads as propose, and `propose` is refused",
    SRC + "classification.rs",
    'Classification::Propose => "propose",',
    'Classification::Propose => "write",',
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
for struct in ("AuditRecord", "RecordedResource"):
    mutate(f"unknown-fields-{struct}", f"{struct} accepts unknown fields", SRC + "audit.rs",
           f"#[serde(deny_unknown_fields)]\npub struct {struct} {{", f"pub struct {struct} {{")
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
    ("resources", "        resources,\n        resources_omitted,", "        resources: { let _ = resources; RecordedResources::Named(Vec::new()) },\n        resources_omitted,"),
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
mutate("record-resources-cap-constant", "a row records at most 63 resources, not 64", SRC + "audit.rs",
       "pub const MAX_RECORDED_RESOURCES: usize = 64;", "pub const MAX_RECORDED_RESOURCES: usize = 63;")
mutate("record-resources-reordered", "the row records resources in reverse order", SRC + "audit.rs",
       "        .copied()\n" + RECORDED_TAKE, "        .copied()\n        .rev()\n" + RECORDED_TAKE)
mutate("record-resources-repeats-kept", "a resource named twice is recorded twice", SRC + "audit.rs",
       "        .filter(|resource| seen.insert(*resource))\n", "        .filter(|resource| seen.insert(*resource) || true)\n")
OMITTED = "    let omitted = distinct.len().saturating_sub(kept.len());"
mutate("record-resources-omitted-miscounted", "the row's omitted count is off by one", SRC + "audit.rs",
       OMITTED, "    let omitted = (distinct.len() + 1).saturating_sub(kept.len());")
mutate("record-resources-omitted-counts-repeats", "the row's omitted count includes repeats", SRC + "audit.rs",
       OMITTED, "    let omitted = named.len().saturating_sub(kept.len());")
mutate("record-resources-unknown-as-none", "unknown resources are recorded as an empty list", SRC + "audit.rs",
       "        return (RecordedResources::Unknown, 0);", "        return (RecordedResources::Named(Vec::new()), 0);")
DENIED_KEPT = (
    "    if let Some(denied) = denied\n"
    "        && !kept.contains(&denied)\n"
    "    {\n"
    "        kept.truncate(MAX_RECORDED_RESOURCES - 1);\n"
    "        kept.push(denied);\n"
    "    }\n"
)
mutate("record-resources-denied-dropped", "a resource denial past the cap leaves its resource off the row", SRC + "audit.rs",
       DENIED_KEPT, "    let _ = denied;\n")
mutate("record-resources-denied-not-passed", "begin does not tell the row which resource a denial names", SRC + "audit.rs",
       "        } => Some(resource),\n        _ => None,\n", "        } => { let _ = resource; None }\n        _ => None,\n")
mutate("record-resources-denied-appended", "a resource denial past the cap makes the row hold one more than the cap", SRC + "audit.rs",
       "        kept.truncate(MAX_RECORDED_RESOURCES - 1);\n", "")
mutate("record-resources-denied-first", "a resource denial past the cap is recorded first, not in the order named", SRC + "audit.rs",
       "        kept.push(denied);\n", "        kept.insert(0, denied);\n")
for field, cap in (("system", "sentences::MAX_RENDERED"), ("kind", "sentences::MAX_RENDERED"), ("identifier", "MAX_RECORDED_IDENTIFIER")):
    line = f"            {field}: sentences::safe(&resource.{field}, {cap}),"
    mutate(f"record-resource-{field}-unescaped", f"a recorded resource's {field} is not made safe", SRC + "audit.rs",
           line, f"            {field}: resource.{field}.clone(),")
    mutate(f"record-resource-{field}-uncapped", f"a recorded resource's {field} is not cut short", SRC + "audit.rs",
           line, f"            {field}: sentences::safe(&resource.{field}, usize::MAX),")
mutate("record-resource-identifier-cap-128", "a recorded identifier is cut at 128 characters, like the tool name", SRC + "audit.rs",
       "            identifier: sentences::safe(&resource.identifier, MAX_RECORDED_IDENTIFIER),",
       "            identifier: sentences::safe(&resource.identifier, sentences::MAX_RENDERED),")
mutate("record-resource-identifier-cap-short", "a recorded identifier is cut one character early", SRC + "audit.rs",
       "pub const MAX_RECORDED_IDENTIFIER: usize = 2048;", "pub const MAX_RECORDED_IDENTIFIER: usize = 2047;")
mutate("record-resource-system-kind-swapped", "a recorded resource's system and kind are swapped", SRC + "audit.rs",
       "            system: sentences::safe(&resource.system, sentences::MAX_RENDERED),\n            kind: sentences::safe(&resource.kind, sentences::MAX_RENDERED),",
       "            system: sentences::safe(&resource.kind, sentences::MAX_RENDERED),\n            kind: sentences::safe(&resource.system, sentences::MAX_RENDERED),")
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
    "DELEGATION_WITHOUT_TEAM", "DESTRUCTIVE", "DIRECT_WRITE", "CLASSIFICATION_NOT_PERMITTED",
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
mutate("sentence-propose-reads-as-write", "a proposal the profile does not permit reads as a direct write", SRC + "sentences.rs",
       "            classification: Classification::Write,\n            ..\n        } => fill(DIRECT_WRITE,",
       "            classification: Classification::Write | Classification::Propose,\n            ..\n        } => fill(DIRECT_WRITE,")
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
mutate("safe-backslash", "a backslash is not escaped, so escaping cannot be reversed", SRC + "sentences.rs",
       "            '\\\\' => \"\\\\\\\\\".to_owned(),\n", "")
mutate("safe-no-cap", "values are not cut short", SRC + "sentences.rs",
       "        if length + added > cap {", "        if false && length + added > cap {")

# --- The credential source -----------------------------------------------------------------

mutate_all(
    "credential-source-takes-unproved-principal",
    "a credential can be asked for on behalf of a principal nobody proved",
    (SRC + "credential.rs", "        caller: &'a Proved<Principal>,\n", "        caller: &'a Principal,\n"),
    (TESTKIT_SRC + "credentials.rs", "        caller: &'a Proved<Principal>,\n", "        caller: &'a Principal,\n"),
    (TESTKIT_SRC + "credentials.rs", "        let principal = caller.get();\n", "        let principal = caller;\n"),
    (TESTKIT_SRC + "connector.rs", "self.credentials.credential_for(&connector, &caller).await", "self.credentials.credential_for(&connector, caller.get()).await"),
    # The one test helper that calls the source directly is changed to match, so that what is
    # left to fail is the compile-fail case for a plain principal, which compiles under this
    # mutation: that is the guard under test.
    (TESTKIT + "tests/fakes.rs", '    block_on(source.credential_for(&ConnectorName::from("fixture"), caller))', '    block_on(source.credential_for(&ConnectorName::from("fixture"), caller.get()))'),
)

# --- The identity verifier: the order and each check ---------------------------------------

V = IDENTITY_SRC + "verifier.rs"
SIGNATURE = "        let claims = verify_signature(token, entry.algorithm, key)?;\n"
mutate("identity-signature-not-checked", "claims are read without checking the signature", V, SIGNATURE,
       "        let claims: Claims = jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(|_| VerifyError::MalformedToken)?;\n"
       "        let _ = (entry.algorithm, key);\n")
mutate("identity-subject-looked-up-before-signature", "an unknown subject is refused before its signature is checked", V, SIGNATURE,
       "        let early: Claims = jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(|_| VerifyError::MalformedToken)?;\n"
       "        if let IssuerKind::Workload { subjects } = &entry.kind {\n"
       "            let known = early.get(\"sub\").and_then(Value::as_str).is_some_and(|s| subjects.contains_key(&gateway_core::Subject::from(s)));\n"
       "            if !known {\n                return Err(VerifyError::UnknownSubject);\n            }\n        }\n" + SIGNATURE)
mutate("identity-exp-not-checked", "exp is read but not checked", V,
       "        let expires_at = check_not_expired(&claims, now, entry.leeway)?;\n",
       '        let expires_at = date(&claims, "exp", Claim::ExpiresAt)?;\n')
mutate("identity-exp-optional", "a token with no exp never expires", V,
       '    let expires_at = date(claims, "exp", Claim::ExpiresAt)?;\n',
       '    let expires_at = if claims.contains_key("exp") { date(claims, "exp", Claim::ExpiresAt)? } else { u64::MAX };\n')
mutate("identity-exp-boundary", "a token is valid at exactly exp plus leeway", V,
       "    if now >= expires_at.saturating_add(leeway) {", "    if now > expires_at.saturating_add(leeway) {")
mutate("identity-exp-ignores-leeway", "exp is checked with no leeway", V,
       "    if now >= expires_at.saturating_add(leeway) {", "    if now >= expires_at.saturating_add(0 * leeway) {")
mutate("identity-exp-leeway-doubled", "exp is checked with twice the leeway", V,
       "    if now >= expires_at.saturating_add(leeway) {", "    if now >= expires_at.saturating_add(2 * leeway) {")
mutate("identity-nbf-not-checked", "nbf is not checked", V,
       "        check_not_early(&claims, now, entry.leeway)?;\n", "")
mutate("identity-nbf-boundary", "a token is refused at exactly now plus leeway", V,
       "    if not_before > now.saturating_add(leeway) {", "    if not_before >= now.saturating_add(leeway) {")
mutate("identity-nbf-ignores-leeway", "nbf is checked with no leeway", V,
       "    if not_before > now.saturating_add(leeway) {", "    if not_before > now.saturating_add(0 * leeway) {")
mutate("identity-aud-not-checked", "aud is not checked", V,
       "        check_audience(&claims, &entry.audiences)?;\n", "")
mutate("identity-aud-any", "any audience that is named is accepted", V,
       "    if named.iter().any(|audience| accepted.contains(*audience)) {", "    if !named.is_empty() || accepted.is_empty() {")
mutate("identity-aud-first-only", "only the first audience in an array is considered", V,
       "    if named.iter().any(|audience| accepted.contains(*audience)) {", "    if named.first().is_some_and(|audience| accepted.contains(*audience)) {")
mutate("identity-lifetime-not-checked", "the lifetime ceiling and iat are not checked", V,
       "        check_lifetime(&claims, expires_at, now, entry)?;\n", "        let _ = (expires_at, now);\n")
mutate("identity-lifetime-boundary", "a lifetime exactly at the ceiling is refused", V,
       "    if lifetime > entry.max_lifetime {", "    if lifetime >= entry.max_lifetime {")
mutate("identity-iat-future-not-checked", "a token issued in the future is accepted", V,
       "    if issued_at > now.saturating_add(entry.leeway) {", "    if false {")
mutate("identity-exp-before-iat-wraps", "exp before iat is read as a lifetime of zero", V,
       "        .checked_sub(issued_at)\n        .ok_or(VerifyError::ExpiresBeforeIssue)?;", "        .checked_sub(issued_at)\n        .unwrap_or(0);")
mutate("identity-sub-optional", "a token with no sub is accepted with an empty subject", V,
       "        None => Err(VerifyError::MissingClaim(Claim::Subject)),", '        None => Ok("".into()),')

# --- The identity verifier: the shape of each claim ----------------------------------------

DATE = "        Some(value) => value.as_u64().ok_or(VerifyError::MalformedClaim(claim)),"
mutate("identity-date-fraction-truncated", "a fractional date is rounded down", V, DATE,
       "        Some(value) => value.as_u64().or_else(|| value.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)).ok_or(VerifyError::MalformedClaim(claim)),")
mutate("identity-date-digits-parsed", "a date written as a string of digits is read as a number", V, DATE,
       "        Some(value) => value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok())).ok_or(VerifyError::MalformedClaim(claim)),")
mutate("identity-date-negative-is-epoch", "a negative date reads as the epoch", V, DATE,
       "        Some(value) => value.as_u64().or_else(|| value.as_i64().map(|_| 0)).ok_or(VerifyError::MalformedClaim(claim)),")
mutate("identity-nbf-null-is-absent", "an nbf of null is treated as no nbf", V,
       '    if !claims.contains_key("nbf") {', '    if claims.get("nbf").is_none_or(Value::is_null) {')
mutate("identity-iss-array-read", "an iss that is an array is read from its first element", V,
       '            .get("iss")\n            .and_then(Value::as_str)',
       '            .get("iss")\n            .and_then(|v| v.as_str().or_else(|| v.get(0).and_then(Value::as_str)))')
mutate("identity-aud-array-skips-non-strings", "an aud array's non-string members are skipped", V,
       "            .map(Value::as_str)\n            .collect::<Option<_>>()\n            .ok_or(VerifyError::MalformedClaim(Claim::Audience))?,",
       "            .filter_map(Value::as_str)\n            .collect(),")
mutate("identity-aud-other-type-names-none", "an aud of another type names no audience rather than being malformed", V,
       "        Some(_) => return Err(VerifyError::MalformedClaim(Claim::Audience)),", "        Some(_) => Vec::new(),")
mutate("identity-sub-may-be-empty", "an empty sub is accepted", V,
       "        Some(Value::String(subject)) if !subject.is_empty() => Ok(subject.as_str().into()),",
       "        Some(Value::String(subject)) => Ok(subject.as_str().into()),")
mutate("identity-sub-any-type-read-as-text", "a sub that is not a string is read as its JSON text", V,
       "        Some(_) => Err(VerifyError::MalformedClaim(Claim::Subject)),", "        Some(other) => Ok(other.to_string().as_str().into()),")
mutate("identity-groups-skip-non-strings", "a groups array's non-string members are skipped", V,
       "            .map(|group| group.as_str().map(GroupId::from))\n            .collect::<Option<_>>()\n            .ok_or(VerifyError::MalformedClaim(Claim::Groups)),",
       "            .filter_map(|group| group.as_str().map(GroupId::from))\n            .map(Ok::<_, VerifyError>)\n            .collect(),")
mutate("identity-groups-null-is-none", "a groups claim of null is a user in no group", V,
       "        Some(_) => Err(VerifyError::MalformedClaim(Claim::Groups)),\n    }\n}",
       "        Some(Value::Null) => Ok(BTreeSet::new()),\n        Some(_) => Err(VerifyError::MalformedClaim(Claim::Groups)),\n    }\n}")
mutate("identity-groups-string-is-one-group", "a groups claim that is a string is one group", V,
       "        Some(_) => Err(VerifyError::MalformedClaim(Claim::Groups)),\n    }\n}",
       "        Some(Value::String(one)) => Ok([GroupId::from(one.as_str())].into()),\n        Some(_) => Err(VerifyError::MalformedClaim(Claim::Groups)),\n    }\n}")

mutate("identity-kid-not-required","the header's kid is ignored and the first key is used", V,
       "        let kid = header.kid.as_deref().ok_or(VerifyError::MissingKeyId)?;\n"
       "        let key = entry.keys.get(kid).ok_or(VerifyError::UnknownKeyId)?;\n",
       "        let _ = &header.kid;\n        let key = entry.keys.values().next().ok_or(VerifyError::UnknownKeyId)?;\n")
mutate("identity-kid-must-exist-not-checked", "an unknown kid falls back to the first key", V,
       "        let key = entry.keys.get(kid).ok_or(VerifyError::UnknownKeyId)?;\n",
       "        let key = entry.keys.get(kid).or_else(|| entry.keys.values().next()).ok_or(VerifyError::UnknownKeyId)?;\n")
# The library also refuses a header algorithm that is not the validation's, so the explicit
# check is a second line of defence. Loosening both is what shows the table notices a header
# that names another algorithm of the same family.
mutate_all("identity-alg-not-checked", "a header may name any algorithm of the issuer's family",
           (V, "        if header.alg != entry.algorithm.jwt() {", "        if false {"),
           (V, "    let mut validation = Validation::new(algorithm.jwt());", "    let mut validation = Validation::new_for_family(algorithm.jwt().family());"))
mutate("identity-unlisted-issuer-accepted", "a token naming an unlisted issuer is checked under the first issuer", V,
       "        self.issuers.get(issuer).ok_or(VerifyError::UnknownIssuer)",
       "        self.issuers.get(issuer).or_else(|| self.issuers.values().next()).ok_or(VerifyError::UnknownIssuer)")
mutate("identity-issuer-match-ignores-case", "the issuer is matched without regard to case", V,
       "        self.issuers.get(issuer).ok_or(VerifyError::UnknownIssuer)",
       "        self.issuers.iter().find(|(name, _)| name.eq_ignore_ascii_case(issuer)).map(|(_, entry)| entry).ok_or(VerifyError::UnknownIssuer)")
mutate("identity-principal-ignores-issuer", "the principal's issuer is not the issuer that vouched", V,
       "                issuer: entry.issuer.clone(),\n                subject,", '                issuer: "".into(),\n                subject,')
mutate("identity-unknown-subject-accepted", "an unknown workload subject is given the first team in the table", V,
       "                    .ok_or(VerifyError::UnknownSubject)?\n                    .clone();",
       "                    .or_else(|| subjects.values().next())\n                    .ok_or(VerifyError::UnknownSubject)?\n                    .clone();")
mutate("identity-groups-ignored", "a user's groups are not read", V,
       "                groups: groups_of(&claims, groups_claim)?,", "                groups: BTreeSet::new(),")
mutate("identity-groups-claim-name-ignored", "groups are always read from `groups`", V,
       "                groups: groups_of(&claims, groups_claim)?,", '                groups: groups_of(&claims, "groups")?,')
mutate("identity-crit-ignored", "a token carrying crit is checked as if it did not", V,
       "        if carries_crit(token) {", "        if false {")
CRIT = '        .is_none_or(|header| header.contains_key("crit"))'
mutate("identity-crit-null-ignored", "a crit of null is read as no crit", V, CRIT,
       '        .is_none_or(|header| header.get("crit").is_some_and(|crit| !crit.is_null()))')
mutate("identity-crit-empty-allowed", "a crit that lists nothing is accepted", V, CRIT,
       '        .is_none_or(|header| header.get("crit").is_some_and(|crit| crit.as_array().is_none_or(|names| !names.is_empty())))')
mutate("identity-token-size-unbounded", "a token of any size is parsed", V,
       "    if token.len() > MAX_TOKEN_BYTES {", "    if false && token.len() > MAX_TOKEN_BYTES {")
mutate("identity-clock-is-the-system-clock", "verification reads the system time, not the injected clock", V,
       "        let now = unix_seconds(self.clock.as_ref());", "        let now = jsonwebtoken::get_current_timestamp();")
mutate("identity-unknown-alg-reads-as-malformed", "a header with an algorithm nobody supports is reported as malformed", V,
       "            .is_some_and(|alg| alg.parse::<jsonwebtoken::Algorithm>().is_err());", "            .is_some_and(|alg| alg.is_empty());")
mutate("identity-unusable-key-reads-as-bad-signature", "a key that cannot verify is reported as a bad signature", V,
       "            jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey\n            | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_)\n            | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => VerifyError::UnusableKey,\n",
       "            jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey\n            | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_)\n            | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => VerifyError::BadSignature,\n")

# --- The identity verifier: configuration --------------------------------------------------

mutate("identity-config-no-issuers-allowed", "checking can be on with no issuer", V,
       "        if issuers.is_empty() {\n            return Err(ConfigError::NoIssuers);", "        if false {\n            return Err(ConfigError::NoIssuers);")
mutate("identity-config-duplicate-issuer-allowed", "an issuer can be configured twice", V,
       "            if entries.insert(name.clone(), entry).is_some() {", "            if entries.insert(name.clone(), entry).is_some() && false {")
mutate("identity-config-empty-issuer-allowed", "an issuer with no name is configured", V,
       "        if issuer.as_str().is_empty() {", "        if false {")
mutate("identity-config-no-audience-allowed", "an issuer with no audience is configured", V,
       "        if config.audiences.is_empty() || config.audiences.iter().any(String::is_empty) {", "        if false {")
mutate("identity-config-empty-audience-allowed", "an issuer with an empty audience is configured", V,
       "        if config.audiences.is_empty() || config.audiences.iter().any(String::is_empty) {", "        if config.audiences.is_empty() {")
mutate("identity-config-zero-lifetime-allowed", "an issuer with a zero lifetime ceiling is configured", V,
       "        if max_lifetime == 0 {", "        if false {")
mutate("identity-config-no-subjects-allowed", "a workload issuer with no subjects is configured", V,
       "            IssuerKind::Workload { subjects } if subjects.is_empty() => {", "            IssuerKind::Workload { subjects } if false && subjects.is_empty() => {")
mutate("identity-config-empty-groups-claim-allowed", "a user issuer with an unnamed groups claim is configured", V,
       "            IssuerKind::User { groups_claim } if groups_claim.is_empty() => {", "            IssuerKind::User { groups_claim } if false && groups_claim.is_empty() => {")
mutate("identity-config-no-keys-allowed", "an issuer with no keys is configured", V,
       "        if keys.is_empty() {", "        if keys.is_empty() && first_unfit.is_some() {")
mutate("identity-config-key-without-kid-allowed", "a key with no kid is given a blank one", V,
       "                .ok_or_else(|| ConfigError::KeyWithoutId(issuer.clone()))?;", "                .unwrap_or_default();")
mutate("identity-config-duplicate-kid-allowed", "two keys can share a kid", V,
       "            if !kids.insert(kid.clone()) {", "            if !kids.insert(kid.clone()) && false {")
FITS = "    shape && declared_algorithm && declared_use && declared_operations"
mutate("identity-config-key-shape-ignored", "a key of the wrong type is accepted for the issuer's algorithm", V,
       FITS, "    declared_algorithm && declared_use && declared_operations")
mutate("identity-config-key-curve-ignored", "an EC key on another curve is accepted for ES256", V,
       "            params.curve == EllipticCurve::P256", "            true")
mutate("identity-config-key-algorithm-ignored", "a key that declares another algorithm is accepted", V,
       FITS, "    shape && declared_use && declared_operations")
mutate("identity-config-key-use-ignored", "a key that declares itself for encryption is accepted", V,
       FITS, "    shape && declared_algorithm && declared_operations")
mutate("identity-config-key-ops-ignored", "a key whose key_ops leave out verify is accepted", V,
       FITS, "    shape && declared_algorithm && declared_use")
mutate("identity-config-key-ops-any-listed", "a key that lists any operation is accepted", V,
       "        .is_none_or(|operations| operations.contains(&KeyOperations::Verify));",
       "        .is_none_or(|operations| !operations.is_empty());")
RSA_LENGTH = "        if bits < MIN_RSA_BITS {"
mutate("identity-config-rsa-length-unchecked", "an RSA key of any length is accepted", V, RSA_LENGTH, "        if false {")
mutate("identity-config-rsa-length-boundary", "an RSA key of exactly the minimum length is refused", V, RSA_LENGTH,
       "        if bits <= MIN_RSA_BITS {")
MODULUS_BITS = "    Some((significant.count() + 1) * 8 - unused)"
mutate("identity-config-rsa-length-in-bytes", "an RSA modulus is measured in whole bytes, leading zeros and all", V, MODULUS_BITS,
       "    Some(bytes.len() * 8 + 0 * unused + 0 * significant.count())")
mutate("identity-config-rsa-length-ignores-top-byte", "the unused bits of a modulus's top byte are counted", V, MODULUS_BITS,
       "    Some((significant.count() + 1) * 8 + 0 * unused)")
mutate("identity-config-rsa-zero-modulus-allowed", "a modulus of zero is measured as one byte", V,
       "    let top = significant.next()?;", "    let top = significant.next().unwrap_or(&0xff);")
mutate("identity-config-weak-key-reported-as-unfit", "a short RSA key is reported as a key of the wrong kind", V,
       "            Unfit::Weak(bits) => ConfigError::WeakKey { issuer, kid, bits },",
       "            Unfit::Weak(_) => ConfigError::KeyDoesNotFit { issuer, kid, algorithm: algorithm.as_str() },")
mutate("identity-config-rsa-backend-check-skipped", "an RSA key the crypto backend cannot use is accepted", V,
       "        rsa_key_usable(&params.n, &params.e)?;\n", "")
mutate("identity-config-unusable-rsa-key-reported-as-unfit", "an RSA key the backend cannot use is reported as a key of the wrong kind", V,
       "            Unfit::UnusableRsa(reason) => ConfigError::UnusableRsaKey {\n                issuer,\n                kid,\n                reason,\n            },\n",
       "            Unfit::UnusableRsa(_) => ConfigError::KeyDoesNotFit { issuer, kid, algorithm: algorithm.as_str() },\n")
mutate_all("identity-config-unfit-key-refuses-issuer", "one key that cannot verify refuses its whole issuer",
           (V, "                Err(unfit) => {\n                    first_unfit.get_or_insert((kid, unfit));\n                }",
            "                Err(unfit) => {\n                    return Err(unfit.error(issuer.clone(), kid, config.algorithm));\n                }"),
           (V, "        let mut first_unfit = None;\n", "        let mut first_unfit: Option<(String, Unfit)> = None;\n"))
mutate("identity-config-no-usable-key-allowed", "an issuer none of whose keys can verify is configured", V,
       "        if keys.is_empty() {", "        if keys.is_empty() && first_unfit.is_none() {")
mutate("identity-config-last-unfit-key-reported", "the last key that cannot verify is reported, not the first", V,
       "                    first_unfit.get_or_insert((kid, unfit));", "                    first_unfit = Some((kid, unfit));")
mutate("identity-config-duplicate-kid-among-usable-only", "a kid may repeat if one of its keys is left out", V,
       "            if !kids.insert(kid.clone()) {", "            if !kids.insert(kid.clone()) && decoding_key(jwk, config.algorithm).is_ok() {")
LEEWAY = "        if config.leeway > MAX_LEEWAY {"
mutate("identity-config-leeway-unbounded", "an issuer can be configured with any leeway", V, LEEWAY, "        if false {")
mutate("identity-config-leeway-boundary", "a leeway of exactly the maximum is refused", V, LEEWAY, "        if config.leeway >= MAX_LEEWAY {")
mutate("identity-config-leeway-whole-seconds", "a leeway is compared in whole seconds", V, LEEWAY,
       "        if config.leeway.as_secs() > MAX_LEEWAY.as_secs() {")
mutate("identity-config-second-user-issuer-allowed", "two user issuers can be configured", V,
       "                return Err(ConfigError::SecondUserIssuer { first, second });", "                let _ = (first, second);")

# --- The identity gate and the opaque failure ----------------------------------------------

mutate("identity-missing-token-is-disabled", "no token reads as checking being off", IDENTITY_SRC + "identity.rs",
       "            return Verification::Failed(IdentityFailure::new(VerifyError::MissingToken));", "            return Verification::Disabled;")
mutate("identity-failure-is-disabled", "a refused token reads as checking being off", IDENTITY_SRC + "identity.rs",
       "            Err(failure) => Verification::Failed(failure),", "            Err(_) => Verification::Disabled,")
mutate("identity-enforcing-is-disabled", "configured checking is not applied", IDENTITY_SRC + "identity.rs",
       "            IdentityConfig::Enforce(issuers) => Some(TokenVerifier::new(issuers, clock)?),", "            IdentityConfig::Enforce(issuers) => TokenVerifier::new(issuers, clock).ok().filter(|_| false),")
mutate("identity-failure-display-names-the-cause", "the failure displays as its cause", IDENTITY_SRC + "error.rs",
       "        f.write_str(IDENTITY_FAILURE)\n    }\n}\n\nimpl std::error::Error",
       "        write!(f, \"{}\", self.detail)\n    }\n}\n\nimpl std::error::Error")
mutate("identity-failure-outward-names-the-cause", "the outward sentence differs by cause", IDENTITY_SRC + "error.rs",
       "    pub fn outward(&self) -> &'static str {\n        IDENTITY_FAILURE", "    pub fn outward(&self) -> &'static str {\n        if self.detail == VerifyError::UnknownSubject { \"unknown subject\" } else { IDENTITY_FAILURE }")
mutate("identity-groups-claim-sentence", "the log names the groups claim as `the groups claim claim`", IDENTITY_SRC + "error.rs",
       '            Claim::Groups => "groups claim",', '            Claim::Groups => "the groups claim claim",')
mutate("identity-state-names","the proved state is recorded under another name", IDENTITY_SRC + "identity.rs",
       '            VerificationState::Proved => "proved",', '            VerificationState::Proved => "ok",')
mutate_all(
    "identity-dependency-added",
    "the identity crate gains a dependency outside the allowlist",
    (IDENTITY + "Cargo.toml", 'thiserror = "2"\n', 'thiserror = "2"\nproptest = "1"\n'),
    (IDENTITY + "Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\nproptest = "1"\n', '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n'),
)
# Enabling `aws_lc_rs` itself would add crates to Cargo.lock, which `--locked` refuses before any
# test runs, so that mutation could never give a verdict. Any second entry in the feature list
# fails the same assertion a second backend would, and leaves the lock as it is.
mutate("identity-second-crypto-backend", "the crypto feature list gains a second entry", IDENTITY + "Cargo.toml",
       'features = ["rust_crypto"] }\n', 'features = ["rust_crypto", "rust_crypto"] }\n')

# --- The testkit's fakes: each failure switch ----------------------------------------------

A = TESTKIT_SRC + "audit.rs"
mutate("fake-audit-fail-next-begin-ignored", "a begin told to fail does not", A, "            if state.begin_failing.take() {", "            if false {")
mutate("fake-audit-fail-next-finish-ignored", "a finish told to fail does not", A, "            if state.finish_failing.take() {", "            if false {")
mutate("fake-audit-fail-next-is-fail-all", "a failure meant for the next call is never cleared", A,
       "            Failing::Next => {\n                *self = Failing::Never;\n                true\n            }", "            Failing::Next => true,")
mutate("fake-audit-fail-all-is-fail-next", "a failure meant for every call is cleared after one", A,
       "            Failing::Always => true,", "            Failing::Always => {\n                *self = Failing::Never;\n                true\n            }")
mutate("fake-audit-begin-hold-ignored", "a held begin is not held", A, "            state.begin_gate.clone()", "            None::<Gate>")
mutate("fake-audit-finish-hold-ignored", "a held finish is not held", A, "            state.finish_gate.clone()", "            None::<Gate>")
mutate("fake-audit-begin-attempts-not-counted", "begin attempts are not counted", A, "            state.begin_attempts += 1;\n", "")
mutate("fake-audit-finish-attempts-not-counted", "finish attempts are not counted", A, "            state.finish_attempts += 1;\n", "")
mutate("fake-audit-double-finish-allowed", "a row can be finished twice", A, "            if row.completion.is_some() {", "            if false {")
mutate("fake-audit-row-ids-not-positions", "every row has the same identifier", A, "            Ok(AuditRowId::new(position.to_string()))", '            Ok(AuditRowId::new("0"))')

C = TESTKIT_SRC + "credentials.rs"
NEXT_FAILURE = "            Refusing::Next(failure) => {\n                state.refusing = Refusing::Never;\n                Some(failure)\n            }"
mutate("fake-credentials-refuse-next-ignored", "a request told to fail is issued", C, NEXT_FAILURE, "            Refusing::Next(_) => None,")
mutate("fake-credentials-refuse-next-is-refuse-all", "a failure meant for the next request is never cleared", C, NEXT_FAILURE, "            Refusing::Next(failure) => Some(failure),")
mutate("fake-credentials-refuse-all-ignored", "requests told to fail are issued", C, "            Refusing::Always(failure) => Some(failure),", "            Refusing::Always(_) => None,")
mutate("fake-credentials-unavailable-is-refused", "a source told to be unavailable refuses instead", C,
       "            Some(Failure::Unavailable) => Err(CredentialError::Unavailable(", "            Some(Failure::Unavailable) => Err(CredentialError::Refused(")
mutate("fake-credentials-count-not-kept", "every credential has the same number", C, "            state.issued += 1;\n", "")
mutate("fake-credentials-label-ignores-team", "every team's credential is labelled alike", C,
       "                Some(team) => team.to_string(),", '                Some(_) => "team".to_owned(),')
mutate("fake-credentials-requests-not-recorded", "requests are not recorded", C, "        state.requests.push(CredentialRequest {", "        let _ = (CredentialRequest {")

K = TESTKIT_SRC + "connector.rs"
mutate("fake-connector-fail-ignored", "a connector told to fail does not", K,
       "            let fail = match state.failing {", "            let fail = match state.failing {\n                _ if true => false,")
mutate("fake-connector-fail-next-is-fail-all", "a failure meant for the next call is never cleared", K,
       "                Failing::Next => {\n                    state.failing = Failing::Never;\n                    true\n                }", "                Failing::Next => true,")
mutate("fake-connector-hang-ignored", "a connector told to hang does not", K,
       "            if let Some(gate) = hang {\n                gate.wait().await;\n            }", "            let _ = hang;")
mutate("fake-connector-hang-next-is-hang-all", "a hang meant for the next call is never cleared", K,
       "                    let gate = gate.clone();\n                    state.hang = Hang::Never;\n                    Some(gate)", "                    Some(gate.clone())")
mutate("fake-connector-calls-not-recorded", "calls are not recorded", K, "            state.received.push(ReceivedCall {", "            let _ = (ReceivedCall {")
mutate("fake-connector-write-not-recorded", "a write is not recorded", K, "        self.state().writes.push(write);", "        drop(write);")
mutate("fake-connector-draft-guard-ignored", "the draft tool revises a draft the gateway did not open", K,
       "                .filter(|draft| state.drafts.get(*draft) == Some(&document))", "                .filter(|_| true)")
mutate("fake-connector-draft-any-document", "the draft tool revises a draft through a call naming another document", K,
       "state.drafts.get(*draft) == Some(&document)", "state.drafts.contains_key(*draft)")
mutate("fake-connector-scope-ignored", "the scoped tool refuses nothing", K,
       "                    match named.filter(|name| !scope.contains(*name)) {", "                    match named.filter(|name| false && !scope.contains(*name)) {")
mutate("fake-connector-scope-any-team", "a workload may reach any team's documents through the scoped tool", K,
       "                    state.team_scopes.get(team).cloned().unwrap_or_default()", "                    state.team_scopes.values().flatten().cloned().collect()")
mutate("fake-connector-scope-any-group", "a user may reach any group's documents through the scoped tool", K,
       "                    .filter_map(|group| state.group_scopes.get(group))", "                    .flat_map(|_| state.group_scopes.values())")
mutate("fake-connector-credential-refusal-ignored", "a refused credential does not stop the call", K,
       "                Err(_) => {\n                    return ToolOutcome::Error(\n                        \"the fixture connector could not get a credential\".into(),\n                    );\n                }",
       "                Err(_) => String::new(),")
mutate("fake-connector-echo-drops-credential", "the echo does not carry the credential label", K,
       '    json!({"tool": tool, "echo": arguments, "credential": credential})', '    json!({"tool": tool, "echo": arguments, "credential": ""})')
mutate("fake-connector-time-not-taken", "a connector told to take time does not", K, "                clock.advance(duration);", "                let _ = (clock, duration);")

# --- The testkit's issuer, clocks and gate -------------------------------------------------

I = TESTKIT_SRC + "issuer.rs"
mutate("fake-issuer-without-kid-is-a-no-op", "a token cannot be made without a kid", I, '        self.header.remove("kid");\n', "")
mutate("fake-issuer-signed-by-is-a-no-op", "a token cannot be signed by another issuer", I, "        self.signing = Signing::Other(other);\n", "        let _ = other;\n")
mutate("fake-issuer-corrupt-is-a-no-op", "a corrupted signature is not corrupted", I, "        Some(first) => *first ^= 0x80,", "        Some(first) => *first ^= 0x00,")
mutate("fake-issuer-jwks-document-empty", "the served JWKS document holds no keys", I,
       "        serde_json::to_string(&self.jwk_set())", "        serde_json::to_string(&JwkSet { keys: Vec::new() })")
mutate("fake-issuer-lifetime-ignores-iat", "a lifetime is counted from the epoch", I, "        self.expires_at(issued + lifetime)", "        self.expires_at(lifetime + 0 * issued)")
mutate("fake-issuer-unsigned-is-signed", "an unsigned token is signed", I,
       "            Signing::Unsigned => String::new(),", "            Signing::Unsigned => sign(&self.issuer.key, self.issuer.algorithm, &signing_input),")
mutate("fake-issuer-jwk-has-no-kid", "the published key has no kid", I, "        jwk.common.key_id = Some(key_id.clone());\n", "")
mutate("fake-clock-advance-is-a-no-op", "a steppable clock does not move", TESTKIT_SRC + "clock.rs", "                Some(millis.saturating_add(by))", "                Some(millis)")
mutate("fake-gate-open-wakes-nobody", "opening a gate wakes nothing", TESTKIT_SRC + "gate.rs", "        for waker in wakers {\n            waker.wake();\n        }\n", "        drop(wakers);\n")
F = TESTKIT_SRC + "fixture.rs"
mutate("fake-fixture-profile-for-everyone", "every caller gets team A's profile", F,
       "        ProfileName::new(selected.unwrap_or(UNKNOWN_PROFILE))", "        ProfileName::new(selected.map_or(PROFILE_TEAM_A, |_| PROFILE_TEAM_A))")
mutate("fake-fixture-profile-from-first-group", "a user's profile is chosen from its first group only", F,
       "                    .filter_map(|group| profile_for(&GROUP_PROFILES, group.as_str()))", "                    .take(1)\n                    .filter_map(|group| profile_for(&GROUP_PROFILES, group.as_str()))")
mutate("fake-fixture-several-profiles-pick-one", "a user whose groups select two profiles gets one of them", F,
       "                if profiles.len() == 1 {", "                if !profiles.is_empty() {")


# --- The core's dependencies ---------------------------------------------------------------

# A new crate would change Cargo.lock, which `--locked` refuses before any test runs. Moving a
# dev-dependency into the core's own dependencies leaves the lock as it is.
mutate_all(
    "dependency-added",
    "the core gains a dependency outside the allowlist",
    (CRATE + "Cargo.toml", 'thiserror = "2"\n', 'thiserror = "2"\nproptest = "1"\n'),
    (CRATE + "Cargo.toml", '[dev-dependencies]\nproptest = "1"\n', "[dev-dependencies]\n"),
)


# --- gateway-mcp ---------------------------------------------------------------------------

MCP = "crates/gateway-mcp/src/"
MCP_PARSE = MCP + "parse.rs"
MCP_REPLY = MCP + "reply.rs"
MCP_REJECTION = MCP + "rejection.rs"

mutate("mcp-get-served", "GET is answered", MCP_PARSE,
       "    if method != Method::POST {", "    if method != Method::POST && method != Method::GET {")
mutate("mcp-delete-served", "DELETE is answered", MCP_PARSE,
       "    if method != Method::POST {", "    if method != Method::POST && method != Method::DELETE {")
mutate("mcp-content-type-ignored", "a body not declared as JSON is served", MCP_PARSE,
       "    if !content_type_is_json(headers) {", "    if false && !content_type_is_json(headers) {")
mutate("mcp-accept-ignored", "an Accept excluding JSON is served", MCP_PARSE,
       "    if !accept_admits_json(headers) {", "    if false && !accept_admits_json(headers) {")
mutate("mcp-accept-quality-zero-admits", "an Accept range with q=0 admits JSON", MCP + "headers.rs",
       "is_ok_and(|q| q <= 0.0)", "is_ok_and(|q| q < 0.0)")
mutate("mcp-allow-header-dropped", "a 405 does not say POST is allowed", MCP_REJECTION,
       '                response\n                    .headers\n                    .insert(ALLOW, HeaderValue::from_static("POST"));\n',
       "")
mutate("mcp-challenge-dropped", "a 401 carries no WWW-Authenticate challenge", MCP_REJECTION,
       "                response\n                    .headers\n                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));\n",
       "")
mutate("mcp-batch-accepted", "the first request of a JSON array is processed", MCP_PARSE,
       '        Value::Array(_) => {\n            return Err(Rejection::invalid_request(\n'
       '                "Invalid request: batches are not supported",\n            ));\n        }\n',
       "        Value::Array(mut batch) if !batch.is_empty() => match batch.remove(0) {\n"
       "            Value::Object(object) => object,\n"
       '            _ => return Err(Rejection::invalid_request("not an object")),\n        },\n')
mutate("mcp-null-id-accepted", "id: null is accepted", MCP_PARSE,
       '        Some(Value::Null) => {\n            return Err(Rejection::invalid_request(\n'
       '                "Invalid request: id must not be null",\n            ));\n        }\n',
       "        Some(Value::Null) => Some(RequestId::Number(0)),\n")
mutate("mcp-notification-gets-body", "a notification is answered 200", MCP_REPLY,
       "            status: StatusCode::ACCEPTED,", "            status: StatusCode::OK,")
mutate("mcp-initialize-era-from-meta", "an initialize carrying a modern _meta version is served as modern", MCP_PARSE,
       '    if method == "initialize" {\n        return Era::Legacy;\n    }\n', "")
mutate("mcp-session-id-issued", "initialize gains Mcp-Session-Id", MCP_REPLY,
       "            return result_response(id, result);\n",
       "            let mut response = result_response(id, result);\n"
       '            response.headers.insert(http::HeaderName::from_static("mcp-session-id"), HeaderValue::from_static("dummy-session"));\n'
       "            return response;\n")
mutate("mcp-initialize-echoes-version", "initialize answers a version other than 2025-06-18", MCP_REPLY,
       '"protocolVersion": LEGACY,', '"protocolVersion": MODERN,')
mutate("mcp-protocol-header-optional-modern", "the modern MCP-Protocol-Version header is not required", MCP_PARSE,
       "        Single::Absent | Single::Malformed => {\n            return Err(Rejection::header_mismatch(\n"
       '                id,\n                "Header mismatch: one MCP-Protocol-Version header is required",\n',
       "        Single::Absent => {}\n        Single::Malformed => {\n            return Err(Rejection::header_mismatch(\n"
       '                id,\n                "Header mismatch: one MCP-Protocol-Version header is required",\n')
mutate("mcp-protocol-header-mismatch-accepted", "an MCP-Protocol-Version header that disagrees with _meta is accepted", MCP_PARSE,
       "        Single::One(header) if header == version => {}", "        Single::One(header) if !header.is_empty() => {}")
mutate("mcp-unsupported-version-served", "an unsupported version is served", MCP_PARSE,
       "    if version != MODERN {", "    if version.is_empty() {")
mutate("mcp-capabilities-not-required", "clientCapabilities is optional", MCP_PARSE,
       ".is_some_and(Value::is_object)", ".is_none_or(Value::is_object)")
mutate("mcp-method-header-not-compared", "Mcp-Method is not compared with the body", MCP_PARSE,
       "        Single::One(header) if header == method => {}", "        Single::One(header) if !header.is_empty() => {}")
mutate("mcp-name-header-not-compared", "Mcp-Name is not compared with the body", MCP_PARSE,
       "        Some(decoded) if decoded == name => Ok(()),", "        Some(_) => Ok(()),")
mutate("mcp-name-sentinel-not-decoded", "the base64 sentinel in Mcp-Name is compared raw", MCP_PARSE,
       "    match header_name_value(header) {", "    match Some(header.to_owned()) {")
mutate("mcp-modern-ping-served", "ping is served under 2026-07-28", MCP_PARSE,
       '        "server/discover" => Ok(Call::Discover),\n',
       '        "server/discover" => Ok(Call::Discover),\n        "ping" => Ok(Call::Ping),\n')
mutate("mcp-modern-unknown-method-200", "an unknown modern method is answered 200, not 404", MCP_REJECTION,
       "            Era::Modern => StatusCode::NOT_FOUND,", "            Era::Modern => StatusCode::OK,")
mutate("mcp-legacy-any-header-version", "a legacy request accepts any MCP-Protocol-Version", MCP_PARSE,
       "        Single::One(header) if header == LEGACY => {}", "        Single::One(_) => {}")
mutate("mcp-cursor-accepted", "a cursor the server never issued is accepted", MCP_PARSE,
       "        None | Some(Value::Null) => Ok(Call::ToolsList),", "        _ => Ok(Call::ToolsList),")
mutate("mcp-list-cache-public", "a modern tools/list is marked public", MCP_REPLY,
       '"cacheScope": "private",', '"cacheScope": "public",')
mutate("mcp-legacy-structured-non-object", "a legacy result carries structuredContent that is not an object", MCP_REPLY,
       "            if era == Era::Modern || value.is_object() {", "            if true {")
mutate("mcp-denial-code-changed", "the denial code becomes -32602", MCP + "constants.rs",
       "pub const DENIAL_CODE: i64 = -32001;", "pub const DENIAL_CODE: i64 = -32602;")


# --- gateway -------------------------------------------------------------------------------

GW = "crates/gateway/src/"
BOOT = GW + "boot.rs"
SELECTOR = GW + "selector.rs"
CATALOG = GW + "catalog.rs"

# The identity and audit gates: configured, explicitly disabled, neither, both.
mutate("gw-boot-identity-neither-starts", "identity neither enforced nor disabled starts, unchecked", BOOT,
       "        (None, false) => return Err(BootError::IdentityUnconfigured),\n",
       "        (None, false) => (IdentityConfig::Disabled, GateState::Disabled),\n")
mutate("gw-boot-identity-both-starts", "identity both enforced and disabled starts, unchecked", BOOT,
       "        (Some(_), true) => return Err(BootError::IdentityContradiction),\n",
       "        (Some(_), true) => (IdentityConfig::Disabled, GateState::Disabled),\n")
mutate("gw-boot-audit-neither-starts", "audit with no store and no opt-out starts, recording nothing", BOOT,
       "        (None, false) => Err(BootError::AuditUnconfigured),\n",
       "        (None, false) => Ok((Arc::new(DisabledAuditStore::new()), GateState::Disabled)),\n")
mutate("gw-boot-audit-both-starts", "audit with a store and an opt-out starts", BOOT,
       "        (Some(_), true) => Err(BootError::AuditContradiction),\n",
       "        (Some(store), true) => Ok((store, GateState::On)),\n")
mutate("gw-noop-store-when-enforced", "the no-op store is used although a store was supplied", BOOT,
       "        (Some(store), false) => Ok((store, GateState::On)),\n",
       "        (Some(_), false) => Ok((Arc::new(DisabledAuditStore::new()), GateState::On)),\n")
mutate("gw-disabled-store-constructible", "anyone can make the no-op audit store", GW + "audit.rs",
       "    pub(crate) fn new() -> Self {", "    pub fn new() -> Self {")
mutate("gw-boot-no-allowed-hosts-starts", "a gateway that would refuse every Host starts", BOOT,
       "    if config.http.allowed_hosts.is_empty() {\n        return Err(BootError::NoAllowedHosts);\n    }\n", "")

# Tool definitions.
mutate("gw-boot-missing-catalog-entry", "an approved tool without a definition is served", CATALOG,
       "            if !self.definitions.contains_key(name) {\n                return Err(CatalogError::Missing(name.clone()));\n            }\n",
       "")
mutate("gw-boot-catalog-not-checked", "boot does not check the catalog against the snapshot", BOOT,
       "    catalog.check(&approved)?;\n", "    let _ = &approved;\n")
mutate("gw-catalog-unapproved-accepted", "a definition for a tool nobody approved is kept", CATALOG,
       "            Some(name) => Err(CatalogError::NotApproved(name.clone())),", "            Some(_) => Ok(()),")
mutate("gw-catalog-duplicate-accepted", "a second definition for a tool replaces the first", CATALOG,
       "            if let Some(previous) = catalog.insert(definition.name.clone(), definition) {\n"
       "                return Err(CatalogError::Duplicate(previous.name));\n            }\n",
       "            catalog.insert(definition.name.clone(), definition);\n")
mutate("gw-catalog-schema-not-checked", "an input schema that is not an object schema is accepted", CATALOG,
       '    schema.get("type").and_then(serde_json::Value::as_str) == Some("object")',
       "    let _ = schema;\n    true")

# Connectors.
mutate("gw-boot-unregistered-connector", "a served tool with no registered connector is accepted", BOOT,
       "        if !connectors.contains_key(&tool.connector) {", "        if false && !connectors.contains_key(&tool.connector) {")
mutate("gw-boot-duplicate-connector-accepted", "a connector registered twice keeps the last one", BOOT,
       "    for (name, registered) in registrations {\n"
       "        if connectors.insert(name.clone(), registered).is_some() {\n"
       "            return Err(BootError::DuplicateConnector(name));\n        }\n",
       "    for (name, registered) in registrations {\n        connectors.insert(name, registered);\n")
mutate("gw-boot-registry-duplicate-connector-accepted", "a proxied connector registered twice keeps the last one", BOOT,
       "        };\n        if connectors.insert(name.clone(), registered).is_some() {\n"
       "            return Err(BootError::DuplicateConnector(name));\n        }\n",
       "        };\n        connectors.insert(name, registered);\n")

# Profile selection: the rules, and the checks on them at boot.
mutate("gw-selector-first-group-only", "only the user's first group selects a profile", SELECTOR,
       "                    .iter()\n                    .filter_map(|group| rules.and_then(|rules| rules.get(group)))",
       "                    .iter()\n                    .take(1)\n                    .filter_map(|group| rules.and_then(|rules| rules.get(group)))")
mutate("gw-selector-ignores-issuer", "a user's groups select through another issuer's rules", SELECTOR,
       "                let rules = self.users.get(issuer);", "                let rules = self.users.values().next();")
mutate("gw-selector-workload-ignores-issuer", "a workload's team selects through another issuer's rules", SELECTOR,
       "                .get(issuer)\n                .and_then(|teams| teams.get(team))",
       "                .values()\n                .find_map(|teams| teams.get(team))")
mutate("gw-selector-ambiguous-picks-first", "a user whose groups select two profiles gets the first", SELECTOR,
       "        (Some(profile), None) => Some(profile),", "        (Some(profile), _) => Some(profile),")
mutate("gw-selector-duplicate-workload-rule", "a second rule for one workload key replaces the first", SELECTOR,
       "            if teams.insert(rule.team.clone(), rule.profile).is_some() {",
       "            if teams.insert(rule.team.clone(), rule.profile).is_some() && false {")
mutate("gw-selector-duplicate-user-rule", "a second rule for one user key replaces the first", SELECTOR,
       "            if groups.insert(rule.group.clone(), rule.profile).is_some() {",
       "            if groups.insert(rule.group.clone(), rule.profile).is_some() && false {")
mutate("gw-boot-reserved-profile-accepted", "a policy may define the profile given to unselected callers", BOOT,
       "    if snapshot.profile(&ProfileName::new(NO_PROFILE)).is_some() {",
       "    if false && snapshot.profile(&ProfileName::new(NO_PROFILE)).is_some() {")
mutate("gw-boot-unknown-profile-accepted", "a rule may select a profile the policy lacks", BOOT,
       "        .find(|profile| snapshot.profile(profile).is_none())", "        .find(|_| false)")
mutate("gw-boot-rule-issuer-not-checked", "a rule may name an issuer that is not configured", BOOT,
       "        rules_name_configured_issuers(&config.profiles, issuers)?;\n", "        let _ = issuers;\n")
mutate("gw-boot-rule-issuer-any-kind", "a workload rule may name a user issuer", BOOT,
       "        .find(|rule| !issuers.workloads.contains(&rule.issuer))",
       "        .find(|rule| !issuers.workloads.contains(&rule.issuer) && !issuers.users.contains(&rule.issuer))")

# The testkit is a test tool. Moving it from the gateway's dev-dependencies into its own leaves
# Cargo.lock as it is, so `--locked` still builds and the allowlist test is what notices.
mutate_all(
    "gw-dependency-testkit",
    "the gateway depends on the testkit",
    ("crates/gateway/Cargo.toml", 'tracing = "0.1"\n', 'tracing = "0.1"\ngateway-testkit = { path = "../gateway-testkit" }\n'),
    ("crates/gateway/Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n', "[dev-dependencies]\n"),
)


# --- gateway path --------------------------------------------------------------------------

GW_PATH = GW + "path.rs"
LIST_SURFACE = (
    "entries(&self.inner.gates.policy(), snapshot.surface(&surface).map(|surface| surface.tools.iter()"
    ".filter_map(|name| snapshot.tool(name)).collect()).unwrap_or_default())"
)

mutate("gw-body-parsed-before-identity", "the body is parsed before identity is checked", GW_PATH,
       "        let admitted = match self.admit(method, headers) {\n",
       "        if let Err(rejection) = gateway_mcp::parse(method, headers, body) {\n"
       "            return rejection.response();\n        }\n"
       "        let admitted = match self.admit(method, headers) {\n")
mutate("gw-transport-after-identity", "identity is checked before the transport checks", GW_PATH,
       "        gateway_mcp::check_transport(method, headers).map_err(|rejection| rejection.response())?;\n"
       "        let gates = &self.inner.gates;\n",
       "        let gates = &self.inner.gates;\n"
       "        if let Verification::Failed(_) = gates.identity().check(bearer_token(headers)) {\n"
       "            return Err(Rejection::unauthorized(IDENTITY_FAILURE).response());\n        }\n"
       "        gateway_mcp::check_transport(method, headers).map_err(|rejection| rejection.response())?;\n")
mutate("gw-identity-detail-returned", "the identity failure's cause goes to the caller", GW_PATH,
       "Err(Rejection::unauthorized(IDENTITY_FAILURE).response())",
       "Err(Rejection::unauthorized(&failure.detail().to_string()).response())")
mutate("gw-missing-token-distinct", "a caller with no token gets a different body", GW_PATH,
       "Err(Rejection::unauthorized(IDENTITY_FAILURE).response())",
       "Err(Rejection::unauthorized(if *failure.detail() == gateway_identity::VerifyError::MissingToken "
       '{ "No token was presented." } else { IDENTITY_FAILURE }).response())')
mutate("gw-bearer-duplicate-accepted", "the first of two Authorization headers is used", GW_PATH,
       "    if values.next().is_some() {\n        return None;\n    }\n", "")
mutate("gw-bearer-scheme-case-sensitive", "only `Bearer` spelled with one capital is accepted", GW_PATH,
       '.eq_ignore_ascii_case("bearer")', '.eq("Bearer")')
mutate("gw-bearer-any-scheme", "a token under any scheme is accepted", GW_PATH,
       '.eq_ignore_ascii_case("bearer")', '.ne("")')
mutate("gw-tool-use-id-unbounded", "a tool-use identifier of any length reaches the row", GW_PATH,
       "        && value.len() <= MAX_TOOL_USE_ID\n", "")
mutate("gw-tool-use-id-any-characters", "a tool-use identifier with control characters reaches the row", GW_PATH,
       "\n        && value.bytes().all(|byte| byte.is_ascii_graphic());", ";")
mutate("gw-tool-use-id-dropped", "the tool-use identifier never reaches the row", GW_PATH,
       "tool_use_id: bounded_tool_use_id(tool_use_id),",
       "tool_use_id: bounded_tool_use_id(tool_use_id).filter(|_| false),")
mutate("gw-resources-always-empty", "the resource adapter is ignored", GW_PATH,
       "            Some((tool, adapter)) => adapter.resources(tool, arguments),",
       "            Some(_) => Resources::Named(Vec::new()),")
mutate("gw-resources-from-requested-not-approved", "the adapter is chosen by the requested name", GW_PATH,
       "gates.resource_adapter(&tool.connector)?",
       "gates.resource_adapter(&gateway_core::ConnectorName::new(requested.as_str()))"
       ".or(gates.resource_adapter(&tool.connector))?")
mutate("gw-disabled-identity-lists", "with identity disabled, the surface's tools are listed", GW_PATH,
       "        let Caller::Proved(principal) = caller else {\n            return Vec::new();\n        };\n",
       "        let Caller::Proved(principal) = caller else {\n"
       "            let snapshot = self.inner.gates.snapshot();\n"
       f"            return {LIST_SURFACE};\n        }};\n")
mutate("gw-list-unfiltered", "tools/list returns every tool on the surface, undecided", GW_PATH,
       "        let caller = self.caller_context(&policy, principal, surface);\n"
       "        entries(&policy, list_tools(policy.snapshot(), &caller))\n",
       "        let _ = principal;\n        let snapshot = self.inner.gates.snapshot();\n"
       f"        {LIST_SURFACE}\n")
mutate("gw-disabled-identity-unannounced", "initialize does not say identity is disabled", GW_PATH,
       "        notes.push(IDENTITY_DISABLED_NOTE);\n", "")
mutate("gw-disabled-audit-unannounced", "initialize does not say audit is disabled", GW_PATH,
       "        notes.push(AUDIT_DISABLED_NOTE);\n", "")
mutate("gw-refusal-answered-as-success", "a scope refusal is answered as a result with isError false", GW_PATH,
       "Answer::Refused(sentence) => Reply::Denied(sentence),",
       "Answer::Refused(sentence) => Reply::ToolOk(Value::from(sentence)),")
mutate("gw-audit-failed-as-tool-error", "an unrecorded scope refusal is answered as a tool error", GW_PATH,
       "Answer::AuditFailed { sentence } => Reply::Denied(sentence.to_owned()),",
       "Answer::AuditFailed { sentence } => Reply::ToolError(sentence.to_owned()),")
mutate("gw-tool-error-as-denial", "a tool error is answered as a denial, not a result", GW_PATH,
       "Answer::Error(message) => Reply::ToolError(message),",
       "Answer::Error(message) => Reply::Denied(message),")
mutate("gw-finish-failure-replaces-success", "a failed finish replaces a result with the audit sentence", GW_PATH,
       "        if let Some(failure) = finished.failure() {\n",
       "        if let Some(failure) = finished.failure() {\n"
       "            return Reply::Denied(failure.sentence().to_owned());\n")
mutate("gw-latency-not-measured", "every call is recorded as taking no time", GW_PATH,
       "let latency_ms = elapsed_millis(gates.clock().as_ref(), started);",
       "let latency_ms = 0;")
mutate("gw-read-only-hint-always", "every tool is listed as read-only", GW_PATH,
       "read_only: tool.classification == Classification::Read,", "read_only: true,")


# --- gateway server ------------------------------------------------------------------------

GW_SERVER = GW + "server.rs"
HOST_CHECK = (
    "    if let Err(rejection) = check_host(gates, parts) {\n"
    "        return refused(&rejection);\n    }\n"
)
ADMIT = "    let admitted = match path.admit(&parts.method, &parts.headers) {\n"

mutate("gw-host-check-skipped", "a request for any Host is served", GW_SERVER, HOST_CHECK, "")
mutate_all(
    "gw-host-after-identity",
    "the Host is checked after identity",
    (GW_SERVER, HOST_CHECK, ""),
    (GW_SERVER, "    let Ok(Path(surface)) =", HOST_CHECK + "    let Ok(Path(surface)) ="),
)
mutate("gw-host-port-compared", "the Host is compared with its port", GW_SERVER,
       "let allowed = host.map(without_port).is_some_and(", "let allowed = host.is_some_and(")
mutate("gw-host-first-of-two", "the first of two Host headers is checked", GW_SERVER,
       "        (Some(_), Some(_)) => None,", "        (Some(value), Some(_)) => value.to_str().ok(),")
mutate("gw-host-prefix-match", "a Host that starts with an allowed one is allowed", GW_SERVER,
       ".any(|allowed| allowed.eq_ignore_ascii_case(host))", ".any(|allowed| host.starts_with(allowed.as_str()))")
mutate("gw-origin-check-skipped", "a request from any Origin is served", GW_SERVER,
       "    if let Err(rejection) = check_origin(gates, &parts.headers) {\n        return refused(&rejection);\n    }\n", "")
mutate("gw-origin-required", "a request with no Origin is refused, which shuts out command-line clients", GW_SERVER,
       "    let Some(first) = values.next() else {\n        return Ok(());",
       "    let Some(first) = values.next() else {\n        return Err(Rejection::forbidden_origin());")
mutate("gw-origin-first-of-two", "the first of two Origin headers is checked", GW_SERVER,
       "    let allowed = values.next().is_none()\n        && first", "    let allowed = first")
mutate("gw-declared-length-not-checked", "a declared length over the limit reaches identity", GW_SERVER,
       "    if declared_length(&parts.headers).is_some_and(|length| length > MAX_BODY_BYTES) {",
       "    if false && declared_length(&parts.headers).is_some_and(|length| length > MAX_BODY_BYTES) {")
mutate("gw-declared-length-limit-exclusive", "a body of exactly the limit is refused", GW_SERVER,
       "|length| length > MAX_BODY_BYTES)", "|length| length >= MAX_BODY_BYTES)")
mutate("gw-body-unlimited", "a body with no declared length is read whatever its size", GW_SERVER,
       "axum::body::to_bytes(body, MAX_BODY_BYTES)", "axum::body::to_bytes(body, usize::MAX)")
mutate("gw-body-read-before-identity", "the body is read before identity is checked", GW_SERVER, ADMIT,
       "    let body = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {\n"
       "        Ok(body) => Body::from(body),\n        Err(_) => return unreadable(),\n    };\n" + ADMIT)
mutate("gw-call-on-request-future", "the answer runs on the request's future, so a disconnect cancels it", GW_SERVER,
       "    match tokio::spawn(answering.instrument(span)).await {",
       "    match Ok::<_, tokio::task::JoinError>(answering.instrument(span).await) {")


# --- gateway-dev ---------------------------------------------------------------------------

DEV = "crates/gateway-dev/src/"
DEV_START = DEV + "start.rs"
DEV_PRINTER = DEV + "printer.rs"
DEV_TOKENS = DEV + "tokens.rs"
DEV_CLIENT = DEV + "client.rs"

mutate("dev-listens-on-every-interface", "the fixture gateway listens on every interface, not loopback", DEV_START,
       "pub const LISTEN_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;", "pub const LISTEN_HOST: Ipv4Addr = Ipv4Addr::UNSPECIFIED;")
mutate("dev-identity-off-by-default", "the fixture gateway starts with identity disabled unless told otherwise", DEV_START,
       "            identity_disabled: false,", "            identity_disabled: true,")
mutate("dev-identity-option-ignored", "asking for identity disabled starts it enforced", DEV_START,
       '        config["identity"] = json!({"disabled": true});\n', "")
mutate("dev-clock-option-ignored", "the gateway verifies on the system clock whatever clock it is given", DEV_START,
       "    let mut wiring = Wiring::new(clock.clone()).connector(",
       "    let mut wiring = Wiring::new(Arc::new(SystemClock)).connector(")
mutate("dev-printer-not-wired", "asking for audit rows to be printed prints nothing", DEV_START,
       "            Some(out) => Arc::new(AuditPrinter::new(store.clone(), out)),", "            Some(_) => store.clone(),")
mutate("dev-printer-swallows-begin-failure", "the printer turns a failed begin into a row id, so the call runs with no row", DEV_PRINTER,
       "            begun\n        })", '            begun.or_else(|_| Ok(AuditRowId::new("printed")))\n        })')
mutate("dev-tokens-readable-by-all", "the tokens file keeps whatever mode it was created with", DEV_TOKENS,
       "    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;\n", "")
mutate("dev-token-lifetime-over-ceiling", "the tokens file's tokens live longer than the issuers allow", DEV_TOKENS,
       "pub const TOKEN_LIFETIME_SECS: u64 = DEFAULT_MAX_LIFETIME;", "pub const TOKEN_LIFETIME_SECS: u64 = DEFAULT_MAX_LIFETIME + 1;")
mutate("dev-client-prints-token", "the scripted client prints the bearer token", DEV_CLIENT,
       "\"> authorization: Bearer <{}'s token, not shown>\",\n                self.caller",
       "\"> authorization: Bearer {}\",\n                self.token")
mutate("dev-client-ignores-unexpected", "the scripted client passes whatever the answers were", DEV_CLIENT,
       "            if !exchange.as_expected() {", "            if false && !exchange.as_expected() {")
mutate("dev-client-any-error-is-a-denial", "the scripted client takes any JSON-RPC error for a denial", DEV_CLIENT,
       'Expect::Denied => status == 200 && body["error"]["code"] == json!(DENIAL_CODE),',
       'Expect::Denied => status == 200 && body.get("error").is_some(),')


# --- gateway-dev end-to-end ----------------------------------------------------------------
# Guards the end-to-end tests in crates/gateway-dev/tests/ watch: the server's wait for running
# answers at shutdown, and the fixture world those tests and switchboard-dev share.

DEV_WORLD = DEV + "world.rs"

mutate("gw-shutdown-leaves-answers-running", "the server returns while a call whose client has gone is still running", GW_SERVER,
       "    answers.finished().await;\n", "")
mutate("gw-shutdown-answer-not-counted", "an answer stops being counted as soon as its task starts", GW_SERVER,
       "        let _running = running;\n", "        drop(running);\n")
mutate("dev-resources-ignore-tool", "the fixture's documents are read as if every tool declared them", DEV_WORLD,
       "        FixtureConnector::resources_of(tool.name.as_str(), arguments)",
       "        FixtureConnector::resources_of(gateway_testkit::READ_TOOL, arguments)")
mutate("dev-fixture-allows-an-origin", "the fixture gateway accepts a browser page on localhost", DEV_WORLD,
       '"allowed_origins": []}', '"allowed_origins": ["http://localhost:6274"]}')
mutate("dev-team-b-selects-team-a-profile", "team B's workloads get team A's profile", DEV_WORLD,
       '"team": TEAM_B, "profile": PROFILE_TEAM_B}', '"team": TEAM_B, "profile": PROFILE_TEAM_A}')
mutate("dev-fixture-accepts-another-audience", "the fixture gateway accepts tokens meant for someone else", DEV_WORLD,
       '"audiences": [AUDIENCE],', '"audiences": [AUDIENCE, "someone-else"],')
mutate("dev-fixture-lifetime-unbounded", "the fixture gateway accepts tokens that live for days", DEV_WORLD,
       '"max_lifetime_secs": DEFAULT_MAX_LIFETIME,', '"max_lifetime_secs": DEFAULT_MAX_LIFETIME * 48,')


# --- gateway-dev: switchboard-client -------------------------------------------------------

DEV_CLIENT_BIN = DEV + "bin/switchboard-client.rs"

mutate("dev-client-bin-caller-ignored", "switchboard-client presents team A's token whatever caller it is asked for", DEV_CLIENT_BIN,
       "read_token(&arguments.tokens, caller, SURFACE_READ)", "read_token(&arguments.tokens, Caller::TeamA, SURFACE_READ)")
mutate("dev-client-bin-era-ignored", "switchboard-client runs both eras whatever era it is asked for", DEV_CLIENT_BIN,
       "    for era in arguments.eras {", "    for era in [Era::Legacy, Era::Modern] {")
mutate("dev-client-bin-unexpected-exits-0", "switchboard-client exits 0 when an answer was not as expected", DEV_CLIENT_BIN,
       "    } else {\n        ExitCode::from(1)\n    }", "    } else {\n        ExitCode::SUCCESS\n    }")


# --- mock-docs-server ------------------------------------------------------------------------

MOCK = "crates/mock-docs-server/"
MS = MOCK + "src/server.rs"
MC = MOCK + "src/config.rs"
MD = MOCK + "src/documents.rs"
mutate("mock-any-bearer-accepted", "every bearer is accepted", MS,
       "                accepted: self.inner.accepted.accepts(token),", "                accepted: true,")
mutate("mock-no-bearer-accepted", "a request without a bearer is accepted", MS,
       "            None => Caller {\n                bearer_sha256: None,\n                accepted: false,",
       "            None => Caller {\n                bearer_sha256: None,\n                accepted: true,")
mutate("mock-credential-compares-one-byte", "only the first byte of the digest is compared", MC,
       "            .zip(self.digest.iter())\n", "            .zip(self.digest.iter())\n            .take(1)\n")
mutate("mock-scheme-ignored", "any scheme carries the token", MS,
       '    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())', "    (!scheme.is_empty() && !token.is_empty())")
mutate("mock-post-refusal-skipped", "POST /mcp answers a caller it did not accept", MS,
       '    let mut line = request_line("request", &method, &uri, &caller);\n    if !caller.accepted {',
       '    let mut line = request_line("request", &method, &uri, &caller);\n    if false {')
mutate("mock-other-refusal-skipped", "other methods and paths answer a caller they did not accept", MS,
       '        .write(request_line("request", &method, &uri, &caller));\n    if !caller.accepted {',
       '        .write(request_line("request", &method, &uri, &caller));\n    if false {')
mutate("mock-admin-get-refusal-skipped", "the admin tool list answers a caller it did not accept", MS,
       '        .write(request_line("admin", &method, &uri, &caller));\n    if !caller.accepted {',
       '        .write(request_line("admin", &method, &uri, &caller));\n    if false {')
mutate("mock-admin-put-refusal-skipped", "the admin endpoint changes the tools for a caller it did not accept", MS,
       '    let line = request_line("admin", &method, &uri, &caller);\n    if !caller.accepted {',
       '    let line = request_line("admin", &method, &uri, &caller);\n    if false {')
mutate("mock-log-names-accepted-credential", "the log names the accepted credential, not the one received", MS,
       "                bearer_sha256: Some(logged_prefix(&sha256(token))),", "                bearer_sha256: Some(self.inner.accepted.logged_prefix()),")
mutate("mock-log-full-digest", "the log carries the whole digest, not its prefix", MC, "    hex.truncate(LOGGED_PREFIX_HEX);\n", "")
mutate("mock-protocol-version-unchecked", "any MCP-Protocol-Version header is accepted", MS,
       "        if !ACCEPTED_PROTOCOL_VERSIONS.contains(&version) {", "        if ACCEPTED_PROTOCOL_VERSIONS.is_empty() {")
mutate("mock-documents-keyed-by-name", "a document is found by its name alone, in any project", MD,
       "        self.0.get(&(project.to_owned(), document.to_owned()))",
       "        let _ = project;\n        self.0.iter().find(|((_, name), _)| name == document).map(|(_, content)| content)")
mutate("mock-list-ignores-project", "listing a project lists every project's documents", MD,
       "            .filter(|(owner, _)| owner == project)", "            .filter(|(owner, _)| !owner.is_empty() || project.is_empty())")
mutate("mock-withdrawn-tool-callable", "a tool not offered can still be called", MS,
       "            .filter(|tool| self.offers(*tool))\n", "")
mutate("mock-extra-argument-accepted", "an argument the tool does not declare is accepted", MS,
       "        .find(|key| !tool.arguments().contains(&key.as_str()))", "        .find(|key| key.is_empty())")
mutate("mock-slow-doc-not-slow", "slow-doc answers at once", MS, "                tokio::time::sleep(self.inner.slow).await;\n", "")
mutate("mock-hang-doc-answers", "hang-doc answers", MS,
       "            Some(Content::Hang) => std::future::pending().await,", "            Some(Content::Hang) => Ok(text_result(String::new())),")
mutate("mock-hang-doc-is-slow", "hang-doc answers after slow-doc's delay", MS,
       "            Some(Content::Hang) => std::future::pending().await,",
       "            Some(Content::Hang) => {\n                tokio::time::sleep(self.inner.slow).await;\n                Ok(text_result(String::new()))\n            }")
mutate("mock-fail-doc-succeeds", "fail-doc answers with a result", MS,
       "            Some(Content::Fail) => Err(RpcError::new(", "            Some(Content::Fail) => Ok(text_result(String::new())).map_err(|_: RpcError| RpcError::new(")
mutate("mock-huge-doc-half-size", "huge-doc answers with half a mebibyte", MS, '"x".repeat(HUGE_BYTES)', '"x".repeat(HUGE_BYTES / 2)')
mutate("mock-two-credentials-take-the-file", "with both credential variables set, the file wins", MC,
       "            (Some(path), None, None) => read_token_file", "            (Some(path), _, _) => read_token_file")
mutate("mock-token-file-not-trimmed", "the token file's trailing newline is part of the token", MC,
       "    let token = text.trim();", "    let token = text.as_str();")
mutate("mock-tool-list-repeat-accepted", "MOCK_DOCS_TOOLS may name a tool twice", MOCK + "src/tools.rs",
       "        if tools.contains(&tool) {", "        if false {")
mutate("mock-admin-repeat-accepted", "the admin endpoint may name a tool twice", MS,
       "                if tools.contains(&tool) {", "                if false {")
# Moving a dev-dependency into the server's own dependencies leaves Cargo.lock as it is.
mutate_all(
    "mock-dependency-added",
    "the mock server gains a dependency outside the allowlist",
    (MOCK + "Cargo.toml", 'features = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"] }\n',
     'features = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"] }\nreqwest = { version = "0.12", default-features = false, features = ["json"] }\n'),
    (MOCK + "Cargo.toml", '[dev-dependencies]\nreqwest = { version = "0.12", default-features = false, features = ["json"] }\n', "[dev-dependencies]\n"),
)


# --- connector-proxy -------------------------------------------------------------------------

PROXY = "crates/connector-proxy/"
PC = PROXY + "src/connector.rs"
PO = PROXY + "src/outcome.rs"
PK = PROXY + "src/credentials.rs"
# The bounds.
mutate("proxy-deadline-not-applied", "a call is never abandoned", PC,
       "        match tokio::time::timeout(self.deadline, self.exchange(request)).await {",
       "        match Ok::<_, ()>(self.exchange(request).await) {")
mutate("proxy-default-deadline-longer", "the default deadline is 30 s", PC,
       "Duration = Duration::from_secs(5);", "Duration = Duration::from_secs(30);")
mutate("proxy-default-cap-larger", "the default cap is 1 MiB", PC, "usize = 64 * 1024;", "usize = 1024 * 1024;")
mutate("proxy-streamed-size-unchecked", "a body without a declared length is read whatever its size", PC,
       "                if received.len() + data.len() > self.max_response_bytes {", "                if false {")
mutate("proxy-streamed-size-off-by-one", "a streamed body of exactly the cap is discarded", PC,
       "                if received.len() + data.len() > self.max_response_bytes {",
       "                if received.len() + data.len() >= self.max_response_bytes {")
mutate("proxy-declared-length-ignored", "a declared length over the cap is not refused before reading", PC,
       "            .is_some_and(|length| length > self.max_response_bytes as u64)", "            .is_some_and(|_| false)")
mutate("proxy-declared-length-off-by-one", "a declared length of exactly the cap is refused", PC,
       "            .is_some_and(|length| length > self.max_response_bytes as u64)",
       "            .is_some_and(|length| length >= self.max_response_bytes as u64)")
mutate("proxy-broken-body-read-as-complete", "a body that breaks off is read as if complete", PC,
       "            let frame = frame.map_err(|_| ToolOutcome::Error(outcome::BROKEN_OFF.to_owned()))?;",
       "            let Ok(frame) = frame else { break };")
# What is sent, and to whom.
mutate("proxy-credential-not-sent", "the request carries no credential", PC,
       "            .header(AUTHORIZATION, authorization)\n", "")
mutate("proxy-connector-unchecked", "a tool routed to another connector is forwarded", PC,
       "        if tool.connector != self.connector {", "        if false {")
mutate("proxy-unmapped-tool-sent-as-is", "a tool with no upstream name is sent under its exposed name", PC,
       "        let Some(upstream_name) = self.tools.get(&tool.name) else {\n"
       "            return ToolOutcome::Refused(outcome::NOT_SERVED.to_owned());\n        };",
       "        let upstream_name = self.tools.get(&tool.name).map_or(tool.name.as_str(), String::as_str);")
mutate("proxy-exposed-name-sent", "the exposed name is sent instead of the upstream name", PC,
       "self.request(id, upstream_name, arguments, secret)", "self.request(id, tool.name.as_str(), arguments, secret)")
mutate("proxy-arguments-unchecked", "arguments that are not an object are sent as an empty object", PC,
       "        let Value::Object(arguments) = call.arguments() else {\n"
       "            return ToolOutcome::Refused(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned());\n        };",
       "        let empty = Map::new();\n        let arguments = match call.arguments() {\n"
       "            Value::Object(arguments) => arguments,\n            _ => &empty,\n        };")
# Statuses.
mutate("proxy-401-not-named", "a rejected credential is reported as a bare status", PC,
       "        if status == StatusCode::UNAUTHORIZED {", "        if false {")
mutate("proxy-403-is-an-error", "the server's refusal is recorded as an error", PC,
       "            return Err(ToolOutcome::Refused(outcome::UPSTREAM_REFUSED.to_owned()));",
       "            return Err(ToolOutcome::Error(outcome::UPSTREAM_REFUSED.to_owned()));")
mutate("proxy-any-status-read", "a body is read whatever the status", PC,
       "        if status != StatusCode::OK {", "        if false {")
# Reading the answer.
mutate("proxy-media-type-unchecked", "an answer of any media type is read as JSON", PO,
       "    if !content_type.is_some_and(is_json) {", "    if false {")
mutate("proxy-version-unchecked", "an answer without jsonrpc 2.0 is accepted", PO,
       '    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")\n',
       '    if message.get("jsonrpc").and_then(Value::as_str) == Some("never")\n')
mutate("proxy-id-unchecked", "an answer to another request is accepted", PO,
       '        || message.get("id").and_then(Value::as_u64) != Some(id)\n', "")
mutate("proxy-result-and-error-accepted", "an answer with a result and an error is read as a result", PO,
       "        (Some(Value::Object(result)), None) => tool_result(result),",
       "        (Some(Value::Object(result)), _) => tool_result(result),")
mutate("proxy-content-unchecked", "a result without content is accepted", PO,
       '    let Some(Value::Array(content)) = result.get("content") else {\n'
       "        return ToolOutcome::Error(NOT_MCP.to_owned());\n    };",
       "    let empty = Vec::new();\n"
       '    let content = match result.get("content") {\n        Some(Value::Array(content)) => content,\n        _ => &empty,\n    };')
mutate("proxy-tool-error-is-ok", "a tool result marked isError is passed on as success", PO,
       '    if result.get("isError") != Some(&Value::Bool(true)) {', "    if true {")
mutate("proxy-server-text-uncut", "the server's text reaches the caller at any length", PO,
       "        .take(MAX_MESSAGE_CHARS)\n", "")
mutate("proxy-server-control-characters-kept", "the server's control characters reach the caller", PO,
       "        .map(|c| if c.is_control() { ' ' } else { c })\n", "")
# Configuration.
mutate("proxy-https-accepted", "a URL of any scheme is accepted", PC,
       '    let acceptable = endpoint.scheme_str() == Some("http")\n', "    let acceptable = endpoint.scheme_str().is_some()\n")
mutate("proxy-user-information-accepted", "a URL carrying a user name or password is accepted", PC,
       "        && !authority.as_str().contains('@');", ";")
mutate("proxy-no-tools-accepted", "a server exposing no tools is accepted", PC, "        if tools.is_empty() {", "        if false {")
mutate("proxy-empty-upstream-name-accepted", "an empty upstream name is accepted", PC,
       ".find(|(_, upstream)| upstream.is_empty())", ".find(|_| false)")
mutate("proxy-zero-deadline-accepted", "a zero deadline is accepted", PC, "        if deadline.is_zero() {", "        if false {")
mutate("proxy-zero-cap-accepted", "a zero cap is accepted", PC, "        if max_response_bytes == 0 {", "        if false {")
mutate("proxy-missing-credential-accepted", "a connector with no credential is built", PC,
       "        if !credentials.connectors().any(|held| *held == connector) {", "        if false {")
# The credential source.
mutate("proxy-credential-not-trimmed", "the credential file's trailing newline is part of the token", PK,
       "    let token = text.trim();", "    let token = text.as_str();")
mutate("proxy-empty-credential-accepted", "an empty credential file is accepted", PK, "    if token.is_empty() {", "    if false {")
mutate("proxy-credential-any-bytes", "a credential with spaces or control characters is accepted", PK,
       "    if !token.bytes().all(is_token_byte) {", "    if false {")
mutate("proxy-credential-size-unbounded", "a credential file of any size is read", PK,
       "    if length > MAX_CREDENTIAL_BYTES {", "    if false {")
mutate("proxy-credential-size-off-by-one", "a credential file of exactly the limit is refused", PK,
       "    if length > MAX_CREDENTIAL_BYTES {", "    if length >= MAX_CREDENTIAL_BYTES {")
mutate("proxy-duplicate-credential-accepted", "two files for one connector are accepted", PK,
       "            if entries.contains_key(&connector) {", "            if false {")
mutate("proxy-credential-for-any-connector", "a credential is issued for a connector that has none", PK,
       "        match self.entries.get(connector) {", "        match self.entries.values().next() {")
mutate("proxy-debug-shows-secret", "the source's debug output shows the secret", PK,
       "                    .map(|(connector, stored)| (connector, &stored.label)),",
       "                    .map(|(connector, stored)| (connector, &stored.secret.0)),")
# Moving a dev-dependency into the connector's own dependencies leaves Cargo.lock as it is.
mutate_all(
    "proxy-dependency-added",
    "the connector links the test fakes",
    (PROXY + "Cargo.toml", 'tokio = { version = "1", features = ["time"] }\n',
     'tokio = { version = "1", features = ["time"] }\ngateway-testkit = { path = "../gateway-testkit" }\n'),
    (PROXY + "Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n', "[dev-dependencies]\n"),
)


# --- gateway-registry ----------------------------------------------------------------------

REGISTRY = "crates/gateway-registry/"
RF = REGISTRY + "src/file.rs"
RR = REGISTRY + "src/registry.rs"
RA = REGISTRY + "src/adapter.rs"
RS = REGISTRY + "src/selection.rs"
RD = REGISTRY + "src/definition.rs"

for struct in ["RegistryFile", "ServerFile", "ToolFile", "SourceFile", "SurfaceFile", "PrincipalIdFile",
               "ProfileFile", "RuleFile", "LimitsFile", "ResourceFile"]:
    mutate(f"registry-unknown-field-{struct}", f"{struct} ignores fields it does not know", RF,
           f"#[serde(deny_unknown_fields)]\npub(crate) struct {struct} {{", f"pub(crate) struct {struct} {{")
mutate("registry-unknown-field-CredentialFile", "a credential ignores fields it does not know", RF,
       '#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]', '#[serde(tag = "mode", rename_all = "snake_case")]')
mutate("registry-empty-text-accepted", "required text may be empty", RR,
       "    if value.is_empty() {\n        Err(RegistryError::EmptyField {", "    if false {\n        Err(RegistryError::EmptyField {")
mutate("registry-limit-identifier-empty", "a limit may name the empty identifier", RR,
       '            require(&resource.identifier, "identifier", place)?;\n', "")
mutate("registry-credential-reference-empty", "a credential may have no reference", RR,
       '                require(&reference, "credential.reference", place)?;\n', "")
mutate("registry-duplicate-server", "a second server of one name replaces the first", RR,
       "        if servers.insert(server.name.clone(), checked).is_some() {", "        if servers.insert(server.name.clone(), checked).is_some() && false {")
mutate("registry-address-unchecked", "any address is accepted", RR, "        if !http {", "        if false {")
mutate("registry-address-host-unchecked", "an address with no host is accepted", RR,
       ".is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))", ".is_some()")
mutate("registry-duplicate-tool-left-to-core", "a tool approved twice is not refused by the loader", RR,
       "        if definitions.contains_key(&checked.definition.name) {", "        if false {")
mutate("registry-duplicate-upstream", "one upstream tool may be approved under two names", RR,
       "        if !upstream.insert((", "        if false && !upstream.insert((")
mutate("registry-unknown-server", "a tool on an unregistered server takes the first server", RR,
       "    let Some(server) = servers.get(&tool.server) else {", "    let Some(server) = servers.get(&tool.server).or(servers.values().next()) else {")
mutate("registry-name-outside-system", "a tool may be named after any system", RR, "    if !under_system {", "    if false {")
mutate("registry-name-nothing-after-system", "a tool may be named `{system}__` alone", RR,
       "        .is_some_and(|rest| !rest.is_empty());", "        .is_some();")
mutate("registry-approved-at-offset", "an approval time may have no offset", RR, "    if at.offset.is_none() {", "    if false {")
mutate("registry-hash-unchecked", "a definition changed after approval loads", RR,
       "    if computed != tool.definition_sha256 {", "    if false {")
mutate("registry-hash-ignores-title", "the approval hash does not cover the title", RD,
       '        definition.insert("title".into(), Value::String(title.into()));', "        let _ = title;")
mutate("registry-schema-type-unchecked", "an input schema need not be an object schema", RR,
       '    if tool.input_schema.get("type") != Some(&Value::String("object".into())) {', "    if false {")
mutate("registry-schema-keywords-unchecked", "a schema may use keywords the argument check does not follow", RA,
       ".find(|keyword| object.contains_key(**keyword))", ".find(|keyword| false && object.contains_key(**keyword))")
mutate("registry-schema-properties-unwalked", "keywords inside a property are not looked for", RA,
       "            followable(property, &at.child(name))?;", "            let _ = (property, name);")
mutate("registry-schema-items-unwalked", "keywords inside items are not looked for", RA,
       '        followable(items, &at.child("items"))?;', "        let _ = items;")
mutate("registry-schema-properties-not-object", "`properties` may be something other than an object", RA,
       "            return Err(SchemaProblem::Malformed { at });", "            return Ok(());")
mutate("registry-schema-node-not-schema", "a property or items may be something other than a schema", RA,
       "        _ => return Err(SchemaProblem::Malformed { at: at.clone() }),", "        _ => return Ok(()),")
mutate("registry-adapter-without-sources", "a tool may read its resources from no argument", RR,
       "            if sources.is_empty() {\n                return Err(RegistryError::AdapterWithoutSources(name));",
       "            if false {\n                return Err(RegistryError::AdapterWithoutSources(name));")
mutate("registry-adapter-argument-undeclared", "an adapter may read an argument the schema does not declare", RR,
       "properties.and_then(|p| p.get(&source.from_argument)) else {",
       'properties.and_then(|p| p.get(&source.from_argument)).or(tool.input_schema.get("type")) else {')
mutate("registry-adapter-argument-not-string", "an adapter may read an argument not typed as a string", RR,
       '                if property.get("type") != Some(&Value::String("string".into())) {', "                if false {")
mutate("registry-read-only-not-derived", "every definition is shown as read-only", RR,
       "            read_only: tool.classification == gateway_core::Classification::Read,", "            read_only: true,")
mutate("registry-declaration-no-resources", "a tool with an adapter is approved as naming no resources", RA,
       "        if self.sources.is_empty() {\n            ResourceDeclaration::NoResources", "        if true {\n            ResourceDeclaration::NoResources")
mutate("registry-rule-unknown-profile", "a rule may name a profile that is not defined", RR,
       "        if snapshot.profile(&rule.profile).is_none() {", "        if false {")
mutate("registry-duplicate-rule", "two rules may cover the same principals", RR,
       "        if !covered.insert((rule.issuer.clone(), principal.clone())) {",
       "        if false && !covered.insert((rule.issuer.clone(), principal.clone())) {")
mutate("adapter-missing-argument-skipped", "a missing argument drops its resource and keeps the others", RA,
       "                _ => return Resources::Named(Vec::new()),", "                _ => continue,")
mutate("adapter-empty-identifier-accepted", "the empty string names a resource", RA,
       "Some(Value::String(identifier)) if !identifier.is_empty() => {", "Some(Value::String(identifier)) => {")
mutate("adapter-not-an-object-accepted", "arguments that are not an object pass the check", RA,
       "        if !arguments.is_object() {", "        if false {")
mutate("adapter-undeclared-accepted", "an undeclared argument passes the check", RA,
       "                    None => Some(at.child(key)),", "                    None => None,")
mutate("adapter-undeclared-not-nested", "nested objects are not checked", RA,
       "                    Some(property) => undeclared(property, value, &at.child(key)),", "                    Some(_) => None,")
mutate("adapter-undeclared-not-in-items", "array elements are not checked", RA,
       "        Value::Array(items) => {", "        Value::Array(items) if false => {")
mutate("adapter-pointer-unescaped", "a pointer does not escape `~` and `/`", RA,
       "            token.replace('~', \"~0\").replace('/', \"~1\")", "            token")
mutate("selection-issuer-ignored", "a rule covers principals of any issuer", RS,
       "        principal.id.issuer == self.issuer\n", "        true\n")
mutate("selection-group-ignored", "a group rule covers users in any group", RS,
       "groups.contains(group)", "!groups.is_empty() || groups.contains(group)")
mutate("selection-kind-ignored", "a workload rule covers users and a group rule covers workloads", RS,
       "                _ => false,", "                _ => true,")
mutate("selection-first-rule-wins", "disagreeing rules resolve to one of them", RS,
       "            (Some(_), Some(_)) => Err(NoProfile::Ambiguous(profiles)),", "            (Some(first), Some(_)) => Ok(first.clone()),")
# Moving the dev-dependency leaves Cargo.lock as it is, so the build still runs under --locked.
mutate("registry-links-testkit", "the registry, and so the gateway, links the testkit", REGISTRY + "Cargo.toml",
       'toml = "1"\n\n[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n',
       'toml = "1"\ngateway-testkit = { path = "../gateway-testkit" }\n\n[dev-dependencies]\n')


# --- audit-postgres ------------------------------------------------------------------------

# Most of these are caught only by the tests against Postgres, which run when
# SWITCHBOARD_TEST_DATABASE_URL names a superuser on a throwaway server (see the crate's
# documentation). Without it they survive. The `pg-columns-*` ones need no server, nor do
# pg-check-durability-ignored, pg-check-delete-ignored and pg-retry-slow-attempt-final.
PG = "crates/audit-postgres/"
PG_SQL = PG + "sql/migrations/0001_call_rows.sql"
PG_STORE = PG + "src/store.rs"
PG_COLUMNS = PG + "src/columns.rs"
mutate("pg-trigger-second-completion-allowed", "a completed row can be completed again", PG_SQL,
       "    IF OLD.outcome IS NOT NULL THEN", "    IF false THEN")
mutate("pg-trigger-denial-completed", "the trigger lets a denial be completed", PG_SQL,
       "    IF OLD.decision <> 'allow' THEN", "    IF false THEN")
mutate("pg-trigger-empty-completion-allowed", "an update with no outcome passes the trigger", PG_SQL,
       "        RAISE EXCEPTION 'a completion of audit row % has no outcome', OLD.id;", "        NULL;")
mutate("pg-trigger-other-columns-allowed", "a completion may change other columns", PG_SQL,
       "        RAISE EXCEPTION 'only the completion of audit row % may be written', OLD.id;", "        NULL;")
mutate("pg-trigger-finished-at-not-set", "the database does not set the completion time", PG_SQL,
       "    NEW.finished_at := clock_timestamp();\n", "")
mutate("pg-trigger-not-created", "the write-once trigger is never attached", PG_SQL,
       "CREATE TRIGGER complete_once\n    BEFORE UPDATE ON switchboard_audit.call_rows\n"
       "    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();\n", "")
mutate("pg-grant-insert-begun-at", "the gateway may write the begin time", PG_SQL,
       "    tool_use_id, deployment, surface, profile, tool, connector, classification,\n",
       "    begun_at, tool_use_id, deployment, surface, profile, tool, connector, classification,\n")
mutate("pg-grant-update-widened", "the gateway may update a begin column", PG_SQL,
       "GRANT UPDATE (outcome, outcome_sentence, latency_ms)", "GRANT UPDATE (outcome, outcome_sentence, latency_ms, tool)")
mutate("pg-grant-select-widened", "the gateway may read who called", PG_SQL,
       "GRANT SELECT (id, decision, outcome, outcome_sentence, latency_ms)",
       "GRANT SELECT (id, decision, outcome, outcome_sentence, latency_ms, proved_subject)")
mutate("pg-grant-delete", "the gateway may delete rows", PG_SQL,
       "REVOKE ALL ON switchboard_audit.call_rows FROM PUBLIC;\n",
       "REVOKE ALL ON switchboard_audit.call_rows FROM PUBLIC;\n"
       "GRANT DELETE ON switchboard_audit.call_rows TO switchboard_gateway;\n")
mutate("pg-grant-gateway-creates", "the gateway may create objects in the database", PG + "sql/roles.sql",
       "'GRANT CONNECT ON DATABASE %I TO switchboard_gateway'", "'GRANT CONNECT, CREATE ON DATABASE %I TO switchboard_gateway'")
mutate("pg-check-denial-sentence", "a denial may lack its sentence", PG_SQL,
       "WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL",
       "WHEN 'deny' THEN reason IS NOT NULL AND outcome IS NULL")
mutate("pg-check-allowed-connector", "an allowed call may lack its connector and classification", PG_SQL,
       "\n                AND connector IS NOT NULL AND classification IS NOT NULL", "")
mutate("pg-check-workload-team", "a workload may lack its team", PG_SQL,
       "        (proved_kind = 'workload') = (proved_team IS NOT NULL)\n", "        true\n")
mutate("pg-check-refusal-sentence", "only a refusal carrying a sentence is not checked", PG_SQL,
       "        AND coalesce(outcome = 'refused', false) = (outcome_sentence IS NOT NULL)\n", "")
mutate("pg-check-resources-shape", "resources may be any JSON", PG_SQL,
       "        CHECK (jsonb_typeof(resources) = 'array' OR resources = '\"unknown\"'::jsonb),", "        CHECK (true),")
mutate("pg-migrate-any-role", "any role may run the migrations", PG + "src/migrate.rs",
       "    if current_user != OWNER_ROLE {", "    if false {")
mutate("pg-session-not-synchronous", "sessions keep the role's synchronous_commit", PG_STORE,
       "        config.options(options);\n", "        let _ = options;\n")
mutate("pg-session-options-replaced", "the caller's session options are dropped", PG_STORE,
       'format!("{existing} {SESSION_OPTIONS}")', "SESSION_OPTIONS.to_owned()")
mutate("pg-finish-uses-begin-pool", "finish waits on the begin pool", PG_STORE,
       "            pool: self.finish.clone(),", "            pool: self.begin.clone(),")
mutate("pg-finish-overwrites", "finish does not skip a completed row", PG_COLUMNS,
       "WHERE id = ($1::text)::uuid AND outcome IS NULL", "WHERE id = ($1::text)::uuid")
mutate("pg-finish-same-again-refused", "the same completion written again is an error", PG_STORE,
       "        Some(outcome) if finish.is(&outcome, outcome_sentence.as_deref(), latency_ms) => Ok(()),",
       "        Some(outcome) if false && finish.is(&outcome, outcome_sentence.as_deref(), latency_ms) => Ok(()),")
mutate("pg-finish-different-accepted", "a different second completion is accepted", PG_STORE,
       "        _ => Err(PgAuditError::CompletedDifferently {\n            row: row.to_owned(),\n        }),",
       "        _ => Ok(()),")
mutate("pg-finish-missing-row-accepted", "finishing a row that is not there succeeds", PG_STORE,
       "        return Err(PgAuditError::NoSuchRow {\n            row: row.to_owned(),\n        });",
       "        return Ok(());")
mutate("pg-columns-complete-record-begun", "begin drops a completion it was handed", PG_COLUMNS,
       "        if record.completion.is_some() {", "        if false {")
mutate("pg-columns-claimed-team-from-delegation", "the claimed team column holds the proved delegation team", PG_COLUMNS,
       "            claimed_team: record\n                .claimed_team", "            claimed_team: record\n                .proved_delegation_team")
mutate("pg-columns-workload-team-as-group", "a workload's team is written as a group", PG_COLUMNS,
       '            PrincipalKind::Workload { team } => ("workload", Some(team.to_string()), None),',
       '            PrincipalKind::Workload { team } => ("workload", None, Some(vec![team.to_string()])),')
mutate("pg-columns-latency-not-compared", "a completion with another latency counts as the same", PG_COLUMNS,
       "            && Some(self.latency_ms) == latency_ms\n", "")

# The store's time budgets, and its boot checks.
PG_CHECK = PG + "src/check.rs"
mutate("pg-begin-pool-wait-unbounded", "begin waits for a connection past its budget", PG_STORE,
       "timeout_at(deadline, self.begin.get())", "timeout_at(deadline + Duration::from_secs(3600), self.begin.get())")
mutate("pg-begin-insert-unbounded", "begin waits for its insert past its budget", PG_STORE,
       "timeout_at(deadline, &mut receiver)", "timeout_at(deadline + Duration::from_secs(3600), &mut receiver)")
mutate("pg-timeout-not-cancelled", "a statement that ran out of time is left running", PG_STORE,
       "    tokio::spawn(cancel(client.cancel_token()));\n", "    let _ = cancel;\n")
mutate("pg-timeout-connection-kept", "a connection that ran out of time goes back to its pool", PG_STORE,
       "    drop(Object::take(client));", "    drop(client);")
mutate("pg-finish-waits-past-answer-budget", "finish holds the answer until its deadline", PG_STORE,
       "let answer_by = started + self.budgets.answer;", "let answer_by = started + self.budgets.finish_deadline;")
mutate("pg-finish-stops-at-answer-budget", "finish stops trying when the answer goes out", PG_STORE,
       "            deadline: started + self.budgets.finish_deadline,", "            deadline: started + self.budgets.answer,")
mutate("pg-finish-no-retry", "finish gives up after one failed attempt", PG_STORE,
       "                Err(error) => error,", "                Err(error) => return Err(error),")
mutate("pg-finish-retries-final-errors", "finish retries a failure that trying again cannot fix", PG_STORE,
       "                Err(error) if !error.is_transient() => return Err(error),", "                Err(error) if false => return Err(error),")
mutate("pg-finish-no-deadline", "finish keeps trying past its deadline", PG_STORE,
       "            if now >= self.deadline {", "            if false {")
mutate("pg-retry-connect-failure-final", "a connection that could not be made is not retried", PG_STORE,
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {",
       "            Self::Pool(PoolError::Timeout(_)) | Self::AttemptTimedOut => {")
mutate("pg-retry-slow-attempt-final", "an attempt that ran out of time is not retried", PG_STORE,
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {",
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) => {")
mutate("pg-finish-given-up-not-counted", "a finish that gave up is not counted", PG_STORE,
       "            in_flight.0.given_up.fetch_add(1, Ordering::SeqCst);\n", "")
mutate("pg-check-durability-ignored", "a server without fsync passes the check", PG_CHECK,
       "    (found != expected).then_some(", "    false.then_some(")
mutate("pg-check-superuser-ignored", "a superuser passes the check", PG_CHECK,
       '            (1, "SUPERUSER"),\n', "")
mutate("pg-check-bypassrls-ignored", "a role that bypasses row security passes the check", PG_CHECK,
       '            (5, "BYPASSRLS"),\n', "")
mutate("pg-check-attributes-own-role-only", "a role the session can become is not checked for attributes", PG_CHECK,
       "             WHERE pg_has_role(current_user, oid, 'MEMBER')", "             WHERE rolname = current_user")
mutate("pg-check-owner-membership-ignored", "a member of the table's owner passes the check", PG_CHECK,
       "                 AND pg_has_role(current_user, c.relowner, 'MEMBER')",
       "                 AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)")
mutate("pg-check-table-missing-ignored", "a missing table passes the check", PG_CHECK,
       "        None => problems.push(Problem::TableMissing),", "        None => {}")
mutate("pg-check-column-missing-ignored", "a missing column passes the check", PG_CHECK,
       "            None => problems.push(Problem::ColumnMissing { column }),", "            None => {}")
mutate("pg-check-column-type-ignored", "a column of another type passes the check", PG_CHECK,
       "                if found != *expected {", "                if false {")
mutate("pg-check-trigger-missing-ignored", "a missing trigger passes the check", PG_CHECK,
       "        None => problems.push(Problem::TriggerMissing),", "        None => {}")
mutate("pg-check-trigger-replica-enabled", "a trigger that fires only for replication passes the check", PG_CHECK,
       'Some(enabled) if enabled != "O" && enabled != "A" => {', 'Some(enabled) if enabled == "D" => {')
mutate("pg-check-extra-column-ignored", "a column grant beyond the gateway's passes the check", PG_CHECK,
       "    for (privilege, column) in held.difference(&expected) {", "    for (privilege, column) in held.difference(&held) {")
mutate("pg-check-missing-column-grant-ignored", "a column grant the store needs may be missing", PG_CHECK,
       "    for (privilege, column) in expected.difference(&held) {", "    for (privilege, column) in expected.difference(&expected) {")
mutate("pg-check-whole-table-per-column", "a privilege on the whole table is also reported for every column", PG_CHECK,
       "        if !whole.contains(privilege) {", "        if true {")
mutate("pg-check-delete-ignored", "DELETE on the table passes the check", PG_CHECK,
       '        "DELETE",\n', "")
mutate("pg-check-other-tables-ignored", "column grants on another table in the schema pass the check", PG_CHECK,
       "                     OR (c.relname <> 'call_rows'", "                     OR (false")
mutate("pg-check-schema-usage-ignored", "a role without USAGE on the schema passes the check", PG_CHECK,
       "        if !schema.get::<_, bool>(0) {", "        if false {")
mutate("pg-check-schema-create-ignored", "CREATE on the schema passes the check", PG_CHECK,
       "        if schema.get::<_, bool>(1) {", "        if false {")
mutate("pg-check-database-create-ignored", "CREATE on the database passes the check", PG_CHECK,
       "    if database.get::<_, bool>(1) {", "    if false {")
mutate("pg-check-replication-role-ignored", "a role that may set session_replication_role passes the check", PG_CHECK,
       "        if can_set {", "        if false {")


# --- demo-checks ---------------------------------------------------------------------------
# The demo's scripts and manifests in deploy/, watched by crates/demo-checks.

WORKLOAD = "deploy/demo/workload.sh"
DRIVER = "deploy/demo/demo.sh"
COMPOSE = "deploy/compose/compose.yaml"
POLICY = "deploy/kind/policy/networkpolicies.yaml"

mutate("demo-workload-check-always-passes", "every workload check passes whatever it got", WORKLOAD,
       """  if [ "$1" = "$2" ]; then pass "$3"; else fail""", """  if true; then pass "$3"; else fail""")
mutate("demo-workload-exits-zero-on-failure", "the workload exits 0 after a FAIL", WORKLOAD,
       """  echo "RESULT: FAIL ($FAILS of $total failed)"\n  exit 1\n""", """  echo "RESULT: FAIL ($FAILS of $total failed)"\n  exit 0\n""")
mutate("demo-workload-iserror-defaults-false", "an answer with no result reads as isError false", WORKLOAD,
       """body '.result.isError')""", """body '.result.isError // false')""")
mutate("demo-workload-limit-sentence-unchecked", "any denial sentence passes as the resource-limit one", WORKLOAD,
       """grep -c "^Tool \\`$READ_TOOL\\` names docs project \\`$OTHER_PROJECT\\`, which is outside what .*\\. Name only resources within that limit\\.$")" 1""",
       """grep -c ".")" 1""")
mutate("demo-workload-identity-sentence-unchecked", "an identity refusal's sentence is not checked", WORKLOAD,
       """  check "$(body '.error.message')" "$IDENTITY_FAILURE" "$2: sentence"\n""", "")
mutate("demo-workload-direct-any-failure", "any failed direct call passes, not only a timeout", WORKLOAD,
       """    check "$?" 28 "direct""", """    check "$([ $? -ne 0 ] && echo 28)" 28 "direct""")
mutate("demo-workload-before-policy-status-unchecked", "before the policy, any answer from the server passes", WORKLOAD,
       """  check "$status" 401 "before policy""", """  check 401 401 "before policy""")
mutate("demo-driver-otto-dev-allowed", "the driver runs against otto-dev", DRIVER,
       """if [ "$CLUSTER" = "otto-dev" ]; then""", """if false; then""")
mutate("demo-driver-keeps-kubeconfig-env", "the caller's KUBECONFIG reaches kubectl and kind", DRIVER,
       "\nunset KUBECONFIG\n", "\n: unset KUBECONFIG\n")
mutate("demo-driver-default-kubeconfig", "kubectl uses whatever kubeconfig is the default", DRIVER,
       """k() { kubectl --kubeconfig "$KCFG" --context""", """k() { kubectl --context""")
mutate("demo-driver-down-default-kubeconfig", "down deletes the cluster through the default kubeconfig", DRIVER,
       """down_kind() { kind delete cluster --name "$CLUSTER" --kubeconfig "$KCFG"; }""", """down_kind() { kind delete cluster --name "$CLUSTER"; }""")
mutate("demo-driver-workload-exit-ignored", "a workload's non-zero exit without a FAIL line is not counted", DRIVER,
       """  elif [ "$status" -ne 0 ] && [ "$failed" -eq 0 ]; then""", """  elif false; then""")
mutate("demo-driver-result-ignores-failures", "the RESULT passes with FAILs counted", DRIVER,
       """  if [ "$FAILS" -eq 0 ] && [ "$total" -gt 0 ] && [ -n "$FINISHED" ]; then""", """  if [ "$total" -gt 0 ] && [ -n "$FINISHED" ]; then""")
mutate("demo-driver-any-bearer-is-the-gateways", "mock-docs' accepted bearers are not compared with the gateway's", DRIVER,
       """'$1 == "accepted" && !(length($2) >= 8 && index(sha, $2) == 1) { n++ }""", """'$1 == "accepted" && 0 { n++ }""")
mutate("demo-compose-gateway-on-every-interface", "the gateway is published on every interface", COMPOSE,
       '"127.0.0.1:18080:8080"', '"18080:8080"')
mutate("demo-compose-postgres-published", "Postgres is published", COMPOSE,
       "    image: postgres:17-alpine\n", "    image: postgres:17-alpine\n    ports:\n      - \"127.0.0.1:15433:5432\"\n")
mutate("demo-policy-any-switchboard-pod", "mock-docs admits any pod in the switchboard namespace", POLICY,
       "              kubernetes.io/metadata.name: switchboard\n          podSelector:\n            matchLabels:\n              app: gateway\n",
       "              kubernetes.io/metadata.name: switchboard\n")
mutate("demo-policy-in-base", "the base applies the network policy before the direct call is shown", "deploy/kind/base/kustomization.yaml",
       "  - workloads.yaml\n", "  - workloads.yaml\n  - ../policy\n")
mutate("demo-credential-hash-mismatch", "mock-docs holds the hash of another credential", "deploy/compose/dummy-credentials/docs-credential.sha256",
       "35078c7e636169b1", "35078c7e636169b2")


# --- gateway: the first slice from files ---------------------------------------------------
# The deployment file, the wiring that builds the gateway from it, the registry-mode boot gates
# and reload, the mock server's digest file, the development issuer and the demo driver's
# request count.

DEPLOY = GW + "deployment.rs"
START = GW + "start.rs"
PROXIED = GW + "proxied.rs"
RELOAD = GW + "reload.rs"
POLICY_RS = GW + "policy.rs"
DEV_ISSUER = "crates/gateway-dev/src/issuer.rs"
DEV_BIN = "crates/gateway-dev/src/bin/switchboard-dev.rs"
MOCK_CONFIG = "crates/mock-docs-server/src/config.rs"

for struct in ["DeploymentFile", "RegistrySection", "IssuerFile", "TeamManifest"]:
    mutate(f"gw-deploy-unknown-field-{struct}", f"{struct} ignores fields it does not know", DEPLOY,
           f"#[serde(deny_unknown_fields)]\npub struct {struct} {{", f"pub struct {struct} {{")
mutate_all("gw-deploy-disabled-identity-takes-anything", "identity disabled ignores issuers still listed",
           (DEPLOY, "    /// names a unit variant, so `mode = \"disabled\"` with issuers still listed would load.\n    Disabled {},",
            "    /// names a unit variant, so `mode = \"disabled\"` with issuers still listed would load.\n    Disabled,"),
           (DEPLOY, "            IdentityFile::Disabled {} => IdentitySection {", "            IdentityFile::Disabled => IdentitySection {"))
mutate_all("gw-deploy-disabled-audit-takes-anything", "audit disabled ignores a URL variable still given",
           (DEPLOY, "    /// Record nothing. An empty struct for the same reason as [`IdentityFile::Disabled`].\n    Disabled {},",
            "    /// Record nothing. An empty struct for the same reason as [`IdentityFile::Disabled`].\n    Disabled,"),
           (DEPLOY, "            AuditFile::Disabled {} => AuditChoice::Disabled,", "            AuditFile::Disabled => AuditChoice::Disabled,"))
mutate("gw-deploy-poll-zero", "the registry may be read again never", DEPLOY,
       "        if file.registry.poll_seconds == 0 {", "        if false {")
mutate("gw-deploy-workload-without-manifest", "a workload issuer with no team manifest gets an empty one", DEPLOY,
       "        (IssuerKindName::Workload, None, _) => {\n            return Err(DeploymentError::NoManifest(issuer.issuer));\n        }",
       "        (IssuerKindName::Workload, None, _) => IssuerKindEntry::Workload {\n            subjects: BTreeMap::new(),\n        },")
mutate("gw-deploy-groups-on-workload", "a workload issuer may carry a groups claim", DEPLOY,
       "        (IssuerKindName::Workload, Some(manifest), None) => IssuerKindEntry::Workload {",
       "        (IssuerKindName::Workload, Some(manifest), _) => IssuerKindEntry::Workload {")
mutate("gw-deploy-manifest-for-user", "a user issuer may carry a team manifest", DEPLOY,
       "        (IssuerKindName::User, None, groups_claim) => IssuerKindEntry::User {",
       "        (IssuerKindName::User, _, groups_claim) => IssuerKindEntry::User {")
mutate("gw-deploy-empty-database-url", "an empty database URL is taken as one", DEPLOY,
       "                Some(url) if !url.is_empty() => AuditChoice::Postgres { url },",
       "                Some(url) => AuditChoice::Postgres { url },")
mutate("gw-deploy-paths-not-relative-to-file", "the registry path is read from the working directory", DEPLOY,
       "            registry_file: base.join(file.registry.file),", "            registry_file: file.registry.file,")

mutate("gw-start-credential-any-file", "a server whose reference has no file takes another", START,
       "        let Some(path) = files.get(reference) else {", "        let Some(path) = files.get(reference).or(files.values().next()) else {")
mutate("gw-start-credential-unused", "a credential file no server uses is accepted", START,
       "    if let Some(unused) = files.keys().find(|reference| !used.contains(*reference)) {",
       "    if let Some(unused) = files.keys().find(|reference| !used.contains(*reference)).filter(|_| false) {")
mutate("gw-start-audit-unchecked", "the audit store serves without its boot checks", START,
       "    match tokio::time::timeout(AUDIT_CHECK_BUDGET, store.check_at_boot()).await {",
       "    match tokio::time::timeout(AUDIT_CHECK_BUDGET, async { Ok::<(), BootCheckError>(()) }).await {")
mutate("gw-start-postgres-ignored", "audit set to Postgres connects to nothing", START,
       "        AuditChoice::Postgres { url } => Some(audit_store(url).await?),",
       "        AuditChoice::Postgres { .. } => None::<Arc<PgAuditStore>>,")

mutate("gw-proxied-undeclared-forwarded", "a call with an undeclared argument is sent anyway", PROXIED,
       "            Err(sentence) => Box::pin(std::future::ready(ToolOutcome::Refused(sentence))),",
       "            Err(_sentence) => self.inner.run(call),")
mutate("gw-proxied-withdrawn-forwarded", "a tool withdrawn after its decision is sent anyway", PROXIED,
       "            None => Err(withdrawn_while_deciding(tool.as_str())),", "            None => Ok(()),")
mutate("gw-proxied-resources-never-named", "the registry's adapter is not asked for resources", PROXIED,
       "            (Some(adapter), Some(arguments)) => adapter.resources(arguments),",
       "            (Some(_adapter), Some(_arguments)) => Resources::Named(Vec::new()),")

mutate("gw-boot-registry-connector-unwrapped", "a proxied connector runs without the argument check", BOOT,
       "            connector: Arc::new(CheckedArguments::new(connector, live.clone())),", "            connector,")
mutate("gw-boot-registry-server-unconnected", "a registry server with no connector starts", BOOT,
       "        if !basis.connectors.contains(&route.server) {", "        if false {")
mutate("gw-boot-registry-rule-issuer-unchecked", "a registry rule may name an untrusted issuer", BOOT,
       "            if !configured.contains(&rule.issuer) {", "            if false {")
mutate("gw-boot-registry-reserved-profile", "a registry may define the reserved profile", BOOT,
       "        .profile(&ProfileName::new(NO_PROFILE))\n        .is_some()\n    {",
       "        .profile(&ProfileName::new(NO_PROFILE))\n        .is_some()\n        && false\n    {")
mutate("gw-boot-proxied-without-registry", "a proxied connector starts with no registry to read its arguments", BOOT,
       "        return Err(BootError::ProxiedWithoutRegistry(name));\n", "")
mutate("gw-boot-adapter-beside-registry", "a connector's own adapter is taken beside the registry", BOOT,
       "        return Err(BootError::AdapterBesideRegistry(name));\n", "")

mutate("gw-reload-servers-unchecked", "a reload may change a server the connectors were built for", RELOAD,
       "        if registry.servers() != started.servers() {", "        if false {")
mutate("gw-reload-routes-unchecked", "a reload may route a tool somewhere new", RELOAD,
       "            if started.routes().get(tool) != Some(route) {", "            if false {")
mutate("gw-reload-gates-skipped", "a reload skips the boot gates", RELOAD,
       "        check_registry_policy(registry, &policy, &self.basis)?;\n", "")
mutate("gw-reload-never-reads-again", "the watcher never serves a new file", RELOAD,
       "            if bytes == seen {", "            if true {")

mutate("gw-policy-no-rule-gets-a-profile", "a caller no registry rule covers gets the demo's profile", POLICY_RS,
       "                    ProfileName::new(NO_PROFILE)\n", "                    ProfileName::new(\"workload-read\")\n")
mutate("gw-path-identity-failure-unnamed", "an identity failure's log line has no event name", GW + "path.rs",
       "                    event = \"identity_failed\",\n", "")

mutate("mock-digest-file-beside-token", "a digest file and a token file may both be set", MOCK_CONFIG,
       "            (None, None, Some(path)) => read_digest_file(Path::new(&path))?,",
       "            (_, _, Some(path)) => read_digest_file(Path::new(&path))?,")
mutate("mock-digest-file-read-as-token", "a digest file is read as the token itself", MOCK_CONFIG,
       "            (None, None, Some(path)) => read_digest_file(Path::new(&path))?,",
       "            (None, None, Some(path)) => read_token_file(Path::new(&path))?,")

mutate("dev-issuer-any-subject", "the development issuer signs for any subject", DEV_ISSUER,
       "        self.subjects.contains(subject).then(|| {", "        true.then(|| {")
mutate("dev-issuer-unknown-parameter", "the development issuer ignores parameters it does not know", DEV_ISSUER,
       "            _ => return Err(format!(\"unknown parameter `{name}`\")),", "            _ => continue,")
mutate("dev-issuer-repeated-parameter", "a parameter given twice takes the last value", DEV_ISSUER,
       "        if slot.replace(value).is_some() {", "        if slot.replace(value).is_some() && false {")
mutate("dev-issuer-empty-values", "an empty subject or audience is signed", DEV_ISSUER,
       "        (Some(subject), Some(audience)) if !subject.is_empty() && !audience.is_empty() => {",
       "        (Some(subject), Some(audience)) => {")
mutate("dev-issuer-no-subject", "the development issuer starts with no subjects", DEV_BIN,
       "        subjects: (!subjects.is_empty())", "        subjects: (true)")

mutate("demo-driver-health-checks-counted", "the outage step counts health checks as requests", DRIVER,
       "select(.accepted == true)' | awk 'END { print NR }'", "select(.event == \"request\")' | awk 'END { print NR }'")
mutate("demo-compose-dev-issuer-published", "the development issuer is published", COMPOSE,
       "      - issuer-keys:/shared/issuer\n    healthcheck:",
       "      - issuer-keys:/shared/issuer\n    ports:\n      - \"127.0.0.1:18090:8090\"\n    healthcheck:")


# --- first slice: resources on rows, late begins, naming what goes down ---------------------

# The pg-late-* and pg-begin-not-cancelled ones are caught only against Postgres
# (SWITCHBOARD_TEST_DATABASE_URL); the pg-columns-resources-* ones need no server.
mutate("pg-late-row-left-open", "an allowed row that commits after its begin failed is left open", PG_STORE,
       "                Ok(committed) if allowed => {", "                Ok(committed) if false => {")
mutate("pg-late-denial-completed", "a denied row that commits late is given an outcome", PG_STORE,
       "                Ok(committed) if allowed => {", "                Ok(committed) if true => {")
mutate("pg-late-connection-kept", "a connection whose insert answered late goes back to its pool", PG_STORE,
       "            std::mem::drop(Object::take(client));", "            std::mem::drop(client);")
mutate("pg-begin-not-cancelled", "an insert past the begin budget is left running", PG_STORE,
       "                tokio::spawn(self.cancel.as_ref()(token));", "                let _ = token;")
mutate("pg-columns-resources-dropped", "a row records no resources", PG_COLUMNS,
       "    (Some(column), omitted)", "    (None, 0)")
mutate("pg-columns-resources-omitted-dropped", "a row counts no resources as left out", PG_COLUMNS,
       "    (Some(column), omitted)", "    (Some(column), 0)")
mutate("pg-columns-resources-unknown-as-none", "unknown resources are recorded as none named", PG_COLUMNS,
       '        RecordedResources::Unknown => Value::String("unknown".to_owned()),',
       "        RecordedResources::Unknown => Value::Array(vec![]),")
mutate("demo-driver-down-unnamed-takes-all", "down with nothing named takes down Compose and the cluster", DRIVER,
       "      all) down_compose && down_kind ;;", '      all | "") down_compose && down_kind ;;')
mutate("demo-driver-down-compose-deletes-cluster", "taking Compose down deletes the cluster too", DRIVER,
       "      compose) down_compose ;;", "      compose) down_compose && down_kind ;;")


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
    broken = re.findall(r"could not compile `gateway-[a-z]+` \(([^)]*)\)", output)
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
