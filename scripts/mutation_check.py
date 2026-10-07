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
