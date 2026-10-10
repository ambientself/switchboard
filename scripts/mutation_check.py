#!/usr/bin/env python3
"""Break each guard in the gateway crates, one at a time, and require the tests to notice.

    python3 scripts/mutation_check.py                   # every mutation
    python3 scripts/mutation_check.py --list            # what would run
    python3 scripts/mutation_check.py --targets         # check every target still matches, no cargo
    python3 scripts/mutation_check.py ID [ID ...]       # only these
    python3 scripts/mutation_check.py --shard 0/4       # every fourth mutation, from the first
    python3 scripts/mutation_check.py --all-catchers ID # name every test that catches it

Each mutation is one or more exact text replacements in the workspace's files. The script copies
the workspace into a temporary directory and checks that the unmutated copy passes
`cargo test --workspace --locked`, which also builds everything once. Then for each mutation it
applies the edits to the copy, runs the tests that can see them, and restores the copy. The
working tree is never written to.

The tests that can see a mutation are those of the packages that hold its edited files, of every
workspace package that depends on those (normal, dev or build dependencies, all the way up), and
of the packages that read the edited files from their tests (the READERS table below). A file
outside every crate that the table does not name runs the whole workspace. They run in two steps:
first the packages that hold or read an edited file, which build fastest and catch most; then,
only if those pass, the dependents. Each step stops at the first test binary that fails.
--all-catchers runs both steps at once and to the end, to name every test that fails. The first
time a set of packages is needed, it is run once unmutated ("baseline for [...]"): built on their
own, packages get their dependencies with fewer features, and a set that fails that way is not
used: the end of its output is printed, and its mutations run the whole workspace instead.

The first step builds only its own packages. So a mutation that compiles there but breaks the
build of a package that depends on them is judged by the first step's tests: it is CAUGHT if one
of them fails, though the whole workspace would not build. That is a stale mutation, such as one
that changes a trait in the core but not a crate that implements it. --all-catchers builds the
dependents too and reports such a mutation as NO-VERDICT; run with it to find them.

A scoped run that passes is not trusted on its own: the mutation runs again with the full
`cargo test --workspace --locked --no-fail-fast`, and only if that passes too is it SURVIVED. A
scoped run with no verdict is retried the same way. So a gap in the table costs time, never a
verdict. Each line names the packages that ran ("then workspace" after a retry) and the seconds.

--shard I/N runs every N-th selected mutation starting at the I-th (0-based), after any IDs, so
N processes can split a full run. Each process copies and builds its own workspace; give each its
own Postgres too (see CONTRIBUTING.md).

Verdicts, one line per mutation:

    CAUGHT      a test failed (the line names which), or, for a mutation marked as meaning to
                break the build, the library itself did not compile
    SURVIVED    every test in the workspace passed: nothing watches this guard
    ERROR       the mutation's target text did not match exactly once, so the mutation is
                stale and was not run; it is never counted as caught
    NO-VERDICT  cargo failed without a test failing (a test target did not compile, a timeout),
                in the whole workspace too: nothing was learned

The exit status is zero only if every mutation was caught. CI does not run this. Run it after
changing a guard or the tests that watch one, and add a mutation for every guard you add.

Needs Python 3.12 or later and nothing outside the standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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
# The tests that need Postgres skip, and pass, when this is not set (see CONTRIBUTING.md).
DATABASE_VARIABLE = "SWITCHBOARD_TEST_DATABASE_URL"


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
# The policy structs are the gateway configuration's policy section too: the gateway's boot test
# probes the ones the core's own tests do not.
for path, struct in [
    (SRC + "policy.rs", "Surface"),
    (SRC + "policy.rs", "ApprovedTool"),
    (SRC + "policy.rs", "SnapshotData"),
    (SRC + "policy.rs", "Profile"),
    (SRC + "policy.rs", "ResourceLimits"),
    (SRC + "policy.rs", "Resource"),
    (SRC + "principal.rs", "PrincipalId"),
    (SRC + "audit.rs", "AuditRecord"),
    (SRC + "audit.rs", "RecordedResource"),
]:
    mutate(f"unknown-fields-{struct}", f"{struct} accepts unknown fields", path,
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
    (SRC + "principal.rs", "#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct PrincipalId {",
     "#[derive(Clone, Debug, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct PrincipalId {"),
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
       "    let outcome = connector.run(ToolCall::new(call, tool, arguments)).await;",
       "    let outcome = connector.run(ToolCall::new(call, tool, serde_json::Value::Null)).await;")
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
    "    store\n        .begin(&row, &record)\n        .await\n        .map_err(AuditFailure::from_store)?;",
    "    if let Err(error) = store.begin(&row, &record).await\n        && let Decided::Allow(_) = &decided\n    {\n        return Err(AuditFailure::from_store(error));\n    }",
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
    ("revision", "        policy_revision,\n        proved_principal: call.caller", '        policy_revision: { let _ = policy_revision; PolicyRevision::new("x") },\n        proved_principal: call.caller'),
    ("delegation-team", "            .caller\n            .delegation\n            .as_ref()\n            .map(|delegation| delegation.team().into()),",
     "            .caller\n            .delegation\n            .as_ref()\n            .map(|_| None).flatten(),"),
    ("acting-person", "            .caller\n            .delegation\n            .as_ref()\n            .map(|delegation| delegation.acting_person()),",
     "            .caller\n            .delegation\n            .as_ref()\n            .map(|_| None).flatten(),"),
    ("tool-unescaped", "        tool: sentences::escape(call.tool.as_str(), sentences::MAX_RENDERED),", "        tool: call.tool.as_str().to_owned(),"),
    ("surface-unescaped", "        surface: SurfaceName::new(sentences::escape(\n            call.caller.surface.as_str(),\n            sentences::MAX_RENDERED,\n        )),",
     "        surface: call.caller.surface.clone(),"),
    ("surface-constant", "        surface: SurfaceName::new(sentences::escape(\n            call.caller.surface.as_str(),", '        surface: SurfaceName::new(sentences::escape(\n            "x",'),
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
    line = f"            {field}: sentences::escape(&resource.{field}, {cap}),"
    mutate(f"record-resource-{field}-unescaped", f"a recorded resource's {field} is not made safe", SRC + "audit.rs",
           line, f"            {field}: resource.{field}.clone(),")
    mutate(f"record-resource-{field}-uncapped", f"a recorded resource's {field} is not cut short", SRC + "audit.rs",
           line, f"            {field}: sentences::escape(&resource.{field}, usize::MAX),")
mutate("record-resource-identifier-cap-128", "a recorded identifier is cut at 128 characters, like the tool name", SRC + "audit.rs",
       "            identifier: sentences::escape(&resource.identifier, MAX_RECORDED_IDENTIFIER),",
       "            identifier: sentences::escape(&resource.identifier, sentences::MAX_RENDERED),")
mutate("record-resource-identifier-cap-short", "a recorded identifier is cut one character early", SRC + "audit.rs",
       "pub const MAX_RECORDED_IDENTIFIER: usize = 2048;", "pub const MAX_RECORDED_IDENTIFIER: usize = 2047;")
mutate("record-resource-system-kind-swapped", "a recorded resource's system and kind are swapped", SRC + "audit.rs",
       "            system: sentences::escape(&resource.system, sentences::MAX_RENDERED),\n            kind: sentences::escape(&resource.kind, sentences::MAX_RENDERED),",
       "            system: sentences::escape(&resource.kind, sentences::MAX_RENDERED),\n            kind: sentences::escape(&resource.system, sentences::MAX_RENDERED),")
mutate("finish-ignores-outcome", "finish writes ok whatever happened", SRC + "audit.rs",
       "            outcome: recorded,\n            latency_ms,", "            outcome: { let _ = recorded; Outcome::Ok },\n            latency_ms,")
mutate("finish-ignores-latency", "finish writes a latency of zero", SRC + "audit.rs",
       "            outcome: recorded,\n            latency_ms,", "            outcome: recorded,\n            latency_ms: { let _ = latency_ms; 0 },")
mutate("finish-wrong-row", "finish completes row 0 whatever ran", SRC + "audit.rs",
       "    let completion = RowCompletion {\n        row,\n        completion: Completion {\n            outcome: recorded,",
       '    let completion = RowCompletion {\n        row: { let _ = row; AuditRowId::new("0") },\n        completion: Completion {\n            outcome: recorded,')
mutate("finish-error-swallowed", "a store error on finish is not reported", SRC + "audit.rs",
       "            failure: Some(AuditFailure::from_store(error)),", "            failure: { let _ = error; None },")
mutate("finish-refusal-unrecorded-answered", "a refusal that could not be recorded is still answered with its sentence", SRC + "audit.rs",
       "                Answer::Refused(_) => Answer::AuditFailed {\n                    sentence: sentences::AUDIT_FAILURE,\n                },\n",
       "")
mutate("finish-refusal-sentence-differs", "the refusal the caller reads is not the one recorded", SRC + "audit.rs",
       "            Answer::Refused(sentence),", "            Answer::Refused(sentence.to_uppercase()),")
# A guard given up (decision 0009): its row is completed as error, never ok, through the store.
mutate("core-give-up-completes-ok", "a guard given up records its call as ok", SRC + "audit.rs",
       "            outcome: Outcome::Error,\n            latency_ms: 0,", "            outcome: Outcome::Ok,\n            latency_ms: 0,")
mutate("core-give-up-skips-finish", "a guard given up leaves its row open and reports no failure", SRC + "audit.rs",
       "    let failure = store\n        .finish(&completion)\n        .await\n        .err()\n        .map(AuditFailure::from_store);",
       "    let failure: Option<AuditFailure> = None;")
# A caller that goes away (decision 0009, "Where a call runs"): a read is cancelled, a side effect
# is not.
mutate("core-side-effect-cancelled", "a side effect is cancelled when its caller goes, like a read", SRC + "audit.rs",
       "    if guard.tool.classification != Classification::Read {\n        return run(connector, guard).await;\n    }\n",
       "")
mutate("core-run-unless-drops-arguments", "a read run through run_unless is not given the call's arguments", SRC + "audit.rs",
       "    let mut running = connector.run(ToolCall::new(call, tool, arguments));",
       "    let mut running = connector.run(ToolCall::new(call, tool, serde_json::Value::Null));")
mutate("core-read-not-cancelled-mid-run", "a read whose caller goes while it runs is not cancelled", SRC + "audit.rs",
       "        gone.as_mut().poll(context).map(|()| cancelled())\n",
       "        Poll::Pending\n")
mutate("core-read-gone-already-called", "a read whose caller has already gone is called all the same", SRC + "audit.rs",
       "    if already_gone {\n", "    if false && already_gone {\n")
mutate("core-read-cancel-outcome-ok", "a cancelled read is recorded as ok", SRC + "audit.rs",
       "    let cancelled = || ToolOutcome::Error(sentences::CALLER_DISCONNECTED.to_owned());",
       "    let cancelled = || ToolOutcome::Ok(serde_json::Value::Null);")
# A list row (decision 0009): the tools it names, its count, and the value only it can make.
mutate("core-list-cap-removed", "a list row names every tool the answer lists", SRC + "audit.rs",
       "            .take(MAX_RECORDED_TOOLS)\n", "")
mutate("core-list-omitted-miscounted", "a list row counts the tools it names as left out too", SRC + "audit.rs",
       "    let tools_omitted = tools.len().saturating_sub(MAX_RECORDED_TOOLS);", "    let tools_omitted = tools.len();")
mutate("core-list-fields-public", "a Listed can be made without its row", SRC + "audit.rs",
       "pub struct Listed {\n    row: AuditRowId,\n    tools: Vec<ApprovedTool>,",
       "pub struct Listed {\n    pub row: AuditRowId,\n    pub tools: Vec<ApprovedTool>,")
mutate("core-list-failure-swallowed", "a list whose row could not be written is answered", SRC + "audit.rs",
       "    store\n        .list(&row, &record)\n        .await\n        .map_err(AuditFailure::from_store)?;",
       "    let _ = store.list(&row, &record).await;")
mutate("core-list-answer-cut", "a Listed holds only the tools its row names", SRC + "audit.rs",
       "        tools: tools.into_iter().cloned().collect(),",
       "        tools: tools.into_iter().take(MAX_RECORDED_TOOLS).cloned().collect(),")
mutate("core-list-surface-unescaped", "a list row records the caller's surface as given", SRC + "audit.rs",
       "        surface: SurfaceName::new(sentences::escape(\n            caller.surface.as_str(),\n"
       "            sentences::MAX_RENDERED,\n        )),\n",
       "        surface: caller.surface.clone(),\n")
mutate("core-list-instance-uncapped", "a list row records the instance uncapped", SRC + "audit.rs",
       "    let record = ListRecord {\n        instance: InstanceName::new(sentences::escape(\n"
       "            instance.as_str(),\n            sentences::MAX_RENDERED,\n        )),\n",
       "    let record = ListRecord {\n        instance,\n")
mutate("core-list-delegation-team-dropped", "a list row leaves out the delegation's proved team", SRC + "audit.rs",
       "        proved_delegation_team: caller\n            .delegation\n            .as_ref()\n"
       "            .map(|delegation| delegation.team().into()),\n",
       "        proved_delegation_team: None,\n")
mutate("core-list-acting-person-dropped", "a list row leaves out the delegation's acting person", SRC + "audit.rs",
       "            .map(|delegation| delegation.acting_person()),\n        claimed_team,\n",
       "            .map(|delegation| delegation.acting_person()).filter(|_| false),\n        claimed_team,\n")
mutate("core-list-claimed-team-dropped", "a list row leaves out the team the caller claimed", SRC + "audit.rs",
       "        claimed_team,\n        tools: tools\n",
       "        claimed_team: None,\n        tools: tools\n")

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
       "            Some((_, Piece::Text(value))) => sentence.push_str(&escape(value, MAX_RENDERED)),",
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
    # Connector-proxy's file source implements the trait too, and is changed the same way.
    ("crates/connector-proxy/src/credentials.rs", "        _caller: &Proved<Principal>,\n", "        _caller: &Principal,\n"),
    ("crates/connector-proxy/src/credentials.rs", "        caller: &'a Proved<Principal>,\n", "        caller: &'a Principal,\n"),
    ("crates/connector-proxy/src/connector.rs", ".issue(&self.connector, &call.call().caller.principal)", ".issue(&self.connector, call.call().caller.principal.get())"),
    # The tests that call a source directly are changed to match, so that the whole workspace
    # still builds and what is left to fail is the compile-fail case for a plain principal,
    # which compiles under this mutation: that is the guard under test.
    (TESTKIT + "tests/fakes.rs", '    block_on(source.credential_for(&ConnectorName::from("fixture"), caller))', '    block_on(source.credential_for(&ConnectorName::from("fixture"), caller.get()))'),
    ("crates/connector-proxy/tests/credentials.rs", "credentials.credential_for(&ConnectorName::new(DOCS), &caller)", "credentials.credential_for(&ConnectorName::new(DOCS), caller.get())"),
    ("crates/connector-proxy/tests/credentials.rs", 'credentials.credential_for(&ConnectorName::new("other"), &caller)', 'credentials.credential_for(&ConnectorName::new("other"), caller.get())'),
    ("crates/connector-proxy/tests/credentials.rs", "credentials.credential_for(&ConnectorName::new(CONNECTOR), &caller)", "credentials.credential_for(&ConnectorName::new(CONNECTOR), caller.get())"),
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
       "        if token.len() > MAX_TOKEN_BYTES {", "        if false && token.len() > MAX_TOKEN_BYTES {")
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
# Replacing an issuer's keys while the gate runs: the new set goes through the boot checks by
# rebuilding the whole verifier, and is stored only if that succeeds.
REPLACE_SWAP = ("        *self\n            .verifier\n            .write()\n"
                "            .unwrap_or_else(PoisonError::into_inner) = Arc::new(verifier);\n")
REPLACE_BUILD = "        let verifier = TokenVerifier::new(next.clone(), Arc::clone(&self.clock))?;\n"
mutate("identity-replace-keys-ignored", "a replacement reports success and leaves the old keys in force", IDENTITY_SRC + "identity.rs",
       REPLACE_SWAP, "        drop(verifier);\n")
mutate("identity-replace-keys-swaps-before-check", "a refused set is stored as the configuration later replacements build on", IDENTITY_SRC + "identity.rs",
       REPLACE_BUILD, "        *issuers = next.clone();\n" + REPLACE_BUILD)
mutate("identity-replace-keys-any-issuer", "keys for an issuer that is not configured replace the first issuer's", IDENTITY_SRC + "identity.rs",
       "            .ok_or_else(|| ConfigError::UnknownIssuerForKeys(issuer.clone()))?;", "            .unwrap_or(0);")
mutate("identity-replace-keys-drops-other-issuers", "a replacement rebuilds the verifier with only the replaced issuer", IDENTITY_SRC + "identity.rs",
       REPLACE_BUILD, "        let verifier = TokenVerifier::new(vec![next[index].clone()], Arc::clone(&self.clock))?;\n")
mutate("identity-replace-keys-while-disabled", "keys supplied to a disabled gate are accepted", IDENTITY_SRC + "identity.rs",
       "            return Err(ConfigError::KeysWhileDisabled(issuer.clone()));", "            return Ok(KeysReplaced::default());")

# --- The identity gate and the opaque failure ----------------------------------------------

mutate("identity-missing-token-is-disabled", "no token reads as checking being off", IDENTITY_SRC + "identity.rs",
       "            return Verification::Failed(IdentityFailure::new(VerifyError::MissingToken));", "            return Verification::Disabled;")
mutate("identity-failure-is-disabled", "a refused token reads as checking being off", IDENTITY_SRC + "identity.rs",
       "            Err(failure) => Verification::Failed(failure),", "            Err(_) => Verification::Disabled,")
mutate("identity-enforcing-is-disabled", "configured checking is not applied", IDENTITY_SRC + "identity.rs",
       "            IdentityConfig::Enforce(issuers) => Some(Enforcing::new(issuers, clock)?),", "            IdentityConfig::Enforce(issuers) => Enforcing::new(issuers, clock).ok().filter(|_| false),")
mutate("identity-failure-display-names-the-cause", "the failure displays as its cause", IDENTITY_SRC + "error.rs",
       "        f.write_str(IDENTITY_FAILURE)\n    }\n}\n\nimpl std::error::Error",
       "        write!(f, \"{}\", self.detail)\n    }\n}\n\nimpl std::error::Error")
mutate("identity-failure-outward-names-the-cause", "the outward sentence differs by cause", IDENTITY_SRC + "error.rs",
       "    pub fn outward(&self) -> &'static str {\n        IDENTITY_FAILURE", "    pub fn outward(&self) -> &'static str {\n        if self.detail == VerifyError::UnknownSubject { \"unknown subject\" } else { IDENTITY_FAILURE }")
mutate("identity-groups-claim-sentence", "the log names the groups claim as `the groups claim claim`", IDENTITY_SRC + "error.rs",
       '            Claim::Groups => "groups claim",', '            Claim::Groups => "the groups claim claim",')
mutate("identity-state-names","the proved state is recorded under another name", IDENTITY_SRC + "identity.rs",
       '            VerificationState::Proved => "proved",', '            VerificationState::Proved => "ok",')
# What a refused token claimed: kept beside the failure, escaped and capped, for the
# identity-failure event, and never in the cause, the caller's sentence or the failure's Debug.
# The cause has no field a claimed value could go in, so no mutation puts one there; giving it
# one breaks the token table's exhaustive match before any test runs.
CLAIMED_KEPT = "        let kept = |text: &str| Claimed::new(escape(text, MAX_CLAIMED));\n"
mutate("identity-claimed-not-escaped", "a claimed issuer or subject is kept as the token wrote it, only cut short", IDENTITY_SRC + "error.rs",
       CLAIMED_KEPT, "        let kept = |text: &str| Claimed::new(text.chars().take(MAX_CLAIMED).collect::<String>());\n")
mutate("identity-claimed-not-capped", "a claimed issuer or subject is kept at any length", IDENTITY_SRC + "error.rs",
       CLAIMED_KEPT, "        let kept = |text: &str| Claimed::new(escape(text, usize::MAX));\n")
mutate("identity-claimed-in-outward", "the outward sentence names the claimed subject", IDENTITY_SRC + "error.rs",
       "    pub fn outward(&self) -> &'static str {\n        IDENTITY_FAILURE",
       "    pub fn outward(&self) -> &'static str {\n        Box::leak(format!(\"{IDENTITY_FAILURE} {:?}\", self.claimed.subject()).into_boxed_str())")
mutate("identity-claimed-in-display", "the failure displays the claimed issuer", IDENTITY_SRC + "error.rs",
       "        f.write_str(IDENTITY_FAILURE)\n    }\n}\n\nimpl std::error::Error",
       "        write!(f, \"{IDENTITY_FAILURE} {:?}\", self.claimed.issuer())\n    }\n}\n\nimpl std::error::Error")
mutate("identity-claimed-in-debug", "the failure's Debug includes what the token claimed", IDENTITY_SRC + "error.rs",
       '            .field("detail", &self.detail)\n            .finish_non_exhaustive()',
       '            .field("detail", &self.detail)\n            .field("claimed", &self.claimed)\n            .finish()')
CLAIMED_READ = '    ClaimedCaller::new(text("iss"), text("sub"))\n'
mutate("identity-claimed-issuer-dropped", "a refusal keeps no claimed issuer", V, CLAIMED_READ, '    ClaimedCaller::new(None, text("sub"))\n')
mutate("identity-claimed-subject-dropped", "a refusal keeps no claimed subject", V, CLAIMED_READ, '    ClaimedCaller::new(text("iss"), None)\n')
mutate("identity-claimed-non-string-kept", "a claim that is not a string is kept as empty text", V,
       "    let text = |name: &str| unverified.get(name).and_then(Value::as_str);",
       "    let text = |name: &str| unverified.get(name).map(|value| value.as_str().unwrap_or_default());")
mutate("identity-claimed-from-oversize-token", "a token too large to verify is read for what it claims", V,
       "    if token.len() > MAX_TOKEN_BYTES {\n        return ClaimedCaller::default();",
       "    if false {\n        return ClaimedCaller::default();")
mutate("identity-claimed-only-for-unknown-issuer", "only a token from an unlisted issuer keeps what it claimed", V,
       "            .map_err(|detail| IdentityFailure::claiming(detail, claimed_by(token)))",
       "            .map_err(|detail| if detail == VerifyError::UnknownIssuer { IdentityFailure::claiming(detail, claimed_by(token)) } else { IdentityFailure::new(detail) })")
mutate_all(
    "identity-dependency-added",
    "the identity crate gains a dependency outside the allowlist",
    (IDENTITY + "Cargo.toml", 'thiserror = "2"\n', 'thiserror = "2"\nproptest = "1"\n'),
    (IDENTITY + "Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\nproptest = "1"\n', '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n'),
)
mutate_all(
    "identity-dependency-added-under-spaced-target",
    "the identity crate gains a dependency outside the allowlist, under a target table spelled with spaces",
    (IDENTITY + "Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\nproptest = "1"\n', '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n'),
    (IDENTITY + "Cargo.toml", "\n[lints]\n", "\n[ target.'cfg(all())'.dependencies ]\nproptest = \"1\"\n\n[lints]\n"),
)
# Enabling `aws_lc_rs` itself would add crates to Cargo.lock, which `--locked` refuses before any
# test runs, so that mutation could never give a verdict. Any second entry in the feature list
# fails the same assertion a second backend would, and leaves the lock as it is.
mutate("identity-second-crypto-backend", "the crypto feature list gains a second entry", IDENTITY + "Cargo.toml",
       'features = ["rust_crypto"] }\n', 'features = ["rust_crypto", "rust_crypto"] }\n')

# --- The testkit's fakes: each failure switch ----------------------------------------------

A = TESTKIT_SRC + "audit.rs"
mutate("fake-audit-fail-next-begin-ignored", "a begin told to fail does not", A,
       "            if state.begin_failing.take() {\n                return Err(down());\n            }\n            if state.list_rows",
       "            if false {\n                return Err(down());\n            }\n            if state.list_rows")
mutate("fake-audit-fail-next-finish-ignored", "a finish told to fail does not", A, "            if state.finish_failing.take() {", "            if false {")
mutate("fake-audit-fail-next-is-fail-all", "a failure meant for the next call is never cleared", A,
       "            Failing::Next => {\n                *self = Failing::Never;\n                true\n            }", "            Failing::Next => true,")
mutate("fake-audit-fail-all-is-fail-next", "a failure meant for every call is cleared after one", A,
       "            Failing::Always => true,", "            Failing::Always => {\n                *self = Failing::Never;\n                true\n            }")
mutate("fake-audit-begin-hold-ignored", "a held begin is not held", A, "            state.begin_gate.clone()", "            None::<Gate>")
mutate("fake-audit-finish-hold-ignored", "a held finish is not held", A, "            state.finish_gate.clone()", "            None::<Gate>")
mutate("fake-audit-begin-attempts-not-counted", "begin attempts are not counted", A, "            state.begin_attempts += 1;\n", "")
mutate("fake-audit-finish-attempts-not-counted", "finish attempts are not counted", A, "            state.finish_attempts += 1;\n", "")
FAKE_FINISHED_DIFFERENTLY = '            Some(_) => Err("the row was already finished, with a different completion".into()),'
mutate("fake-audit-double-finish-allowed", "a different second completion of a row is accepted", A,
       FAKE_FINISHED_DIFFERENTLY, "            Some(_) => Ok(()),")
mutate("testkit-finish-overwrites", "a different second completion overwrites the first", A,
       FAKE_FINISHED_DIFFERENTLY,
       "            Some(_) => {\n                row.completion = Some(completion.clone());\n                Ok(())\n            }")
FAKE_BEGIN_PUSH = "                    state.rows.push((row.clone(), record.clone(), times));"
mutate("fake-audit-begin-drops-resources", "the store keeps a row without the resources begin recorded", A, FAKE_BEGIN_PUSH,
       "                    state.rows.push((row.clone(), AuditRecord { resources: gateway_core::audit::RecordedResources::Unknown, ..record.clone() }, times));")
mutate("fake-audit-begin-resets-omitted", "the store keeps a row without the count of resources begin omitted", A, FAKE_BEGIN_PUSH,
       "                    state.rows.push((row.clone(), AuditRecord { resources_omitted: 0, ..record.clone() }, times));")
FAKE_FINISH_WRITE = "                row.completion = Some(completion.clone());\n                Ok(())"
mutate("fake-audit-finish-resets-omitted", "finishing a row clears its count of omitted resources", A, FAKE_FINISH_WRITE,
       "                row.completion = Some(completion.clone());\n                row.resources_omitted = 0;\n                Ok(())")
mutate("fake-audit-finish-rewrites-row", "finishing a row changes more than its completion", A, FAKE_FINISH_WRITE,
       "                row.completion = Some(completion.clone());\n                row.resources_omitted += 1;\n                Ok(())")
mutate("fake-audit-row-id-ignored", "the store keeps every row under one identifier, not the one begin was given", A,
       FAKE_BEGIN_PUSH, '                    state.rows.push((AuditRowId::new("0"), record.clone(), times));')
mutate("testkit-begin-duplicates-row", "a begin with a known identifier writes a second row", A,
       "            match state.rows.iter().find(|(id, _, _)| id == row) {",
       "            match state.rows.iter().find(|(id, _, _)| id == row && false) {")
mutate("fake-audit-begin-decision-not-compared", "a begin with a known identifier and another decision succeeds", A,
       "                Some((_, stored, _)) if stored.decision == record.decision => {}",
       "                Some((_, stored, _)) if stored.decision == record.decision || true => {}")
mutate("testkit-deadline-wrong-clock", "the in-memory store reads the system clock, not its own, for a row's times", A,
       "        let begun_at = self.clock.now();", "        let begun_at = SystemTime::now();")
mutate("testkit-lost-confirmation-left-open", "an allowed row whose begin confirmation was lost is left open", A,
       "                let _ = state.complete(row, &error);", "                let _ = &error;")
mutate("testkit-lost-confirmation-ignored", "a begin told to lose its confirmation succeeds", A,
       "            if state.confirmation_lost.take() {\n                let error", "            if false {\n                let error")
mutate("testkit-lost-list-confirmation-ignored", "a list told to lose its confirmation succeeds", A,
       "            if state.confirmation_lost.take() {\n                return Err(lost());", "            if false {\n                return Err(lost());")
mutate("testkit-lost-confirmation-before-write", "a lost confirmation writes no row", A,
       "            if state.begin_failing.take() {\n                return Err(down());\n            }\n            if state.list_rows",
       "            if state.begin_failing.take() || state.confirmation_lost.take() {\n                return Err(down());\n            }\n            if state.list_rows")
mutate("testkit-answer-budget-written-at-once", "a finish past the answer budget is written before its gate opens", A,
       "state.answer_gate.clone().filter(|gate| !gate.is_open())", "None::<Gate>")
mutate("testkit-answer-budget-never-written", "a finish past the answer budget is never written", A,
       ".partition::<Vec<_>, _>(|late| late.gate.is_open());", ".partition::<Vec<_>, _>(|late| late.gate.is_open() && false);")
mutate("testkit-forgotten-finish-written", "a finish from a lost process is written", A,
       "            if state.finishes_forgotten {", "            if false {")
mutate("testkit-forgotten-late-completion-written", "a completion still being tried when the process is lost is written", A,
       "        state.late.clear();\n", "")
mutate("testkit-nul-accepted", "the in-memory store writes a value with U+0000, which Postgres cannot hold", A,
       "        Value::String(text) => text.contains('\\0'),", "        Value::String(_) => false,")
mutate("testkit-past-bigint-accepted", "the in-memory store writes a count, latency or allowance past a Postgres bigint", A,
       "    if i64::try_from(value).is_err() {", "    if false {")
mutate("testkit-list-unchecked", "the in-memory store writes any list record", A,
       "            refused_at_list(row, record)?;\n", "")
mutate("testkit-non-uuid-accepted", "the in-memory store writes a row under an identifier that is not a lowercase hyphenated UUID", A,
       "    if !uuid {\n", "    if false {\n")
mutate("testkit-complete-at-begin-accepted", "the in-memory store's begin writes a record that is already complete", A,
       "    if record.completion.is_some() {\n", "    if false {\n")
mutate("testkit-unknown-resources-omitted-accepted", "the in-memory store writes unknown resources with a count left out", A,
       "    if record.resources == RecordedResources::Unknown && record.resources_omitted != 0 {",
       "    if false {")
mutate("testkit-completion-unchecked", "the in-memory store writes any completion", A,
       "            refused_at_finish(completion.completion())?;\n", "")
mutate("testkit-allowance-wraps", "a call deadline near the largest wraps round to a short deadline", A,
       "        .saturating_add(call_deadline_ms)", "        .wrapping_add(call_deadline_ms)")
mutate("testkit-allowance-rounds-up", "a budget is counted in part milliseconds, not whole ones as Postgres counts it", A,
       "    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)",
       "    u64::try_from(duration.as_millis() + u128::from(duration.subsec_nanos() % 1_000_000 > 0)).unwrap_or(u64::MAX)")
mutate("testkit-denial-completed", "the in-memory store completes a denial, which complete_once refuses", A,
       "        if row.decision != DecisionKind::Allow {", "        if false {")
mutate("testkit-list-row-completed", "the in-memory store finds no row, rather than a listing, when finish names a list row", A,
       "        if self.list_rows.iter().any(|(stored, _, _)| stored == id) {", "        if false {")
mutate("testkit-list-kind-completed", "the in-memory store completes a call row of kind list, which complete_once refuses", A,
       "        if row.kind != RowKind::Call {", "        if false {")
mutate("testkit-deadline-past-postgres-end", "the in-memory store writes a deadline past what a Postgres time holds", A,
       "    if begun_micros + i128::from(span_micros) >= POSTGRES_END_MICROS {", "    if false {")
mutate("testkit-deadline-end-accepted", "the in-memory store writes a deadline at the end of what a Postgres time holds", A,
       "    if begun_micros + i128::from(span_micros) >= POSTGRES_END_MICROS {",
       "    if begun_micros + i128::from(span_micros) > POSTGRES_END_MICROS {")
mutate("testkit-interval-overflow-accepted", "the in-memory store writes an allowance past what a Postgres interval holds", A,
       "    if product >= TWO_TO_THE_63 {", "    if false {")
mutate("testkit-deadline-exact-arithmetic", "the in-memory store adds the allowance exactly, not through float8 as Postgres does", A,
       "    let span_micros = product as u64;", "    let span_micros = allowance_ms.saturating_mul(1000);")

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
# A table header with spaces is still a table to Cargo, and one under a target is still built.
mutate_all(
    "dependency-added-under-spaced-target",
    "the core gains a dependency outside the allowlist, under a target table spelled with spaces",
    (CRATE + "Cargo.toml", '[dev-dependencies]\nproptest = "1"\n', "[dev-dependencies]\n"),
    (CRATE + "Cargo.toml", "\n[lints]\n", "\n[ target.'cfg(all())'.dependencies ]\nproptest = \"1\"\n\n[lints]\n"),
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
       ".is_some_and(|(_, quality)| quality > 0.0)", ".is_some_and(|(_, quality)| quality >= 0.0)")
mutate("mcp-accept-specificity-ignored", "a broader Accept range outvotes application/json;q=0", MCP + "headers.rs",
       ".max_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)))", ".max_by(|a, b| a.1.total_cmp(&b.1))")
mutate("mcp-row-meta-drops-server-info", "the row replaces a modern result's _meta instead of joining it", MCP_REPLY,
       "        let meta = map.entry(\"_meta\").or_insert_with(|| json!({}));\n"
       "        insert(meta, AUDIT_ROW_META, Value::from(row));\n",
       "        map.insert(\"_meta\".to_owned(), json!({AUDIT_ROW_META: row}));\n")
mutate("mcp-accept-least-specific-wins", "the least specific Accept range decides", MCP + "headers.rs",
       ".max_by(|a, b| a.0.cmp(&b.0).then(", ".max_by(|a, b| a.0.cmp(&b.0).reverse().then(")
mutate("mcp-allow-header-dropped", "a 405 does not say POST is allowed", MCP_REJECTION,
       '                response\n                    .headers\n                    .insert(ALLOW, HeaderValue::from_static("POST"));\n',
       "")
mutate("mcp-challenge-dropped", "a 401 carries no WWW-Authenticate challenge", MCP_REJECTION,
       "                response\n                    .headers\n                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));\n",
       "")
mutate("mcp-request-timeout-keeps-connection", "a 408 leaves the connection open for the rest of the late body", MCP_REJECTION,
       '                    .insert(CONNECTION, HeaderValue::from_static("close"));',
       '                    .insert(CONNECTION, HeaderValue::from_static("keep-alive"));')
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
mutate("mcp-method-header-optional", "a modern request with no Mcp-Method header is served", MCP_PARSE,
       '        Single::Absent | Single::Malformed => {\n            return Err(Rejection::header_mismatch(\n'
       '                id,\n                "Header mismatch: one Mcp-Method header is required",\n',
       "        Single::Absent => {}\n        Single::Malformed => {\n            return Err(Rejection::header_mismatch(\n"
       '                id,\n                "Header mismatch: one Mcp-Method header is required",\n')
mutate("mcp-name-header-optional", "a modern tools/call with no Mcp-Name header is served", MCP_PARSE,
       "fn check_name_header(headers: &HeaderMap, id: &RequestId, name: &str) -> Result<(), Rejection> {\n",
       "fn check_name_header(headers: &HeaderMap, id: &RequestId, name: &str) -> Result<(), Rejection> {\n"
       "    if matches!(single(headers, NAME_HEADER), Single::Absent) {\n        return Ok(());\n    }\n")
mutate("mcp-duplicate-header-first-used", "the first of two copies of a single-valued MCP header is used", MCP + "headers.rs",
       "    if values.next().is_some() {\n        return Single::Malformed;\n    }\n", "")
mutate("mcp-name-sentinel-not-decoded", "the base64 sentinel in Mcp-Name is compared raw", MCP_PARSE,
       "    match header_name_value(header) {", "    match Some(header.to_owned()) {")
mutate("mcp-modern-ping-served", "ping is served under 2026-07-28", MCP_PARSE,
       '        "server/discover" => Ok(Call::Discover),\n',
       '        "server/discover" => Ok(Call::Discover),\n        "ping" => Ok(Call::Ping),\n')
mutate("mcp-legacy-ping-unknown", "ping is not served under 2025-06-18", MCP_PARSE,
       '        "ping" => Ok(Call::Ping),\n', "")
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
mutate("mcp-era-header-ignored", "a request with the modern version header and no _meta is served as legacy", MCP_PARSE,
       "    if params.meta(PROTOCOL_VERSION_META).is_some() || header_is_modern {",
       "    if params.meta(PROTOCOL_VERSION_META).is_some() {")
mutate("mcp-era-meta-ignored", "a request whose _meta names its version, with no version header, is served as legacy", MCP_PARSE,
       "    if params.meta(PROTOCOL_VERSION_META).is_some() || header_is_modern {",
       "    if header_is_modern {")
mutate("mcp-content-type-any-charset", "a JSON content type with a charset other than UTF-8 is served", MCP + "headers.rs",
       '            || value.trim().trim_matches(\'"\').eq_ignore_ascii_case("utf-8")',
       '            || !value.is_empty()')
mutate("mcp-jsonrpc-version-unchecked", "a request that does not say jsonrpc 2.0 is served", MCP_PARSE,
       '    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {',
       '    if false && object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {')
mutate("mcp-response-refused-as-methodless", "a posted response is refused only for having no method", MCP_PARSE,
       '        None if object.contains_key("result") || object.contains_key("error") => {',
       '        None if false => {')
mutate("mcp-fractional-id-accepted", "a fractional or out-of-range id is read as an integer", MCP_PARSE,
       "        Some(Value::Number(id)) => match id.as_i64() {",
       "        Some(Value::Number(id)) => match id.as_i64().or_else(|| id.as_f64().map(|id| id as i64)) {")
mutate("mcp-params-not-object-accepted", "params that are not an object are read as empty", MCP_PARSE,
       "        Some(_) => Params::Malformed,", "        Some(_) => Params::Object(Map::new()),")
mutate("mcp-call-name-optional", "a tools/call with no name is served with an empty name", MCP_PARSE,
       '    let Some(Value::String(name)) = params.remove("name") else {',
       '    let Some(Value::String(name)) = params.remove("name").or(Some(Value::String(String::new()))) else {')
mutate("mcp-method-not-string-accepted", "a method that is not a string is read as its JSON text", MCP_PARSE,
       '        Some(_) => {\n            return Err(Rejection::invalid_request(\n'
       '                "Invalid request: method must be a string",\n            ));\n        }\n',
       "        Some(method) => method.to_string(),\n")
mutate("mcp-no-method-accepted", "a request with no method is read as one with an empty method", MCP_PARSE,
       '        None => return Err(Rejection::invalid_request("Invalid request: no method")),',
       "        None => String::new(),")
mutate("mcp-structured-id-accepted", "an id that is an object or an array is dropped, making the request a notification", MCP_PARSE,
       '        Some(_) => {\n            return Err(Rejection::invalid_request(\n'
       '                "Invalid request: id must be a string or an integer",\n            ));\n        }\n    };\n',
       "        Some(_) => None,\n    };\n")
mutate("mcp-call-arguments-array-accepted","a tools/call whose arguments are an array is served with none", MCP_PARSE,
       "        None | Some(Value::Null) => Map::new(),", "        None | Some(Value::Null | Value::Array(_)) => Map::new(),")
# The adapter's dependency fence. It has no dev-dependency to move, so the mutation adds a crate
# the workspace already locks and edits Cargo.lock to match, which `--locked` accepts.
mutate_all(
    "mcp-dependency-thiserror",
    "the adapter depends on a crate outside its allowlist",
    ("crates/gateway-mcp/Cargo.toml", 'serde_json = "1"\n\n[lints]\n', 'serde_json = "1"\nthiserror = "2"\n\n[lints]\n'),
    ("Cargo.lock", 'name = "gateway-mcp"\nversion = "0.1.0"\ndependencies = [\n "base64 0.22.1",\n "http",\n "serde_json",\n]\n',
     'name = "gateway-mcp"\nversion = "0.1.0"\ndependencies = [\n "base64 0.22.1",\n "http",\n "serde_json",\n "thiserror",\n]\n'),
)


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

# The receipt-store gate (decision 0009): a tool not classified `read` on a surface is refused
# outside a development build, at boot on both paths and on every registry reload. The tests
# are in a development build, so the unit tests in boot.rs and reload.rs pass the exemption.
RECEIPT_CONFIG_PATH = "    receipt_gate(&snapshot, receipt_exempt)?;\n"
RECEIPT_REGISTRY_PATH = "    receipt_gate(policy.snapshot(), basis.receipt_exempt)?;\n"
REGISTRY_BOOT_POLICY = "    check_registry_policy(&basis.registry, &live.current(), &basis)?;\n"
mutate_all("gw-receipt-gate-removed", "no path runs the receipt-store gate",
           (BOOT, RECEIPT_CONFIG_PATH, ""), (BOOT, RECEIPT_REGISTRY_PATH, ""))
mutate("gw-receipt-gate-config-path-skipped", "the JSON configuration's boot does not run the receipt-store gate", BOOT,
       RECEIPT_CONFIG_PATH, "")
mutate_all("gw-receipt-gate-only-at-boot", "the registry's policy meets the receipt-store gate at boot but not on a reload",
           (BOOT, RECEIPT_REGISTRY_PATH, ""),
           (BOOT, REGISTRY_BOOT_POLICY,
            REGISTRY_BOOT_POLICY + "    receipt_gate(live.current().snapshot(), basis.receipt_exempt)?;\n"))
mutate("gw-receipt-gate-exempt-always", "every build is exempt from the receipt-store gate", BOOT,
       "    if exempt || receipt_store_configured() {", "    if true || exempt || receipt_store_configured() {")
mutate("gw-receipt-store-always-configured", "a receipt store counts as configured when there is none", BOOT,
       "fn receipt_store_configured() -> bool {\n    false\n}", "fn receipt_store_configured() -> bool {\n    true\n}")
mutate("gw-receipt-gate-propose-passes", "the receipt-store gate refuses `write` but lets `propose` through", BOOT,
       "            if tool.classification != Classification::Read {",
       "            if !matches!(tool.classification, Classification::Read | Classification::Propose) {")

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

# Every struct the gateway's own configuration sections nest refuses a key it does not know. The
# policy section is gateway-core's snapshot; its structs are mutated with the core's, under "The
# snapshot".
for path, struct in [
    (GW + "config.rs", "Config"),
    (GW + "config.rs", "IdentitySection"),
    (GW + "config.rs", "AuditSection"),
    (GW + "config.rs", "HttpSection"),
    (GW + "config.rs", "IssuerEntry"),
    (CATALOG, "ToolDefinition"),
    (SELECTOR, "SelectorRules"),
    (SELECTOR, "WorkloadRule"),
    (SELECTOR, "UserRule"),
]:
    mutate(f"gw-unknown-fields-{struct}", f"{struct} accepts unknown fields", path,
           f"#[serde(deny_unknown_fields)]\npub struct {struct} {{", f"pub struct {struct} {{")
mutate("gw-unknown-fields-IssuerKindEntry", "an issuer's kind accepts unknown fields", GW + "config.rs",
       '#[serde(rename_all = "snake_case", deny_unknown_fields)]\npub enum IssuerKindEntry {',
       '#[serde(rename_all = "snake_case")]\npub enum IssuerKindEntry {')

# Connectors.
mutate("gw-boot-unregistered-connector", "a served tool with no registered connector is accepted", BOOT,
       "        if !connectors.contains_key(&tool.connector) {", "        if false && !connectors.contains_key(&tool.connector) {")
mutate("gw-boot-duplicate-connector-accepted", "a connector registered twice keeps the last one", BOOT,
       "    for (name, mut registered) in registrations {\n"
       "        if let Some(deadline) = call_deadlines.get(&name) {\n"
       "            registered.call_deadline = *deadline;\n"
       "        }\n"
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
mutate_all(
    "gw-dependency-testkit-under-spaced-target",
    "the gateway depends on the testkit, under a target table spelled with spaces",
    ("crates/gateway/Cargo.toml", '[dev-dependencies]\ngateway-testkit = { path = "../gateway-testkit" }\n', "[dev-dependencies]\n"),
    ("crates/gateway/Cargo.toml", "\n[lints]\n",
     "\n[ target.'cfg(all())'.dependencies ]\ngateway-testkit = { path = \"../gateway-testkit\" }\n\n[lints]\n"),
)
# A dependency renamed to an allowed name cannot be shown here: every allowed name is already a
# dependency, and Cargo refuses one name for two packages. The fences compare the package each
# entry resolves to, which is what a rename would change.
mutate("gw-dependency-testkit-as-build-dependency", "the gateway builds with the testkit, under a build-dependencies table spelled with spaces",
       "crates/gateway/Cargo.toml",
       "\n[lints]\n", "\n[ build-dependencies ]\ngateway-testkit = { path = \"../gateway-testkit\" }\n\n[lints]\n")


# The binary loads its deployment, starts the audit store and runs the boot gates before it
# binds a socket. Where it listens when the deployment file does not say is loopback only.
GW_BIN = GW + "bin/switchboard.rs"
GW_DEPLOY = GW + "deployment.rs"
BIN_PREPARE = (
    "    let prepared = match start::prepare(deployment, instance, Arc::new(SystemClock)).await {\n"
    "        Ok(prepared) => prepared,\n        Err(error) => return refuse(&error.to_string()),\n    };\n"
)
BIN_BIND = (
    "    let listener = match TcpListener::bind(listen).await {\n"
    "        Ok(listener) => listener,\n"
    '        Err(error) => return refuse(&format!("cannot listen on {listen}: {error}")),\n'
    "    };\n"
)
DEFAULT_LISTEN = "SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);"
mutate("gw-bin-default-listen-every-interface", "switchboard listens on every interface unless told otherwise", GW_DEPLOY,
       DEFAULT_LISTEN, "SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);")
mutate("gw-bin-default-listen-ipv6-every-interface", "switchboard listens on every IPv6 interface unless told otherwise", GW_DEPLOY,
       DEFAULT_LISTEN, "SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 8080);")
mutate("gw-bin-binds-before-boot-gates", "switchboard binds its socket before the audit store and the boot gates are ready", GW_BIN,
       BIN_PREPARE + BIN_BIND, BIN_BIND + BIN_PREPARE)
mutate("gw-instance-unset-starts", "with nothing naming the instance, switchboard starts under a made-up name", GW + "start.rs",
       "        .ok_or(StartError::NoInstance)", '        .or(Some(InstanceName::new("unnamed")))\n        .ok_or(StartError::NoInstance)')


# Telemetry. emit counts every event, then queues it without waiting; a full or closed queue
# drops it and counts the drop. A surface is escaped and capped when it is made.
TELEMETRY = GW + "telemetry.rs"
mutate("telemetry-drop-not-counted", "an event the queue had no room for is dropped without being counted", TELEMETRY,
       "        if self.sender.try_send(event).is_err() {\n            self.counters.dropped.fetch_add(1, Ordering::Relaxed);\n        }\n",
       "        let _ = self.sender.try_send(event);\n")
mutate("telemetry-counter-skipped", "emit queues an event without counting it", TELEMETRY,
       "        counter.fetch_add(1, Ordering::Relaxed);\n", "        let _ = counter;\n")
mutate("telemetry-surface-unescaped", "a surface is kept as it arrived in the URL", TELEMETRY,
       "        Self(escape(raw, MAX_SURFACE))", "        Self(raw.to_owned())")
mutate("telemetry-emit-awaits", "emit blocks until the queue has room", TELEMETRY,
       "        if self.sender.try_send(event).is_err() {", "        if self.sender.blocking_send(event).is_err() {")
mutate("telemetry-identity-failed-info", "a refused identity is logged at info, below RUST_LOG=warn", TELEMETRY,
       '        } => tracing::warn!(\n            event = "identity_failed",',
       '        } => tracing::info!(\n            event = "identity_failed",')

# Issuer keys. An issuer takes a keys file or a keys URL, never both. A keys URL is fetched at
# boot, and a failed first fetch refuses to start; then it is fetched on a timer, and a failed
# refresh keeps the keys in use. The stale key below is a P-256 public key nothing signs with.
KEYS = GW + "keys.rs"
STALE_KEY = ('{"keys": [{"kty": "EC", "crv": "P-256", "kid": "stale", '
             '"x": "S8cWydNibCrzVUwFcMpa8CorM1ZTnJmxVTZWONUI_-o", '
             '"y": "0ziqidx7IOWX78hzezpoVuoCwdilEjtBLXKRwcxVbeo"}]}')
mutate("gw-keys-refresh-never-runs", "the refresh timer ticks and fetches nothing", KEYS,
       "        let _ = refresh(&identity, &refreshed.source, &mut last_failure).await;\n",
       "        let _ = (&identity, &refreshed.source, &mut last_failure);\n")
mutate("gw-keys-refresh-failure-clears-keys", "a failed refresh drops the keys in use for a key the issuer does not sign with", KEYS,
       "        Err(error) => Err(RefreshError::from(error)),\n",
       "        Err(error) => {\n"
       f"            let stale = serde_json::from_str(r#\"{STALE_KEY}\"#).unwrap_or_default();\n"
       "            let _ = identity.replace_keys(issuer, stale);\n"
       "            Err(RefreshError::from(error))\n        }\n")
mutate("gw-keys-first-fetch-failure-starts", "the gateway starts without an issuer whose keys it could not fetch at boot", GW + "start.rs",
       "        let keys = source\n            .fetch()\n            .await\n"
       "            .map_err(|cause| StartError::KeysFetch {\n                issuer: issuer.clone(),\n"
       "                cause,\n            })?;\n",
       "        let Ok(keys) = source.fetch().await else {\n"
       "            if let Some(issuers) = identity.enforce.as_mut() {\n"
       "                issuers.retain(|entry| entry.issuer != issuer);\n            }\n"
       "            continue;\n        };\n")
mutate("gw-keys-url-and-file-both-accepted", "an issuer with both a keys file and a keys URL loads, reading the file", GW_DEPLOY,
       "        (Some(_), Some(_)) => return Err(DeploymentError::KeysTwice(issuer.issuer)),\n"
       "        (None, None) => return Err(DeploymentError::NoKeys(issuer.issuer)),\n"
       "        (Some(file), None) => {\n",
       "        (None, None) => return Err(DeploymentError::NoKeys(issuer.issuer)),\n"
       "        (Some(file), _) => {\n")

# --- gateway path --------------------------------------------------------------------------

GW_PATH = GW + "path.rs"
LIST_SURFACE = (
    "entries(&self.inner.gates.policy(), &snapshot.surface(&surface).map(|surface| surface.tools.iter()"
    ".filter_map(|name| snapshot.tool(name)).cloned().collect::<Vec<_>>()).unwrap_or_default())"
)

mutate("gw-row-id-fixed", "every call's row has one identifier, not one made per call", GW_PATH,
       "            row: AuditRowId::new(Uuid::now_v7().to_string()),\n            instance: gates.instance().clone(),\n"
       "            call_deadline_ms: millis(",
       '            row: AuditRowId::new("01990000-0000-7000-8000-000000000000"),\n            instance: gates.instance().clone(),\n'
       "            call_deadline_ms: millis(")
mutate("gw-list-row-id-fixed", "every list's row has one identifier, not one made per list", GW_PATH,
       "            row: AuditRowId::new(Uuid::now_v7().to_string()),\n            instance: gates.instance().clone(),\n"
       "            call_deadline_ms: 0,",
       '            row: AuditRowId::new("01990000-0000-7000-8000-000000000000"),\n            instance: gates.instance().clone(),\n'
       "            call_deadline_ms: 0,")

mutate("gw-body-parsed-before-identity", "the body is parsed before identity is checked", GW_PATH,
       "        let admitted = match self.admit(method, headers, &source) {\n",
       "        if let Err(rejection) = gateway_mcp::parse(method, headers, body) {\n"
       "            return rejection.response();\n        }\n"
       "        let admitted = match self.admit(method, headers, &source) {\n")
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
       "            Some(Reads::Adapter(adapter)) => adapter.resources(approved, arguments),",
       "            Some(Reads::Adapter(_)) => Resources::Named(Vec::new()),")
mutate("gw-resources-from-requested-not-approved", "the adapter is chosen by the requested name", GW_PATH,
       "            .registered(&approved.connector)\n",
       "            .registered(&gateway_core::ConnectorName::new(requested.as_str()))\n"
       "            .or(gates.registered(&approved.connector))\n")
mutate("gw-disabled-identity-lists", "with identity disabled, the surface's tools are listed", GW_PATH,
       "            return (Reply::Tools(Vec::new()), None);\n",
       "            let snapshot = self.inner.gates.snapshot();\n"
       f"            return (Reply::Tools({LIST_SURFACE}), None);\n")
mutate("gw-list-unfiltered", "tools/list returns every tool on the surface, undecided", GW_PATH,
       "        let tools = list_tools(policy.snapshot(), &caller);\n",
       "        let snapshot = policy.snapshot();\n"
       "        let tools: Vec<&ApprovedTool> = snapshot.surface(&caller.surface).map(|surface| surface.tools.iter()"
       ".filter_map(|name| snapshot.tool(name)).collect()).unwrap_or_default();\n")
# A tools/list row (decision 0009): written before the answer, which comes only from it.
mutate("gw-list-no-row", "tools/list answers without writing its row", GW_PATH,
       "            gates.audit_store().as_ref(),\n            start,\n            &caller,\n",
       "            &crate::audit::DisabledAuditStore::new(),\n            start,\n            &caller,\n")
mutate("gw-list-answered-when-row-fails", "a list whose row could not be written is answered with the tools", GW_PATH,
       "                (Reply::Denied(failure.sentence().to_owned()), None)\n",
       "                let _ = failure;\n"
       "                let tools: Vec<ApprovedTool> = list_tools(policy.snapshot(), &caller).into_iter().cloned().collect();\n"
       "                (Reply::Tools(entries(&policy, &tools)), None)\n")
mutate("gw-list-row-not-in-meta", "a tools/list answer does not name its row", GW_PATH,
       "                let row = self.quotable(listed.row());\n",
       "                let row: Option<AuditRowId> = None;\n")
mutate("gw-list-wrong-revision", "a list row records a revision other than the one served", GW_PATH,
       "            policy.revision().clone(),\n            tools,\n",
       "            \"not-the-served-revision\".into(),\n            tools,\n")
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
mutate("gw-begin-failure-as-tool-error", "a call whose row could not be begun is answered as a tool error", GW_PATH,
       "                return (Reply::Denied(failure.sentence().to_owned()), None);",
       "                return (Reply::ToolError(failure.sentence().to_owned()), None);")
mutate("gw-policy-denial-as-tool-error", "a policy denial is answered as a tool error, not a denial", GW_PATH,
       "                return (Reply::Denied(refusal.sentence().to_owned()), row);",
       "                return (Reply::ToolError(refusal.sentence().to_owned()), row);")
mutate("gw-identity-disabled-as-tool-error", "with identity disabled, a call is answered as a tool error", GW_PATH,
       "            return (Reply::Denied(IDENTITY_DISABLED.to_owned()), None);",
       "            return (Reply::ToolError(IDENTITY_DISABLED.to_owned()), None);")
mutate("gw-tool-use-id-empty-kept", "an empty tool-use identifier reaches the row", GW_PATH,
       "    let acceptable = !value.is_empty()\n", "    let acceptable = true\n")
mutate("gw-finish-failure-replaces-success", "a failed finish replaces a result with the audit sentence", GW_PATH,
       "        if let Some(failure) = finished.failure() {\n",
       "        if let Some(failure) = finished.failure() {\n"
       "            return (Reply::Denied(failure.sentence().to_owned()), None);\n")
mutate("gw-latency-not-measured", "every call is recorded as taking no time", GW_PATH,
       "let latency_ms = elapsed_millis(gates.clock().as_ref(), started);",
       "let latency_ms = 0;")
mutate("gw-read-only-hint-always", "every tool is listed as read-only", GW_PATH,
       "read_only: tool.classification == Classification::Read,", "read_only: true,")
mutate("gw-row-not-in-meta", "a call that ran does not name its row in the answer", GW_PATH,
       "        (reply, named)\n", "        let _ = named;\n        (reply, None)\n")
mutate("gw-row-not-in-error-data", "a denial does not name its row in error.data", GW_PATH,
       "                let row = self.quotable(refusal.row());\n",
       "                let row: Option<AuditRowId> = None;\n")
mutate("gw-disabled-row-leaked", "with audit disabled, the answer names a row nothing wrote", GW_PATH,
       "        (self.inner.gates.audit_state() == GateState::On).then(|| row.clone())",
       "        Some(row.clone())")
# Telemetry events (decision 0009): one identity_failed per refusal, naming where it came from
# and nothing from the token but the claimed issuer and subject the identity crate escaped.
mutate("gw-identity-event-no-surface", "an identity failure's event does not name the surface", GW_PATH,
       "                    surface: source.surface.clone(),\n", "                    surface: None,\n")
mutate("gw-identity-event-no-source", "an identity failure's event does not name the peer", GW_PATH,
       "                    source: source.address,\n                    cause:",
       "                    source: None,\n                    cause:")
# ClaimedCaller's constructor is private to the identity crate, so the path cannot record the
# token, or anything from it, as the claimed caller: this must not compile.
mutate("gw-identity-event-carries-token", "the raw token is recorded as the claimed subject", GW_PATH,
       "                    claimed: failure.claimed().clone(),\n",
       "                    claimed: gateway_identity::ClaimedCaller::new(None, bearer_token(headers)),\n",
       breaks_build=True)
mutate("gw-ping-no-event", "a ping is answered with no event", GW_PATH,
       "            Call::Ping => {\n"
       "                self.emit(Event::Ping {\n"
       "                    deployment: deployment(),\n"
       "                    surface: source.surface,\n"
       "                    source: source.address,\n"
       "                });\n"
       "                (Reply::Pong, None)\n"
       "            }\n",
       "            Call::Ping => (Reply::Pong, None),\n")
# A call given up (decision 0009): with no connector registered, or with its client gone before
# the connector is called, the row is completed as error and the connector is not called.
mutate("gw-unregistered-row-left-open", "an allowed call whose connector is not registered leaves its row open", GW_PATH,
       "            let gave_up = audit::give_up(store, guard).await;\n"
       "            tracing::error!(\n"
       "                row = row.as_str(),\n"
       "                %connector,\n"
       "                \"an allowed tool's connector is not registered; its row was completed as error\"\n"
       "            );\n"
       "            if let Some(failure) = gave_up.failure() {\n",
       "            drop(guard);\n"
       "            let _ = connector;\n"
       "            if let Some(failure) = None::<gateway_core::audit::AuditFailure> {\n")
mutate("gw-disconnect-before-run-ignored", "a call whose client has gone before it runs is run all the same", GW_PATH,
       "        if disconnect.has_fired() {\n", "        if false && disconnect.has_fired() {\n")
mutate("gw-read-not-cancelled", "a read whose client goes is run to completion", GW_PATH,
       "        let ran = audit::run_unless(connector, guard, disconnect.fired()).await;",
       "        let ran = audit::run(connector, guard).await;")
mutate("gw-disconnect-never-fires", "dropping the handler does not fire the disconnect", GW_PATH,
       "            let _ = sender.send(());\n", "            drop(sender);\n")
mutate("gw-unparsable-no-event", "a body refused at the protocol layer gives no event", GW_PATH,
       "                    path.emit(Event::Unparsable {\n"
       "                        deployment: path.inner.gates.deployment().clone(),\n"
       "                        surface: source.surface,\n"
       "                        source: source.address,\n"
       "                        rejection: rejection.kind(),\n"
       "                    });\n",
       "")


# --- gateway server ------------------------------------------------------------------------

GW_SERVER = GW + "server.rs"
HOST_CHECK = (
    "    if let Err(rejection) = check_host(gates, parts) {\n"
    "        return refused(&rejection);\n    }\n"
)
ADMIT = "    let admitted = match path.admit(&parts.method, &parts.headers, &source) {\n"

mutate("gw-host-check-skipped", "a request for any Host is served", GW_SERVER, HOST_CHECK, "")
mutate_all(
    "gw-host-after-identity",
    "the Host is checked after identity",
    (GW_SERVER, HOST_CHECK, ""),
    (GW_SERVER, "    let Some(surface) = surface else {", HOST_CHECK + "    let Some(surface) = surface else {"),
)
mutate("gw-host-port-compared", "the Host is compared with its port", GW_SERVER,
       "let allowed = host.map(without_port).is_some_and(", "let allowed = host.is_some_and(")
mutate("gw-host-bracket-suffix-ignored", "whatever follows a bracketed host is dropped unchecked", GW_SERVER,
       "            Some(close) => host.split_at(close + 1),", "            Some(close) => return &host[..=close],")
mutate("gw-host-empty-port-accepted", "a Host ending in a colon with no port is allowed", GW_SERVER,
       "let is_port = |port: &str| !port.is_empty() && port.bytes()", "let is_port = |port: &str| port.bytes()")
mutate("gw-host-first-of-two", "the first of two Host headers is checked", GW_SERVER,
       "        (Some(_), Some(_)) => None,", "        (Some(value), Some(_)) => value.to_str().ok(),")
mutate("gw-host-absent-allowed", "a request with no Host and no authority is taken as for localhost", GW_SERVER,
       "        (None, _) => parts.uri.authority().map(|authority| authority.as_str()),",
       '        (None, _) => Some("localhost"),')
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
mutate("gw-head-timeout-unset", "a request's head may take hyper's default 30 seconds, not the configured time", GW_SERVER,
       "    http.timer(TokioTimer::new())\n        .header_read_timeout(timeouts.header_read);\n",
       "    http.timer(TokioTimer::new());\n")
mutate("gw-head-timeout-no-timer", "the head's deadline is configured with no timer to run it", GW_SERVER,
       "    http.timer(TokioTimer::new())\n        .header_read_timeout(", "    http.header_read_timeout(")
mutate("gw-body-read-untimed", "a body may take an hour to arrive", GW_SERVER,
       "tokio::time::timeout(endpoint.body_read, reading)", "tokio::time::timeout(Duration::from_secs(3600), reading)")
mutate("gw-shutdown-waits-for-every-connection", "shutting down waits an hour for a connection that stopped part way", GW_SERVER,
       "tokio::time::timeout(timeouts.shutdown_grace, connections.shutdown())",
       "tokio::time::timeout(Duration::from_secs(3600), connections.shutdown())")
mutate("gw-shutdown-leaves-connections-open", "a connection still open after the grace keeps serving after the server returns", GW_SERVER,
       "        tasks.spawn(async move {", "        tokio::spawn(async move {")
mutate("gw-call-on-request-future", "the answer runs on the request's future, so a disconnect cancels it", GW_SERVER,
       "    let answered = tokio::spawn(answering.instrument(span)).await;",
       "    let answered = Ok::<_, tokio::task::JoinError>(answering.instrument(span).await);")
# A disconnect reaches a call only through the signal (decision 0009): the answer task is never
# dropped or aborted with the handler, so begin and a side effect run to their end.
mutate("gw-begin-on-request-future", "a disconnect aborts the answer task wherever it is, begin included", GW_SERVER,
       "    let answered = tokio::spawn(answering.instrument(span)).await;",
       "    struct Abort(tokio::task::AbortHandle);\n"
       "    impl Drop for Abort {\n        fn drop(&mut self) {\n            self.0.abort();\n        }\n    }\n"
       "    let task = tokio::spawn(answering.instrument(span));\n"
       "    let abort = Abort(task.abort_handle());\n"
       "    let answered = task.await;\n"
       "    std::mem::forget(abort);")
mutate("gw-side-effect-cancelled-on-disconnect", "the path drops any call, a side effect too, when its client goes", GW_PATH,
       "        let ran = audit::run_unless(connector, guard, disconnect.fired()).await;",
       "        let ran = tokio::select! {\n"
       "            ran = audit::run(connector, guard) => ran,\n"
       "            () = disconnect.fired() => return (Reply::ToolError(DISCONNECTED_BEFORE_RUN.to_owned()), named),\n"
       "        };")
# No answer starts once the gateway stops taking connections, and every one starts until then.
mutate("gw-calls-start-in-grace", "a request whose body arrives during the shutdown grace starts its call", GW_SERVER,
       "    if !endpoint.starting.load(Ordering::SeqCst) {\n", "    if false && !endpoint.starting.load(Ordering::SeqCst) {\n")
mutate("gw-calls-stop-at-unready", "no call starts once the readiness check fails, inside the removal", GW_SERVER,
       "    ready.store(false, Ordering::SeqCst);\n", "    ready.store(false, Ordering::SeqCst);\n    starting.store(false, Ordering::SeqCst);\n")
mutate("gw-request-timeout-bare", "a body that does not arrive in time gets a bare 408 with no sentence", GW_SERVER,
       "        return refused(&Rejection::request_timeout());",
       "        return HttpResponse { status: StatusCode::REQUEST_TIMEOUT, headers: HeaderMap::new(), body: Vec::new() };")
mutate("gw-ready-never-fails", "the readiness check still passes while the gateway stops", GW_SERVER,
       "    ready.store(false, Ordering::SeqCst);\n", "")
mutate("gw-stops-before-unready", "the gateway stops taking connections before the readiness removal, not after", GW_SERVER,
       "    accepting\n        .until(&mut tasks, tokio::time::sleep(timeouts.readiness_removal))\n        .await;\n"
       "    // From here no answer starts, so no call starts after the readiness removal.\n"
       "    starting.store(false, Ordering::SeqCst);\n"
       "    drop(listener);\n",
       "    drop(listener);\n    tokio::time::sleep(timeouts.readiness_removal).await;\n"
       "    starting.store(false, Ordering::SeqCst);\n")
# Telemetry at shutdown (decision 0009): the queue is closed and emptied before serving returns.
mutate("gw-drain-not-awaited-on-shutdown", "serving returns without waiting for the queued events to be written", GW_SERVER,
       "    if let Err(error) = draining.await {\n"
       "        tracing::error!(%error, \"the task writing telemetry failed\");\n    }\n",
       "    let _ = draining;\n")
mutate("gw-event-source-not-peer", "events name the gateway's own address, not the peer's", GW_SERVER,
       "                    Ok(accepted) => accepted,\n",
       "                    Ok((stream, _)) => match self.listener.local_addr() {\n"
       "                        Ok(local) => (stream, local),\n"
       "                        Err(_) => continue,\n"
       "                    },\n")


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
       "    let mut wiring = Wiring::new(clock.clone()).instance(instance).connector(",
       "    let mut wiring = Wiring::new(Arc::new(SystemClock)).instance(instance).connector(")
mutate("dev-printer-not-wired", "asking for audit rows to be printed prints nothing", DEV_START,
       "            Some(out) => Arc::new(AuditPrinter::new(store.clone(), out)),", "            Some(_) => store.clone(),")
mutate("dev-printer-swallows-begin-failure", "the printer turns a failed begin into success, so the call runs with no row", DEV_PRINTER,
       "            begun\n        })", "            begun.or_else(|_| Ok(()))\n        })")
mutate("dev-printer-swallows-list-failure", "the printer turns a failed list into success, so audit::listed hands out a Listed with no row stored", DEV_PRINTER,
       "            listed\n        })", "            listed.or_else(|_| Ok(()))\n        })")
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


# --- gateway-dev: switchboard-dev ----------------------------------------------------------

DEV_BIN = DEV + "bin/switchboard-dev.rs"

mutate("dev-bin-unexpected-answer-ignored", "switchboard-dev's script passes whatever the answers were", DEV_BIN,
       "            as_expected = false;\n", "")
mutate("dev-bin-once-unexpected-exits-0", "switchboard-dev --once exits 0 when an answer was not as expected", DEV_BIN,
       '    if !as_expected {\n        return Err("an answer was not as expected".to_owned());\n    }\n',
       "    let _ = as_expected;\n")
mutate("dev-bin-once-unclean-stop-exits-0", "switchboard-dev --once exits 0 when the gateway did not stop cleanly", DEV_BIN,
       "    if let Err(error) = stopped {", "    if let (Err(error), false) = (stopped, true) {")


# --- mock-docs-server ------------------------------------------------------------------------

MOCK = "crates/mock-docs-server/"
MS = MOCK + "src/server.rs"
MC = MOCK + "src/config.rs"
MD = MOCK + "src/documents.rs"
MJ = MOCK + "src/jwt.rs"
mutate("mock-any-bearer-accepted", "every bearer is accepted", MS,
       "                accepted: accepted.accepts(token),", "                accepted: true,")
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
       "                bearer_sha256: Some(logged_prefix(&sha256(token))),", "                bearer_sha256: Some(accepted.logged_prefix()),")
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
mutate("mock-docs-mcp-body-read-before-auth", "POST /mcp waits for the whole body before checking the caller", MS,
       '    let caller = server.authenticate(&headers);\n    let mut line = request_line("request", &method, &uri, &caller);\n',
       '    let body = Body::from(read_body(body).await.unwrap_or_default());\n'
       '    let caller = server.authenticate(&headers);\n    let mut line = request_line("request", &method, &uri, &caller);\n')
mutate("mock-docs-admin-body-read-before-auth", "PUT /admin/tools waits for the whole body before checking the caller", MS,
       '    let caller = server.authenticate(&headers);\n    let line = request_line("admin", &method, &uri, &caller);\n',
       '    let body = Body::from(read_body(body).await.unwrap_or_default());\n'
       '    let caller = server.authenticate(&headers);\n    let line = request_line("admin", &method, &uri, &caller);\n')
mutate("mock-admin-repeat-accepted", "the admin endpoint may name a tool twice", MS,
       "                if tools.contains(&tool) {", "                if false {")
# The JWT mode (decision 0010).
mutate("mock-docs-jwt-subject-unchecked", "any subject from the trusted issuer is accepted", MJ,
       "            Some(subject) if subject == self.subject => Ok(subject.to_owned()),",
       "            Some(subject) => Ok(subject.to_owned()),")
mutate("mock-docs-jwt-audience-off", "a token for any audience is accepted", MJ,
       "        validation.set_audience(&[&self.audience]);", "        validation.validate_aud = false;")
mutate("mock-docs-jwt-exp-off", "an expired token is accepted", MJ,
       "        validation.validate_exp = true;", "        validation.validate_exp = false;")
mutate("mock-docs-jwt-kid-fallback", "a token with no kid, or an unknown one, is checked against the only key", MJ,
       "            .and_then(|kid| self.keys.get(kid))\n",
       "            .and_then(|kid| self.keys.get(kid))\n            .or_else(|| self.keys.values().next())\n")
mutate("mock-docs-jwt-logs-unverified-sub", "a refused token's claimed subject is logged as the caller", MS,
       "        Err(refusal) => (None, Some(refusal)),",
       "        Err(refusal) => (\n"
       "            token\n"
       "                .and_then(|token| jsonwebtoken::dangerous::insecure_decode_claims::<Value>(token).ok())\n"
       "                .and_then(|claims| claims.get(\"sub\").and_then(Value::as_str).map(str::to_owned)),\n"
       "            Some(refusal),\n"
       "        ),")
mutate("mock-docs-jwt-subject-before-audience", "the subject is checked before the issuer and audience", MJ,
       "        validation.set_audience(&[&self.audience]);",
       "        validation.set_audience(&[&self.audience]);\n        validation.sub = Some(self.subject.clone());")
mutate("mock-docs-jwt-issuer-array", "an array of issuers that includes the trusted one is accepted", MJ,
       "        if claims.get(\"iss\").and_then(Value::as_str) != Some(self.issuer.as_str()) {", "        if false {")
# Without aud required, jsonwebtoken 11 accepts a token with no aud. Dropping iss from the list
# is not registered: the exact-issuer check after decoding refuses a token with no iss anyway.
mutate("mock-docs-jwt-aud-optional", "a token with no audience is accepted", MJ,
       '        validation.set_required_spec_claims(&["exp", "iss", "aud"]);',
       '        validation.set_required_spec_claims(&["exp", "iss"]);')
mutate("mock-docs-jwt-exp-optional", "a token with no expiry is accepted", MJ,
       '        validation.set_required_spec_claims(&["exp", "iss", "aud"]);',
       '        validation.set_required_spec_claims(&["iss", "aud"]);')
mutate("mock-docs-jwt-alg-unchecked", "a token whose header is not RS256 is refused only as malformed", MJ,
       "        if header.alg != Algorithm::RS256 {", "        if false {")
mutate("mock-docs-jwt-nbf-off", "a token not yet valid is accepted", MJ,
       "        validation.validate_nbf = true;", "        validation.validate_nbf = false;")
mutate("mock-docs-jwt-leeway-default", "the leeway is jsonwebtoken's 60 s, not 30 s", MJ,
       "        validation.leeway = LEEWAY_SECONDS;\n", "")
mutate("mock-docs-jwt-leeway-zero", "a token a few seconds past exp is refused", MJ,
       "        validation.leeway = LEEWAY_SECONDS;", "        validation.leeway = 0;")
mutate("mock-docs-jwt-static-and-jwt-takes-jwt", "with a static credential and JWT settings, the JWT mode starts", MC,
       "            (true, true) => return Err(ConfigError::StaticAndJwt),\n"
       "            (true, false) => Credential::Jwt(read_jwt(&var)?),",
       "            (true, _) => Credential::Jwt(read_jwt(&var)?),")
mutate("mock-docs-jwt-empty-setting-accepted", "a JWT setting of only whitespace counts as set", MC,
       "            .filter(|value| !value.is_empty())\n", "")
mutate("mock-docs-jwt-non-rsa-key-accepted", "a JWK set may hold an EC or symmetric key", MJ,
       "            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {", "            if false {")
mutate("mock-docs-jwt-key-alg-unchecked", "a key declared for another algorithm is accepted", MJ,
       "                .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)", "                .is_some_and(|_| false)")
mutate("mock-docs-jwt-key-use-unchecked", "a key declared for encryption is accepted", MJ,
       "                .is_some_and(|key_use| *key_use != PublicKeyUse::Signature)", "                .is_some_and(|_| false)")
mutate("mock-docs-jwt-duplicate-kid-accepted", "two keys with one kid are accepted, the last one kept", MJ,
       "            if keys.insert(kid.clone(), key).is_some() {", "            if keys.insert(kid.clone(), key).is_some() && false {")
# Moving a dev-dependency into the server's own dependencies leaves Cargo.lock as it is.
mutate_all(
    "mock-dependency-added",
    "the mock server gains a dependency outside the allowlist",
    (MOCK + "Cargo.toml", 'features = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"] }\n',
     'features = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"] }\nreqwest = { version = "0.12", default-features = false, features = ["json"] }\n'),
    (MOCK + "Cargo.toml", 'features = ["getrandom"] }\nreqwest = { version = "0.12", default-features = false, features = ["json"] }\n',
     'features = ["getrandom"] }\n'),
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
       "self.request(id, upstream_name, arguments, &secret)", "self.request(id, tool.name.as_str(), arguments, &secret)")
mutate("proxy-arguments-unchecked", "arguments that are not an object are sent as an empty object", PC,
       "        let Value::Object(arguments) = call.arguments() else {\n"
       "            return ToolOutcome::Error(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned());\n        };",
       "        let empty = Map::new();\n        let arguments = match call.arguments() {\n"
       "            Value::Object(arguments) => arguments,\n            _ => &empty,\n        };")
mutate("proxy-arguments-not-object-refused", "arguments that are not an object are recorded as refused, not as an error", PC,
       "            return ToolOutcome::Error(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned());",
       "            return ToolOutcome::Refused(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned());")
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
mutate("proxy-credential-read-unbounded", "the whole credential file is read before its size is checked", PK,
       ".and_then(|file| file.take(MAX_CREDENTIAL_BYTES + 1).read_to_end(&mut bytes))",
       ".and_then(|mut file| file.read_to_end(&mut bytes))")
mutate("proxy-credential-failure-not-logged", "a call refused for its credential logs nothing", PC,
       "                tracing::warn!(\n"
       '                    event = "credential_unreadable",\n'
       "                    connector = %self.connector,\n"
       "                    reason = %reason,\n"
       "                    \"the gateway's credential could not be read; the call was refused and nothing was sent\"\n"
       "                );\n", "                let _ = reason;\n")
mutate("proxy-credential-failure-reason-dropped", "a call refused for its credential is logged without the reason", PC,
       "                    reason = %reason,\n", "")
mutate("proxy-duplicate-credential-accepted", "two files for one connector are accepted", PK,
       "            if entries.contains_key(&connector) {", "            if false {")
mutate("proxy-credential-for-any-connector", "a credential is issued for a connector that has none", PK,
       "        let Some(stored) = self.entries.get(connector) else {",
       "        let Some(stored) = self.entries.values().next() else {")
mutate("proxy-debug-shows-secret", "the source's debug output reads and shows the secret", PK,
       "                    .map(|(connector, stored)| (connector, &stored.label)),",
       "                    .map(|(connector, stored)| (connector, std::fs::read_to_string(&stored.path).unwrap_or_default())),")
mutate("proxy-credential-unchecked-at-boot", "a credential file is not read until the first call", PK,
       "            read_secret(&connector, path)?;\n", "")
mutate_all(
    "proxy-credential-cached-at-load",
    "the credential is read once at load, so a rotated token is never sent",
    (PK, "struct Stored {\n    label: String,\n    path: PathBuf,\n}",
     "struct Stored {\n    label: String,\n    path: PathBuf,\n    secret: Secret,\n}"),
    (PK, "            read_secret(&connector, path)?;\n", "            let secret = read_secret(&connector, path)?;\n"),
    (PK, "            entries.insert(connector, Stored { label, path });",
     "            entries.insert(connector, Stored { label, path, secret });"),
    (PK, "        let secret = read_secret(connector, &stored.path)\n",
     "        let secret = Ok::<_, CredentialFileError>(Secret(stored.secret.0.clone()))\n"),
)
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
# pg-check-durability-ignored, pg-check-delete-ignored, pg-check-truncate-ignored,
# pg-session-search-path-kept, pg-retry-slow-attempt-final, pg-retry-closed-connection-final,
# pg-retry-socket-failure-final, pg-finish-dropped-task-not-reported,
# pg-finish-pause-past-deadline and pg-finish-pause-uncapped.
PG = "crates/audit-postgres/"
PG_SQL = PG + "sql/migrations/0001_call_rows.sql"
# 0003 replaces set_times, so the mutations of its body edit 0003, not 0001.
PG_ROW_DEADLINE = PG + "sql/migrations/0003_row_deadline.sql"
# 0004 replaces complete_once and decision_shape, so the mutations of their bodies edit 0004.
PG_LIST_ROWS = PG + "sql/migrations/0004_list_rows.sql"
PG_STORE = PG + "src/store.rs"
PG_COLUMNS = PG + "src/columns.rs"
mutate("pg-trigger-second-completion-allowed", "a completed row can be completed again", PG_LIST_ROWS,
       "    IF OLD.outcome IS NOT NULL THEN", "    IF false THEN")
mutate("pg-trigger-denial-completed", "the trigger lets a denial be completed", PG_LIST_ROWS,
       "    IF OLD.decision IS DISTINCT FROM 'allow' THEN", "    IF false THEN")
mutate("pg-trigger-empty-completion-allowed", "an update with no outcome passes the trigger", PG_LIST_ROWS,
       "        RAISE EXCEPTION 'a completion of audit row % has no outcome', OLD.id;", "        NULL;")
mutate("pg-trigger-other-columns-allowed", "a completion may change other columns", PG_LIST_ROWS,
       "        RAISE EXCEPTION 'only the completion of audit row % may be written', OLD.id;", "        NULL;")
mutate("pg-trigger-finished-at-not-set", "the database does not set the completion time", PG_LIST_ROWS,
       "    NEW.finished_at := clock_timestamp();\n", "")
mutate("pg-trigger-not-created", "the write-once trigger is never attached", PG_SQL,
       "CREATE TRIGGER complete_once\n    BEFORE UPDATE ON switchboard_audit.call_rows\n"
       "    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();\n", "")
mutate("pg-trigger-search-path-unpinned", "the write-once trigger looks names up in the session's search path", PG_LIST_ROWS,
       "    LANGUAGE plpgsql\n    SET search_path = pg_catalog\nAS $complete_once$", "    LANGUAGE plpgsql\nAS $complete_once$")
mutate("pg-times-search-path-unpinned", "the trigger that sets the times looks names up in the session's search path", PG_ROW_DEADLINE,
       "    LANGUAGE plpgsql\n    SET search_path = pg_catalog\nAS $set_times$", "    LANGUAGE plpgsql\nAS $set_times$")
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
mutate("pg-roles-unlocked", "two runs of the roles script grant at once", PG + "sql/roles.sql",
       "    PERFORM pg_advisory_xact_lock(6005341489043162114);\n", "")
mutate("pg-check-denial-sentence", "a denial may lack its sentence", PG_LIST_ROWS,
       "WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL",
       "WHEN 'deny' THEN reason IS NOT NULL AND outcome IS NULL")
mutate("pg-check-allowed-connector", "an allowed call may lack its connector and classification", PG_LIST_ROWS,
       "\n                AND connector IS NOT NULL AND classification IS NOT NULL", "")
mutate("pg-check-workload-team", "a workload may lack its team", PG_SQL,
       "        (proved_kind = 'workload') = (proved_team IS NOT NULL)\n", "        true\n")
mutate("pg-check-refusal-sentence", "only a refusal carrying a sentence is not checked", PG_SQL,
       "        AND coalesce(outcome = 'refused', false) = (outcome_sentence IS NOT NULL)\n", "")
mutate("pg-check-resources-shape", "resources may be any JSON", PG_SQL,
       "        CHECK (jsonb_typeof(resources) = 'array' OR resources = '\"unknown\"'::jsonb),", "        CHECK (true),")
mutate("pg-check-denial-reason", "a denial may lack its reason", PG_LIST_ROWS,
       "WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL",
       "WHEN 'deny' THEN sentence IS NOT NULL AND outcome IS NULL")
mutate("pg-check-denial-outcome", "a denial may have an outcome", PG_LIST_ROWS,
       "WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL AND outcome IS NULL",
       "WHEN 'deny' THEN reason IS NOT NULL AND sentence IS NOT NULL")
mutate("pg-check-allowed-reason", "an allowed call may have a reason", PG_LIST_ROWS,
       "            WHEN 'allow' THEN reason IS NULL AND sentence IS NULL\n", "            WHEN 'allow' THEN sentence IS NULL\n")
mutate("pg-check-allowed-sentence", "an allowed call may have a sentence", PG_LIST_ROWS,
       "            WHEN 'allow' THEN reason IS NULL AND sentence IS NULL\n", "            WHEN 'allow' THEN reason IS NULL\n")
mutate("pg-check-allowed-connector-only", "an allowed call may lack its connector", PG_LIST_ROWS,
       "AND connector IS NOT NULL AND classification IS NOT NULL", "AND classification IS NOT NULL")
mutate("pg-check-allowed-classification-only", "an allowed call may lack its classification", PG_LIST_ROWS,
       "AND connector IS NOT NULL AND classification IS NOT NULL", "AND connector IS NOT NULL")
mutate("pg-check-user-groups", "a user may lack its groups, and a workload have some", PG_SQL,
       "        AND (proved_kind = 'user') = (proved_groups IS NOT NULL)\n", "")
mutate("pg-check-completion-latency", "an outcome may lack its latency", PG_SQL,
       "        (outcome IS NULL) = (latency_ms IS NULL)\n", "        true\n")
mutate("pg-check-completion-time", "an outcome may lack its time", PG_SQL,
       "        AND (outcome IS NULL) = (finished_at IS NULL)\n", "")
# Since 0004, decision_shape refuses a decision that is neither allow nor deny as well, so
# pg-check-decision-any is caught only because the test names the column's own check.
for column, values in [
    ("classification", "'read', 'propose', 'write', 'destructive'"),
    ("decision", "'allow', 'deny'"),
    ("proved_kind", "'workload', 'user'"),
    ("outcome", "'ok', 'error', 'refused'"),
]:
    what = "the decision column's own check accepts" if column == "decision" else f"the {column} column takes"
    mutate(f"pg-check-{column.replace('_', '-')}-any", f"{what} any text", PG_SQL,
           f"CHECK ({column} IN ({values}))", "CHECK (true)")
for column in ["resources_omitted", "latency_ms"]:
    mutate(f"pg-check-{column.replace('_', '-')}-negative", f"the {column} column takes a negative number", PG_SQL,
           f"CHECK ({column} >= 0)", "CHECK (true)")
mutate("pg-migrate-any-role", "any role may run the migrations", PG + "src/migrate.rs",
       "    if current_user != OWNER_ROLE {", "    if false {")
mutate("pg-session-not-synchronous", "sessions keep the role's synchronous_commit", PG_STORE,
       "        config.options(options);\n", "        let _ = options;\n")
mutate("pg-session-options-replaced", "the caller's session options are dropped", PG_STORE,
       'format!("{existing} {SESSION_OPTIONS}")', "SESSION_OPTIONS.to_owned()")
mutate("pg-session-search-path-kept", "sessions look names up in the schemas a default puts first", PG_STORE,
       '"-c synchronous_commit=on -c search_path=pg_catalog,pg_temp"', '"-c synchronous_commit=on"')
mutate("pg-session-options-caller-last", "the caller's session options override the store's", PG_STORE,
       'format!("{existing} {SESSION_OPTIONS}")', 'format!("{SESSION_OPTIONS} {existing}")')
mutate("pg-begin-no-on-conflict", "a retried begin inserts again and fails on its own row", PG_COLUMNS,
       '$24, $25\n        ) ON CONFLICT (id) DO NOTHING";', '$24, $25\n        )";')
mutate("pg-begin-decision-not-compared", "a begin with a known identifier and another decision succeeds", PG_STORE,
       "    if decision == row.decision {", "    if true {")
mutate("pg-columns-id-unchecked", "an identifier that is not a lowercase UUID is sent to the database", PG_COLUMNS,
       "            return Err(PgAuditError::CompleteAtBegin);\n        }\n        if !is_uuid(id.as_str()) {",
       "            return Err(PgAuditError::CompleteAtBegin);\n        }\n        if false {")
PG_ROW_IDS = PG + "sql/migrations/0002_row_ids.sql"
mutate("pg-row-ids-default-kept", "the database still makes an identifier for a row inserted without one", PG_ROW_IDS,
       "ALTER TABLE switchboard_audit.call_rows ALTER COLUMN id DROP DEFAULT;\n", "")
mutate("pg-row-ids-not-granted", "the gateway may not write the identifier it chose", PG_ROW_IDS,
       "GRANT INSERT (id) ON switchboard_audit.call_rows TO switchboard_gateway;\n", "")
mutate("pg-finish-uses-begin-pool", "finish waits on the begin pool", PG_STORE,
       "            pool: self.finish.clone(),\n            cancel: Arc::clone(&self.cancel),\n            row: row.as_str().to_owned(),\n            finish,\n",
       "            pool: self.begin.clone(),\n            cancel: Arc::clone(&self.cancel),\n            row: row.as_str().to_owned(),\n            finish,\n")
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
       "record.claimed_team.as_ref().map(|team| team.get().as_str()),\n            )?,\n            instance: stored(\"instance\", record.instance.as_str())?,\n            kind:",
       "record.proved_delegation_team.as_ref().map(|team| team.get().as_str()),\n            )?,\n            instance: stored(\"instance\", record.instance.as_str())?,\n            kind:")
mutate("pg-insert-delegation-and-acting-person-swapped", "the INSERT writes the proved delegation team and the claimed acting person in each other's columns", PG_COLUMNS,
       "            &self.proved_delegation_team,\n            &self.claimed_acting_person,\n            &self.claimed_team,\n            &self.instance,\n            &self.kind,\n",
       "            &self.claimed_acting_person,\n            &self.proved_delegation_team,\n            &self.claimed_team,\n            &self.instance,\n            &self.kind,\n")
mutate("pg-columns-workload-team-as-group", "a workload's team is written as a group", PG_COLUMNS,
       '            "workload",\n            Some(stored("proved_team", team.as_str())?),\n            None,',
       '            "workload",\n            None,\n            Some(vec![stored("proved_team", team.as_str())?]),')
mutate("pg-columns-latency-not-compared", "a completion with another latency counts as the same", PG_COLUMNS,
       "            && Some(self.latency_ms) == latency_ms\n", "")
mutate("pg-columns-unknown-as-none", "resources nobody could name are written as none named", PG_COLUMNS,
       '        RecordedResources::Unknown => Value::String("unknown".to_owned()),',
       "        RecordedResources::Unknown => Value::Array(vec![]),")
mutate("pg-columns-resource-kind-as-system", "a resource's kind is written as its system", PG_COLUMNS,
       '"system": stored("resources", &resource.system)?,', '"system": stored("resources", &resource.kind)?,')
mutate("pg-columns-omitted-saturates", "a count of resources left out past the column is cut short", PG_COLUMNS,
       "    let omitted = i64::try_from(record.resources_omitted).map_err(|_| {\n"
       "        PgAuditError::Column(\"a count of resources left out past the column's range\")\n"
       "    })?;",
       "    let omitted = i64::try_from(record.resources_omitted).unwrap_or(i64::MAX);")
mutate("pg-columns-nul-kept", "a NUL in a text value is passed on to the database", PG_COLUMNS,
       "    if text.contains('\\0') {\n        return Err(PgAuditError::Nul { column });\n    }\n", "")
mutate("pg-columns-nul-replaced", "a NUL in a text value is written as another character", PG_COLUMNS,
       "    if text.contains('\\0') {\n        return Err(PgAuditError::Nul { column });\n    }\n    Ok(text.to_owned())",
       "    let _ = column;\n    Ok(text.replace('\\0', \"\\u{FFFD}\"))")
mutate("pg-columns-tool-use-id-nul-kept", "a NUL in the tool-use identifier is passed on to the database", PG_COLUMNS,
       '            tool_use_id: optional(\n                "tool_use_id",\n                record.tool_use_id.as_ref().map(|id| id.as_str()),\n            )?,',
       "            tool_use_id: record.tool_use_id.as_ref().map(|id| id.as_str().to_owned()),")
mutate("pg-columns-outcome-sentence-nul-kept", "a NUL in a refusal's sentence is passed on to the database", PG_COLUMNS,
       'Outcome::Refused { sentence } => Some(stored("outcome_sentence", sentence)?),',
       "Outcome::Refused { sentence } => Some(sentence.clone()),")
mutate("pg-columns-latency-saturates", "a latency past the column is recorded as the most it holds", PG_COLUMNS,
       """            .map_err(|_| PgAuditError::Column("a latency past the column's range"))?;""",
       """            .unwrap_or(i64::MAX);""")
mutate("pg-sql-resources-nullable", "a call row may record no resources at all", PG_LIST_ROWS,
       "                AND resources IS NOT NULL AND resources_omitted IS NOT NULL\n",
       "                AND resources_omitted IS NOT NULL\n")
mutate("pg-sql-omitted-nullable", "a call row may leave out the count of resources left out", PG_LIST_ROWS,
       "                AND resources IS NOT NULL AND resources_omitted IS NOT NULL\n",
       "                AND resources IS NOT NULL\n")
mutate("pg-check-unknown-resources-omitted", "resources nobody could name may have some left out", PG_SQL,
       "        resources <> '\"unknown\"'::jsonb OR resources_omitted = 0\n", "        true\n")
mutate("pg-times-begun-at-from-insert", "an insert may choose its begin time", PG_ROW_DEADLINE,
       "    NEW.begun_at := clock_timestamp();\n", "    NEW.begun_at := coalesce(NEW.begun_at, clock_timestamp());\n")
mutate("pg-times-finished-at-from-insert", "an insert may choose its completion time", PG_ROW_DEADLINE,
       "    NEW.finished_at := CASE WHEN NEW.outcome IS NULL THEN NULL ELSE NEW.begun_at END;\n", "")
mutate("pg-times-trigger-not-created", "the trigger that sets the times is never attached", PG_SQL,
       "CREATE TRIGGER set_times\n    BEFORE INSERT ON switchboard_audit.call_rows\n"
       "    FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();\n", "")
mutate("pg-times-begun-at-default", "the begin time falls back to a default the trigger need not set", PG_SQL,
       "    begun_at               timestamptz NOT NULL,\n",
       "    begun_at               timestamptz NOT NULL DEFAULT clock_timestamp(),\n")
mutate("pg-set-times-no-deadline", "the trigger that sets the times sets no deadline", PG_ROW_DEADLINE,
       "    NEW.deadline := CASE WHEN NEW.kind = 'call'\n"
       "        THEN NEW.begun_at + NEW.allowance_ms * interval '1 millisecond' END;\n", "")
mutate("pg-set-times-deadline-from-insert", "an insert may choose its deadline", PG_ROW_DEADLINE,
       "    NEW.deadline := CASE WHEN NEW.kind = 'call'\n",
       "    NEW.deadline := CASE WHEN NEW.deadline IS NOT NULL THEN NEW.deadline WHEN NEW.kind = 'call'\n")
mutate("pg-deadline-shape-removed", "a call row may be stored without a deadline", PG_ROW_DEADLINE,
       "    ADD CONSTRAINT deadline_shape CHECK ((kind = 'call') = (deadline IS NOT NULL));",
       "    ADD CONSTRAINT deadline_shape CHECK (true);")
mutate("pg-allowance-without-begin-budget", "a row's deadline leaves out the begin budget", PG_COLUMNS,
       "    millis(budgets.begin)\n        .saturating_add(call_deadline_ms)\n", "    call_deadline_ms\n")
mutate("pg-allowance-without-finish-deadline", "a row's deadline leaves out the finish deadline", PG_COLUMNS,
       "        .saturating_add(millis(budgets.finish_deadline))\n", "\n")
mutate("pg-allowance-wraps", "a long call deadline wraps round to a short allowance", PG_COLUMNS,
       "        .saturating_add(call_deadline_ms)\n", "        .wrapping_add(call_deadline_ms)\n")
mutate("pg-grant-insert-deadline", "the gateway may write the deadline", PG_ROW_DEADLINE,
       "GRANT INSERT (instance, kind, allowance_ms)", "GRANT INSERT (instance, kind, allowance_ms, deadline)")
# List rows (0004).
mutate("pg-complete-once-accepts-list-row", "the trigger tests only the decision, which a list row lacks, and lets it be completed", PG_LIST_ROWS,
       "    IF OLD.kind IS DISTINCT FROM 'call' THEN\n"
       "        RAISE EXCEPTION 'audit row % records a listing, which is never completed', OLD.id;\n"
       "    END IF;\n"
       "    IF OLD.decision IS DISTINCT FROM 'allow' THEN\n",
       "    IF OLD.decision <> 'allow' THEN\n")
mutate("pg-set-times-gives-list-deadline", "the trigger that sets the times gives a list row a deadline", PG_ROW_DEADLINE,
       "        THEN NEW.begun_at + NEW.allowance_ms * interval '1 millisecond' END;\n",
       "        THEN NEW.begun_at + NEW.allowance_ms * interval '1 millisecond' ELSE NEW.begun_at END;\n")
mutate("pg-kind-shape-removed", "a row may hold the columns of either kind, or neither", PG_LIST_ROWS,
       "    ADD CONSTRAINT kind_shape CHECK (\n", "    ADD CONSTRAINT kind_shape CHECK (true OR\n")
mutate("pg-kind-shape-list-null-hole", "a list row with no tools passes kind_shape, whose test of them is NULL", PG_LIST_ROWS,
       "WHEN 'list' THEN listed_tools IS NOT NULL AND jsonb_typeof(listed_tools) = 'array'",
       "WHEN 'list' THEN jsonb_typeof(listed_tools) = 'array'")
mutate("pg-kind-shape-list-call-columns", "a list row may carry a call's decision, outcome and deadline", PG_LIST_ROWS,
       "                AND decision IS NULL AND reason IS NULL AND sentence IS NULL\n"
       "                AND outcome IS NULL AND allowance_ms IS NULL AND deadline IS NULL\n", "")
mutate("pg-kind-shape-call-lists-tools", "a call row may list tools", PG_LIST_ROWS,
       "            WHEN 'call' THEN listed_tools IS NULL AND listed_omitted IS NULL\n",
       "            WHEN 'call' THEN true\n")
mutate("pg-list-not-granted", "the gateway may not write a list row's tools", PG_LIST_ROWS,
       "GRANT INSERT (listed_tools, listed_omitted) ON switchboard_audit.call_rows TO switchboard_gateway;\n", "")
mutate("pg-list-kind-not-compared", "a list with a call row's identifier succeeds", PG_STORE,
       '    if kind == "list" {', "    if true {")
mutate("pg-begin-list-row-accepted", "a begin with a list row's identifier succeeds", PG_STORE,
       "    let Some(decision) = decision else {\n        return Err(PgAuditError::OtherKind {\n            row: row.id.clone(),\n        });\n    };",
       "    let Some(decision) = decision else {\n        return Ok(());\n    };")
mutate("pg-list-no-on-conflict", "a retried list inserts again and fails on its own row", PG_COLUMNS,
       '$15, $16\n        ) ON CONFLICT (id) DO NOTHING";', '$15, $16\n        )";')
mutate("pg-list-columns-id-unchecked", "a list row's identifier that is not a lowercase UUID is sent to the database", PG_COLUMNS,
       "    pub fn from_record(id: &AuditRowId, record: &ListRecord) -> Result<Self, PgAuditError> {\n        if !is_uuid(id.as_str()) {",
       "    pub fn from_record(id: &AuditRowId, record: &ListRecord) -> Result<Self, PgAuditError> {\n        if false {")
mutate("pg-list-tools-omitted-saturates", "a count of tools left out past the column is cut short", PG_COLUMNS,
       "            listed_omitted: i64::try_from(record.tools_omitted).map_err(|_| {\n"
       "                PgAuditError::Column(\"a count of tools left out past the column's range\")\n"
       "            })?,",
       "            listed_omitted: i64::try_from(record.tools_omitted).unwrap_or(i64::MAX),")

# The store's time budgets, and its boot checks.
PG_CHECK = PG + "src/check.rs"
mutate("pg-begin-pool-wait-unbounded", "begin waits for a connection past its budget", PG_STORE,
       "timeout_at(deadline, self.begin.get())", "timeout_at(deadline + Duration::from_secs(3600), self.begin.get())")
mutate("pg-finish-pool-wait-unbounded", "a finish attempt waits for a connection past its time", PG_STORE,
       "timeout_at(by, self.pool.get())", "timeout_at(by + Duration::from_secs(3600), self.pool.get())")
mutate("pg-begin-insert-unbounded", "begin waits for its insert past its budget", PG_STORE,
       "timeout_at(deadline, insert_on(&client, row, sent))", "timeout_at(deadline + Duration::from_secs(3600), insert_on(&client, row, sent))")
mutate("pg-begin-insert-budget-restarts", "begin's insert has a budget of its own after the wait for a connection", PG_STORE,
       "match timeout_at(deadline, insert_on(&client, row, sent)).await {",
       "match timeout_at(Instant::now() + budget, insert_on(&client, row, sent)).await {")
mutate("pg-timeout-not-cancelled", "a statement that ran out of time is left running", PG_STORE,
       "    tokio::spawn(cancel(client.cancel_token()));\n", "    let _ = cancel;\n")
mutate("pg-timeout-connection-kept", "a connection that ran out of time goes back to its pool", PG_STORE,
       "    drop(Object::take(client));\n}\n", "    drop(client);\n}\n")
# The same two, at finish's call alone: begin's tests do not reach it.
mutate("pg-finish-timeout-not-cancelled", "a finish attempt that ran out of time is left running", PG_STORE,
       "                abandon(client, &self.cancel);\n                Err(PgAuditError::AttemptTimedOut)",
       "                drop(Object::take(client));\n                Err(PgAuditError::AttemptTimedOut)")
mutate("pg-finish-timeout-connection-kept", "a finish connection that ran out of time goes back to its pool", PG_STORE,
       "                abandon(client, &self.cancel);\n                Err(PgAuditError::AttemptTimedOut)",
       "                drop(client);\n                Err(PgAuditError::AttemptTimedOut)")
mutate("pg-finish-waits-past-answer-budget", "finish holds the answer until its deadline", PG_STORE,
       "let answer_by = started + self.budgets.answer;", "let answer_by = started + self.budgets.finish_deadline;")
mutate("pg-finish-stops-at-answer-budget", "finish stops trying when the answer goes out", PG_STORE,
       "            deadline: started + self.budgets.finish_deadline,", "            deadline: started + self.budgets.answer,")
mutate("pg-finish-attempt-unbounded-by-answer", "a finish attempt is limited only by the deadline, not the answer budget", PG_STORE,
       "            attempt: self.budgets.answer,\n            deadline: started + self.budgets.finish_deadline,",
       "            attempt: self.budgets.finish_deadline,\n            deadline: started + self.budgets.finish_deadline,")
mutate("pg-finish-no-retry", "finish gives up after one failed attempt", PG_STORE,
       "                Err(error) if !error.is_transient() => return Err(error),\n                Err(error) => error,",
       "                Err(error) if !error.is_transient() => return Err(error),\n                Err(error) => return Err(error),")
mutate("pg-finish-retries-final-errors", "finish retries a failure that trying again cannot fix", PG_STORE,
       "                Err(error) if !error.is_transient() => return Err(error),", "                Err(error) if false => return Err(error),")
mutate_all("pg-finish-no-deadline", "finish keeps trying past its deadline",
           (PG_STORE, "            if now >= self.deadline {", "            if false {"),
           (PG_STORE, "            if !self.row_may_commit && Instant::now() >= self.deadline {", "            if false {"))
mutate("pg-finish-pause-past-deadline", "a pause between finish attempts may run past the deadline", PG_STORE,
       "sleep_until((now + pause).min(self.deadline)).await;", "sleep_until(now + pause).await;")
mutate("pg-finish-pause-uncapped", "the pause between attempts doubles without a cap", PG_STORE,
       "    (pause * 2).min(LONGEST_PAUSE)\n", "    pause * 2\n")
mutate("pg-retry-connect-failure-final", "a connection that could not be made is not retried", PG_STORE,
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {",
       "            Self::Pool(PoolError::Timeout(_)) | Self::AttemptTimedOut => {")
mutate("pg-retry-slow-attempt-final", "an attempt that ran out of time is not retried", PG_STORE,
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {",
       "            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) => {")
mutate("pg-finish-given-up-not-counted", "a finish that gave up is not counted", PG_STORE,
       "        self.in_flight.0.given_up.fetch_add(1, Ordering::SeqCst);\n", "")
mutate("pg-finish-given-up-not-reported", "a finish that gave up is not reported", PG_STORE,
       "        (self.report)(GivenUp {\n            row: &self.row,\n            outcome: self.outcome,\n            error,\n        });\n",
       "        let _ = error;\n")
mutate("pg-finish-dropped-task-not-reported", "a finish dropped with its runtime is not counted or reported", PG_STORE,
       "        if !self.settled {", "        if false {")
mutate("pg-finish-unstorable-not-settled", "a completion the row cannot hold is not counted or reported", PG_STORE,
       "                let result = Err(error);\n                settle.settle(&result);\n",
       "                let result = Err(error);\n                std::mem::forget(settle);\n")
# One retried SQLSTATE class at a time.
RETRIED_CLASSES = ["08", "40", "53", "57", "58"]
for retried in RETRIED_CLASSES:
    kept = " | ".join(f'"{other}"' for other in RETRIED_CLASSES if other != retried)
    mutate(f"pg-retry-class-{retried}-final", f"a failure of SQLSTATE class {retried} is not retried", PG_STORE,
           'Some("08" | "40" | "53" | "57" | "58")', f"Some({kept})")
mutate("pg-retry-read-only-final", "a server that has become read-only is not retried", PG_STORE,
       '|| matches!(code.code(), "25006" | "55P03")', '|| matches!(code.code(), "55P03")')
mutate("pg-retry-lock-timeout-final", "a lock not had within lock_timeout is not retried", PG_STORE,
       '|| matches!(code.code(), "25006" | "55P03")', '|| matches!(code.code(), "25006")')
mutate("pg-retry-failed-connection-kept", "a connection whose attempt failed is used again", PG_STORE,
       "every attempt on it would find.\n                drop(Object::take(client));",
       "every attempt on it would find.\n                drop(client);")
mutate("pg-begin-failed-connection-kept", "a begin connection that found the server read-only goes back to its pool", PG_STORE,
       "rather than fail on this one.\n                drop(Object::take(client));",
       "rather than fail on this one.\n                drop(client);")
mutate("pg-retry-closed-connection-final", "a connection found closed is not retried", PG_STORE,
       "                    error.is_closed()\n", "                    false\n")
mutate("pg-retry-socket-failure-final", "a connection whose socket failed is not retried", PG_STORE,
       "                        || std::error::Error::source(error)\n"
       "                            .is_some_and(|source| source.is::<std::io::Error>())\n", "")
mutate("pg-retry-attempt-past-deadline", "one attempt may run past the finish deadline", PG_STORE,
       "            (Instant::now() + self.attempt).min(self.deadline)\n", "            Instant::now() + self.attempt\n")
mutate("pg-cancel-unbounded", "a cancel the server does not answer is waited for without end", PG_STORE,
       "let _ = tokio::time::timeout(CANCEL_WAIT, token.cancel_query(tls)).await;",
       "let _ = CANCEL_WAIT;\n                let _ = token.cancel_query(tls).await;")
# Begin retried by identifier, and a lost confirmation's row completed as error (decision 0009).
mutate("pg-begin-retry-removed", "begin gives up after one failed attempt", PG_STORE,
       "            if !error.is_transient() {\n                break error;",
       "            if true {\n                break error;")
mutate_all("pg-begin-retry-new-identifier", "begin is retried under a new identifier",
           (PG_STORE, "    async fn insert(&self, row: Insert) -> Result<(), PgAuditError> {",
            "    async fn insert(&self, mut row: Insert) -> Result<(), PgAuditError> {"),
           (PG_STORE, "            pause = longer(pause);\n        };",
            "            pause = longer(pause);\n"
            "            if let Insert::Call(call) = &mut row {\n"
            "                let first = if call.id.starts_with('0') { \"1\" } else { \"0\" };\n"
            "                call.id.replace_range(..1, first);\n"
            "            }\n        };"))
mutate("pg-lost-confirmation-left-open", "a row whose begin confirmation was lost is left open", PG_STORE,
       "            self.complete_lost_begin(AuditRowId::new(call.id.clone()));\n", "            let _ = call;\n")
mutate("pg-lost-confirmation-for-denial", "a lost confirmation for a denial starts a completion", PG_STORE,
       '            && call.decision == "allow"\n', "            && !call.decision.is_empty()\n")
mutate("pg-lost-confirmation-after-refusal", "a begin the database refused starts a completion of the row under its identifier", PG_STORE,
       "            may_be_written |= sent && unanswered;", "            may_be_written |= sent;")
mutate("pg-lost-confirmation-forgotten-on-later-error", "a later attempt's error undoes an earlier lost confirmation", PG_STORE,
       "            may_be_written |= sent && unanswered;", "            may_be_written = sent && unanswered;")
mutate("pg-lost-confirmation-not-in-flight", "a lost confirmation's completion is not counted in flight", PG_STORE,
       "            in_flight: InFlight::start(&self.counters),\n            report: Arc::clone(&self.given_up),\n            row: row.clone(),\n            outcome: \"error\",",
       "            in_flight: InFlight::start(&Arc::default()),\n            report: Arc::clone(&self.given_up),\n            row: row.clone(),\n            outcome: \"error\",")
mutate("pg-recovery-no-such-row-final", "a lost confirmation's completion stops at the first missing row", PG_STORE,
       "Err(error @ PgAuditError::NoSuchRow { .. }) if self.row_may_commit => error,",
       "Err(error @ PgAuditError::NoSuchRow { .. }) if false => error,")
mutate("pg-lost-confirmation-before-insert-executed", "a begin whose insert was never executed starts a completion", PG_STORE,
       "        match timeout_at(deadline, insert_on(&client, row, sent)).await {",
       "        *sent = true;\n        match timeout_at(deadline, insert_on(&client, row, sent)).await {")
mutate("pg-recovery-attempt-cut-by-deadline", "a lost confirmation's completion has its attempts cut short by its deadline", PG_STORE,
       "        let by = if self.row_may_commit {", "        let by = if false {")
mutate("pg-recovery-stops-before-finish-deadline", "a lost confirmation's completion stops one answer budget before its deadline", PG_STORE,
       "            if !self.row_may_commit && Instant::now() >= self.deadline {",
       "            if (Instant::now() + if self.row_may_commit { self.attempt } else { Duration::ZERO })\n"
       "                >= self.deadline\n            {")
mutate("pg-recovery-no-attempt-at-deadline", "a lost confirmation's completion makes no attempt at its deadline", PG_STORE,
       "            if !self.row_may_commit && Instant::now() >= self.deadline {",
       "            if Instant::now() >= self.deadline {")
mutate("pg-recovery-no-deadline", "a lost confirmation's completion keeps trying past its deadline", PG_STORE,
       "            if now >= self.deadline {", "            if false {")
mutate("pg-recovery-missing-row-given-up", "a row that was never written is reported as given up", PG_STORE,
       "                    if matches!(*last, PgAuditError::NoSuchRow { .. }) =>",
       "                    if false =>")
mutate("pg-migrate-unlocked", "two migrators run at once", PG + "src/migrate.rs",
       'SELECT pg_advisory_xact_lock($1)', 'SELECT $1::bigint')
mutate("pg-check-durability-ignored", "a server without fsync passes the check", PG_CHECK,
       "    (found != expected).then_some(", "    false.then_some(")
mutate("pg-check-superuser-ignored", "a superuser passes the check", PG_CHECK,
       '            (1, "SUPERUSER"),\n', "")
for index, attribute in [(2, "CREATEROLE"), (3, "CREATEDB"), (4, "REPLICATION")]:
    mutate(f"pg-check-{attribute.lower()}-attribute-ignored", f"a role with {attribute} passes the check", PG_CHECK,
           f'            ({index}, "{attribute}"),\n', "")
mutate("pg-check-bypassrls-ignored","a role that bypasses row security passes the check", PG_CHECK,
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
       "        None => Some(Problem::TriggerMissing {\n            trigger: trigger.name,\n"
       "            purpose: trigger.purpose,\n            fires: trigger.fires,\n        }),",
       "        None => None,")
mutate("pg-check-trigger-replica-enabled", "a trigger that fires only for replication passes the check", PG_CHECK,
       'Some("O" | "A") => None,', 'Some("O" | "A" | "R") => None,')
mutate("pg-check-trigger-time-ignored", "a trigger that fires at another time passes the check", PG_CHECK,
       "AND t.tgtype = $3 AND", "AND (t.tgtype = $3 OR true) AND")
mutate("pg-check-trigger-condition-ignored", "a trigger with a condition passes the check", PG_CHECK,
       "AND t.tgqual IS NULL", "AND (t.tgqual IS NULL OR true)")
mutate("pg-check-trigger-columns-ignored", "a trigger on some columns only passes the check", PG_CHECK,
       "AND cardinality(t.tgattr::int2[]) = 0", "AND (cardinality(t.tgattr::int2[]) = 0 OR true)")
mutate("pg-check-set-times-unchecked", "the trigger that sets the times is not checked", PG_CHECK,
       '    Trigger {\n        name: "set_times",\n        purpose: "sets both times and the deadline from the database\'s clock",\n'
       '        fires: "before each insert",\n        tgtype: 1 | 2 | 4,\n    },\n', "")
mutate("pg-check-extra-column-ignored", "a column grant beyond the gateway's passes the check", PG_CHECK,
       "    for (privilege, column) in reachable.difference(&expected) {",
       "    for (privilege, column) in reachable.difference(&reachable) {")
mutate("pg-check-needed-grant-reachable-only", "a column grant the store needs passes when only SET ROLE reaches it", PG_CHECK,
       "    for (privilege, column) in expected.difference(&held) {", "    for (privilege, column) in expected.difference(&reachable) {")
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
mutate("pg-check-session-settings-ignored", "a session without the store's settings passes the check", PG_CHECK,
       "        if found != *expected {\n            problems.push(Problem::SessionSetting {",
       "        if false {\n            problems.push(Problem::SessionSetting {")
mutate("pg-check-unlogged-ignored", "an unlogged table passes the check", PG_CHECK,
       "                 AND c.relpersistence <> 'p'", "                 AND false")
mutate("pg-check-unlogged-table-ignored", "an unlogged table that is not partitioned passes the check", PG_CHECK,
       "             WHERE (c.oid = $1::oid\n", "             WHERE (false\n")
mutate("pg-check-unlogged-partition-ignored", "an unlogged partition passes the check", PG_CHECK,
       "OR c.oid IN (SELECT relid", "OR false AND c.oid IN (SELECT relid")
mutate("pg-check-partitioned-ignored", "a partitioned table passes the check", PG_CHECK,
       "            if partitioned {", "            if false {")
mutate("pg-check-children-ignored", "a table that inherits from call_rows, or a partition of it, passes the check", PG_CHECK,
       "WHERE i.inhparent = $1::oid OR i.inhrelid = $1::oid", "WHERE i.inhrelid = $1::oid")
mutate("pg-check-parents-ignored", "call_rows inheriting from a table passes the check", PG_CHECK,
       "WHERE i.inhparent = $1::oid OR i.inhrelid = $1::oid", "WHERE i.inhparent = $1::oid")
mutate("pg-check-parameter-grants-ignored", "a role holding a grant on a setting passes the check", PG_CHECK,
       "    if version >= 150_000 {", "    if false {")
mutate("pg-check-alter-system-ignored", "a role that may change a setting with ALTER SYSTEM passes the check", PG_CHECK,
       "unnest(ARRAY['ALTER SYSTEM', 'SET']) AS p", "unnest(ARRAY['SET']) AS p")
mutate("pg-check-setting-set-ignored", "a role that may set a setting only a superuser may set passes the check", PG_CHECK,
       "OR NOT EXISTS (SELECT FROM pg_catalog.pg_settings s", "OR false AND NOT EXISTS (SELECT FROM pg_catalog.pg_settings s")
mutate("pg-check-replication-role-only", "SET is refused on session_replication_role alone", PG_CHECK,
       "OR NOT EXISTS (SELECT FROM pg_catalog.pg_settings s",
       "OR a.parname = 'session_replication_role' AND NOT EXISTS (SELECT FROM pg_catalog.pg_settings s")
mutate("pg-check-user-setting-set-refused", "SET on a setting any role may set is refused", PG_CHECK,
       "AND s.context = 'user'", "AND false")
for relkind, kind in [("v", "view"), ("m", "materialized-view"), ("f", "foreign-table")]:
    kinds = ", ".join(f"'{k}'" for k in ["r", "p", "v", "m", "f"] if k != relkind)
    mutate(f"pg-check-{kind}-ignored", f"a grant on a {kind.replace('-', ' ')} in the schema passes the check", PG_CHECK,
           "c.relkind IN ('r', 'p', 'v', 'm', 'f')", f"c.relkind IN ({kinds})")
for privilege in ["SELECT", "INSERT", "UPDATE", "TRUNCATE", "REFERENCES", "TRIGGER"]:
    mutate(f"pg-check-{privilege.lower()}-ignored", f"{privilege} on the table passes the check", PG_CHECK,
           f'        "{privilege}",\n', "")
mutate("pg-check-maintain-ignored", "MAINTAIN on the table passes the check", PG_CHECK,
       '        privileges.push("MAINTAIN");', "")
mutate("pg-check-trigger-function-any-schema", "a trigger calling a function of the same name in another schema passes the check", PG_CHECK,
       "AND n.nspname = 'switchboard_audit' AND p.proname = $2", "AND p.proname = $2")
mutate("pg-check-trigger-function-any-name", "a trigger calling another of the schema's functions passes the check", PG_CHECK,
       "AND n.nspname = 'switchboard_audit' AND p.proname = $2", "AND n.nspname = 'switchboard_audit' AND $2::text IS NOT NULL")
mutate("pg-check-column-references-ignored", "REFERENCES on a column passes the check", PG_CHECK,
       '    "REFERENCES",\n    "SELECT WITH GRANT OPTION",', '    "SELECT WITH GRANT OPTION",')
mutate("pg-check-sequence-select-ignored", "SELECT on a sequence in the schema passes the check", PG_CHECK,
       "unnest(ARRAY['USAGE', 'SELECT', 'UPDATE'])", "unnest(ARRAY['USAGE', 'UPDATE'])")
mutate("pg-check-sequence-update-ignored", "UPDATE on a sequence in the schema, which allows setval, passes the check", PG_CHECK,
       "unnest(ARRAY['USAGE', 'SELECT', 'UPDATE'])", "unnest(ARRAY['USAGE', 'SELECT'])")
mutate("pg-check-table-any-relkind", "a relation named call_rows that is not a table is taken for the table", PG_CHECK,
       "                 AND c.relkind IN ('r', 'p')\",", "                 AND true\",")
mutate("pg-check-schema-owner-membership-ignored", "a member of the schema's owner passes the check", PG_CHECK,
       "                 AND pg_has_role(current_user, n.nspowner, 'MEMBER')",
       "                 AND n.nspowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)")
mutate("pg-check-function-owner-membership-ignored", "a member of the trigger functions' owner passes the check", PG_CHECK,
       "                 AND pg_has_role(current_user, p.proowner, 'MEMBER')",
       "                 AND p.proowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)")
mutate("pg-check-database-owner-ignored", "the database's owner passes the check", PG_CHECK,
       "                 AND pg_has_role(current_user, d.datdba, 'MEMBER')", "                 AND false")
mutate("pg-check-database-owner-membership-ignored", "a role that can become the database's owner passes the check", PG_CHECK,
       "                 AND pg_has_role(current_user, d.datdba, 'MEMBER')",
       "                 AND d.datdba = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)")
mutate("pg-check-replica-session-ignored", "a session in replica mode, where the triggers do not fire, passes the check", PG_CHECK,
       '    if replication_role == "replica" {', "    if false {")
mutate("pg-check-encoding-ignored", "a database that is not UTF8 passes the check", PG_CHECK,
       '    if encoding != "UTF8" {', "    if false {")
mutate("pg-check-logged-in-as-ignored", "a session that logged in as another role passes the check", PG_CHECK,
       "    if logged_in != role {", "    if false {")
mutate("pg-check-privileges-own-role-only", "a role the session can become is not checked for privileges", PG_CHECK,
       "                 WHERE pg_has_role(current_user, r.oid, 'MEMBER') AND {test})",
       "                 WHERE r.rolname = current_user AND {test})")
# Each privilege check asked of the session's role alone, one at a time.
for site, test in [
    ("column", "has_column_privilege(r.oid, $1::oid, a.attnum, p)"),
    ("whole-table", "has_table_privilege(r.oid, $1::oid, p)"),
    ("table", "has_table_privilege(r.oid, c.oid, p)"),
    ("other-table-column", "has_any_column_privilege(r.oid, c.oid, p)"),
    ("sequence", "has_sequence_privilege(r.oid, c.oid, p)"),
    ("schema-create", "has_schema_privilege(r.oid, n.oid, 'CREATE')"),
    ("schema-grant-option", "has_schema_privilege(r.oid, n.oid, 'USAGE WITH GRANT OPTION')"),
    ("database-create", "has_database_privilege(r.oid, current_database(), 'CREATE')"),
    ("parameter", "has_parameter_privilege(r.oid, a.parname, p)"),
    ("reaching-table", "has_table_privilege(r.oid, v.oid, p)"),
    ("reaching-column", "has_any_column_privilege(r.oid, v.oid, p)"),
    ("definer-execute", "has_function_privilege(r.oid, d.oid, 'EXECUTE')"),
    ("server-function", "has_function_privilege(r.oid, p.oid, 'EXECUTE')"),
]:
    mutate(f"pg-check-{site}-own-role-only", f"the {site} privilege check asks only of the session's role", PG_CHECK,
           f'"{test}"', f'"r.rolname = current_user AND {test}"')
mutate("pg-check-grant-option-ignored", "the gateway's own column privileges with grant option pass the check", PG_CHECK,
       '    "SELECT WITH GRANT OPTION",\n    "INSERT WITH GRANT OPTION",\n    "UPDATE WITH GRANT OPTION",\n', "")
mutate("pg-check-schema-grant-option-ignored", "USAGE on the schema with grant option passes the check", PG_CHECK,
       "        if schema.get::<_, bool>(2) {", "        if false {")
mutate("pg-check-server-roles-ignored", "a role that reaches the server's files or programs passes the check", PG_CHECK,
       "            problems.push(Problem::ServerAccess { role, reach });", "            let _ = (role, reach);")
mutate("pg-check-server-roles-inherited-only", "a server role reached without inheriting it passes the check", PG_CHECK,
       "WHERE rolname = $1 AND pg_has_role(current_user, oid, 'MEMBER'))",
       "WHERE rolname = $1 AND pg_has_role(current_user, oid, 'USAGE'))")
for server_role in ["pg_execute_server_program", "pg_read_server_files", "pg_write_server_files"]:
    mutate(f"pg-check-{server_role.replace('_', '-')}-ignored", f"a member of {server_role} passes the check", PG_CHECK,
           f'        "{server_role}",\n', '        "pg_monitor",\n')

mutate("pg-check-rule-ignored", "a rule on the table passes the check", PG_CHECK,
       "            .map(|row| Problem::Rule { rule: row.get(0) }),",
       "            .filter(|_| false)\n            .map(|row| Problem::Rule { rule: row.get(0) }),")
mutate("pg-check-reaching-ignored", "a grant on a view or rule outside the schema that reaches the table passes the check", PG_CHECK,
       "                 WHERE n.nspname <> 'switchboard_audit'\n                     AND ({}",
       "                 WHERE false\n                     AND ({}")
mutate("pg-check-reaching-direct-only", "a view over a view over the table is not followed", PG_CHECK,
       "            JOIN pg_catalog.pg_depend d ON d.refobjid = x.oid\n",
       "            JOIN pg_catalog.pg_depend d ON d.refobjid = x.oid AND x.oid = $1::oid\n")
mutate("pg-check-reaching-views-only", "a rule on another table that writes the table is not followed", PG_CHECK,
       "            JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid\n",
       "            JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid AND rw.rulename = '_RETURN'\n")
mutate("pg-check-reaching-column-grants-ignored", "a column grant on a view that reaches the table passes the check", PG_CHECK,
       "OR (p IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') AND {}))", "OR (false AND {}))")
mutate("pg-check-definers-ignored", "a SECURITY DEFINER function that can reach the table passes the check", PG_CHECK,
       "                     WHERE p.prosecdef\n                         AND (EXISTS (SELECT FROM reaching x",
       "                     WHERE false AND p.prosecdef\n                         AND (EXISTS (SELECT FROM reaching x")
mutate("pg-check-definer-trigger-ignored", "a write to a table whose trigger runs such a function passes the check", PG_CHECK,
       "unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS w", "unnest(ARRAY[]::text[]) AS w")
mutate("pg-check-definer-trigger-own-role-only", "the trigger route asks only of the session's role, for a privilege on the whole table", PG_CHECK,
       "has_table_privilege(r.oid, c.oid, w)", "r.rolname = current_user AND has_table_privilege(r.oid, c.oid, w)")
mutate("pg-check-definer-trigger-column-own-role-only", "the trigger route asks only of the session's role, for a column privilege", PG_CHECK,
       "has_any_column_privilege(r.oid, c.oid, w)", "r.rolname = current_user AND has_any_column_privilege(r.oid, c.oid, w)")
mutate("pg-check-definer-column-owner-ignored", "a definer function whose owner holds only column privileges passes the check", PG_CHECK,
       "OR has_any_column_privilege(p.proowner, x.oid,", "OR false AND has_any_column_privilege(p.proowner, x.oid,")
mutate("pg-check-definer-view-owner-ignored", "a definer function whose owner holds privileges only on a view over the table passes the check", PG_CHECK,
       "SELECT FROM reaching x\n", "SELECT FROM (SELECT $1::oid AS oid) x\n")
mutate("pg-check-definer-schema-owner-ignored", "a definer function of the schema's owner passes the check", PG_CHECK,
       "OR EXISTS (SELECT FROM pg_catalog.pg_namespace s", "OR false AND EXISTS (SELECT FROM pg_catalog.pg_namespace s")
mutate("pg-check-definer-chain-not-followed", "a definer function that reaches the table through another passes the check", PG_CHECK,
       "                         JOIN pg_catalog.pg_proc p ON p.prosecdef\n",
       "                         JOIN pg_catalog.pg_proc p ON false AND p.prosecdef\n")
mutate("pg-check-definer-chain-execute-not-followed", "a definer function that runs another passes the check", PG_CHECK,
       "AND (has_function_privilege(p.proowner, d.oid, 'EXECUTE')", "AND (false AND has_function_privilege(p.proowner, d.oid, 'EXECUTE')")
mutate("pg-check-definer-chain-trigger-not-followed", "a definer function that writes to a table whose trigger runs another passes the check", PG_CHECK,
       "OR EXISTS (SELECT FROM pg_catalog.pg_trigger t", "OR false AND EXISTS (SELECT FROM pg_catalog.pg_trigger t")
mutate("pg-check-server-functions-ignored", "a role that can run a function reaching the server's files passes the check", PG_CHECK,
       "    problems.extend(found.into_iter().map(|row| Problem::ServerFunction {",
       "    problems.extend(found.into_iter().filter(|_| false).map(|row| Problem::ServerFunction {")
# The pg_file_* functions are adminpack's, which PostgreSQL 17, the version the tests run on,
# no longer has, so nothing can catch their removal.
for server_function in ["lo_export", "lo_import", "pg_ls_dir", "pg_read_binary_file", "pg_read_file", "pg_stat_file"]:
    mutate(f"pg-check-{server_function.replace('_', '-')}-ignored", f"a role that can run {server_function} passes the check", PG_CHECK,
           f'    "{server_function}",\n', "")


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
CLUSTER_CHECK = 'if [ "${SWITCHBOARD_DEMO_CLUSTER:-$CLUSTER}" != "$CLUSTER" ]; then'
mutate("demo-driver-otto-dev-allowed", "the driver runs whatever cluster it is given", DRIVER,
       CLUSTER_CHECK, "if false; then")
mutate_all("demo-driver-other-cluster-allowed", "the driver refuses only otto-dev, and runs any other cluster it is given",
           (DRIVER, "\nCLUSTER=switchboard-demo\n", "\nCLUSTER=${SWITCHBOARD_DEMO_CLUSTER:-switchboard-demo}\n"),
           (DRIVER, CLUSTER_CHECK, 'if [ "$CLUSTER" = "otto-dev" ]; then'))
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
mutate("demo-driver-compose-bearers-whole-log", "the Compose bearer check counts earlier runs' requests too", DRIVER,
       """    compose) dc logs --no-log-prefix --since "$LOG_SINCE" mock-docs ;;""", """    compose) dc logs --no-log-prefix mock-docs ;;""")
mutate("demo-driver-kind-bearers-whole-log", "the kind bearer check counts earlier runs' requests too", DRIVER,
       """    kind) k -n mock-docs logs --since-time "$LOG_SINCE" deploy/mock-docs ;;""", """    kind) k -n mock-docs logs deploy/mock-docs ;;""")
mutate("demo-driver-log-mark-is-epoch", "the log mark is the epoch number, not a time logs accept", DRIVER,
       "  LOG_SINCE=${mark#* }\n", "  LOG_SINCE=${mark% *}\n")
mutate("demo-driver-compose-registry-replaced", "a Compose run replaces the registry directory a reused gateway still mounts", DRIVER,
       """  mkdir -p "$DEMO_DIR/compose-registry"\n  swap_registry""",
       """  rm -rf "$DEMO_DIR/compose-registry"\n  mkdir -p "$DEMO_DIR/compose-registry"\n  swap_registry""")
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
# #47: the gateway's call before the policy, and the rest of decision 0010's control 1.
mutate("demo-before-policy-no-gateway-read", "before the policy, the gateway's call to the server is not made", WORKLOAD,
       '  expect_allowed "$(call "$TOKEN" "$READ_TOOL" "{\\"project\\":\\"$OWN_PROJECT\\",\\"document\\":\\"$DOCUMENT\\"}")" "before policy: read own project through the gateway"\n', "")
mutate("demo-before-policy-own-project-optional", "before-policy runs without OWN_PROJECT", WORKLOAD,
       '  before-policy) : "${OWN_PROJECT:?}"; before_policy ;;\n', "  before-policy) before_policy ;;\n")
mutate("demo-kind-before-policy-no-own-project", "team-b's workload template names no project", "deploy/kind/base/workloads.yaml",
       "                - {name: OWN_PROJECT, value: borealis}\n", "")
mutate("demo-kind-accepted-count-6", "the kind caller check still expects 6 calls, without the before-policy reads", DRIVER,
       '  check_server_callers "$(mock_docs_log)" "$KIND_GATEWAY_SUBJECT" 8 2\n',
       '  check_server_callers "$(mock_docs_log)" "$KIND_GATEWAY_SUBJECT" 6 2\n')
mutate("demo-operator-checks-no-attach", "attach is not checked", DRIVER,
       "        for subresource in exec attach portforward proxy; do\n", "        for subresource in exec portforward proxy; do\n")
mutate_all("demo-operator-checks-no-impersonate", "impersonation is not checked",
           (DRIVER, '    for resource in users groups; do\n      can_i_no "$team" impersonate "$resource"\n    done\n'
                    '    sar_no "$team" impersonate authentication.k8s.io uids\n'
                    '    sar_no "$team" impersonate authentication.k8s.io userextras scopes\n', ""),
           (DRIVER, '      can_i_no "$team" impersonate serviceaccounts -n "$ns"\n', ""))
mutate("demo-operator-checks-one-namespace", "the team's own namespace is not checked", DRIVER,
       '    for ns in mock-docs switchboard "$team"; do\n', "    for ns in mock-docs switchboard; do\n")
mutate("demo-operator-checks-unknown-resource-passes", "a can-i about a resource the API does not serve passes on its no", DRIVER,
       """    *"doesn't have a resource type"*) answer="a resource the API does not serve: ${answer%%$'\\n'*}" ;;\n""", "")
mutate("demo-operator-checks-review-any-answer", "a SubjectAccessReview passes whatever it answers", DRIVER,
       "    false) answer=no ;;\n    true) answer=yes ;;\n", "    *) answer=no ;;\n")
mutate("demo-operator-checks-review-core-group", "the SubjectAccessReview asks about the core group, which no rule for impersonating a UID names", DRIVER,
       "resourceAttributes: {verb: $verb, group: $group,", 'resourceAttributes: {verb: $verb, group: "",')

# The route check's operator step (deploy/route-check), watched by tests/route_check.rs.
ROUTE_CHECK = "deploy/route-check/route-check.sh"
mutate("route-check-enforcement-unchecked", "kindnet with network policy off passes", ROUTE_CHECK,
       """    off) fail "network policy is not enforced: kindnet, $ENFORCEMENT" ;;""",
       """    off) pass "network policy is not enforced: kindnet, $ENFORCEMENT" ;;""")
mutate("route-check-permissions-family-dropped", "the impersonation rows are gone from the permissions list", "deploy/route-check/permissions.tsv",
       "impersonate\tusers\t-\tcluster\nimpersonate\tgroups\t-\tcluster\nimpersonate\tserviceaccounts\t-\tnamespaced\n"
       "impersonate\tuids.authentication.k8s.io\t-\tcluster\nimpersonate\tuserextras.authentication.k8s.io\tscopes\tcluster\n", "")
mutate("route-check-projected-audience-unchecked", "a projected token for a server's audience passes", ROUTE_CHECK,
       """        if [ "$audience" = "$server" ]; then bad+=("$audience"); fi""", "        :")
mutate("route-check-probe-wait-unbounded", "the step waits for the probe for ever", ROUTE_CHECK,
       """    if [ "$left" -le 0 ]; then break; fi\n""", "")
mutate("route-check-evaluation-error-settled", "a review not allowed with an evaluationError counts as a no", ROUTE_CHECK,
       """\n                     and (.status.allowed or (.status.evaluationError // "") == ""))""", ")")
mutate("route-check-version-unread-passes", "an unread Kubernetes version fails nothing", ROUTE_CHECK,
       '    fail "the Kubernetes version is recorded: could not read"', "    :")
mutate("route-check-node-unread-passes", "an unread node image fails nothing", ROUTE_CHECK,
       '    fail "the node image of ${NODE:-its node} is recorded: could not read"', "    :")
mutate("route-check-akamai-docs-shape-missed", "the Akamai pattern misses the docs examples' shape", "deploy/route-check/token-patterns.txt",
       "akab-[A-Za-z0-9]{5,}-[A-Za-z0-9]{5,}", "akab-[A-Za-z0-9]{16}-[A-Za-z0-9]{16}")
# What the step read but could not parse fails as could not read, never as nothing to check.
mutate("route-check-configmap-parse-unchecked", "a ConfigMap whose keys jq cannot list counts as empty", ROUTE_CHECK,
       """<<<"$cm"); then""", """<<<"$cm" || true); then""")
mutate("route-check-configmap-json-unchecked", "an empty or doubled ConfigMap read counts as empty", ROUTE_CHECK,
       """ || ! json_object "$cm" ||""", " ||")
mutate("route-check-kindnet-container-parse-unchecked", "kindnetd flags jq cannot read count as no flag", ROUTE_CHECK,
       """<<<"$container"); then""", """<<<"$container" || true); then""")
mutate("route-check-audiences-parse-unchecked", "projected volumes jq cannot read count as no token", ROUTE_CHECK,
       """<<<"$POD_JSON") ||\n    ! count=$(jq length <<<"$AUDIENCES")""",
       """<<<"$POD_JSON" || true) ||\n    ! count=$(jq length <<<"$AUDIENCES")""")
mutate("route-check-pods-json-unchecked", "an empty or doubled pod list counts as no running pod", ROUTE_CHECK,
       """ || ! json_object "$pods" ||""", " ||")
mutate("route-check-probe-pod-json-unchecked", "an empty or doubled pod read while waiting counts as the probe still running", ROUTE_CHECK,
       """ && json_object "$pod_now" &&""", " &&")
# #47: the probe's lines against the routes, and a wait that keeps to --probe-wait.
mutate("route-check-route-lines-unmatched", "a probe that skipped, added or repeated an attempt passes", ROUTE_CHECK,
       """  elif [ -n "$mismatch" ]; then\n""", "  elif false; then\n")
mutate("route-check-probe-read-timeout-full", "each read while waiting for the probe may take 30 s, whatever the wait has left", ROUTE_CHECK,
       "REQUEST_TIMEOUT=${left}s k get pod", "k get pod")
mutate("route-check-probe-late-end-accepted", "a probe end first seen after the wait counts", ROUTE_CHECK,
       """        [ "$SECONDS" -le "$deadline" ] || state=""\n""", "")
# #64: projected sources, endpoints, and the version and node reads are validated, not skipped.
mutate("route-check-secret-sources-unchecked", "projected sources that are not a list count as none in the Secret check", ROUTE_CHECK,
       "any(sources; .secret)", "any(.projected.sources[]?; .secret)")
mutate("route-check-configmap-sources-unchecked", "projected sources that are not a list count as none in the ConfigMap scan", ROUTE_CHECK,
       "(sources | .configMap.name // empty)", "(.projected.sources[]? | .configMap.name // empty)")
mutate("route-check-audience-sources-unchecked", "projected sources that are not a list count as no token", ROUTE_CHECK,
       ".name as $v | sources\n", ".name as $v | .projected.sources[]?\n")
mutate("route-check-endpoints-unchecked", "endpoints that are not a list are skipped, leaving the ClusterIP alone", ROUTE_CHECK,
       """.endpoints | if . == null then empty elif type == "array" then .[] else error("endpoints are not a list") end""", ".endpoints[]?")
mutate("route-check-endpoints-false-skipped", "endpoints of false read as none, leaving the ClusterIP alone", ROUTE_CHECK,
       "| .endpoints | if . == null then", "| (.endpoints // []) | if . == null then")
mutate("route-check-addresses-unchecked", "endpoint addresses given as an object are read as its values", ROUTE_CHECK,
       """.addresses | if type == "array" then .[] else error("addresses are not a list") end""", ".addresses[]")
mutate("route-check-slices-unchecked", "EndpointSlices given as an object are read as its values", ROUTE_CHECK,
       """$slices.items | if type == "array" then .[] else error("items are not a list") end""", "$slices.items[]")
mutate("route-check-version-json-unchecked", "a version read of two objects is read as the last", ROUTE_CHECK,
       """ && json_object "$version" &&""", " &&")
mutate("route-check-node-json-unchecked", "a node read of two objects is read as the last", ROUTE_CHECK,
       """ && json_object "$node" &&""", " &&")

# The route check's probe (deploy/route-check/probe.sh), watched by tests/route_probe.rs and
# tests/route_check.rs.
PROBE = "deploy/route-check/probe.sh"
mutate("probe-dns-failure-refused", "a name that does not resolve counts as refused", PROBE,
       'record "$row" name "$url" could-not-probe "$host does not resolve"',
       'record "$row" name "$url" refused "$host does not resolve"')
mutate("probe-any-curl-exit-refused", "any failed attempt counts as refused, not only a timeout", PROBE,
       "    28)\n      # Refused only", "    [0-9]*)\n      # Refused only")
mutate("probe-connected-timeout-refused", "a connection that was made and then got no answer in time counts as refused", PROBE,
       "        *) echo could-not-probe ;;\n      esac\n      ;;\n    7)", "        *) echo refused ;;\n      esac\n      ;;\n    7)")
mutate("probe-connect-count-missing", "curl does not report whether it connected, so no timeout can be told apart", PROBE,
       "-w '%{http_code} %{num_connects}'", "-w '%{http_code}'")
mutate("probe-unconnected-timeout-not-refused", "a connect that timed out before it was made, a dropped route, does not count as refused", PROBE,
       "        0) echo refused ;;\n", "        0) echo could-not-probe ;;\n")
mutate("probe-attempt-status-unsplit", "an attempt's status is read with the connection count after it, so no answer reads as open", PROBE,
       "  attempt_code=$transfer_code ", "  attempt_code=$attempt_out ")
mutate("probe-gateway-status-unsplit", "the gateway's status is read with the connection count after it, so no answer reads as reached", PROBE,
       "code=$transfer_code\n", "code=$out\n")
mutate("probe-gateway-reach-skipped", "the routes are tried whether or not the gateway answered", PROBE,
       """  '' | 000) stop "gateway unreachable: $GATEWAY_URL (curl exit $status)" ;;\n""", "  __never__) ;;\n")
mutate("probe-sends-bearer", "each attempt carries a bearer", PROBE,
       "-H 'Authorization:'", "-H 'Authorization: Bearer probe'")
mutate("probe-reads-curlrc", "curl reads the caller's .curlrc, which may add a credential", PROBE,
       "  curl -q -g -s ", "  curl -g -s ")
mutate("probe-name-not-pinned", "curl resolves the name again, so a slow lookup can time out as refused", PROBE,
       ' --resolve "$host:$port:$pinned"', "")
mutate("probe-address-literal-unchecked", "an address column of hex letters or bad numbers goes to curl, which looks it up as a name", PROBE,
       """      literals "$addresses" || { broken "$number" "addresses are not address literals: $addresses"; continue; }\n""", "")
mutate("probe-octet-unbounded", "an octet over 255 passes as an address literal", PROBE,
       '      [ "$octet" -le 255 ] || return 1\n', "")
mutate("probe-octet-leading-zero", "an octet with a leading zero, which curl reads as octal, passes", PROBE,
       "      case $octet in 0) ;; 0* | ????*) return 1 ;; esac\n", "      case $octet in ????*) return 1 ;; esac\n")
# Round 2: a URL glob made one row several requests, and curl's last status hid the others.
mutate("probe-globbing-on", "curl expands a URL glob into several requests", PROBE,
       "  curl -q -g -s ", "  curl -q -s ")
mutate("probe-url-glob-unchecked", "a URL with a glob character passes the row check", PROBE,
       """    *'{'* | *'}'* | *'['* | *']'*) broken "$number" "the URL holds a curl glob character: $url"; continue ;;\n""", "")
mutate("probe-url-glob-after-ipv6-unchecked", "a glob character after an IPv6 host's brackets passes the row check", PROBE,
       "  case $authority in '['*) glob_rest=${rest#*]} ;; esac\n", "  case $authority in '['*) glob_rest='' ;; esac\n")
# Caught only where sh is dash (CI's Ubuntu runner, Debian images): bash strips an unquoted [.
mutate("probe-ipv6-host-bracket-unquoted", "an IPv6 host in a URL fails its row under dash, which reads the bracket as a pattern", PROBE,
       "    '['*']:'*) host=${authority#'['} ", "    '['*']:'*) host=${authority#[} ")
mutate("probe-multi-transfer-accepted", "two requests' results from one curl run are read as one", PROBE,
       "  case $transfer_connects in '' | *[!0-9]*) return 1 ;; esac\n", "")
mutate("probe-multi-transfer-unrefused", "an attempt whose output is not one request's status is classified anyway", PROBE,
       "  if ! one_transfer \"$attempt_out\"; then\n", "  if ! one_transfer \"$attempt_out\" && false; then\n")
mutate("probe-gateway-multi-transfer-accepted", "the gateway check reads two requests' results as one", PROBE,
       """one_transfer "$out" || stop""", """one_transfer "$out" || true ||  stop""")
# #86: a refusal after a connection, an address-literal host the row never tries, a bracketed
# host that is not IPv6, and the proxy variables.
mutate("probe-reject-ok-after-connect-refused", "a refused retry after curl connected counts as refused under reject_ok", PROBE,
       "        *,reject_ok,*:0) echo refused ;;\n", "        *,reject_ok,*) echo refused ;;\n")
mutate("probe-proxy-on", "curl reads the proxy variables, so an attempt can go to a proxy", PROBE,
       "  curl -q -g -s --noproxy '*' -o ", "  curl -q -g -s -o ")
mutate("probe-literal-host-not-in-addresses", "a URL's address-literal host that is not one of the row's addresses passes, and is never tried", PROBE,
       """          *) broken "$number" "the host $host of the URL is not one of its addresses: $addresses"; continue ;;\n""", "")
mutate("probe-bracketed-host-unchecked", "a bracketed host that is not an IPv6 literal passes the row check", PROBE,
       "        *[!0-9a-fA-F.:]*) ;;\n        *:*) literal=1 ;;\n", "        *) literal=1 ;;\n")
mutate("probe-dotted-host-unchecked", "a host of digits and dots that is not an IPv4 literal passes, and curl looks it up as a name", PROBE,
       """      if [ -n "$literal" ] && ! literals "$host"; then\n""", """      if false; then\n""")
mutate("route-check-dotted-host-unchecked", "route-check.sh accepts a host of digits and dots that is not an IPv4 literal", ROUTE_CHECK,
       """elif $literal and ($authority | startswith("[") | not)\n""", """elif false\n""")
mutate("probe-literal-resolve-looked-up", "a resolve row with an address-literal host looks the host up instead of trying it", PROBE,
       "    found=$host\n", "    found=$(resolve \"$host\")\n")
mutate("route-check-literal-host-not-in-addresses", "route-check.sh accepts a row whose address-literal host is not one of its addresses", ROUTE_CHECK,
       """elif $literal and $addresses != "resolve" and (any($addresses | split(",")[]; . == $host) | not) then""", "elif false then")
mutate("route-check-bracketed-host-unchecked", "route-check.sh accepts a bracketed host that is not an IPv6 literal", ROUTE_CHECK,
       """if ($authority | startswith("[")) and ($host | test("^[0-9a-fA-F.:]*:[0-9a-fA-F.:]*$") | not) then""", "if false then")
mutate("route-check-broken-rows-ignored", "route-check.sh starts the probe whatever rows it found broken", ROUTE_CHECK,
       """  if [ -n "$broken" ]; then\n    local row why\n""", """  if false; then\n    local row why\n""")
mutate("probe-not-in-image", "the image does not install the probe", "deploy/Dockerfile",
       "COPY --chmod=0755 deploy/route-check/probe.sh /usr/local/bin/route-probe.sh\n", "")


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
       "            Err(outcome) => Box::pin(std::future::ready(outcome)),",
       "            Err(_outcome) => self.inner.run(call),")
mutate("gw-proxied-invalid-arguments-refused", "a call that fails the argument check is recorded as refused, not as an error", PROXIED,
       "                    ToolOutcome::Error(undeclared_argument(tool.as_str()))",
       "                    ToolOutcome::Refused(undeclared_argument(tool.as_str()))")
mutate("gw-proxied-withdrawn-forwarded", "a tool withdrawn after its decision is sent anyway", PROXIED,
       "            Some(adapter) if !withdrawn => {", "            Some(adapter) => {")
mutate("gw-proxied-checks-live-schema", "a call's arguments are checked against the policy served now, not the one it was decided under", PROXIED,
       "        let adapter = self.policy.arguments(&tool);\n",
       "        let live = self.live.current();\n        let adapter = live.arguments(&tool);\n")
mutate("gw-proxied-resources-never-named", "the registry's adapter is not asked for resources", PROXIED,
       "        (Some(adapter), Some(arguments)) => adapter.resources(arguments),",
       "        (Some(_adapter), Some(_arguments)) => Resources::Named(Vec::new()),")

mutate("gw-path-proxied-unchecked", "a proxied connector runs without the argument check", GW_PATH,
       "            Reads::Adapter(_) => registered.connector.as_ref(),\n",
       "            Reads::Adapter(_) | Reads::Registry => registered.connector.as_ref(),\n")
mutate("gw-boot-proxied-connector-handed-out", "a proxied server's connector is handed out to run unchecked", BOOT,
       "            .filter(|registered| matches!(registered.reads, Reads::Adapter(_)))\n", "")
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
mutate("gw-reload-same-revision-served", "a reload that changes the policy but not its revision is served", RELOAD,
       "        if policy.revision() == served.revision() && policy != *served {", "        if false {")
mutate("gw-reload-same-revision-any-change", "a reload under the same revision is refused even if the policy is the same", RELOAD,
       "        if policy.revision() == served.revision() && policy != *served {",
       "        if policy.revision() == served.revision() {")
mutate("gw-reload-gates-skipped", "a reload skips the boot gates", RELOAD,
       "        check_registry_policy(registry, &policy, &self.basis)?;\n", "")
mutate("gw-reload-never-reads-again", "the watcher never serves a new file", RELOAD,
       "            if bytes == seen {", "            if true {")

mutate("gw-policy-no-rule-gets-a-profile", "a caller no registry rule covers gets the demo's profile", POLICY_RS,
       "                    ProfileName::new(NO_PROFILE)\n", "                    ProfileName::new(\"workload-read\")\n")
mutate("gw-path-identity-failure-unnamed", "an identity failure's log line has no event name", GW + "telemetry.rs",
       "            event = \"identity_failed\",\n", "")

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

mutate("demo-driver-bearer-count-floor", "a denied call that reached mock-docs passes the bearer check", DRIVER,
       '  check "$good" "$calls" "mock-docs accepted', '  check_at_least "$good" "$calls" "mock-docs accepted')
mutate("demo-driver-kind-bearer-count-compose", "the kind run expects only Compose's four allowed calls", DRIVER,
       '"$KIND_GATEWAY_SUBJECT" 8 2\n', '"$KIND_GATEWAY_SUBJECT" 4 2\n')
mutate("demo-dockerignore-worktrees-sent", "the image's build context takes in .claude and its worktrees", ".dockerignore",
       "\n.claude\n", "\n")
mutate("demo-dockerignore-nested-targets-sent", "the image's build context takes in nested target directories", ".dockerignore",
       "\n**/target\n", "\n")
mutate("demo-driver-health-checks-counted", "the outage step counts health checks as requests", DRIVER,
       "select(.accepted == true)' | awk 'END { print NR }'", "select(.event == \"request\")' | awk 'END { print NR }'")
mutate("demo-compose-dev-issuer-published", "the development issuer is published", COMPOSE,
       "      - issuer-keys:/shared/issuer\n    healthcheck:",
       "      - issuer-keys:/shared/issuer\n    ports:\n      - \"127.0.0.1:18090:8090\"\n    healthcheck:")


# --- first slice: resources on rows, naming what goes down ------------------------------------

# The pg-columns-resources-* ones need no server. The audit store's own section has the
# mutation that writes unknown resources as none named.
mutate("pg-columns-resources-dropped", "a row records no resources", PG_COLUMNS,
       "    Ok((resources, omitted))", "    Ok((json!([]), omitted))")
mutate("pg-columns-resources-omitted-dropped", "a row counts no resources as left out", PG_COLUMNS,
       "    Ok((resources, omitted))", "    Ok((resources, 0))")
mutate("demo-driver-down-unnamed-takes-all", "down with nothing named takes down Compose and the cluster", DRIVER,
       "      all) down_compose && down_kind ;;", '      all | "") down_compose && down_kind ;;')
mutate("demo-driver-down-compose-deletes-cluster", "taking Compose down deletes the cluster too", DRIVER,
       "      compose) down_compose ;;", "      compose) down_compose && down_kind ;;")


# --- first slice: the kind run's image ---------------------------------------------------------
# A kind run deploys its image under a tag taken from the image's ID, so a run on an existing
# cluster replaces the previous build's pods.

mutate("demo-driver-kind-fixed-tag", "a kind run deploys the manifests' fixed tag", DRIVER,
       r'''  k kustomize "$ROOT/deploy/kind/base" | sed "s|image: $IMG\$|image: $IMG_RUN|" | k apply -f -''',
       r'''  k kustomize "$ROOT/deploy/kind/base" | k apply -f -''')
mutate("demo-driver-kind-tag-not-from-id", "the run's tag is not taken from the image's ID", DRIVER,
       "  IMG_RUN=${IMG%:*}:${image_id:0:12}\n", "  IMG_RUN=$IMG\n")
mutate("demo-driver-kind-image-id-unchecked", "a run goes on without the image's ID", DRIVER,
       "    '' | *[!0-9a-f]*)\n", "    __never__)\n")

# The image's switchboard is the release build: `-p gateway` alone, no features, copied out
# before the development binaries are built with `test-support` (decision 0009).
DOCKERFILE = "deploy/Dockerfile"
RELEASE_BUILD_LINE = "    cargo build --release --locked -p gateway --bin switchboard; \\\n"
mutate("release-build-test-support", "the image's switchboard is built with test-support", DOCKERFILE,
       RELEASE_BUILD_LINE, "    cargo build --release --locked -p gateway --bin switchboard --features gateway/test-support; \\\n")
mutate("release-build-test-support-default", "test-support is a default feature of the gateway", "crates/gateway/Cargo.toml",
       "[features]\ntest-support = []\n", '[features]\ndefault = ["test-support"]\ntest-support = []\n')
mutate("release-build-workspace", "the image's switchboard is built with the workspace, taking its features", DOCKERFILE,
       RELEASE_BUILD_LINE, "    cargo build --release --locked --workspace --bins; \\\n")


# --- first slice: the demo's honesty review ----------------------------------------------------
# Unknown resources for a tool the gateway does not know, the row check that tests what it
# claims, the operator checks for both teams and the API server's routes, team-b's own
# pre-policy probe, proxied results passed on as the server sent them, and the grace periods.
# The given-up event is the gateway's now; its mutations are in the last section.

mutate("gw-unknown-tool-resources-none", "a call to a tool the gateway does not know records no resources", GW + "path.rs",
       "            return Resources::Unknown;\n", "            return Resources::Named(Vec::new());\n")
mutate("gw-proxied-result-wrapped", "a proxied server's result is wrapped again as one JSON text block", GW + "path.rs",
       "            Answer::Ok(value) if results == Some(Results::ToolResults) => passed_on(value),\n", "")
mutate("gw-proxied-structured-content-dropped", "a proxied server's structured content is not passed on", GW + "path.rs",
       '            structured_content: result.get("structuredContent").cloned(),', "            structured_content: None,")
mutate("mcp-tool-result-legacy-structured-non-object", "a legacy pass-through result carries structuredContent that is not an object", MCP_REPLY,
       "structured_content.filter(|value| era == Era::Modern || value.is_object());", "structured_content.filter(|_| true);")
mutate("demo-driver-unknown-row-as-none", "the row check takes none for the resources of a tool the gateway does not know", DRIVER,
       '        elif .reason == "unknown_tool" then "unknown"\n', '        elif .reason == "unknown_tool" then []\n')
mutate("demo-driver-row-check-counts-nothing", "the row check passes whatever rows were wrong", DRIVER,
       '    check "$(count_lines . "$wrong")" 0 \\\n      "audit: every row', '    check 0 0 \\\n      "audit: every row')
# List rows (decision 0009): counted apart, one per tools/list, each naming what was shown.
mutate("demo-driver-list-row-any-resources", "the row check passes a list row whatever resources it names", DRIVER,
       '        if .kind == "list" then null\n', '        if .kind == "list" then .resources\n')
mutate("demo-driver-row-any-kind", "the row check judges a row of any kind as a call", DRIVER,
       '        elif .kind != "call" then "no call of the demo makes this row"\n', "")
mutate("demo-driver-list-count-unchecked", "the list check passes whatever number of list rows there are", DRIVER,
       '  check "$lists" "$expected" "audit: one list row', '  check "$expected" "$expected" "audit: one list row')
mutate("demo-driver-list-check-counts-nothing", "the list check passes whatever list rows were wrong", DRIVER,
       '  check "$(count_lines . "$wrong")" 0 "audit: each list row', '  check 0 0 "audit: each list row')
mutate("demo-driver-list-withdrawn-shown", "the list check expects the withdrawn tool after the withdrawal too", DRIVER,
       '"demo-2": [$list]}', '"demo-2": [$list, $read]}')
mutate("demo-driver-list-omitted-unchecked", "the list check passes a list row that left tools out", DRIVER,
       "            and .omitted == 0) | not)\n", "            and true) | not)\n")
mutate("demo-driver-list-any-team", "the list check passes a list row from any team", DRIVER,
       '        | select(((.team == "team-a" or .team == "team-b")\n', "        | select(((true)\n")
mutate("demo-driver-row-check-no-rows-passes", "the row check passes with no rows", DRIVER,
       '  if [ "$total" -eq 0 ]; then\n', '  if false; then\n')
mutate("demo-driver-operator-checks-team-a-only", "only team-a's workload is checked", DRIVER,
       "  for team in team-a team-b; do\n    for verb in get list watch; do\n",
       "  for team in team-a; do\n    for verb in get list watch; do\n")
mutate("demo-driver-secrets-get-only", "only get is checked on secrets and configuration, not list or watch", DRIVER,
       "    for verb in get list watch; do\n", "    for verb in get; do\n")
mutate("demo-driver-no-node-proxy", "the node proxy is not checked", DRIVER,
       '      can_i_no "$team" "$verb" nodes --subresource=proxy\n', "      :\n")
mutate("demo-driver-no-port-forward-or-pod-proxy", "port-forward and the pod proxy are not checked", DRIVER,
       "        for subresource in exec attach portforward proxy; do\n", "        for subresource in exec attach; do\n")
mutate("demo-driver-no-service-proxy", "the Service proxy is not checked", DRIVER,
       '        can_i_no "$team" "$verb" services --subresource=proxy -n "$ns"\n', "")
mutate("demo-driver-no-team-b-probe", "team-b has no pre-policy probe", DRIVER,
       '  kind_workload "team-b before policy" team-b mock-workload before-policy\n', "")
mutate("demo-workload-wrapped-result-passes", "a result wrapped again passes as the server's own", WORKLOAD,
       '| objects | select(has("content"))]', '| objects | select(false)]')
mutate("demo-kind-default-grace-period", "the kind gateway gets Kubernetes' default 30 s to stop", "deploy/kind/base/gateway.yaml",
       "      terminationGracePeriodSeconds: 50\n", "      terminationGracePeriodSeconds: 30\n")
mutate("demo-kind-slow-readiness-removal", "readiness removal takes longer than the grace period allows", "deploy/kind/base/gateway.yaml",
       "            failureThreshold: 3\n", "            failureThreshold: 10\n")
mutate("demo-kind-tcp-readiness-probe", "the kind probe only opens a connection, which passes while the gateway stops", "deploy/kind/base/gateway.yaml",
       "            httpGet:\n              path: /readyz\n              port: http\n",
       "            tcpSocket:\n              port: http\n")
mutate("demo-compose-default-grace-period", "the Compose gateway gets Compose's default 10 s to stop", COMPOSE,
       "    stop_grace_period: 50s\n", "    stop_grace_period: 10s\n")
# #47: in kind the gateway presents its own projected token, and mock-docs accepts only that
# identity (decision 0010).
KIND_GATEWAY = "deploy/kind/base/gateway.yaml"
KIND_MOCK_DOCS = "deploy/kind/base/mock-docs.yaml"
mutate("demo-kind-gateway-still-mounts-docs-credential", "the kind gateway mounts a static credential from a Secret", KIND_GATEWAY,
       "          projected:\n            sources:\n              - serviceAccountToken:\n"
       "                  audience: mock-docs\n                  expirationSeconds: 600\n                  path: token\n",
       "          secret: {secretName: docs-credential}\n")
mutate("demo-kind-gateway-token-long-lived", "the gateway's token for mock-docs lives a day", KIND_GATEWAY,
       "                  expirationSeconds: 600\n", "                  expirationSeconds: 86400\n")
mutate("demo-kind-mock-docs-any-subject", "mock-docs accepts a workload's ServiceAccount", KIND_MOCK_DOCS,
       '"system:serviceaccount:switchboard:gateway"', '"system:serviceaccount:team-a:mock-workload"')
mutate("demo-kind-issuer-keys-gateway-only", "demo.sh copies the cluster's keys only for the gateway", DRIVER,
       "  for ns in switchboard mock-docs; do\n", "  for ns in switchboard; do\n")
mutate_all("demo-kind-caller-unchecked", "the kind check counts accepted requests whatever their caller",
           (DRIVER, """'$1 == "accepted" && $2 == subject && NF == 2 { n++ }""", """'$1 == "accepted" { n++ }"""),
           (DRIVER, """'$1 == "accepted" && !($2 == subject && NF == 2) { n++ }""", """'$1 == "accepted" && 0 { n++ }"""))
mutate("demo-kind-other-refusals-unchecked", "a refusal the direct calls do not explain passes", DRIVER,
       '  check "$refused" "$refusals" "mock-docs refused nothing else"\n', "")
mutate("demo-driver-kind-identity-failures-whole-log", "the identity failure count reads the gateway's whole log", DRIVER,
       '  gateway_logs=$(k -n switchboard logs --since-time "$LOG_SINCE" deploy/gateway)\n',
       "  gateway_logs=$(k -n switchboard logs deploy/gateway)\n")

# --- first slice: the Postgres store as PR #39 has it -----------------------------------------
# The gateway logs each finish the store reports given up, and the demo's database, set up by
# deploy/demo's scripts for both Compose and kind, passes the store's boot checks. Each is
# caught only against Postgres (SWITCHBOARD_TEST_DATABASE_URL).

mutate("gw-given-up-not-logged", "a finish the store gives up is not logged", GW + "start.rs",
       "        .on_given_up(log_given_up);\n", ";\n")
mutate("gw-given-up-wrong-event", "a finish given up is logged under another event", GW + "start.rs",
       'pub const GIVEN_UP_EVENT: &str = "audit_row_given_up";', 'pub const GIVEN_UP_EVENT: &str = "audit_row_given_up_";')
mutate("gw-given-up-row-unnamed", "the given-up event does not name its row", GW + "start.rs",
       "        row = given_up.row.as_str(),\n", "")
mutate("gw-given-up-outcome-unnamed", "the given-up event does not name the outcome not written", GW + "start.rs",
       "        outcome = given_up.outcome,\n", "")
mutate("gw-given-up-not-error", "the given-up event is logged below ERROR", GW + "start.rs",
       "fn log_given_up(given_up: GivenUp<'_>) {\n    tracing::error!(", "fn log_given_up(given_up: GivenUp<'_>) {\n    tracing::warn!(")
mutate("demo-roles-gateway-owns-database", "the demo's gateway role owns its database", "deploy/demo/roles.sql",
       "CREATE DATABASE switchboard OWNER switchboard_owner", "CREATE DATABASE switchboard OWNER switchboard_gateway")
mutate("demo-roles-gateway-can-create", "the demo's gateway role may create in its database", "deploy/demo/roles.sql",
       "GRANT CONNECT ON DATABASE switchboard TO switchboard_gateway, switchboard_reader;",
       "GRANT CONNECT, CREATE ON DATABASE switchboard TO switchboard_gateway, switchboard_reader;")
mutate("demo-migrate-gateway-reads-everything", "the demo grants the gateway role every column", "deploy/demo/migrate.sh",
       'GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO switchboard_reader;',
       'GRANT SELECT ON ALL TABLES IN SCHEMA :"schema" TO switchboard_reader, switchboard_gateway;')

# --- issuer-keys ---------------------------------------------------------------------------
# The key fetcher reaches the issuer's own origin and nothing else, and each fetch is bounded.

IK = "crates/issuer-keys/src/source.rs"
# Only the issuer's origin.
mutate("issuer-keys-other-host-allowed", "a keys URL on another host is accepted", IK,
       "        if url.host() != origin.host() {", "        if false {")
mutate("issuer-keys-other-port-allowed", "a keys URL on another port is accepted", IK,
       "        if found != expected {", "        if false {")
mutate("issuer-keys-http-for-https-issuer", "an http keys URL is accepted for an https issuer", IK,
       "        if url.scheme() != origin.scheme() {", "        if false {")
mutate("issuer-keys-userinfo-allowed", "a keys URL with a user name or password is accepted", IK,
       "        if !url.username().is_empty() || url.password().is_some() {", "        if false {")
mutate("issuer-keys-fragment-allowed", "a keys URL with a fragment is accepted", IK,
       "        if url.fragment().is_some() {", "        if false {")
mutate("issuer-keys-https-accepted", "an https source is accepted with no TLS client to fetch it", IK,
       '        if url.scheme() != "http" {', "        if false {")
mutate("issuer-keys-zero-deadline-allowed", "a zero deadline is accepted", IK,
       "        if options.deadline.is_zero() {", "        if false {")
mutate("issuer-keys-zero-cap-allowed", "a zero body cap is accepted", IK,
       "        if options.max_body_bytes == 0 {", "        if false {")
mutate("issuer-keys-redirect-followed", "a redirect is followed once, wherever it points", IK,
       "        let response = self.send(self.uri.clone()).await?;\n",
       "        let mut response = self.send(self.uri.clone()).await?;\n"
       "        if response.status().is_redirection() {\n"
       "            let next = response\n"
       "                .headers()\n"
       "                .get(hyper::header::LOCATION)\n"
       "                .and_then(|location| location.to_str().ok())\n"
       "                .and_then(|location| Url::parse(&self.uri.to_string()).ok()?.join(location).ok())\n"
       "                .and_then(|next| next.as_str().parse::<Uri>().ok());\n"
       "            if let Some(next) = next {\n"
       "                response = self.send(next).await?;\n"
       "            }\n"
       "        }\n")
mutate("issuer-keys-status-unchecked", "only a server error status is refused", IK,
       "        if status != StatusCode::OK {", "        if status.is_server_error() {")
# The bounds.
mutate("issuer-keys-no-deadline", "a fetch is never abandoned", IK,
       "        let body = match tokio::time::timeout(self.deadline, self.exchange()).await {",
       "        let body = match Ok::<_, ()>(self.exchange().await) {")
mutate("issuer-keys-default-deadline-longer", "the default deadline is 30 s", IK,
       "Duration = Duration::from_secs(5);", "Duration = Duration::from_secs(30);")
mutate("issuer-keys-body-uncapped", "a streamed body is read whatever its size", IK,
       "                if received.len() + data.len() > self.max_body_bytes {", "                if false {")
mutate("issuer-keys-cap-off-by-one", "a body of exactly the cap is refused", IK,
       "                if received.len() + data.len() > self.max_body_bytes {",
       "                if received.len() + data.len() >= self.max_body_bytes {")
mutate("issuer-keys-declared-length-ignored", "a declared length over the cap is not refused before reading", IK,
       "            .is_some_and(|length| length > self.max_body_bytes as u64)", "            .is_some_and(|_| false)")
mutate("issuer-keys-default-cap-larger", "the default body cap is 1 MiB", IK,
       "usize = 256 * 1024;", "usize = 1024 * 1024;")

# --- Which tests can see a mutation ----------------------------------------------------------
#
# A mutation runs the tests of the packages that can see its edits: the package that holds each
# edited file, every workspace package that depends on that one (as a normal, dev or build
# dependency, and so on up), and the packages whose tests read the file itself. If those pass, the
# mutation runs again against the whole workspace before it is called SURVIVED, so a gap in the
# table below costs time, never a verdict.

# Files read across a package boundary: a path prefix, and the packages whose tests read the files
# under it. Every prefix that matches an edited path adds its packages. These readers read in their
# tests, not in code another package links, so their dependents are not added.
#
# A path outside every crate that no prefix matches runs the whole workspace. That covers the root
# Cargo.toml and Cargo.lock, which every build reads, and docs/, scripts/, .github/, README.md and
# CONTRIBUTING.md, which no test reads today.
#
# Left out on purpose: gateway-testkit's no_private_key_is_checked_in reads every file under
# crates/. A mutation that wrote private key armour would be caught only by the whole-workspace run.
READERS: list[tuple[str, frozenset[str]]] = [
    # demo-checks runs and reads the scripts and manifests under deploy/ (tests/common reads from
    # the repository root) and holds .dockerignore to the Dockerfile.
    ("deploy/", frozenset({"demo-checks"})),
    (".dockerignore", frozenset({"demo-checks"})),
    # gateway/tests/deployment.rs loads both demo deployments; gateway/tests/files includes the
    # kind registry.
    ("deploy/compose/config/", frozenset({"gateway"})),
    ("deploy/kind/base/config/", frozenset({"gateway"})),
    # gateway-testkit/tests/issuer.rs searches conformance/ for private keys.
    ("conformance/", frozenset({"gateway-testkit"})),
    # demo-checks/tests/manifests.rs compares the demo registries with the registry crate's own.
    ("crates/gateway-registry/demo/", frozenset({"demo-checks"})),
    # mock-docs-server/tests/dependencies.rs includes the identity crate's manifest.
    ("crates/gateway-identity/Cargo.toml", frozenset({"mock-docs-server"})),
]


@dataclass(frozen=True)
class Packages:
    # Each workspace package's directory, relative to the workspace root and ending in "/".
    directories: dict[str, str]
    # For each package, the workspace packages that name it as a dependency of any kind.
    dependents: dict[str, frozenset[str]]


def read_packages(workspace: Path) -> Packages:
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=workspace, capture_output=True, text=True, check=True,
    ).stdout
    metadata = json.loads(output)
    root = Path(metadata["workspace_root"])
    directories = {
        package["name"]: Path(package["manifest_path"]).parent.relative_to(root).as_posix() + "/"
        for package in metadata["packages"]
    }
    dependents: dict[str, set[str]] = {name: set() for name in directories}
    for package in metadata["packages"]:
        for dependency in package["dependencies"]:
            if dependency["name"] in directories:
                dependents[dependency["name"]].add(package["name"])
    return Packages(directories, {name: frozenset(names) for name, names in dependents.items()})


def scope(mutation: Mutation, packages: Packages) -> tuple[frozenset[str], frozenset[str]] | None:
    """The packages whose tests can see the mutation's edits, in two parts: those that hold or
    read an edited file, and the other packages that depend on one that holds one. None means
    the whole workspace."""
    owners: set[str] = set()
    readers: set[str] = set()
    for edit in mutation.edits:
        owner = max((name for name, directory in packages.directories.items() if edit.path.startswith(directory)),
                    key=lambda name: len(packages.directories[name]), default=None)
        matched = [names for prefix, names in READERS if edit.path.startswith(prefix)]
        if owner is None and not matched:
            return None
        if owner is not None:
            owners.add(owner)
        for names in matched:
            readers |= names
    near = owners | readers
    seen, waiting = set(owners), list(owners)
    while waiting:
        for dependent in packages.dependents[waiting.pop()] - seen:
            seen.add(dependent)
            waiting.append(dependent)
    return frozenset(near), frozenset(seen - near)


def short(chosen: frozenset[str] | None) -> str:
    if chosen is None:
        return "workspace"
    return ",".join(sorted(name.removeprefix("gateway-") for name in chosen))


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


def run_tests(workspace: Path, target: Path, chosen: frozenset[str] | None = None, *,
              fail_fast: bool = False) -> tuple[int | None, str]:
    """`cargo test` over the chosen packages, or the whole workspace when none are chosen."""
    command = ["cargo", "test"]
    if chosen is None:
        command.append("--workspace")
    else:
        for name in sorted(chosen):
            command += ["-p", name]
    command.append("--locked")
    if not fail_fast:
        command.append("--no-fail-fast")
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
    broken = re.findall(r"could not compile `gateway(?:-[a-z]+)?` \(([^)]*)\)", output)
    if mutation.breaks_build and "lib" in broken:
        return "CAUGHT", "the library does not compile, as intended"
    if broken:
        return "NO-VERDICT", "did not compile: " + ", ".join(broken)
    lines = [line for line in output.splitlines() if line.startswith("error")]
    return "NO-VERDICT", "; ".join(lines[:2]) or f"cargo exited {code}"


def steps(mutation: Mutation, packages: Packages, all_catchers: bool) -> list[frozenset[str] | None]:
    """The runs a mutation takes before any whole-workspace retry; None is the whole workspace.

    The packages that hold or read an edited file run first: they build fastest and catch most.
    Only if they pass do the rest of their dependents run. With --all-catchers both run at once
    and to the end."""
    plan = scope(mutation, packages)
    if plan is None:
        chosen: list[frozenset[str] | None] = [None]
    elif all_catchers:
        chosen = [plan[0] | plan[1]]
    else:
        chosen = [plan[0]] + ([plan[1]] if plan[1] else [])
    return [None if step is not None and step >= packages.directories.keys() else step for step in chosen]


def judge(mutation: Mutation, workspace: Path, target: Path, planned: list[frozenset[str] | None],
          usable: Callable[[frozenset[str]], bool], all_catchers: bool) -> tuple[str, str, str]:
    """The verdict on the mutation as it stands in the workspace, its detail, and what ran.
    A set of packages that is not usable is replaced by the whole workspace."""
    ran = []
    for chosen in planned:
        if chosen is not None and not usable(chosen):
            chosen = None
        code, output = run_tests(workspace, target, chosen, fail_fast=not all_catchers)
        status, detail = verdict(mutation, code, output)
        ran.append(short(chosen))
        if status != "SURVIVED" or chosen is None:
            break
    # A pass over the whole workspace has already run every test; fail-fast changes nothing when
    # nothing fails. Anything else that is not CAUGHT is run again exactly as it always was.
    whole = chosen is None and (status == "SURVIVED" or all_catchers)
    if status in ("SURVIVED", "NO-VERDICT") and not whole:
        code, output = run_tests(workspace, target)
        status, detail = verdict(mutation, code, output)
        ran.append("workspace")
    if status == "SURVIVED":
        detail = "every test in the workspace passed"
    return status, detail, " then ".join(ran)


def shard(text: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)/(\d+)", text)
    if match is None or not int(match.group(1)) < int(match.group(2)):
        raise argparse.ArgumentTypeError("expected I/N with 0 <= I < N, such as 0/4")
    return int(match.group(1)), int(match.group(2))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("only", nargs="*", help="run only these mutation ids")
    parser.add_argument("--list", action="store_true", help="list the mutations and exit")
    parser.add_argument("--targets", action="store_true", help="check every target matches exactly once, without cargo")
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace")
    parser.add_argument("--all-catchers", action="store_true",
                        help="run every test of the chosen packages, not only up to the first failing test binary")
    parser.add_argument("--shard", type=shard, metavar="I/N",
                        help="run every N-th selected mutation, starting at the I-th (0-based)")
    arguments = parser.parse_args()

    sentence_mutations((ROOT / SRC / "sentences.rs").read_text())
    known = {mutation.id for mutation in MUTATIONS}
    if len(known) != len(MUTATIONS):
        sys.exit("two mutations share an id")
    if unknown := [id for id in arguments.only if id not in known]:
        sys.exit(f"no such mutation: {', '.join(unknown)}")
    selected = [mutation for mutation in MUTATIONS if not arguments.only or mutation.id in arguments.only]
    if arguments.shard:
        first, every = arguments.shard
        selected = selected[first::every]

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

    if DATABASE_VARIABLE not in os.environ:
        print(f"warning: {DATABASE_VARIABLE} is not set, so the Postgres tests skip and the mutations "
              "only they catch are left to the whole-workspace run, where they survive", flush=True)
    scratch = Path(tempfile.mkdtemp(prefix="mutation-check-"))
    workspace, target = scratch / "workspace", scratch / "target"
    copy_workspace(workspace)
    print(f"workspace copy: {workspace}", flush=True)
    try:
        packages = read_packages(workspace)
        started = time.monotonic()
        code, output = run_tests(workspace, target)
        if code != 0:
            print(output[-4000:])
            print("the unmutated workspace does not pass its tests; nothing to measure against")
            return 2
        part = f"shard {arguments.shard[0]}/{arguments.shard[1]}: " if arguments.shard else ""
        print(f"baseline passes ({time.monotonic() - started:.0f}s); {part}{len(selected)} mutations to run", flush=True)

        pristine = {path: (workspace / path).read_text() for path in {edit.path for m in selected for edit in m.edits} | {REGRESSIONS}
                    if (workspace / path).exists()}
        counts = {"CAUGHT": 0, "SURVIVED": 0, "ERROR": 0, "NO-VERDICT": 0}
        def restore() -> None:
            # Written afresh, so every restored file is newer than the mutant's build and cargo
            # cannot reuse it; the regression file is restored so that one mutation's saved
            # cases do not change the next one's run.
            for path, text in pristine.items():
                (workspace / path).write_text(text)
            shutil.rmtree(workspace / CRATE / "wip", ignore_errors=True)

        # Each set of packages a mutation runs is first run once unmutated, when it is first
        # needed. The baseline only shows that the whole workspace passes; tests run for a few
        # packages build their dependencies with fewer features, and must pass that way too
        # before a failure there is blamed on a mutation. A set that fails is not used.
        checked: dict[frozenset[str], bool] = {}

        def usable(chosen: frozenset[str], applied: dict[str, str] | None) -> bool:
            if chosen not in checked:
                if applied:
                    restore()
                began = time.monotonic()
                code, output = run_tests(workspace, target, chosen, fail_fast=True)
                checked[chosen] = code == 0
                if not checked[chosen]:
                    print(output[-4000:])
                result = "passes" if checked[chosen] else "FAILS unmutated, so it runs the whole workspace instead"
                print(f"baseline for [{short(chosen)}] {result} ({time.monotonic() - began:.0f}s)", flush=True)
                if applied:
                    for path, text in applied.items():
                        (workspace / path).write_text(text)
            return checked[chosen]

        started = time.monotonic()
        for mutation in selected:
            applied = apply(mutation, lambda path: pristine[path])
            if isinstance(applied, str):
                began = time.monotonic()
                status, detail, ran = "ERROR", applied, "nothing"
            else:
                planned = steps(mutation, packages, arguments.all_catchers)
                if planned[0] is not None:
                    usable(planned[0], None)
                began = time.monotonic()
                try:
                    for path, text in applied.items():
                        (workspace / path).write_text(text)
                    status, detail, ran = judge(mutation, workspace, target, planned,
                                                lambda chosen: usable(chosen, applied), arguments.all_catchers)
                finally:
                    restore()
            counts[status] += 1
            print(f"{status:<10} {mutation.id:<48} {time.monotonic() - began:>5.0f}s  [{ran}]  {detail}", flush=True)

        print(
            f"{len(selected)} mutations: {counts['CAUGHT']} caught, {counts['SURVIVED']} survived, "
            f"{counts['ERROR']} errors, {counts['NO-VERDICT']} without a verdict "
            f"({time.monotonic() - started:.0f}s)"
        )
        return 0 if counts["CAUGHT"] == len(selected) else 1
    finally:
        if arguments.keep:
            print(f"kept {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
