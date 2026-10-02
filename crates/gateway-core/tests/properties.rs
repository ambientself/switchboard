//! Rules that must hold for every input, not just the ones in the decision table.
//!
//! Worlds are drawn from a small universe of issuers, subjects, teams, groups, tools and
//! surfaces, so that collisions (same subject, different issuer; a tool on one surface and not
//! another) are common rather than astronomically rare. Arbitrary worlds mostly fail some check
//! early, which would let a property about a late check pass without testing it, so each
//! property also runs on worlds that [`open_up`] has opened at every check but the one under
//! test. [`an_opened_world_is_allowed`] shows that opening really opens, and
//! [`arbitrary_worlds_reach_every_outcome`] shows the generator is not degenerate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use gateway_core::{
    ApprovedTool, CallContext, CallerContext, Classification, Decision, Delegation, GroupId,
    Issuer, PolicySnapshot, Principal, PrincipalId, PrincipalKind, Profile, ReasonKind, Resource,
    ResourceLimits, Resources, SnapshotData, Subject, Surface, SurfaceName, TeamId, ToolName,
    Verdict, decide, list_tools,
};
use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

const ISSUERS: [&str; 2] = [
    "https://cluster-a.example.test",
    "https://cluster-b.example.test",
];
const SUBJECTS: [&str; 2] = ["subject-1", "subject-2"];
const TEAMS: [&str; 2] = ["team-1", "team-2"];
const GROUPS: [&str; 2] = ["group-1", "group-2"];
const TOOLS: [&str; 3] = ["sys__one", "sys__two", "sys__three"];
const UNAPPROVED_TOOL: &str = "sys__unapproved";
const SURFACES: [&str; 2] = ["surface-a", "surface-b"];
const MISSING_SURFACE: &str = "surface-missing";

#[derive(Clone, Debug)]
struct World {
    data: SnapshotData,
    principal: Principal,
    delegation: Option<Delegation>,
    profile: Profile,
    surface: SurfaceName,
    tool: ToolName,
    resources: Resources,
}

impl World {
    fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot::new(self.data.clone()).expect("a generated snapshot is invalid")
    }

    fn caller(&self) -> CallerContext {
        CallerContext {
            principal: common::proved(&self.principal),
            delegation: self.delegation.as_ref().map(common::proved),
            profile: self.profile.clone(),
            surface: self.surface.clone(),
            deployment: "test".into(),
        }
    }

    fn call(&self) -> CallContext {
        CallContext {
            caller: self.caller(),
            tool: self.tool.clone(),
            resources: self.resources.clone(),
        }
    }

    fn decide(&self) -> Decision {
        decide(&self.snapshot(), &self.call())
    }

    fn approved_tool_mut(&mut self) -> Option<&mut ApprovedTool> {
        let name = self.tool.clone();
        self.data.tools.iter_mut().find(|tool| tool.name == name)
    }

    fn surface_mut(&mut self) -> Option<&mut Surface> {
        let name = self.surface.clone();
        self.data
            .surfaces
            .iter_mut()
            .find(|surface| surface.name == name)
    }
}

/// Opens every check for the world's call, so that only a property's own change can deny it.
fn open_up(world: &mut World) {
    if world.surface.as_str() == MISSING_SURFACE {
        world.surface = SURFACES[0].into();
    }
    if world.tool.as_str() == UNAPPROVED_TOOL {
        world.tool = TOOLS[0].into();
    }
    if let PrincipalKind::User { groups } = &mut world.principal.kind {
        groups.insert(GROUPS[0].into());
    }

    // Check 1: the surface admits the principal.
    let principal = world.principal.clone();
    let tool = world.tool.clone();
    if let Some(surface) = world.surface_mut() {
        match &principal.kind {
            PrincipalKind::Workload { team } => {
                surface.teams.insert(team.clone());
            }
            PrincipalKind::User { groups } => surface.groups.extend(groups.iter().cloned()),
        }
        surface.subjects = None;
        // Check 2: the surface serves the tool.
        surface.tools.insert(tool.clone());
    }

    // Checks 3 and 4: any delegation agrees and lists the tool; one is present if required.
    match &principal.kind {
        PrincipalKind::Workload { team } => {
            if world.profile.requires_delegation && world.delegation.is_none() {
                world.delegation = Some(Delegation {
                    acting_person: gateway_core::Claimed::new("requester@example.test".into()),
                    team: team.clone(),
                    tools: None,
                });
            }
            if let Some(delegation) = &mut world.delegation {
                delegation.team = team.clone();
                if let Some(tools) = &mut delegation.tools {
                    tools.insert(tool.clone());
                }
            }
        }
        PrincipalKind::User { .. } => {
            world.delegation = None;
            world.profile.requires_delegation = false;
        }
    }

    // Check 5: the profile permits every classification, destructive included, so that only
    // the destructive rule itself can deny.
    world.profile.classifications = Classification::ALL.into_iter().collect();

    // Check 6: every named resource is within the limit, and unknown resources are allowed.
    if let Resources::Named(named) = &world.resources {
        let named: BTreeSet<Resource> = named.iter().cloned().collect();
        match &principal.kind {
            PrincipalKind::Workload { team } => {
                world
                    .data
                    .limits
                    .teams
                    .entry(team.clone())
                    .or_default()
                    .extend(named);
            }
            PrincipalKind::User { groups } => {
                for group in groups {
                    let limit = world.data.limits.groups.entry(group.clone()).or_default();
                    limit.extend(named.iter().cloned());
                }
            }
        }
    }
    if let Some(approved) = world.approved_tool_mut() {
        approved.checks_own_scope = true;
    }
}

fn subset<T: Clone + std::fmt::Debug + 'static>(items: Vec<T>) -> impl Strategy<Value = Vec<T>> {
    let size = items.len();
    subsequence(items, 0..=size)
}

fn resource_pool() -> Vec<Resource> {
    [
        ("github", "repository", "org/one"),
        ("github", "repository", "org/two"),
        ("jira", "project", "ONE"),
    ]
    .into_iter()
    .map(|(system, kind, identifier)| Resource {
        system: system.into(),
        kind: kind.into(),
        identifier: identifier.into(),
    })
    .collect()
}

fn principal_ids() -> Vec<PrincipalId> {
    ISSUERS
        .into_iter()
        .flat_map(|issuer| {
            SUBJECTS.into_iter().map(move |subject| PrincipalId {
                issuer: issuer.into(),
                subject: subject.into(),
            })
        })
        .collect()
}

fn names<T: From<&'static str> + Ord>(items: Vec<&'static str>) -> BTreeSet<T> {
    items.into_iter().map(T::from).collect()
}

fn any_principal() -> impl Strategy<Value = Principal> {
    let kind = prop_oneof![
        select(TEAMS.to_vec()).prop_map(|team| PrincipalKind::Workload { team: team.into() }),
        subset(GROUPS.to_vec()).prop_map(|groups| PrincipalKind::User {
            groups: names(groups)
        }),
    ];
    (select(principal_ids()), kind).prop_map(|(id, kind)| Principal { id, kind })
}

fn any_tool(name: &'static str) -> impl Strategy<Value = ApprovedTool> {
    (
        select(Classification::ALL.to_vec()),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            move |(classification, declares_resources, checks_own_scope)| ApprovedTool {
                name: name.into(),
                classification,
                connector: "sys".into(),
                declares_resources,
                checks_own_scope,
            },
        )
}

fn any_surface(name: &'static str) -> impl Strategy<Value = Surface> {
    (
        subset(TOOLS.to_vec()),
        subset(TEAMS.to_vec()),
        subset(GROUPS.to_vec()),
        proptest::option::of(subset(principal_ids())),
    )
        .prop_map(move |(tools, teams, groups, subjects)| Surface {
            name: name.into(),
            tools: names(tools),
            teams: names(teams),
            groups: names(groups),
            subjects: subjects.map(|subjects| subjects.into_iter().collect()),
        })
}

fn any_limits() -> impl Strategy<Value = ResourceLimits> {
    let per = |keys: [&'static str; 2]| {
        (subset(resource_pool()), subset(resource_pool())).prop_map(move |(first, second)| {
            [first, second]
                .into_iter()
                .zip(keys)
                .map(|(resources, key)| (key, resources.into_iter().collect()))
                .collect::<Vec<(&'static str, BTreeSet<Resource>)>>()
        })
    };
    (per(TEAMS), per(GROUPS)).prop_map(|(teams, groups)| ResourceLimits {
        teams: teams
            .into_iter()
            .map(|(team, resources)| (TeamId::from(team), resources))
            .collect::<BTreeMap<_, _>>(),
        groups: groups
            .into_iter()
            .map(|(group, resources)| (GroupId::from(group), resources))
            .collect::<BTreeMap<_, _>>(),
    })
}

fn any_delegation() -> impl Strategy<Value = Option<Delegation>> {
    let mut listable = TOOLS.to_vec();
    listable.push(UNAPPROVED_TOOL);
    proptest::option::of(
        (
            select(TEAMS.to_vec()),
            proptest::option::of(subset(listable)),
        )
            .prop_map(|(team, tools)| Delegation {
                acting_person: gateway_core::Claimed::new("requester@example.test".into()),
                team: team.into(),
                tools: tools.map(names),
            }),
    )
}

fn any_world() -> impl Strategy<Value = World> {
    let mut callable = TOOLS.to_vec();
    callable.push(UNAPPROVED_TOOL);
    let mut reachable = SURFACES.to_vec();
    reachable.push(MISSING_SURFACE);
    let data = (
        any_tool(TOOLS[0]),
        any_tool(TOOLS[1]),
        any_tool(TOOLS[2]),
        any_surface(SURFACES[0]),
        any_surface(SURFACES[1]),
        any_limits(),
    );
    let profile = (subset(Classification::ALL.to_vec()), any::<bool>()).prop_map(
        |(classifications, requires_delegation)| Profile {
            name: "profile".into(),
            classifications: classifications.into_iter().collect(),
            requires_delegation,
        },
    );
    let resources = prop_oneof![
        3 => subset(resource_pool()).prop_map(Resources::Named),
        1 => Just(Resources::Unknown),
    ];
    let call = (
        any_principal(),
        any_delegation(),
        profile,
        select(reachable),
        select(callable),
        resources,
    );
    (data, call).prop_map(
        |(
            (one, two, three, a, b, limits),
            (principal, delegation, profile, surface, tool, resources),
        )| {
            World {
                data: SnapshotData {
                    revision: "generated".into(),
                    tools: vec![one, two, three],
                    surfaces: vec![a, b],
                    profiles: vec![profile.clone()],
                    limits,
                },
                principal,
                delegation,
                profile,
                surface: surface.into(),
                tool: tool.into(),
                resources,
            }
        },
    )
}

/// An arbitrary world, or one opened at every check: half of each.
fn world() -> impl Strategy<Value = World> {
    (any_world(), any::<bool>()).prop_map(|(mut world, open)| {
        if open {
            open_up(&mut world);
        }
        world
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    #[test]
    fn a_tool_not_approved_on_the_surface_is_never_allowed(mut world in world()) {
        let tool = world.tool.clone();
        if let Some(surface) = world.surface_mut() {
            surface.tools.remove(&tool);
        }
        let decision = world.decide();
        prop_assert!(!decision.is_allowed(), "allowed a tool the surface does not serve: {decision:?}");
        prop_assert!(!list_tools(&world.snapshot(), &world.caller()).iter().any(|listed| listed.name == tool));
    }

    #[test]
    fn a_destructive_tool_is_never_allowed(mut world in world()) {
        if let Some(approved) = world.approved_tool_mut() {
            approved.classification = Classification::Destructive;
        }
        let decision = world.decide();
        prop_assert!(!decision.is_allowed(), "allowed a destructive tool: {decision:?}");
        let snapshot = world.snapshot();
        prop_assert!(list_tools(&snapshot, &world.caller())
            .iter()
            .all(|listed| listed.classification != Classification::Destructive));
    }

    #[test]
    fn a_delegation_that_lists_tools_never_allows_one_it_does_not_list(mut world in world()) {
        let tool = world.tool.clone();
        if let Some(delegation) = &mut world.delegation {
            let mut listed = delegation.tools.take().unwrap_or_default();
            listed.remove(&tool);
            delegation.tools = Some(listed);
        }
        let decision = world.decide();
        if world.delegation.is_some() {
            prop_assert!(!decision.is_allowed(), "allowed a tool the delegation does not list: {decision:?}");
        }
    }

    #[test]
    fn principals_from_different_issuers_never_compare_equal(
        first in "[a-z:/.-]{1,24}",
        second in "[a-z:/.-]{1,24}",
        subject in "[a-z:@.-]{1,24}",
        kind in prop_oneof![
            select(TEAMS.to_vec()).prop_map(|team| PrincipalKind::Workload { team: team.into() }),
            subset(GROUPS.to_vec()).prop_map(|groups| PrincipalKind::User { groups: names(groups) }),
        ],
    ) {
        prop_assume!(first != second);
        let id = |issuer: &str| PrincipalId { issuer: Issuer::new(issuer), subject: Subject::new(subject.as_str()) };
        let (a, b) = (id(&first), id(&second));
        prop_assert_ne!(&a, &b);
        prop_assert_eq!(HashSet::from([a.clone(), b.clone()]).len(), 2);
        prop_assert_eq!(BTreeSet::from([a.clone(), b.clone()]).len(), 2);
        let principal = |id: PrincipalId| Principal { id, kind: kind.clone() };
        prop_assert_ne!(principal(a), principal(b));
    }

    #[test]
    fn decide_is_deterministic(world in world()) {
        let snapshot = world.snapshot();
        let call = world.call();
        let first = decide(&snapshot, &call);
        let again = decide(&snapshot, &call);
        let rebuilt = decide(&world.snapshot(), &world.call());
        prop_assert_eq!(&first, &again);
        prop_assert_eq!(&first, &rebuilt);
        prop_assert_eq!(
            first.reason().map(|reason| reason.sentence()),
            rebuilt.reason().map(|reason| reason.sentence())
        );
    }

    #[test]
    fn tools_list_is_decide_run_once_per_tool(world in world()) {
        let snapshot = world.snapshot();
        let caller = world.caller();
        let listed: BTreeSet<ToolName> = list_tools(&snapshot, &caller).iter().map(|tool| tool.name.clone()).collect();
        let served: BTreeSet<ToolName> = snapshot.surface(&world.surface).map(|surface| surface.tools.clone()).unwrap_or_default();
        prop_assert!(listed.is_subset(&served));
        for tool in served {
            let call = CallContext { caller: caller.clone(), tool: tool.clone(), resources: Resources::Named(Vec::new()) };
            prop_assert_eq!(decide(&snapshot, &call).is_allowed(), listed.contains(&tool), "tool {}", tool);
        }
    }

    #[test]
    fn an_opened_world_is_allowed(mut world in any_world(), classification in select(vec![Classification::Read, Classification::Write])) {
        open_up(&mut world);
        if let Some(approved) = world.approved_tool_mut() {
            approved.classification = classification;
        }
        let decision = world.decide();
        prop_assert!(decision.is_allowed(), "open_up left a check closed: {decision:?}");
    }
}

/// Arbitrary worlds, without opening, reach an allow and every kind of reason. Without this,
/// a generator that failed every call at check 1 would make every property above vacuous.
#[test]
fn arbitrary_worlds_reach_every_outcome() {
    let mut runner = TestRunner::deterministic();
    let strategy = any_world();
    let mut allowed = 0;
    let mut reasons = BTreeSet::new();
    for _ in 0..20_000 {
        let world = strategy
            .new_tree(&mut runner)
            .expect("generate a world")
            .current();
        match world.decide().verdict() {
            Verdict::Allow(_) => allowed += 1,
            Verdict::Deny { reason, .. } => {
                reasons.insert(reason.kind());
            }
        }
    }
    assert!(allowed > 0, "no arbitrary world was allowed");
    let missing: Vec<ReasonKind> = ReasonKind::ALL
        .into_iter()
        .filter(|kind| !reasons.contains(kind))
        .collect();
    assert!(
        missing.is_empty(),
        "no arbitrary world was denied for {missing:?}"
    );
}
