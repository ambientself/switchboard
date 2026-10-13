//! The interface that reads a call's arguments for the resources it names, and the one adapter
//! that reads none: the reach.

use gateway_core::{ApprovedTool, PolicySnapshot, Resources};

/// Reads a call's arguments and names the resources the call reaches, for the decision's
/// resource check (decision 0006, check 6).
///
/// The core never reads a tool's arguments, so each connector comes with an adapter that does.
/// One is registered beside each connector in the wiring, so a connector cannot be configured
/// without one. It is chosen by the connector of the approved tool the call names, never by
/// anything else in the request. A tool declared as its connector entry's reach is the
/// exception: the gateway's one constant reach adapter names its resources, whatever its
/// connector.
///
/// An adapter must not guess. For a tool that declares its resources, arguments it cannot read
/// are [`Resources::Unknown`] or an empty list, both of which the decision denies; a guess
/// could name a resource the call does not reach and let it through.
pub trait ResourceAdapter: Send + Sync {
    /// The resources a call to `tool` with `arguments` names.
    fn resources(&self, tool: &ApprovedTool, arguments: &serde_json::Value) -> Resources;
}

/// The one constant adapter that serves every tool declared as its connector entry's reach
/// (decision 0011, section 1). Every call names the entry's whole recorded reach, whatever its
/// arguments, as [`Resources::Reach`], which carries the entry's name so the row records the
/// entry rather than the list.
///
/// It reads the reach from the snapshot it is given, which is the one the call's decision is
/// made from: the policy version the request took. So the reach the decision checks and the
/// policy revision on the row are always the same version's. A tool whose connector has no
/// entry in that snapshot names nothing, which the decision denies; the snapshot refuses such
/// a tool when it loads.
pub(crate) struct ReachAdapter<'a> {
    snapshot: &'a PolicySnapshot,
}

impl<'a> ReachAdapter<'a> {
    /// The adapter for calls decided from `snapshot`.
    pub(crate) fn new(snapshot: &'a PolicySnapshot) -> Self {
        Self { snapshot }
    }
}

impl ResourceAdapter for ReachAdapter<'_> {
    fn resources(&self, tool: &ApprovedTool, _arguments: &serde_json::Value) -> Resources {
        match self.snapshot.entry(&tool.connector) {
            Some(entry) => Resources::Reach {
                entry: entry.name.clone(),
                resources: entry.reach.iter().cloned().collect(),
            },
            None => Resources::Named(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use gateway_core::{
        Classification, ConnectorEntry, CredentialMode, DeclaredFrom, EntryKind, Narrowing,
        PrincipalRestriction, Resource, ResourceDeclaration, SnapshotData, Surface, ToolName,
    };
    use serde_json::json;

    use super::*;

    fn atlas() -> Resource {
        Resource {
            system: "docs".into(),
            kind: "project".into(),
            identifier: "atlas".into(),
        }
    }

    fn snapshot() -> PolicySnapshot {
        let name = ToolName::parse("docs__search").unwrap();
        PolicySnapshot::new(SnapshotData {
            revision: "reach-1".into(),
            tools: vec![ApprovedTool {
                name: name.clone(),
                classification: Classification::Read,
                connector: "docs-team-a".into(),
                resources: ResourceDeclaration::Declared,
                declared_from: Some(DeclaredFrom::Reach),
            }],
            surfaces: vec![Surface {
                name: "docs-team-a".into(),
                tools: [name].into(),
                teams: ["team-a".into()].into(),
                groups: BTreeSet::new(),
                principals: PrincipalRestriction::AnyInTeamsAndGroups,
            }],
            profiles: Vec::new(),
            limits: gateway_core::ResourceLimits {
                teams: [("team-a".into(), [atlas()].into())].into(),
                groups: Default::default(),
            },
            entries: vec![ConnectorEntry {
                name: "docs-team-a".into(),
                kind: EntryKind::Proxied,
                credential: CredentialMode::TeamServiceIdentity,
                principal: "docs-team-a".into(),
                narrowing: Narrowing::None,
                permits: Classification::Read,
                reach: [atlas()].into(),
                reach_tested_on: Some("2026-10-12".into()),
            }],
        })
        .unwrap()
    }

    #[test]
    fn the_reach_is_the_entrys_whatever_the_arguments() {
        let snapshot = snapshot();
        let tool = snapshot
            .tool(&ToolName::parse("docs__search").unwrap())
            .unwrap();
        let reach = Resources::Reach {
            entry: "docs-team-a".into(),
            resources: vec![atlas()],
        };
        for arguments in [
            json!({}),
            json!({"project": "borealis"}),
            json!("not an object"),
        ] {
            assert_eq!(
                ReachAdapter::new(&snapshot).resources(tool, &arguments),
                reach,
                "{arguments}"
            );
        }
        // A connector with no entry has no reach to name.
        let orphan = ApprovedTool {
            connector: "elsewhere".into(),
            ..tool.clone()
        };
        assert_eq!(
            ReachAdapter::new(&snapshot).resources(&orphan, &json!({})),
            Resources::Named(Vec::new())
        );
    }
}
