//! The policy the gateway serves: the snapshot decisions are made from, the definitions
//! `tools/list` answers with, how a caller's profile is selected, and how a tool's arguments
//! are read. Held in a [`LivePolicy`], which the registry reloader can replace while the
//! gateway runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use gateway_core::{PolicyRevision, PolicySnapshot, Principal, ProfileName, ToolName};
use gateway_registry::{ArgumentAdapter, NoProfile, ProfileRules, Registry, RulePrincipal};

use crate::catalog::{CatalogError, ToolCatalog, ToolDefinition};
use crate::grants::WorkloadSelection;
use crate::selector::{NO_PROFILE, ProfileSelector};

/// One version of the policy: everything a request reads from it, taken together, so one
/// request never mixes two versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedPolicy {
    snapshot: Arc<PolicySnapshot>,
    catalog: ToolCatalog,
    selection: Selection,
    arguments: BTreeMap<ToolName, ArgumentAdapter>,
}

/// Where profile rules come from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    /// The rules in the JSON configuration: issuer and team, issuer and group.
    Rules(ProfileSelector),
    /// The registry file's rules: issuer and kind of principal.
    Registry(ProfileRules),
}

impl ServedPolicy {
    /// A policy from the JSON configuration's parts. Its tools have no argument adapters: the
    /// resource adapter registered with each connector reads the arguments.
    pub(crate) fn from_config(
        snapshot: PolicySnapshot,
        catalog: ToolCatalog,
        selector: ProfileSelector,
    ) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            catalog,
            selection: Selection::Rules(selector),
            arguments: BTreeMap::new(),
        }
    }

    /// A policy from a loaded registry: its snapshot, its approved definitions, its profile
    /// rules and each tool's argument adapter.
    pub(crate) fn from_registry(registry: &Registry) -> Result<Self, CatalogError> {
        let definitions = registry
            .definitions()
            .values()
            .map(|definition| ToolDefinition {
                name: definition.name.clone(),
                title: definition.title.clone(),
                description: definition.description.clone(),
                input_schema: definition.input_schema.clone(),
            })
            .collect();
        // The registry builds its snapshot's approved tools and its definitions from the same
        // entries, so every approved tool has exactly one definition already.
        let catalog = ToolCatalog::new(definitions)?;
        Ok(Self {
            snapshot: Arc::new(registry.snapshot().clone()),
            catalog,
            selection: Selection::Registry(registry.profile_rules().clone()),
            arguments: registry.adapters().clone(),
        })
    }

    /// This policy with `withdrawn` removed, under `revision`: from the snapshot's approved
    /// tools and every surface ([`PolicySnapshot::without`]), from the definitions `tools/list`
    /// answers with, and from the argument adapters, so a call decided before the withdrawal
    /// is not sent. Everything else is unchanged, and the loader's rules are not run again: a
    /// removal only narrows (decision 0013, section 6).
    pub(crate) fn without(&self, withdrawn: &BTreeSet<ToolName>, revision: PolicyRevision) -> Self {
        let mut arguments = self.arguments.clone();
        arguments.retain(|tool, _| !withdrawn.contains(tool));
        Self {
            snapshot: Arc::new(self.snapshot.without(withdrawn, revision)),
            catalog: self.catalog.without(withdrawn),
            selection: self.selection.clone(),
            arguments,
        }
    }

    /// The snapshot decisions are made from.
    pub fn snapshot(&self) -> &Arc<PolicySnapshot> {
        &self.snapshot
    }

    /// The snapshot's revision.
    pub fn revision(&self) -> &PolicyRevision {
        self.snapshot.revision()
    }

    /// Every approved tool's definition.
    pub fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    /// The profile `principal`'s calls are decided under, or [`NO_PROFILE`], which the
    /// decision denies. Never a default: a caller no rule covers, or whose rules disagree,
    /// gets no profile.
    pub fn select(&self, principal: &Principal) -> ProfileName {
        match &self.selection {
            Selection::Rules(selector) => selector.select(principal),
            Selection::Registry(rules) => match rules.select(principal) {
                Ok(profile) => profile,
                Err(why) => {
                    match why {
                        NoProfile::NoRule => tracing::debug!(
                            issuer = %principal.id.issuer,
                            "no profile rule covers this caller"
                        ),
                        NoProfile::Ambiguous(profiles) => tracing::warn!(
                            issuer = %principal.id.issuer,
                            ?profiles,
                            "the profile rules covering this caller disagree, so none is selected"
                        ),
                    }
                    ProfileName::new(NO_PROFILE)
                }
            },
        }
    }

    /// Every profile a selection rule names.
    pub(crate) fn selected_profiles(&self) -> Vec<ProfileName> {
        match &self.selection {
            Selection::Rules(selector) => selector.profiles().into_iter().cloned().collect(),
            Selection::Registry(rules) => rules
                .rules()
                .iter()
                .map(|rule| rule.profile.clone())
                .collect(),
        }
    }

    /// Each rule that gives workloads a profile, with the teams it covers: one team for a rule
    /// of the JSON configuration, and every team its issuer vouches for, `None` here, for a
    /// registry's rule for workloads.
    pub(crate) fn workload_selections(&self) -> Vec<WorkloadSelection> {
        match &self.selection {
            Selection::Rules(selector) => selector
                .workload_rules()
                .map(|(issuer, team, profile)| WorkloadSelection {
                    issuer: issuer.clone(),
                    teams: Some(BTreeSet::from([team.clone()])),
                    profile: profile.clone(),
                })
                .collect(),
            Selection::Registry(rules) => rules
                .rules()
                .iter()
                .filter(|rule| rule.principal == RulePrincipal::Workload)
                .map(|rule| WorkloadSelection {
                    issuer: rule.issuer.clone(),
                    teams: None,
                    profile: rule.profile.clone(),
                })
                .collect(),
        }
    }

    /// The adapter that reads `tool`'s arguments, for a policy loaded from a registry.
    pub fn arguments(&self, tool: &ToolName) -> Option<&ArgumentAdapter> {
        self.arguments.get(tool)
    }
}

/// The policy currently served. Cheap to read: a request takes the current version once, as
/// an `Arc`, and keeps it for the whole request.
pub struct LivePolicy {
    current: RwLock<Arc<ServedPolicy>>,
}

impl fmt::Debug for LivePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LivePolicy")
            .field("revision", self.current().revision())
            .finish()
    }
}

impl LivePolicy {
    pub(crate) fn new(policy: ServedPolicy) -> Self {
        Self {
            current: RwLock::new(Arc::new(policy)),
        }
    }

    /// The version served now.
    pub fn current(&self) -> Arc<ServedPolicy> {
        // A writer only swaps an `Arc`, so a poisoned lock still holds a whole policy.
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Serves `policy` from now on. Requests already running keep the version they took.
    pub(crate) fn replace(&self, policy: ServedPolicy) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(policy);
    }
}
