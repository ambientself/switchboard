//! Choosing a caller's profile from configured rules.

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::{GroupId, Issuer, Principal, PrincipalKind, ProfileName, TeamId};
use serde::Deserialize;
use thiserror::Error;

/// The profile name given to a caller no rule selects exactly one profile for.
///
/// The decision function denies it at check 0, because the boot gates refuse a snapshot that
/// holds a profile with this name. The denial is recorded like any other, with this name in
/// the row's profile column.
pub const NO_PROFILE: &str = "no-profile-selected";

/// The rules that select a profile, as configuration states them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorRules {
    /// Rules for workloads, keyed by issuer and team.
    #[serde(default)]
    pub workloads: Vec<WorkloadRule>,
    /// Rules for users, keyed by issuer and group.
    #[serde(default)]
    pub users: Vec<UserRule>,
}

/// A workload whose token `issuer` signed, of `team`, gets `profile`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRule {
    /// The workload issuer.
    pub issuer: Issuer,
    /// The team the issuer's subject table maps the workload to.
    pub team: TeamId,
    /// The profile it gets.
    pub profile: ProfileName,
}

/// A user whose token `issuer` signed, in `group`, gets `profile`, unless their other groups
/// select a different one.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserRule {
    /// The user issuer.
    pub issuer: Issuer,
    /// The group.
    pub group: GroupId,
    /// The profile it gets.
    pub profile: ProfileName,
}

/// Why the selector's rules were refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SelectorError {
    /// Two rules for the same workload issuer and team. Even if they agree, one would be
    /// edited and the other forgotten.
    #[error("two profile rules for workloads of team `{team}` from issuer `{issuer}`")]
    DuplicateWorkloadRule {
        /// The issuer.
        issuer: Issuer,
        /// The team.
        team: TeamId,
    },
    /// Two rules for the same user issuer and group.
    #[error("two profile rules for users in group `{group}` from issuer `{issuer}`")]
    DuplicateUserRule {
        /// The issuer.
        issuer: Issuer,
        /// The group.
        group: GroupId,
    },
}

/// Selects a proved caller's profile from its issuer and its team or groups (design section 6,
/// step 3).
///
/// - A workload gets the profile of the rule for its issuer and team.
/// - A user gets a profile only if the rules for its issuer and **all** its groups select
///   exactly one profile between them. A user whose groups select two different profiles is
///   ambiguous: no rule says which wins, so neither does. Several groups selecting the same
///   profile are not ambiguous.
/// - Anyone else gets [`NO_PROFILE`], which the decision function denies.
///
/// The issuer is part of every key, so a team or group of the same name from another issuer
/// selects nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSelector {
    workloads: BTreeMap<Issuer, BTreeMap<TeamId, ProfileName>>,
    users: BTreeMap<Issuer, BTreeMap<GroupId, ProfileName>>,
}

impl ProfileSelector {
    /// Builds the selector, refusing two rules for one key.
    pub fn new(rules: SelectorRules) -> Result<Self, SelectorError> {
        let mut workloads: BTreeMap<Issuer, BTreeMap<TeamId, ProfileName>> = BTreeMap::new();
        for rule in rules.workloads {
            let teams = workloads.entry(rule.issuer.clone()).or_default();
            if teams.insert(rule.team.clone(), rule.profile).is_some() {
                return Err(SelectorError::DuplicateWorkloadRule {
                    issuer: rule.issuer,
                    team: rule.team,
                });
            }
        }
        let mut users: BTreeMap<Issuer, BTreeMap<GroupId, ProfileName>> = BTreeMap::new();
        for rule in rules.users {
            let groups = users.entry(rule.issuer.clone()).or_default();
            if groups.insert(rule.group.clone(), rule.profile).is_some() {
                return Err(SelectorError::DuplicateUserRule {
                    issuer: rule.issuer,
                    group: rule.group,
                });
            }
        }
        Ok(Self { workloads, users })
    }

    /// The profile for `principal`, or [`NO_PROFILE`].
    pub fn select(&self, principal: &Principal) -> ProfileName {
        let issuer = &principal.id.issuer;
        let selected = match &principal.kind {
            PrincipalKind::Workload { team } => self
                .workloads
                .get(issuer)
                .and_then(|teams| teams.get(team))
                .cloned(),
            PrincipalKind::User { groups } => {
                let rules = self.users.get(issuer);
                let profiles: BTreeSet<&ProfileName> = groups
                    .iter()
                    .filter_map(|group| rules.and_then(|rules| rules.get(group)))
                    .collect();
                only(profiles).cloned()
            }
        };
        selected.unwrap_or_else(|| ProfileName::new(NO_PROFILE))
    }

    /// Every profile a rule names.
    pub fn profiles(&self) -> BTreeSet<&ProfileName> {
        let workloads = self.workloads.values().flat_map(BTreeMap::values);
        let users = self.users.values().flat_map(BTreeMap::values);
        workloads.chain(users).collect()
    }
}

/// The one profile in `profiles`, or `None` if there are none or several.
fn only(profiles: BTreeSet<&ProfileName>) -> Option<&ProfileName> {
    let mut profiles = profiles.into_iter();
    match (profiles.next(), profiles.next()) {
        (Some(profile), None) => Some(profile),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use gateway_core::PrincipalId;

    use super::*;

    const CLUSTER: &str = "https://cluster.example.test";
    const OTHER_CLUSTER: &str = "https://other-cluster.example.test";
    const IDP: &str = "https://idp.example.test";
    const OTHER_IDP: &str = "https://other-idp.example.test";

    fn workload_rule(issuer: &str, team: &str, profile: &str) -> WorkloadRule {
        WorkloadRule {
            issuer: issuer.into(),
            team: team.into(),
            profile: profile.into(),
        }
    }

    fn user_rule(issuer: &str, group: &str, profile: &str) -> UserRule {
        UserRule {
            issuer: issuer.into(),
            group: group.into(),
            profile: profile.into(),
        }
    }

    fn workload(issuer: &str, team: &str) -> Principal {
        Principal {
            id: PrincipalId {
                issuer: issuer.into(),
                subject: "system:serviceaccount:ns:sa".into(),
            },
            kind: PrincipalKind::Workload { team: team.into() },
        }
    }

    fn user(issuer: &str, groups: &[&str]) -> Principal {
        Principal {
            id: PrincipalId {
                issuer: issuer.into(),
                subject: "person@example.test".into(),
            },
            kind: PrincipalKind::User {
                groups: groups.iter().map(|&group| group.into()).collect(),
            },
        }
    }

    fn selector() -> ProfileSelector {
        ProfileSelector::new(SelectorRules {
            workloads: vec![
                workload_rule(CLUSTER, "payments", "workload-rw"),
                workload_rule(CLUSTER, "search", "workload-ro"),
            ],
            users: vec![
                user_rule(IDP, "engineers", "user-ro"),
                user_rule(IDP, "readers", "user-ro"),
                user_rule(IDP, "operators", "user-ops"),
            ],
        })
        .unwrap()
    }

    fn selects(principal: &Principal) -> String {
        selector().select(principal).as_str().to_owned()
    }

    #[test]
    fn a_workload_gets_the_profile_for_its_issuer_and_team() {
        assert_eq!(selects(&workload(CLUSTER, "payments")), "workload-rw");
        assert_eq!(selects(&workload(CLUSTER, "search")), "workload-ro");
        assert_eq!(selects(&workload(CLUSTER, "unlisted")), NO_PROFILE);
    }

    #[test]
    fn the_same_team_from_another_issuer_selects_nothing() {
        assert_eq!(selects(&workload(OTHER_CLUSTER, "payments")), NO_PROFILE);
        assert_eq!(selects(&workload(IDP, "payments")), NO_PROFILE);
    }

    #[test]
    fn the_same_group_from_another_issuer_selects_nothing() {
        assert_eq!(selects(&user(OTHER_IDP, &["engineers"])), NO_PROFILE);
        assert_eq!(selects(&user(CLUSTER, &["engineers"])), NO_PROFILE);
    }

    #[test]
    fn a_user_gets_the_profile_its_groups_select() {
        assert_eq!(selects(&user(IDP, &["engineers"])), "user-ro");
        assert_eq!(selects(&user(IDP, &["operators"])), "user-ops");
        assert_eq!(selects(&user(IDP, &[])), NO_PROFILE);
        assert_eq!(selects(&user(IDP, &["unlisted"])), NO_PROFILE);
    }

    #[test]
    fn a_user_is_selected_by_any_of_its_groups_not_only_the_first() {
        // Groups are held in order; `a-unlisted` comes before `engineers`, and the testkit's
        // stand-in selector looks only at the first.
        assert_eq!(selects(&user(IDP, &["a-unlisted", "engineers"])), "user-ro");
        assert_eq!(selects(&user(IDP, &["engineers", "z-unlisted"])), "user-ro");
    }

    #[test]
    fn groups_that_agree_on_a_profile_select_it() {
        assert_eq!(selects(&user(IDP, &["engineers", "readers"])), "user-ro");
    }

    #[test]
    fn a_user_whose_groups_select_two_profiles_gets_none() {
        assert_eq!(selects(&user(IDP, &["engineers", "operators"])), NO_PROFILE);
        assert_eq!(
            selects(&user(IDP, &["engineers", "operators", "readers"])),
            NO_PROFILE
        );
    }

    #[test]
    fn workload_rules_do_not_select_for_users_or_user_rules_for_workloads() {
        let selector = ProfileSelector::new(SelectorRules {
            workloads: vec![workload_rule(IDP, "shared", "workload-rw")],
            users: vec![user_rule(IDP, "shared", "user-ro")],
        })
        .unwrap();
        assert_eq!(selector.select(&user(IDP, &["shared"])).as_str(), "user-ro");
        assert_eq!(
            selector.select(&workload(IDP, "shared")).as_str(),
            "workload-rw"
        );
    }

    #[test]
    fn two_rules_for_one_workload_key_are_refused() {
        let refused = ProfileSelector::new(SelectorRules {
            workloads: vec![
                workload_rule(CLUSTER, "payments", "workload-rw"),
                workload_rule(OTHER_CLUSTER, "payments", "workload-rw"),
                workload_rule(CLUSTER, "payments", "workload-rw"),
            ],
            users: vec![],
        });
        assert_eq!(
            refused,
            Err(SelectorError::DuplicateWorkloadRule {
                issuer: CLUSTER.into(),
                team: "payments".into(),
            })
        );
    }

    #[test]
    fn two_rules_for_one_user_key_are_refused() {
        let refused = ProfileSelector::new(SelectorRules {
            workloads: vec![],
            users: vec![
                user_rule(IDP, "engineers", "user-ro"),
                user_rule(OTHER_IDP, "engineers", "user-ro"),
                user_rule(IDP, "engineers", "user-ops"),
            ],
        });
        assert_eq!(
            refused,
            Err(SelectorError::DuplicateUserRule {
                issuer: IDP.into(),
                group: "engineers".into(),
            })
        );
    }

    #[test]
    fn the_selector_lists_every_profile_its_rules_name() {
        let selector = selector();
        let profiles: Vec<&str> = selector
            .profiles()
            .into_iter()
            .map(ProfileName::as_str)
            .collect();
        assert_eq!(
            profiles,
            ["user-ops", "user-ro", "workload-ro", "workload-rw"]
        );
    }

    #[test]
    fn rules_are_read_from_configuration_and_unknown_fields_are_refused() {
        let rules: SelectorRules = serde_json::from_str(
            r#"{"workloads": [{"issuer": "i", "team": "t", "profile": "p"}],
                "users": [{"issuer": "u", "group": "g", "profile": "q"}]}"#,
        )
        .unwrap();
        assert_eq!(rules.workloads, [workload_rule("i", "t", "p")]);
        assert_eq!(rules.users, [user_rule("u", "g", "q")]);
        assert!(
            serde_json::from_str::<SelectorRules>(
                r#"{"workloads": [{"issuer": "i", "team": "t", "profile": "p", "group": "g"}]}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<SelectorRules>(r#"{"workload": []}"#).is_err());
    }
}
