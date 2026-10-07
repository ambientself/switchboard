//! Profile selection: which profile a proved principal's calls are decided under, from the
//! issuer and the kind of principal (design.md section 6, step 3).

use std::collections::BTreeSet;
use std::fmt;

use gateway_core::{GroupId, Issuer, Principal, PrincipalKind, ProfileName};
use thiserror::Error;

/// Which principals of an issuer a rule covers.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RulePrincipal {
    /// Every workload the issuer vouches for. Which team it belongs to is the team manifest's
    /// business; limits and surfaces tell teams apart.
    Workload,
    /// Every user the issuer says is in this group.
    UserInGroup(GroupId),
}

impl fmt::Display for RulePrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulePrincipal::Workload => f.write_str("workloads"),
            RulePrincipal::UserInGroup(group) => write!(f, "users in group `{group}`"),
        }
    }
}

/// One rule: principals of this kind from this issuer are decided under this profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRule {
    /// The issuer the principal was proved by, matched exactly.
    pub issuer: Issuer,
    /// Which of the issuer's principals the rule covers.
    pub principal: RulePrincipal,
    /// The profile they get.
    pub profile: ProfileName,
}

impl ProfileRule {
    fn covers(&self, principal: &Principal) -> bool {
        principal.id.issuer == self.issuer
            && match (&self.principal, &principal.kind) {
                (RulePrincipal::Workload, PrincipalKind::Workload { .. }) => true,
                (RulePrincipal::UserInGroup(group), PrincipalKind::User { groups }) => {
                    groups.contains(group)
                }
                _ => false,
            }
    }
}

/// The profile-selection rules, checked at load: no two rules cover the same issuer and kind
/// or group, and every rule names a profile the snapshot holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRules {
    rules: Vec<ProfileRule>,
}

/// Why no profile was selected. The gateway must refuse the call; it must not fall back to a
/// default profile.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NoProfile {
    /// No rule covers this principal.
    #[error("no profile rule covers this principal")]
    NoRule,
    /// Rules covering this principal name different profiles: a user in two groups whose rules
    /// disagree. Which one applies is not guessed, and the order of the file does not decide
    /// it.
    #[error("profile rules covering this principal disagree: {0:?}")]
    Ambiguous(BTreeSet<ProfileName>),
}

impl ProfileRules {
    pub(crate) fn new(rules: Vec<ProfileRule>) -> Self {
        Self { rules }
    }

    /// Every rule, in file order.
    pub fn rules(&self) -> &[ProfileRule] {
        &self.rules
    }

    /// The profile for `principal`: the one profile every rule that covers it names.
    ///
    /// Every rule is considered, not the first that matches, and a user's every group is
    /// considered, not only the first.
    pub fn select(&self, principal: &Principal) -> Result<ProfileName, NoProfile> {
        let profiles: BTreeSet<ProfileName> = self
            .rules
            .iter()
            .filter(|rule| rule.covers(principal))
            .map(|rule| rule.profile.clone())
            .collect();
        let mut names = profiles.iter();
        match (names.next(), names.next()) {
            (Some(only), None) => Ok(only.clone()),
            (None, _) => Err(NoProfile::NoRule),
            (Some(_), Some(_)) => Err(NoProfile::Ambiguous(profiles)),
        }
    }
}
