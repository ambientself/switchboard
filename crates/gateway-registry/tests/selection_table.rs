//! Profile selection from the issuer and the kind of principal, as a table.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use common::{at, base, load, rehash, table_at, value};
use gateway_core::{Principal, PrincipalId, PrincipalKind, ProfileName};
use gateway_registry::{NoProfile, Registry};

const WORKLOADS: &str = "https://workloads.example.test";
const USERS: &str = "https://users.example.test";

/// The base rules (workloads of one issuer, group `group-g` of another) and three more for
/// the second issuer: `group-h` to a different profile, `group-k` to the same one as `group-g`.
fn registry() -> Registry {
    let mut table = base();
    let mut profile = table_at(&mut table, "profiles.1").clone();
    profile.insert("name".into(), value("\"user-other\""));
    at(&mut table, "profiles")
        .as_array_mut()
        .unwrap()
        .push(profile.into());
    for (group, profile) in [("group-h", "user-other"), ("group-k", "user-read")] {
        let mut rule = table_at(&mut table, "profile_rules.1").clone();
        rule.insert(
            "principal".into(),
            value(&format!("{{ user_in_group = \"{group}\" }}")),
        );
        rule.insert("profile".into(), value(&format!("\"{profile}\"")));
        at(&mut table, "profile_rules")
            .as_array_mut()
            .unwrap()
            .push(rule.into());
    }
    rehash(&mut table);
    load(&table).unwrap()
}

fn workload(issuer: &str) -> Principal {
    Principal {
        id: PrincipalId {
            issuer: issuer.into(),
            subject: "system:serviceaccount:team-a:sandbox".into(),
        },
        kind: PrincipalKind::Workload {
            team: "team-a".into(),
        },
    }
}

fn user(issuer: &str, groups: &[&str]) -> Principal {
    Principal {
        id: PrincipalId {
            issuer: issuer.into(),
            subject: "user@example.test".into(),
        },
        kind: PrincipalKind::User {
            groups: groups.iter().map(|&group| group.into()).collect(),
        },
    }
}

fn profile(name: &str) -> Result<ProfileName, NoProfile> {
    Ok(name.into())
}

#[test]
fn the_profile_comes_from_the_issuer_and_the_kind_of_principal() {
    let registry = registry();
    let table = [
        (
            "a workload of the workload issuer",
            workload(WORKLOADS),
            profile("workload-read"),
        ),
        (
            "a workload of another issuer",
            workload(USERS),
            Err(NoProfile::NoRule),
        ),
        (
            "a workload whose issuer differs only in case",
            workload("https://WORKLOADS.example.test"),
            Err(NoProfile::NoRule),
        ),
        (
            "a user of the workload issuer",
            user(WORKLOADS, &["group-g"]),
            Err(NoProfile::NoRule),
        ),
        (
            "a user in the group",
            user(USERS, &["group-g"]),
            profile("user-read"),
        ),
        (
            "a user in the group, not first of their groups",
            user(USERS, &["a-group", "group-g"]),
            profile("user-read"),
        ),
        (
            "a user in the group of another issuer",
            user("https://other.example.test", &["group-g"]),
            Err(NoProfile::NoRule),
        ),
        (
            "a user in two groups whose rules agree",
            user(USERS, &["group-g", "group-k"]),
            profile("user-read"),
        ),
        (
            "a user in two groups whose rules disagree",
            user(USERS, &["group-g", "group-h"]),
            Err(NoProfile::Ambiguous(BTreeSet::from([
                "user-other".into(),
                "user-read".into(),
            ]))),
        ),
        (
            "a user in no group",
            user(USERS, &[]),
            Err(NoProfile::NoRule),
        ),
        (
            "a user in no group with a rule",
            user(USERS, &["group-x"]),
            Err(NoProfile::NoRule),
        ),
    ];
    let mut failures = Vec::new();
    for (name, principal, want) in table {
        let got = registry.select_profile(&principal);
        if got != want {
            failures.push(format!("{name}: got {got:?}, want {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
