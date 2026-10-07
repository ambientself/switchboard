//! A ready-made world: two teams, two user groups, two surfaces, the fixture connector's
//! tools, and the issuers and verifier that prove callers into it.

use std::collections::BTreeSet;
use std::sync::Arc;

use gateway_core::{CallerContext, PolicySnapshot, Principal, PrincipalKind, ProfileName, Proved};
use gateway_identity::{
    ConfigError, Identity, IdentityConfig, IssuerConfig, IssuerKind, SigningAlgorithm,
    TokenVerifier, VerifyError,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::clock::SteppableClock;
use crate::connector::{
    CONNECTOR, DOCUMENT_ARGUMENT, DRAFT_TOOL, READ_TOOL, RESOURCE_KIND, RESOURCE_SYSTEM,
    SCOPED_READ_TOOL, WRITE_TOOL,
};
use crate::issuer::{IssuerError, LocalIssuer};

/// The deployment every fixture call is received by.
pub const DEPLOYMENT: &str = "fixture";
/// The audience the fixture's verifier accepts.
pub const AUDIENCE: &str = "switchboard-fixture";
/// The workload issuer's name.
pub const WORKLOAD_ISSUER: &str = "https://workload-issuer.fixture.test";
/// The user issuer's name.
pub const USER_ISSUER: &str = "https://user-issuer.fixture.test";
/// Team A's one workload.
pub const TEAM_A_SUBJECT: &str = "system:serviceaccount:team-a:sandbox";
/// Team B's one workload.
pub const TEAM_B_SUBJECT: &str = "system:serviceaccount:team-b:sandbox";
/// The one user.
pub const USER_SUBJECT: &str = "user-1@fixture.test";
/// Team A.
pub const TEAM_A: &str = "team-a";
/// Team B.
pub const TEAM_B: &str = "team-b";
/// The user group the fixture's one user is in.
pub const GROUP_G: &str = "group-g";
/// A second user group, with a profile of its own and no surface. It is there so that a user in
/// two groups that select different profiles can be tested.
pub const GROUP_REVIEW: &str = "group-review";
/// The surface serving the read tools, open to both teams and to group G.
pub const SURFACE_READ: &str = "fixture-read";
/// The surface serving all four tools, open to both teams and not to users.
pub const SURFACE_ALL: &str = "fixture-all";
/// The profile of team A's workloads: reads and proposals.
pub const PROFILE_TEAM_A: &str = "workload-propose";
/// The profile of team B's workloads: reads only.
pub const PROFILE_TEAM_B: &str = "workload-ro";
/// The profile of users in group G: reads only.
pub const PROFILE_USER: &str = "user-ro";
/// The profile of users in [`GROUP_REVIEW`]: reads only.
pub const PROFILE_REVIEWER: &str = "user-review";
/// A profile name the fixture policy does not hold, selected for a principal it does not know.
pub const UNKNOWN_PROFILE: &str = "no-such-profile";
/// The one document team A may reach.
pub const TEAM_A_DOCUMENT: &str = "team-a-notes";
/// The one document team B may reach.
pub const TEAM_B_DOCUMENT: &str = "team-b-notes";
/// The one document group G may reach.
pub const GROUP_G_DOCUMENT: &str = "group-g-notes";

/// Who is calling, among the callers the fixture knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    /// Team A's workload.
    TeamA,
    /// Team B's workload.
    TeamB,
    /// A user in group G.
    UserInGroupG,
}

impl Caller {
    /// The profile policy selects for this caller: the stand-in for choosing it from the
    /// issuer, the deployment and the principal.
    pub fn profile(self) -> &'static str {
        match self {
            Caller::TeamA => PROFILE_TEAM_A,
            Caller::TeamB => PROFILE_TEAM_B,
            Caller::UserInGroupG => PROFILE_USER,
        }
    }

    /// The document this caller's limit lets it reach.
    pub fn own_document(self) -> &'static str {
        match self {
            Caller::TeamA => TEAM_A_DOCUMENT,
            Caller::TeamB => TEAM_B_DOCUMENT,
            Caller::UserInGroupG => GROUP_G_DOCUMENT,
        }
    }
}

/// Why the fixture could not be built or could not prove a caller.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// A key could not be generated.
    #[error(transparent)]
    Issuer(#[from] IssuerError),
    /// The identity configuration was refused.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The policy data was refused.
    #[error("the fixture policy was refused: {0}")]
    Policy(#[from] serde_json::Error),
    /// The verifier refused a token the fixture minted, which is a bug in the fixture.
    #[error("the verifier refused a fixture token: {0:?}")]
    Verification(VerifyError),
}

/// The profile each team's workloads get.
const TEAM_PROFILES: [(&str, &str); 2] = [(TEAM_A, PROFILE_TEAM_A), (TEAM_B, PROFILE_TEAM_B)];

/// The profile each user group selects.
const GROUP_PROFILES: [(&str, &str); 2] =
    [(GROUP_G, PROFILE_USER), (GROUP_REVIEW, PROFILE_REVIEWER)];

fn profile_for(table: &[(&'static str, &'static str)], name: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, profile)| *profile)
}

/// The fixture policy as data, exactly as configuration would state it.
///
/// Two surfaces: [`SURFACE_READ`] serves the read and scoped read tools to both teams and to
/// group G, and [`SURFACE_ALL`] serves all four to both teams and to no user. Four profiles:
/// team A may read and propose, team B and the two user groups may only read. No profile
/// lists `write`: the decision function denies a `write` tool in every profile, so
/// [`WRITE_TOOL`] is denied to every caller. One resource limit for each team and for the
/// group, each a single document. The read, draft and write tools declare their resources;
/// the scoped read tool checks its own scope. So every kind of denial the decision function
/// makes is reachable from here with one change to a call: another surface, tool or document.
pub fn policy_data() -> Value {
    let tool = |name: &str, classification: &str, resources: &str| {
        json!({
            "name": name,
            "classification": classification,
            "connector": CONNECTOR,
            "resources": resources,
        })
    };
    let document = |identifier: &str| json!({"system": RESOURCE_SYSTEM, "kind": RESOURCE_KIND, "identifier": identifier});
    json!({
        "revision": "fixture-1",
        "tools": [
            tool(READ_TOOL, "read", "declared"),
            tool(DRAFT_TOOL, "propose", "declared"),
            tool(WRITE_TOOL, "write", "declared"),
            tool(SCOPED_READ_TOOL, "read", "checks_own_scope"),
        ],
        "surfaces": [
            {
                "name": SURFACE_READ,
                "tools": [READ_TOOL, SCOPED_READ_TOOL],
                "teams": [TEAM_A, TEAM_B],
                "groups": [GROUP_G],
                "principals": "any_in_teams_and_groups",
            },
            {
                "name": SURFACE_ALL,
                "tools": [READ_TOOL, DRAFT_TOOL, WRITE_TOOL, SCOPED_READ_TOOL],
                "teams": [TEAM_A, TEAM_B],
                "groups": [],
                "principals": "any_in_teams_and_groups",
            },
        ],
        "profiles": [
            {"name": PROFILE_TEAM_A, "classifications": ["read", "propose"], "requires_delegation": false},
            {"name": PROFILE_TEAM_B, "classifications": ["read"], "requires_delegation": false},
            {"name": PROFILE_USER, "classifications": ["read"], "requires_delegation": false},
            {"name": PROFILE_REVIEWER, "classifications": ["read"], "requires_delegation": false},
        ],
        "limits": {
            "teams": {
                TEAM_A: [document(TEAM_A_DOCUMENT)],
                TEAM_B: [document(TEAM_B_DOCUMENT)],
            },
            "groups": {
                GROUP_G: [document(GROUP_G_DOCUMENT)],
            },
        },
    })
}

/// The fixture policy, loaded through the core's validated path: the same deserialization that
/// refuses a duplicate name or a surface serving an unapproved tool.
pub fn policy() -> Result<PolicySnapshot, serde_json::Error> {
    serde_json::from_value(policy_data())
}

/// The fixture's world for identity: a clock, a workload issuer and a user issuer with their
/// own generated keys, a verifier trusting exactly those two, and the policy.
///
/// Callers are proved through the real [`TokenVerifier`], from tokens the local issuers sign,
/// so a `CallerContext` from here has the provenance a production one has and there is no
/// back door in the fixture. The fixture's clock is steppable: it starts at
/// [`FIXTURE_NOW`](crate::FIXTURE_NOW) and a test moves it.
pub struct Fixture {
    /// The time the verifier reads and tokens are issued at.
    pub clock: SteppableClock,
    /// The workload issuer: team A's and team B's tokens.
    pub workload_issuer: LocalIssuer,
    /// The user issuer.
    pub user_issuer: LocalIssuer,
    /// The fixture policy.
    pub policy: PolicySnapshot,
    configs: Vec<IssuerConfig>,
    verifier: TokenVerifier,
}

impl Fixture {
    /// A fixture whose issuers both sign with ES256, which is quick to generate keys for.
    pub fn new() -> Result<Self, FixtureError> {
        Self::with_algorithms(SigningAlgorithm::Es256, SigningAlgorithm::Es256)
    }

    /// A fixture with the given signing algorithms for the workload and user issuers.
    pub fn with_algorithms(
        workload: SigningAlgorithm,
        user: SigningAlgorithm,
    ) -> Result<Self, FixtureError> {
        let workload_issuer = LocalIssuer::new(WORKLOAD_ISSUER, workload)?;
        let user_issuer = LocalIssuer::new(USER_ISSUER, user)?;
        let subjects = [
            (TEAM_A_SUBJECT.into(), TEAM_A.into()),
            (TEAM_B_SUBJECT.into(), TEAM_B.into()),
        ]
        .into();
        let configs = vec![
            workload_issuer.config(IssuerKind::Workload { subjects }, &[AUDIENCE]),
            user_issuer.config(IssuerKind::user(), &[AUDIENCE]),
        ];
        let clock = SteppableClock::default();
        let verifier = TokenVerifier::new(configs.clone(), Arc::new(clock.clone()))?;
        Ok(Self {
            clock,
            workload_issuer,
            user_issuer,
            policy: policy()?,
            configs,
            verifier,
        })
    }

    /// The issuer entries the verifier was built from, for a test that wants to change one.
    pub fn issuer_configs(&self) -> &[IssuerConfig] {
        &self.configs
    }

    /// The verifier, which is the [`Verifier`](gateway_core::Verifier) for principals.
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }

    /// An identity gate over the same issuers and clock, with checking on.
    pub fn identity(&self) -> Result<Identity, ConfigError> {
        Identity::new(
            IdentityConfig::Enforce(self.configs.clone()),
            Arc::new(self.clock.clone()),
        )
    }

    /// A valid token for `caller`, issued at the clock's current time.
    pub fn token(&self, caller: Caller) -> String {
        let now = gateway_identity::Clock::now(&self.clock);
        match caller {
            Caller::TeamA => self
                .workload_issuer
                .workload_token(TEAM_A_SUBJECT, AUDIENCE, now)
                .build(),
            Caller::TeamB => self
                .workload_issuer
                .workload_token(TEAM_B_SUBJECT, AUDIENCE, now)
                .build(),
            Caller::UserInGroupG => self
                .user_issuer
                .user_token(USER_SUBJECT, AUDIENCE, &[GROUP_G], now)
                .build(),
        }
    }

    /// The principal for `caller`, proved by the verifier from a token the local issuer signs.
    pub fn principal(&self, caller: Caller) -> Result<Proved<Principal>, FixtureError> {
        Proved::verify(&self.verifier, self.token(caller).as_str())
            .map_err(|failure| FixtureError::Verification(failure.detail().clone()))
    }

    /// The profile policy selects for a proved principal: the stand-in for choosing it from
    /// the issuer, the deployment and the principal.
    ///
    /// A workload from the workload issuer gets its team's profile. A user from the user issuer
    /// gets the profile its groups select, looking at every group it is in; groups that select
    /// no profile are passed over. If its groups select more than one profile, it gets none:
    /// the design does not say which would win, so the fixture does not choose. Anything else
    /// gets a profile the snapshot does not hold, which the decision function denies.
    pub fn select_profile(principal: &Principal) -> ProfileName {
        let selected = match (principal.id.issuer.as_str(), &principal.kind) {
            (WORKLOAD_ISSUER, PrincipalKind::Workload { team }) => {
                profile_for(&TEAM_PROFILES, team.as_str())
            }
            (USER_ISSUER, PrincipalKind::User { groups }) => {
                let profiles: BTreeSet<&str> = groups
                    .iter()
                    .filter_map(|group| profile_for(&GROUP_PROFILES, group.as_str()))
                    .collect();
                if profiles.len() == 1 {
                    profiles.first().copied()
                } else {
                    None
                }
            }
            _ => None,
        };
        ProfileName::new(selected.unwrap_or(UNKNOWN_PROFILE))
    }

    /// A caller context for a proved principal on `surface`, with no delegation, the profile
    /// [`select_profile`](Self::select_profile) chooses and the fixture's deployment.
    pub fn context_for(principal: Proved<Principal>, surface: &str) -> CallerContext {
        CallerContext {
            profile: Self::select_profile(principal.get()),
            principal,
            delegation: None,
            surface: surface.into(),
            deployment: DEPLOYMENT.into(),
        }
    }

    /// A caller context for `caller` on `surface`: a token the local issuer signs, proved by
    /// the verifier, with the profile policy selects.
    pub fn caller_context(
        &self,
        caller: Caller,
        surface: &str,
    ) -> Result<CallerContext, FixtureError> {
        Ok(Self::context_for(self.principal(caller)?, surface))
    }

    /// Team A's workload on `surface`.
    pub fn team_a_workload(&self, surface: &str) -> Result<CallerContext, FixtureError> {
        self.caller_context(Caller::TeamA, surface)
    }

    /// Team B's workload on `surface`.
    pub fn team_b_workload(&self, surface: &str) -> Result<CallerContext, FixtureError> {
        self.caller_context(Caller::TeamB, surface)
    }

    /// A user in group G on `surface`.
    pub fn user_in_group_g(&self, surface: &str) -> Result<CallerContext, FixtureError> {
        self.caller_context(Caller::UserInGroupG, surface)
    }

    /// The arguments for a call to one of the document tools naming `document`.
    pub fn arguments_naming(document: &str) -> Value {
        json!({ DOCUMENT_ARGUMENT: document })
    }
}
