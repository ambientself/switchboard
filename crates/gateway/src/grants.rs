//! Turn grants (decision 0012): how they are configured, the boot gates that read that
//! configuration, and what the request path does with a grant a request carries.
//!
//! **Configuration.** [`GrantsSection`] is the grant gate as the boot gates read it, from the
//! deployment file's optional `[grants]` table (see [`crate::deployment`]) or the JSON
//! configuration's `grants`: checking enforced, with each issuer's keys and the tool-name
//! mapping, or checking explicitly disabled. Left out, checking is on and no issuer is
//! configured, so every grant a request carries is refused; the boot gates allow that only
//! while no profile a rule gives workloads requires a delegation. The keys are read at boot
//! only: changing one is a restart, which is one rollout.
//!
//! **The request path.** Every `tools/call` and `tools/list` that carries the
//! [`GRANT_HEADER`] is verified while checking is on, whatever its profile requires, against
//! the deployment that received it, the caller's proved principal and pod, and the gateway's
//! clock (`GrantChecking::present`). A grant that verifies becomes the core's verified
//! delegation; one that does not becomes a delegation that is present and unverified, which
//! check 3 denies. A request with no grant has no delegation, so a profile that requires one
//! denies it as missing. A request with the header more than once is a malformed grant. With
//! checking disabled, which only a development build allows, the header is not read at all.
//!
//! **Signals** (design section 11). Each failure is counted by kind, and each accepted grant by
//! the key it verified under ([`GrantSignals`]). An audience or pod failure is logged at
//! `ERROR`, to be investigated, since an honest sandbox under a correct configuration never
//! makes one. A lifetime failure (expired, not yet valid, or over the ceiling) is counted and
//! never logged one by one, since honest sandboxes make them. Every other failure is logged at
//! `WARN`. A failure's log line holds its kind and, only for a binding's failure (the audience
//! or the pod, since a lifetime failure is not logged), the grant's digest: nothing from the
//! grant's claims, which a [`GrantFailure`] does not carry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::{
    Classification, Delegation, DelegationDigest, DelegationFailure, DelegationIssuer,
    DeploymentName, Egress, ExecutionId, Issuer, KeyId, PolicySnapshot, PresentedDelegation,
    Principal, ProfileName, Proved, SessionId, SurfaceName, TeamId, ToolName, TurnId,
    UnverifiedDelegation, Verifier,
};
use gateway_otto::{
    FailureKind, GrantDigest, GrantFailure, GrantKeys, GrantVerifier, IssuerConfig, KeyConfigError,
    MappingError, PreviousKeyConfig, ToolMapping, VerifiedGrant,
};
use http::HeaderMap;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::boot::GateState;
use crate::telemetry::Surface;

/// The header a turn grant is sent in: `X-Otto-Turn-Grant`.
pub const GRANT_HEADER: &str = gateway_otto::format::HEADER;

/// The `event` field of the log line for each grant refused, other than a lifetime failure.
pub const GRANT_REFUSED_EVENT: &str = "grant_refused";

/// The grant gate: checking enforced with these issuers and this mapping, checking disabled,
/// or neither, which is checking on with no issuer. Both is refused at boot.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantsSection {
    /// Verify every grant against these issuers' keys.
    #[serde(default)]
    pub enforce: Option<GrantsConfig>,
    /// Do not read grants. Only a development build accepts it (decision 0012, "Keys"): the
    /// release build refuses to start.
    #[serde(default)]
    pub disabled: bool,
}

/// The issuers whose grants verify, and the mapping of Otto's tool names to this gateway's.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantsConfig {
    /// Each issuer, with its keys.
    pub issuers: Vec<GrantIssuerEntry>,
    /// Otto's bare tool names to this gateway's, one to one. In JSON, an object of names.
    #[serde(deserialize_with = "tool_mapping")]
    pub tool_mapping: ToolMapping,
}

/// One grant issuer, with the text of its key files.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIssuerEntry {
    /// The issuer's name, recorded on every row its grants verify for.
    pub name: String,
    /// The current key: one Ed25519 public key in PEM.
    pub current_key: String,
    /// The key being rotated away from, if any.
    #[serde(default)]
    pub previous_key: Option<PreviousGrantKey>,
    /// Whether the issuer's grants must carry `pod`, equal to the caller's proved pod.
    pub require_pod: bool,
    /// Whether the issuer's grants must carry `egress`.
    pub require_egress: bool,
}

/// An issuer's previous key and when it retires.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousGrantKey {
    /// One Ed25519 public key in PEM.
    pub key: String,
    /// When the key retires, in seconds since the Unix epoch. Required: the boot gates refuse a
    /// previous key without it.
    #[serde(default)]
    pub retires_at: Option<u64>,
}

impl GrantIssuerEntry {
    fn config(&self) -> IssuerConfig {
        IssuerConfig {
            name: self.name.clone(),
            current_key: self.current_key.clone(),
            previous_key: self
                .previous_key
                .as_ref()
                .map(|previous| PreviousKeyConfig {
                    key: previous.key.clone(),
                    retires_at: previous
                        .retires_at
                        .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
                }),
            require_pod: self.require_pod,
            require_egress: self.require_egress,
        }
    }
}

fn tool_mapping<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ToolMapping, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    ToolMapping::from_json(&value.to_string()).map_err(serde::de::Error::custom)
}

/// The deployment file's `[grants]` table as written.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantsFile {
    /// Verify every grant against these issuers' keys.
    Enforce {
        /// The tool-name mapping file: one JSON object of Otto names to this gateway's.
        tool_mapping_file: PathBuf,
        /// The issuers.
        issuers: Vec<GrantIssuerFile>,
    },
    /// Do not read grants: development builds only. An empty struct, as for the identity gate,
    /// so the table's other fields are refused beside it.
    Disabled {},
}

/// One grant issuer, as the deployment file writes it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIssuerFile {
    /// The issuer's name.
    pub name: String,
    /// The file holding its current public key, in PEM.
    pub key_file: PathBuf,
    /// The key it is rotating away from, if any.
    #[serde(default)]
    pub previous: Option<PreviousKeyFile>,
    /// Whether its grants must carry `pod`.
    pub require_pod: bool,
    /// Whether its grants must carry `egress`.
    pub require_egress: bool,
}

/// An issuer's previous key, as the deployment file writes it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousKeyFile {
    /// The file holding the previous public key, in PEM.
    pub key_file: PathBuf,
    /// When it retires: a TOML date and time with an offset, such as `2026-11-01T00:00:00Z`.
    /// Required; left out, the gateway refuses to start.
    #[serde(default)]
    pub retires_at: Option<toml::value::Datetime>,
}

/// Why the `[grants]` table's files could not be read.
#[derive(Debug, Error)]
pub enum GrantsFileError {
    /// A key file or the mapping file could not be read.
    #[error("cannot read `{path}`: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The tool-name mapping was refused.
    #[error("the tool mapping `{path}` was refused: {source}")]
    Mapping {
        /// The file.
        path: PathBuf,
        /// Why.
        source: MappingError,
    },
    /// A previous key's end is not an absolute instant: a date and time with an offset, at or
    /// after the Unix epoch.
    #[error(
        "the previous key of turn-grant issuer `{0}` has a `retires_at` that is not a date and \
         time with an offset, such as 2026-11-01T00:00:00Z"
    )]
    NotAnInstant(String),
}

impl GrantsFile {
    /// The section the boot gates read, with every file the table names read, relative to
    /// `base`.
    pub fn section(self, base: &Path) -> Result<GrantsSection, GrantsFileError> {
        match self {
            GrantsFile::Disabled {} => Ok(GrantsSection {
                enforce: None,
                disabled: true,
            }),
            GrantsFile::Enforce {
                tool_mapping_file,
                issuers,
            } => {
                let path = base.join(tool_mapping_file);
                let tool_mapping = ToolMapping::from_json(&read(&path)?)
                    .map_err(|source| GrantsFileError::Mapping { path, source })?;
                let issuers = issuers
                    .into_iter()
                    .map(|issuer| issuer.entry(base))
                    .collect::<Result<_, _>>()?;
                Ok(GrantsSection {
                    enforce: Some(GrantsConfig {
                        issuers,
                        tool_mapping,
                    }),
                    disabled: false,
                })
            }
        }
    }
}

impl GrantIssuerFile {
    fn entry(self, base: &Path) -> Result<GrantIssuerEntry, GrantsFileError> {
        let previous_key = match self.previous {
            None => None,
            Some(previous) => Some(PreviousGrantKey {
                key: read(&base.join(previous.key_file))?,
                retires_at: previous
                    .retires_at
                    .map(|instant| {
                        unix_seconds(&instant)
                            .ok_or_else(|| GrantsFileError::NotAnInstant(self.name.clone()))
                    })
                    .transpose()?,
            }),
        };
        Ok(GrantIssuerEntry {
            current_key: read(&base.join(self.key_file))?,
            name: self.name,
            previous_key,
            require_pod: self.require_pod,
            require_egress: self.require_egress,
        })
    }
}

fn read(path: &Path) -> Result<String, GrantsFileError> {
    std::fs::read_to_string(path).map_err(|source| GrantsFileError::Read {
        path: path.to_owned(),
        source,
    })
}

/// A TOML date and time with an offset as whole seconds since the Unix epoch, or `None` for a
/// local date, a local time, a local date and time, or an instant before the epoch.
fn unix_seconds(instant: &toml::value::Datetime) -> Option<u64> {
    let (date, time, offset) = (instant.date?, instant.time?, instant.offset?);
    let offset_minutes = match offset {
        toml::value::Offset::Z => 0,
        toml::value::Offset::Custom { minutes } => i64::from(minutes),
    };
    let days = days_from_civil(
        i64::from(date.year),
        i64::from(date.month),
        i64::from(date.day),
    );
    let seconds = days * 86_400
        + i64::from(time.hour) * 3_600
        + i64::from(time.minute) * 60
        + i64::from(time.second.unwrap_or(0))
        - offset_minutes * 60;
    u64::try_from(seconds).ok()
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// What a request carried in the grant header.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PresentedGrant {
    /// No grant header.
    Absent,
    /// One, with its bytes exactly as sent.
    One(Vec<u8>),
    /// More than one: a malformed grant.
    Many,
}

impl fmt::Debug for PresentedGrant {
    /// Never the grant: its claims are encoded, not encrypted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresentedGrant::Absent => f.write_str("Absent"),
            PresentedGrant::One(bytes) => write!(f, "One({} bytes)", bytes.len()),
            PresentedGrant::Many => f.write_str("Many"),
        }
    }
}

impl PresentedGrant {
    /// What `headers` carry in [`GRANT_HEADER`].
    pub(crate) fn of(headers: &HeaderMap) -> Self {
        let mut values = headers.get_all(GRANT_HEADER).iter();
        match (values.next(), values.next()) {
            (None, _) => PresentedGrant::Absent,
            (Some(value), None) => PresentedGrant::One(value.as_bytes().to_vec()),
            (Some(_), Some(_)) => PresentedGrant::Many,
        }
    }
}

/// The core's failure for each of the verifier's: one to one.
pub(crate) fn delegation_failure(kind: FailureKind) -> DelegationFailure {
    match kind {
        FailureKind::Version => DelegationFailure::Version,
        FailureKind::UnknownKey => DelegationFailure::UnknownKey,
        FailureKind::RetiredKey => DelegationFailure::RetiredKey,
        FailureKind::Encoding => DelegationFailure::Encoding,
        FailureKind::Signature => DelegationFailure::Signature,
        FailureKind::Malformed => DelegationFailure::Malformed,
        FailureKind::Expired => DelegationFailure::Expired,
        FailureKind::NotYetValid => DelegationFailure::NotYetValid,
        FailureKind::LifetimeOverCeiling => DelegationFailure::LifetimeOverCeiling,
        FailureKind::WrongAudience => DelegationFailure::WrongAudience,
        FailureKind::WrongPod => DelegationFailure::WrongPod,
    }
}

/// The unverified delegation a failure of `kind` becomes: the core's failure, and `digest`,
/// which the verifier gives only with a binding's failure (the audience, the lifetime or the
/// pod), the only failure the core records one with. Should a digest come with any other
/// failure, it is not recorded.
pub(crate) fn unverified(kind: FailureKind, digest: Option<GrantDigest>) -> UnverifiedDelegation {
    let failure = delegation_failure(kind);
    digest
        .and_then(|digest| DelegationDigest::parse(&digest.to_string()).ok())
        .and_then(|digest| UnverifiedDelegation::after_signature(failure, digest).ok())
        .unwrap_or_else(|| UnverifiedDelegation::new(failure))
}

/// The verified delegation a grant becomes. Its tools are the grant's under this gateway's
/// names, already without any name the mapping lacks, less any the surface the request arrived
/// on does not serve. The person it names stays claimed.
pub(crate) fn delegation(
    grant: &VerifiedGrant,
    presented: &[u8],
    snapshot: &PolicySnapshot,
    surface: &SurfaceName,
) -> Delegation {
    Delegation {
        acting_person: grant.actor().clone(),
        team: grant.team().clone(),
        tools: grant
            .tools()
            .iter()
            .filter(|tool| snapshot.tool_on_surface(surface, tool).is_some())
            .cloned()
            .collect(),
        issuer: DelegationIssuer::new(grant.issuer().as_str()),
        digest: DelegationDigest::of(presented),
        key_id: KeyId::new(grant.key_id().as_str()),
        session: SessionId::new(grant.session()),
        turn: TurnId::new(grant.turn()),
        execution: ExecutionId::new(grant.execution()),
        epoch: grant.epoch(),
        egress: grant.egress().map(|egress| match egress {
            gateway_otto::Egress::Sealed => Egress::Sealed,
            gateway_otto::Egress::Open => Egress::Open,
        }),
    }
}

/// The turn-grant verifier as a [`Verifier`] of delegations, for one request: a grant's bytes
/// in, the core's delegation out. This is where a grant becomes a `Proved<Delegation>`.
struct GrantProof<'a> {
    verifier: &'a GrantVerifier,
    caller: &'a Proved<Principal>,
    now: SystemTime,
    snapshot: &'a PolicySnapshot,
    surface: &'a SurfaceName,
}

impl Verifier for GrantProof<'_> {
    type Evidence = [u8];
    type Fact = Delegation;
    type Error = GrantFailure;

    fn verify(&self, grant: &[u8]) -> Result<Delegation, GrantFailure> {
        let verified = self.verifier.verify(grant, self.caller, self.now)?;
        Ok(delegation(&verified, grant, self.snapshot, self.surface))
    }
}

/// Grant failures by kind and accepted grants by key ID (design section 11). Cheap to clone;
/// clones share the counts.
#[derive(Clone, Debug, Default)]
pub struct GrantSignals(Arc<SignalCounts>);

#[derive(Debug, Default)]
struct SignalCounts {
    failures: [AtomicU64; FailureKind::ALL.len()],
    /// One counter per configured key, made at boot: a grant is accepted only under one.
    accepted: BTreeMap<String, AtomicU64>,
}

/// A snapshot of [`GrantSignals`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantCounts {
    /// Each kind of failure, in the order of [`FailureKind::ALL`], with its count.
    pub failures: Vec<(FailureKind, u64)>,
    /// Each configured key's ID, with the grants accepted under it.
    pub accepted: Vec<(String, u64)>,
}

impl GrantSignals {
    fn for_keys(keys: &GrantKeys) -> Self {
        Self(Arc::new(SignalCounts {
            failures: Default::default(),
            accepted: keys
                .key_ids()
                .map(|(id, _, _)| (id.as_str().to_owned(), AtomicU64::new(0)))
                .collect(),
        }))
    }

    fn failed(&self, kind: FailureKind) {
        if let Some(index) = FailureKind::ALL.iter().position(|each| *each == kind) {
            self.0.failures[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn accepted(&self, key_id: &str) {
        if let Some(count) = self.0.accepted.get(key_id) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counts as they stand.
    pub fn counts(&self) -> GrantCounts {
        GrantCounts {
            failures: FailureKind::ALL
                .iter()
                .zip(&self.0.failures)
                .map(|(kind, count)| (*kind, count.load(Ordering::Relaxed)))
                .collect(),
            accepted: self
                .0
                .accepted
                .iter()
                .map(|(id, count)| (id.clone(), count.load(Ordering::Relaxed)))
                .collect(),
        }
    }
}

/// The grant gate as built at boot: whether grants are read, the verifier, and its counts.
pub struct GrantChecking {
    state: GateState,
    verifier: GrantVerifier,
    issuers: Vec<(String, bool)>,
    signals: GrantSignals,
}

impl fmt::Debug for GrantChecking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantChecking")
            .field("state", &self.state)
            .field("issuers", &self.issuers)
            .finish_non_exhaustive()
    }
}

/// Why the grant gate could not be built.
#[derive(Debug, Error)]
pub enum GrantGateError {
    /// The grant keys were refused.
    #[error(transparent)]
    Keys(#[from] KeyConfigError),
    /// Grant checking is both enforced and disabled.
    #[error("turn-grant checking is both enforced and disabled; choose one")]
    Contradiction,
    /// Grant checking is disabled outside a development build.
    #[error("opt-out")]
    OptOut,
}

impl GrantChecking {
    /// The gate `section` configures, for grants presented at `deployment`. Checking disabled
    /// is refused unless `development`.
    pub(crate) fn new(
        section: GrantsSection,
        deployment: &DeploymentName,
        development: bool,
    ) -> Result<Self, GrantGateError> {
        let (keys, mapping, state) = match (section.enforce, section.disabled) {
            (Some(config), false) => {
                let configs: Vec<IssuerConfig> = config
                    .issuers
                    .iter()
                    .map(GrantIssuerEntry::config)
                    .collect();
                (
                    GrantKeys::new(&configs)?,
                    config.tool_mapping,
                    GateState::On,
                )
            }
            (None, false) => (GrantKeys::none(), ToolMapping::default(), GateState::On),
            (None, true) => {
                if !development {
                    return Err(GrantGateError::OptOut);
                }
                (
                    GrantKeys::none(),
                    ToolMapping::default(),
                    GateState::Disabled,
                )
            }
            (Some(_), true) => return Err(GrantGateError::Contradiction),
        };
        let issuers = keys
            .issuers()
            .map(|(name, require_pod)| (name.as_str().to_owned(), require_pod))
            .collect();
        let signals = GrantSignals::for_keys(&keys);
        Ok(Self {
            state,
            verifier: GrantVerifier::new(keys, deployment.clone(), mapping),
            issuers,
            signals,
        })
    }

    /// Whether grants are read and verified, or checking is disabled.
    pub fn state(&self) -> GateState {
        self.state
    }

    /// Each configured issuer's name, and whether its grants must carry `pod`.
    pub fn issuers(&self) -> &[(String, bool)] {
        &self.issuers
    }

    /// What is counted.
    pub fn signals(&self) -> &GrantSignals {
        &self.signals
    }

    /// The delegation a request presents, for a caller proved as `caller` on `surface`, at
    /// `now`, deciding from `snapshot`: `None` with no grant header or with checking disabled,
    /// and otherwise the grant verified or not. Counts and logs each failure; see the
    /// [module documentation](self).
    pub(crate) fn present(
        &self,
        grant: &PresentedGrant,
        caller: &Proved<Principal>,
        request: &GrantRequest<'_>,
    ) -> Option<PresentedDelegation> {
        if self.state == GateState::Disabled {
            return None;
        }
        let bytes = match grant {
            PresentedGrant::Absent => return None,
            PresentedGrant::Many => {
                self.refused(FailureKind::Malformed, None, caller, request);
                return Some(PresentedDelegation::Unverified(UnverifiedDelegation::new(
                    DelegationFailure::Malformed,
                )));
            }
            PresentedGrant::One(bytes) => bytes.as_slice(),
        };
        let proof = GrantProof {
            verifier: &self.verifier,
            caller,
            now: request.now,
            snapshot: request.snapshot,
            surface: request.surface,
        };
        match Proved::verify(&proof, bytes) {
            Ok(delegation) => {
                self.signals.accepted(delegation.get().key_id.as_str());
                tracing::debug!(
                    key_id = delegation.get().key_id.as_str(),
                    "accepted a turn grant"
                );
                Some(PresentedDelegation::Verified(delegation))
            }
            Err(failure) => {
                let digest = failure.digest();
                self.refused(failure.kind(), digest, caller, request);
                Some(PresentedDelegation::Unverified(unverified(
                    failure.kind(),
                    digest,
                )))
            }
        }
    }

    /// Counts a failure and logs it as its kind calls for.
    fn refused(
        &self,
        kind: FailureKind,
        digest: Option<GrantDigest>,
        caller: &Proved<Principal>,
        request: &GrantRequest<'_>,
    ) {
        self.signals.failed(kind);
        let principal = caller.get();
        let surface = Surface::new(request.surface.as_str());
        let digest = digest.map(|digest| digest.to_string());
        match kind {
            // Honest sandboxes make these: counted, to alert on a rate, never logged one by one.
            FailureKind::Expired | FailureKind::NotYetValid | FailureKind::LifetimeOverCeiling => {}
            FailureKind::WrongAudience | FailureKind::WrongPod => tracing::error!(
                event = GRANT_REFUSED_EVENT,
                failure = kind.as_str(),
                digest,
                deployment = %request.deployment,
                surface = surface.as_str(),
                issuer = %principal.id.issuer,
                subject = %principal.id.subject,
                pod = principal.pod().map(|pod| pod.as_str()),
                "refused a turn grant at a binding no honest sandbox fails under a correct \
                 configuration; investigate it"
            ),
            _ => tracing::warn!(
                event = GRANT_REFUSED_EVENT,
                failure = kind.as_str(),
                digest,
                deployment = %request.deployment,
                surface = surface.as_str(),
                issuer = %principal.id.issuer,
                subject = %principal.id.subject,
                pod = principal.pod().map(|pod| pod.as_str()),
                "refused a turn grant"
            ),
        }
    }
}

/// What a grant is verified against, beside the caller.
pub(crate) struct GrantRequest<'a> {
    /// The deployment that received the request.
    pub(crate) deployment: &'a DeploymentName,
    /// The surface the request arrived on.
    pub(crate) surface: &'a SurfaceName,
    /// The snapshot the request is decided from.
    pub(crate) snapshot: &'a PolicySnapshot,
    /// The gateway's clock, read once for the request.
    pub(crate) now: SystemTime,
}

/// A rule that gives workloads a profile: the issuer that proves them, the teams it covers
/// (`None` for every team), and the profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkloadSelection {
    pub(crate) issuer: Issuer,
    pub(crate) teams: Option<BTreeSet<TeamId>>,
    pub(crate) profile: ProfileName,
}

/// Why the grant configuration and the policy cannot serve together.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum GrantPolicyError {
    /// A profile a rule gives workloads requires a delegation, and no grant issuer is
    /// configured, so no call under it could be allowed.
    #[error(
        "profile `{profile}`, which a profile rule gives the workloads of issuer `{issuer}`, \
         requires a delegation, but no turn-grant issuer is configured: name each issuer in \
         `[grants]` (decision 0012)"
    )]
    NoGrantIssuer {
        /// The profile.
        profile: ProfileName,
        /// The issuer of the rule that gives it.
        issuer: Issuer,
    },
    /// A tool not classified `read` is served to a team whose workloads get a profile that
    /// requires a delegation, and an issuer whose grants verify does not bind the pod.
    #[error(
        "tool `{tool}` is classified `{classification}` and served on surface `{surface}`, \
         which admits team `{team}`, whose workloads get profile `{profile}`, which requires a \
         delegation; but turn-grant issuer `{grant_issuer}` does not require `pod`, so a grant \
         copied out of its sandbox could be used from another pod: set `require_pod = true` \
         for it before serving such a tool (decision 0012)"
    )]
    PodNotRequired {
        /// The tool.
        tool: ToolName,
        /// Its classification.
        classification: Classification,
        /// The surface serving it.
        surface: SurfaceName,
        /// A team the surface admits that the rule covers.
        team: TeamId,
        /// The profile the rule gives.
        profile: ProfileName,
        /// The grant issuer that does not require `pod`.
        grant_issuer: String,
    },
}

/// The boot gate of decision 0012, "Keys": while grants are checked, a profile a rule gives
/// workloads may require a delegation only if some grant issuer is configured. Checked at boot.
pub(crate) fn issuer_gate(
    snapshot: &PolicySnapshot,
    rules: &[WorkloadSelection],
    grants: &GrantChecking,
) -> Result<(), GrantPolicyError> {
    if grants.state == GateState::Disabled || !grants.issuers.is_empty() {
        return Ok(());
    }
    match rules
        .iter()
        .find(|rule| requires_delegation(snapshot, &rule.profile))
    {
        Some(rule) => Err(GrantPolicyError::NoGrantIssuer {
            profile: rule.profile.clone(),
            issuer: rule.issuer.clone(),
        }),
        None => Ok(()),
    }
}

/// The pod gate of decision 0012, "Keys": no tool not classified `read` is served on a surface
/// whose allowlist admits a team that a rule gives a profile requiring a delegation, while a
/// grant issuer does not require `pod`. Nothing in configuration ties a grant issuer to a
/// rule, and any configured issuer's grant verifies for any caller, so every configured issuer
/// must require `pod` once such a tool is served. Checked at boot and at every snapshot load.
///
/// With checking disabled, or no issuer configured, no grant verifies and the gate holds.
pub(crate) fn pod_gate(
    snapshot: &PolicySnapshot,
    rules: &[WorkloadSelection],
    grant_issuers: &[(String, bool)],
) -> Result<(), GrantPolicyError> {
    let Some((unbound, _)) = grant_issuers.iter().find(|(_, require_pod)| !require_pod) else {
        return Ok(());
    };
    for rule in rules {
        if !requires_delegation(snapshot, &rule.profile) {
            continue;
        }
        for surface in snapshot.surfaces() {
            let Some(team) = surface.teams.iter().find(|team| {
                rule.teams
                    .as_ref()
                    .is_none_or(|covered| covered.contains(*team))
            }) else {
                continue;
            };
            if let Some(tool) = surface
                .tools
                .iter()
                .filter_map(|name| snapshot.tool(name))
                .find(|tool| tool.classification != Classification::Read)
            {
                return Err(GrantPolicyError::PodNotRequired {
                    tool: tool.name.clone(),
                    classification: tool.classification,
                    surface: surface.name.clone(),
                    team: team.clone(),
                    profile: rule.profile.clone(),
                    grant_issuer: unbound.clone(),
                });
            }
        }
    }
    Ok(())
}

fn requires_delegation(snapshot: &PolicySnapshot, profile: &ProfileName) -> bool {
    snapshot
        .profile(profile)
        .is_some_and(|profile| profile.requires_delegation)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_kind_maps_to_the_core_failure_of_its_name() {
        let mapped: BTreeSet<DelegationFailure> = FailureKind::ALL
            .iter()
            .map(|kind| delegation_failure(*kind))
            .collect();
        assert_eq!(mapped.len(), FailureKind::ALL.len(), "two kinds map to one");
        for kind in FailureKind::ALL {
            let core = delegation_failure(kind);
            let expected = match kind {
                FailureKind::LifetimeOverCeiling => "lifetime_over_ceiling",
                other => other.as_str(),
            };
            assert_eq!(core.as_str(), expected, "{kind:?}");
        }
    }

    #[test]
    fn a_digest_is_recorded_only_with_a_bindings_failure() {
        let digest = GrantDigest::of(b"v3.key.claims.signature");
        let hex = digest.to_string();
        for kind in FailureKind::ALL {
            let with = unverified(kind, Some(digest));
            let core = delegation_failure(kind);
            assert_eq!(with.failure(), core);
            let recorded = with.digest().map(DelegationDigest::to_hex);
            if core.follows_signature() {
                assert_eq!(recorded.as_deref(), Some(hex.as_str()), "{kind:?}");
            } else {
                assert_eq!(recorded, None, "{kind:?}");
            }
            assert_eq!(unverified(kind, None).digest(), None, "{kind:?}");
        }
    }

    /// A verified grant's tools are mapped, with any name the mapping lacks dropped, and then
    /// narrowed to what the surface the request arrived on serves: an approved tool on another
    /// surface, and a mapped name the policy does not approve, are dropped too.
    #[test]
    fn a_delegation_keeps_only_the_mapped_tools_the_surface_serves() {
        use gateway_otto::minter::TestMinter;
        use gateway_testkit::{
            Caller, DRAFT_TOOL, FIXTURE_NOW, Fixture, READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A,
        };
        use serde_json::json;

        let fixture = Fixture::new().unwrap();
        let minter = TestMinter::generate();
        let keys = GrantKeys::new(&[IssuerConfig {
            name: "otto-test".into(),
            current_key: minter.public_key_pem(),
            previous_key: None,
            require_pod: false,
            require_egress: false,
        }])
        .unwrap();
        let mapping = ToolMapping::from_pairs([
            ("otto_read", READ_TOOL),
            ("otto_draft", DRAFT_TOOL),
            ("otto_nowhere", "fixture__nowhere"),
        ])
        .unwrap();
        let verifier = GrantVerifier::new(keys, DeploymentName::new("fixture"), mapping);
        let grant = minter.mint(&json!({
            "aud": ["fixture"],
            "iat": FIXTURE_NOW,
            "exp": FIXTURE_NOW + 600,
            "team": TEAM_A,
            "tools": ["otto_read", "otto_draft", "otto_nowhere", "otto_unmapped"],
            "epoch": 1,
            "sid": "s",
            "tid": "t",
            "eid": "e",
            "actor": "a@example.test",
        }));
        let caller = fixture.principal(Caller::TeamA).unwrap();
        let verified = verifier
            .verify(
                grant.as_bytes(),
                &caller,
                UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW),
            )
            .unwrap();
        let tools = |surface: &str| -> Vec<String> {
            delegation(
                &verified,
                grant.as_bytes(),
                &fixture.policy,
                &SurfaceName::new(surface),
            )
            .tools
            .iter()
            .map(|tool| tool.as_str().to_owned())
            .collect()
        };
        assert_eq!(tools(SURFACE_READ), [READ_TOOL]);
        assert_eq!(tools(SURFACE_ALL), [DRAFT_TOOL, READ_TOOL]);
        assert!(tools("no-such-surface").is_empty());

        let delegation = delegation(
            &verified,
            grant.as_bytes(),
            &fixture.policy,
            &SurfaceName::new(SURFACE_READ),
        );
        assert_eq!(delegation.digest.to_hex(), verified.digest().to_string());
        assert_eq!(delegation.key_id.as_str(), minter.key_id().as_str());
        assert_eq!(delegation.issuer.as_str(), "otto-test");
        assert_eq!(delegation.egress, None);
    }

    #[test]
    fn a_previous_keys_end_must_be_an_instant() {
        let parse = |text: &str| -> toml::value::Datetime { text.parse().unwrap() };
        assert_eq!(unix_seconds(&parse("1970-01-01T00:00:00Z")), Some(0));
        assert_eq!(
            unix_seconds(&parse("2026-11-01T00:00:00Z")),
            Some(1_793_491_200)
        );
        assert_eq!(
            unix_seconds(&parse("2026-11-01T02:00:00+02:00")),
            Some(1_793_491_200)
        );
        assert_eq!(
            unix_seconds(&parse("2000-02-29T12:30:15Z")),
            Some(951_827_415)
        );
        for local in ["2026-11-01T00:00:00", "2026-11-01", "00:00:00"] {
            assert_eq!(unix_seconds(&parse(local)), None, "{local}");
        }
        assert_eq!(unix_seconds(&parse("1969-12-31T23:59:59Z")), None);
    }

    #[test]
    fn the_header_is_absent_once_or_more_than_once() {
        let mut headers = HeaderMap::new();
        assert_eq!(PresentedGrant::of(&headers), PresentedGrant::Absent);
        headers.append(GRANT_HEADER, "v3.a.b.c".parse().unwrap());
        assert_eq!(
            PresentedGrant::of(&headers),
            PresentedGrant::One(b"v3.a.b.c".to_vec())
        );
        headers.append(GRANT_HEADER, "v3.a.b.c".parse().unwrap());
        assert_eq!(PresentedGrant::of(&headers), PresentedGrant::Many);
        assert_eq!(
            format!("{:?}", PresentedGrant::One(b"v3.secret".to_vec())),
            "One(9 bytes)"
        );
    }
}
