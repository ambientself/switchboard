//! Decision 0012's currency question on the request path (#22): how Otto's resolver is
//! configured, the gate that needs one, and when a call asks it.
//!
//! **Configuration.** [`ResolverSection`] names Otto's resolver interface
//! (`docs/resolver-interface.md`): its base URL, the CA bundle its certificate must chain to,
//! and the file holding the token the gateway presents, a projected ServiceAccount token whose
//! audience is the resolver. It is the deployment file's optional `[resolver]` table (see
//! [`crate::deployment`]). [`start::prepare`](crate::start::prepare) builds the client from it,
//! with `gateway_otto::HttpResolver::new`, which refuses a configuration it cannot use, and
//! hands it to the boot gates with [`Wiring::resolver`](crate::Wiring::resolver).
//!
//! **The gate.** A profile a rule selects that requires currency needs a resolver: with none,
//! every side effect under it would be denied as unconfirmed. So the gateway refuses to start
//! with such a profile and no resolver, and refuses a registry version that adds one while it
//! runs, keeping the version it serves, as it does for the grant gates. With no profile
//! requiring currency the table may be left out, and nothing is asked.
//!
//! **When a call asks.** [`question`] says: a `tools/call` of a tool that the snapshot the call
//! is decided from serves on the call's surface and does not classify `read`, under a profile
//! that requires currency, with a verified delegation. Then the request path asks the resolver
//! once, with the question [`CurrencyQuestion::of`] the delegation makes, and decides with
//! `Currency::Asked` and the answer, which the core records on the row. Every other call is
//! decided with `Currency::NotAsked`: a read, a call under a profile that does not require
//! currency, a tool the surface does not serve, which check 2 denies, and a call with no
//! delegation or one that did not verify, which check 3 denies before the currency check. A
//! `tools/list` never asks, and nothing is cached: each call that asks is one question.
//!
//! How a question fails is the client's business, in gateway-otto: every failure is
//! unconfirmed, at most the one-second budget after asking, and the core denies it. Reads are
//! never asked about, so they keep working while the resolver is down.

use std::fmt;
use std::path::{Path, PathBuf};

use gateway_core::{
    CallerContext, Classification, PolicySnapshot, PresentedDelegation, ProfileName, RequestedTool,
};
use gateway_otto::{CurrencyQuestion, ResolverConfig};
use serde::Deserialize;

use crate::policy::ServedPolicy;

/// Where Otto's resolver interface is, and the files that authenticate it and the gateway: the
/// deployment file's `[resolver]` table.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverSection {
    /// The interface's base URL: `https`, or plain `http` to a loopback address only.
    pub url: String,
    /// The PEM bundle of the only CAs the resolver's certificate may chain to. Required for
    /// `https`, refused for `http`.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// The file holding the bearer token sent with each question: a projected ServiceAccount
    /// token whose audience is the resolver, read at boot and again for every question.
    /// Refused for `http`.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

impl fmt::Debug for ResolverSection {
    /// Never the URL: one that carries a password, which the client refuses, would print it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverSection")
            .field("ca_file", &self.ca_file)
            .field("token_file", &self.token_file)
            .finish_non_exhaustive()
    }
}

impl ResolverSection {
    /// This section with its files read from `base`, the deployment file's directory.
    pub(crate) fn relative_to(self, base: &Path) -> Self {
        Self {
            url: self.url,
            ca_file: self.ca_file.map(|path| base.join(path)),
            token_file: self.token_file.map(|path| base.join(path)),
        }
    }

    /// The client's configuration.
    pub fn config(&self) -> ResolverConfig {
        ResolverConfig {
            url: self.url.clone(),
            ca_file: self.ca_file.clone(),
            token_file: self.token_file.clone(),
        }
    }
}

/// The first profile a rule of `policy` selects that requires currency, if any: what the
/// currency gate refuses while no resolver is configured.
pub(crate) fn profile_requiring_currency(policy: &ServedPolicy) -> Option<ProfileName> {
    policy.selected_profiles().into_iter().find(|profile| {
        policy
            .snapshot()
            .profile(profile)
            .is_some_and(|profile| profile.requires_currency)
    })
}

/// The question a `tools/call` of `requested` from `caller`, decided from `snapshot`, asks the
/// resolver, or `None` when it asks nothing. See the [module documentation](self).
pub(crate) fn question(
    snapshot: &PolicySnapshot,
    caller: &CallerContext,
    requested: &RequestedTool,
) -> Option<CurrencyQuestion> {
    let requires_currency = snapshot
        .profile(&caller.profile)
        .is_some_and(|profile| profile.requires_currency);
    if !requires_currency {
        return None;
    }
    let side_effect = requested
        .name()
        .ok()
        .and_then(|name| snapshot.tool_on_surface(&caller.surface, &name))
        .is_some_and(|tool| tool.classification != Classification::Read);
    if !side_effect {
        return None;
    }
    match &caller.delegation {
        Some(PresentedDelegation::Verified(delegation)) => {
            Some(CurrencyQuestion::of(delegation.get()))
        }
        Some(PresentedDelegation::Unverified(_)) | None => None,
    }
}
