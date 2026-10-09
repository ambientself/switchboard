//! The gateway's own credentials for proxied servers, read from files.
//!
//! Each proxied server gets one credential file, named in configuration by the server's
//! connector. Every file is read when the source is loaded, so a missing, empty or malformed
//! file stops the gateway at boot rather than failing its first call. Each file is then read
//! again on every call, with the same checks, so a token rotated in place, such as a projected
//! service account token the kubelet replaces, is the one sent. A file that fails those checks
//! later refuses the call, and nothing is sent; the connector logs why at warn, naming the
//! connector and the file but never what it holds.
//!
//! The secret never leaves this crate, and the source keeps no copy of it.
//! [`CredentialSource::credential_for`] hands out a [`CredentialHandle`], which carries only a
//! label; the bearer token itself is read by [`ProxyConnector`](crate::ProxyConnector) through
//! a crate-private method, and only while it builds the upstream request.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use gateway_core::{
    BoxFuture, ConnectorName, CredentialError, CredentialHandle, CredentialSource, Principal,
    Proved,
};
use thiserror::Error;

/// The longest credential file read, in bytes. A bearer token is far shorter; a larger file is
/// the wrong file.
pub const MAX_CREDENTIAL_BYTES: u64 = 8 * 1024;

/// The gateway's credentials for proxied servers, one per connector, each read from its file on
/// every call.
///
/// These are gateway credentials: the same one is used for every caller of a connector, and
/// the caller's own token is never among them. The caller is still passed in, as the core's
/// interface requires, so a source that narrows per team can replace this one.
pub struct FileCredentials {
    entries: BTreeMap<ConnectorName, Stored>,
}

struct Stored {
    label: String,
    path: PathBuf,
}

/// A bearer token. It implements neither `Debug` nor `Display`, so it cannot be formatted by
/// mistake; only [`bearer`](Self::bearer) reads it.
pub(crate) struct Secret(String);

impl Secret {
    /// The token, for the `Authorization` header and nothing else.
    pub(crate) fn bearer(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FileCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.entries
                    .iter()
                    .map(|(connector, stored)| (connector, &stored.label)),
            )
            .finish()
    }
}

/// Why the credential files could not be loaded. No variant carries a file's contents.
#[derive(Debug, Error)]
pub enum CredentialFileError {
    /// Two entries named the same connector.
    #[error("connector `{0}` is given more than one credential file")]
    Duplicate(ConnectorName),
    /// The file could not be read.
    #[error(
        "the credential file for connector `{connector}` at {path} could not be read: {source}"
    )]
    Unreadable {
        /// The connector the file is for.
        connector: ConnectorName,
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_CREDENTIAL_BYTES`].
    #[error(
        "the credential file for connector `{connector}` at {path} is larger than {MAX_CREDENTIAL_BYTES} bytes"
    )]
    TooLarge {
        /// The connector the file is for.
        connector: ConnectorName,
        /// The file.
        path: PathBuf,
    },
    /// The file holds nothing but whitespace.
    #[error("the credential file for connector `{connector}` at {path} is empty")]
    Empty {
        /// The connector the file is for.
        connector: ConnectorName,
        /// The file.
        path: PathBuf,
    },
    /// The file holds something a bearer token cannot be: text that is not UTF-8, or a space or
    /// control character inside the token.
    #[error(
        "the credential file for connector `{connector}` at {path} does not hold one bearer token"
    )]
    NotAToken {
        /// The connector the file is for.
        connector: ConnectorName,
        /// The file.
        path: PathBuf,
    },
}

impl FileCredentials {
    /// Reads one credential file per connector, and keeps each file's path to read it again on
    /// every call.
    ///
    /// Each file holds one bearer token. Whitespace around it, such as a trailing newline, is
    /// trimmed. The token must be printable ASCII with no spaces, which is what an HTTP header
    /// can carry. Any file that cannot be read or does not hold a token refuses the whole set.
    pub fn load<I, P>(files: I) -> Result<Self, CredentialFileError>
    where
        I: IntoIterator<Item = (ConnectorName, P)>,
        P: AsRef<Path>,
    {
        let mut entries = BTreeMap::new();
        for (connector, path) in files {
            if entries.contains_key(&connector) {
                return Err(CredentialFileError::Duplicate(connector));
            }
            let path = path.as_ref();
            read_secret(&connector, path)?;
            let label = format!("gateway credential for {connector}");
            let path = path.to_owned();
            entries.insert(connector, Stored { label, path });
        }
        Ok(Self { entries })
    }

    /// The connectors this source holds a credential for.
    pub fn connectors(&self) -> impl Iterator<Item = &ConnectorName> {
        self.entries.keys()
    }

    /// The handle and the secret for a call to `connector`, with the secret read from its file
    /// now. Only this crate sees the secret.
    ///
    /// A file that no longer passes the checks [`load`](Self::load) made refuses the call. The
    /// refusal names the connector and the file, never what the file holds.
    pub(crate) fn issue(
        &self,
        connector: &ConnectorName,
        _caller: &Proved<Principal>,
    ) -> Result<(CredentialHandle, Secret), CredentialError> {
        let Some(stored) = self.entries.get(connector) else {
            return Err(CredentialError::Refused(format!(
                "no gateway credential is configured for connector `{connector}`"
            )));
        };
        let secret = read_secret(connector, &stored.path)
            .map_err(|failed| CredentialError::Refused(failed.to_string()))?;
        Ok((CredentialHandle::new(stored.label.clone()), secret))
    }
}

impl CredentialSource for FileCredentials {
    fn credential_for<'a>(
        &'a self,
        connector: &'a ConnectorName,
        caller: &'a Proved<Principal>,
    ) -> BoxFuture<'a, Result<CredentialHandle, CredentialError>> {
        let issued = self.issue(connector, caller).map(|(handle, _)| handle);
        Box::pin(std::future::ready(issued))
    }
}

/// Reads and checks the token in `path`, reading no more than one byte past the limit, so a
/// file that grows while it is read is still refused.
fn read_secret(connector: &ConnectorName, path: &Path) -> Result<Secret, CredentialFileError> {
    let unreadable = |source| CredentialFileError::Unreadable {
        connector: connector.clone(),
        path: path.to_owned(),
        source,
    };
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_CREDENTIAL_BYTES + 1).read_to_end(&mut bytes))
        .map_err(unreadable)?;
    let length = bytes.len() as u64;
    if length > MAX_CREDENTIAL_BYTES {
        return Err(CredentialFileError::TooLarge {
            connector: connector.clone(),
            path: path.to_owned(),
        });
    }
    let not_a_token = || CredentialFileError::NotAToken {
        connector: connector.clone(),
        path: path.to_owned(),
    };
    let text = String::from_utf8(bytes).map_err(|_| not_a_token())?;
    let token = text.trim();
    if token.is_empty() {
        return Err(CredentialFileError::Empty {
            connector: connector.clone(),
            path: path.to_owned(),
        });
    }
    if !token.bytes().all(is_token_byte) {
        return Err(not_a_token());
    }
    Ok(Secret(token.to_owned()))
}

/// Printable ASCII other than the space: what a bearer token can be made of.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_graphic()
}
