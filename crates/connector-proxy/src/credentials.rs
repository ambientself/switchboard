//! The gateway's own credentials for proxied servers, read from files.
//!
//! Each proxied server gets one credential file, named in configuration by the server's
//! connector. The files are read once, when the source is loaded, so a missing, empty or
//! malformed file stops the gateway at boot rather than failing its first call. Changing a
//! credential means restarting the gateway.
//!
//! The secret never leaves this crate. [`CredentialSource::credential_for`] hands out a
//! [`CredentialHandle`], which carries only a label; the bearer token itself is read by
//! [`ProxyConnector`](crate::ProxyConnector) through a crate-private method, and only while it
//! builds the upstream request.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use gateway_core::{
    BoxFuture, ConnectorName, CredentialError, CredentialHandle, CredentialSource, Principal,
    Proved,
};
use thiserror::Error;

/// The longest credential file read, in bytes. A bearer token is far shorter; a larger file is
/// the wrong file.
pub const MAX_CREDENTIAL_BYTES: u64 = 8 * 1024;

/// The gateway's credentials for proxied servers, one per connector, each read from a file.
///
/// These are gateway credentials: the same one is used for every caller of a connector, and
/// the caller's own token is never among them. The caller is still passed in, as the core's
/// interface requires, so a source that narrows per team can replace this one.
pub struct FileCredentials {
    entries: BTreeMap<ConnectorName, Stored>,
}

struct Stored {
    label: String,
    secret: Secret,
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
    /// Reads one credential file per connector.
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
            let secret = read_secret(&connector, path.as_ref())?;
            let label = format!("gateway credential for {connector}");
            entries.insert(connector, Stored { label, secret });
        }
        Ok(Self { entries })
    }

    /// The connectors this source holds a credential for.
    pub fn connectors(&self) -> impl Iterator<Item = &ConnectorName> {
        self.entries.keys()
    }

    /// The handle and the secret for a call to `connector`. Only this crate sees the secret.
    pub(crate) fn issue(
        &self,
        connector: &ConnectorName,
        _caller: &Proved<Principal>,
    ) -> Result<(CredentialHandle, &Secret), CredentialError> {
        match self.entries.get(connector) {
            Some(stored) => Ok((CredentialHandle::new(stored.label.clone()), &stored.secret)),
            None => Err(CredentialError::Refused(format!(
                "no gateway credential is configured for connector `{connector}`"
            ))),
        }
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

fn read_secret(connector: &ConnectorName, path: &Path) -> Result<Secret, CredentialFileError> {
    let unreadable = |source| CredentialFileError::Unreadable {
        connector: connector.clone(),
        path: path.to_owned(),
        source,
    };
    let length = std::fs::metadata(path).map_err(unreadable)?.len();
    if length > MAX_CREDENTIAL_BYTES {
        return Err(CredentialFileError::TooLarge {
            connector: connector.clone(),
            path: path.to_owned(),
        });
    }
    let bytes = std::fs::read(path).map_err(unreadable)?;
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
