//! The client the gateway asks the custodian with.
//!
//! [`CustodianClient::token`] connects to the socket, sends one [`TokenRequest`] and reads one
//! answer, all within the client's deadline. It returns a [`Token`] or a [`ClientError`], and
//! [`ClientError::error_kind`] is the kind an audit row records for it: a refusal by the
//! custodian is [`ErrorKind::CustodianRefusal`], GitHub's refusal of the token
//! [`ErrorKind::VendorRefusal`], and anything else [`ErrorKind::Other`].
//!
//! The client links nothing that reads the key: the key is in the custodian's process only.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use gateway_core::ErrorKind;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::protocol::{Answer, Failure, MAX_ANSWER_BYTES, Refusal, Secret, TokenRequest};

/// An installation token. Its `Debug` and `Display` never show it.
#[derive(Clone)]
pub struct Token {
    secret: Secret,
    expires_at: u64,
}

impl Token {
    /// The token's text, for an `Authorization` header and nothing else.
    pub fn expose(&self) -> &str {
        self.secret.expose()
    }

    /// When it stops being usable, in seconds since the Unix epoch.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("secret", &self.secret)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted token, expires at {}]", self.expires_at)
    }
}

/// Why no token came back.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The custodian refused the request.
    #[error("the custodian refused the token request ({}): {message}", reason.as_str())]
    Refused {
        /// Why.
        reason: Refusal,
        /// The custodian's sentence.
        message: String,
    },
    /// GitHub gave no token.
    #[error("GitHub gave no token ({}): {message}", reason.as_str())]
    Failed {
        /// Why.
        reason: Failure,
        /// The custodian's sentence.
        message: String,
    },
    /// The custodian could not be reached, or closed the connection without an answer.
    #[error("the custodian could not be asked: {0}")]
    Unavailable(String),
    /// No answer came within the deadline.
    #[error("the custodian did not answer within {0:?}")]
    Deadline(Duration),
    /// The answer was not one the client understands.
    #[error("the custodian's answer could not be read")]
    Protocol,
}

impl ClientError {
    /// The kind an audit row records for this error.
    pub fn error_kind(&self) -> ErrorKind {
        match self {
            Self::Refused { .. } => ErrorKind::CustodianRefusal,
            Self::Failed {
                reason: Failure::VendorRefused,
                ..
            } => ErrorKind::VendorRefusal,
            Self::Failed { .. } | Self::Unavailable(_) | Self::Deadline(_) | Self::Protocol => {
                ErrorKind::Other
            }
        }
    }
}

/// Asks the custodian at a socket for tokens.
#[derive(Clone, Debug)]
pub struct CustodianClient {
    socket: PathBuf,
    deadline: Duration,
}

impl CustodianClient {
    /// A client for the custodian at `socket`, giving each request `deadline`.
    pub fn new(socket: impl Into<PathBuf>, deadline: Duration) -> Self {
        Self {
            socket: socket.into(),
            deadline,
        }
    }

    /// Asks for a token for `request`.
    pub async fn token(&self, request: &TokenRequest) -> Result<Token, ClientError> {
        let mut line = serde_json::to_vec(request).map_err(|_| ClientError::Protocol)?;
        line.push(b'\n');
        let exchange = async {
            let mut stream = UnixStream::connect(&self.socket)
                .await
                .map_err(|error| ClientError::Unavailable(error.to_string()))?;
            stream
                .write_all(&line)
                .await
                .map_err(|error| ClientError::Unavailable(error.to_string()))?;
            let limit = u64::try_from(MAX_ANSWER_BYTES).unwrap_or(u64::MAX);
            let mut reader = BufReader::new(stream.take(limit));
            let mut answer = Vec::new();
            reader
                .read_until(b'\n', &mut answer)
                .await
                .map_err(|error| ClientError::Unavailable(error.to_string()))?;
            if answer.last() != Some(&b'\n') {
                return Err(if answer.is_empty() {
                    ClientError::Unavailable("the connection closed with no answer".into())
                } else {
                    ClientError::Protocol
                });
            }
            serde_json::from_slice::<Answer>(&answer).map_err(|_| ClientError::Protocol)
        };
        let answer = tokio::time::timeout(self.deadline, exchange)
            .await
            .map_err(|_| ClientError::Deadline(self.deadline))??;
        match answer {
            Answer::Issued { token, expires_at } => Ok(Token {
                secret: token,
                expires_at,
            }),
            Answer::Refused { reason, message } => Err(ClientError::Refused { reason, message }),
            Answer::Failed { reason, message } => Err(ClientError::Failed { reason, message }),
        }
    }
}
