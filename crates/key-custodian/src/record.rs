//! The custodian's own record: one JSON line per request, issued, refused or failed.
//!
//! A line names when, the peer's UID, the outcome and its reason, and what the request asked
//! for: the team, the tool, the repositories, the permissions and the revision it was decided
//! under, with the revision the custodian checked it against. Repositories are listed up to
//! [`LISTED_REPOSITORIES`], and past that only counted. A request refused before it was read,
//! or that did not parse, has only what is known. A malformed request has the tool, which
//! parsed as a tool name, and the team unless the team is what is malformed; the rest of it is
//! left out. A line never holds a token or the key.
//!
//! ```json
//! {"at":1760529600,"peer_uid":10001,"outcome":"issued","reason":null,"team":"team-a",
//!  "tool":"github__get_issue","repository_count":1,"repositories":["example-org/atlas"],
//!  "permissions":{"issues":"read"},"revision":"r7","checked_revision":"r7",
//!  "expires_at":1760529900}
//! ```

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Mutex, PoisonError};

use gateway_registry::Access;
use serde::Serialize;

use crate::protocol::TokenRequest;

/// The most repositories a line lists. Past this a line has only the count. The audit row
/// keeps 64 resources too.
pub const LISTED_REPOSITORIES: usize = 64;

/// One line of the record.
#[derive(Debug, Serialize)]
pub struct RecordLine<'a> {
    /// When, in seconds since the Unix epoch.
    pub at: u64,
    /// The connecting process's UID.
    pub peer_uid: u32,
    /// `issued`, `refused` or `failed`.
    pub outcome: &'static str,
    /// The refusal's or failure's reason; none for `issued`.
    pub reason: Option<&'static str>,
    /// The team, if the request was read.
    pub team: Option<&'a str>,
    /// The tool, if the request was read.
    pub tool: Option<&'a str>,
    /// How many repositories the request named, if it was read.
    pub repository_count: Option<usize>,
    /// The repositories, if the request was read and named no more than
    /// [`LISTED_REPOSITORIES`].
    pub repositories: Option<&'a [String]>,
    /// The permissions, if the request was read.
    pub permissions: Option<&'a BTreeMap<String, Access>>,
    /// The revision the request was decided under, if it was read.
    pub revision: Option<&'a str>,
    /// The revision of the copy of policy the custodian checked against.
    pub checked_revision: &'a str,
    /// When the token handed out expires, for `issued`.
    pub expires_at: Option<u64>,
}

impl<'a> RecordLine<'a> {
    /// A line for a request from `peer_uid` checked against `checked_revision`, before its
    /// outcome is known.
    pub fn new(at: u64, peer_uid: u32, checked_revision: &'a str) -> Self {
        Self {
            at,
            peer_uid,
            outcome: "refused",
            reason: None,
            team: None,
            tool: None,
            repository_count: None,
            repositories: None,
            permissions: None,
            revision: None,
            checked_revision,
            expires_at: None,
        }
    }

    /// The line with who asked, for a request refused as malformed: the tool, and the team if
    /// it is well formed (see [`TokenRequest::team_well_formed`]).
    pub fn attribution(mut self, request: &'a TokenRequest) -> Self {
        self.tool = Some(request.tool.as_str());
        self.team = request.team_well_formed().then_some(request.team.as_str());
        self
    }

    /// The line with what `request` asked for.
    pub fn request(mut self, request: &'a TokenRequest) -> Self {
        self.team = Some(request.team.as_str());
        self.tool = Some(request.tool.as_str());
        self.repository_count = Some(request.repositories.len());
        self.repositories = (request.repositories.len() <= LISTED_REPOSITORIES)
            .then_some(request.repositories.as_slice());
        self.permissions = Some(&request.permissions);
        self.revision = Some(request.revision.as_str());
        self
    }
}

/// Where the record goes: standard output for the custodian, a buffer in tests.
pub struct Recorder(Mutex<Box<dyn Write + Send>>);

impl Recorder {
    /// A record written to `sink`.
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self(Mutex::new(sink))
    }

    /// Writes `line` and flushes it. A failure is logged; the answer still goes.
    pub fn write(&self, line: &RecordLine<'_>) {
        let mut text = match serde_json::to_vec(line) {
            Ok(text) => text,
            Err(error) => {
                tracing::error!(%error, "could not serialize a record line");
                return;
            }
        };
        text.push(b'\n');
        let mut sink = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(error) = sink.write_all(&text).and_then(|()| sink.flush()) {
            tracing::error!(%error, "could not write a record line");
        }
    }
}
