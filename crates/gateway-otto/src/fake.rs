//! A fake resolver, behind the `test-support` feature: a local HTTP server that answers the
//! currency question as a test tells it. Decision 0012 has the adapter built and tested against
//! a fake resolver before Otto agrees to the interface.
//!
//! It speaks just enough HTTP/1.1 to answer one request per connection, written out by hand so
//! that it can send a body without its end, or nothing at all. It records every request it
//! reads, so a test can count the questions that reached it and look at what each carried.
//! Given a TLS server configuration, it serves over TLS instead.
//!
//! Nothing here is used by a running gateway.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::resolver::{Answer, MAX_ANSWER_BYTES, ResolverConfig, VERSION};

/// A member of the question, which [`FakeReply::OtherQuestion`] changes in its echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    /// `question`: the answer is to another kind of question.
    Question,
    /// `request_id`: the answer is to another request.
    RequestId,
    /// `sid`: another session.
    Session,
    /// `eid`: another execution.
    Execution,
    /// `tid`: another turn.
    Turn,
    /// `epoch`: another epoch.
    Epoch,
}

impl Member {
    /// Every member.
    pub const ALL: [Member; 6] = [
        Member::Question,
        Member::RequestId,
        Member::Session,
        Member::Execution,
        Member::Turn,
        Member::Epoch,
    ];

    /// The member's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Member::Question => "question",
            Member::RequestId => "request_id",
            Member::Session => "sid",
            Member::Execution => "eid",
            Member::Turn => "tid",
            Member::Epoch => "epoch",
        }
    }
}

/// What the fake does with each question.
#[derive(Clone, Copy, Debug)]
pub enum FakeReply {
    /// Answers `200` with this answer, echoing the question exactly.
    Answer(Answer),
    /// Answers `200` with this answer, echoing the question, under another version.
    UnknownVersion(Answer),
    /// Answers `200` with this answer, echoing the question with one member changed: the
    /// answer to another question.
    OtherQuestion(Answer, Member),
    /// Answers `200` with this answer to the question, then lets the function change the
    /// object before it is sent.
    Edited(Answer, fn(&mut Map<String, Value>)),
    /// Answers with this status and the body of an honest `current` answer, so only the
    /// status refuses it.
    Status(u16),
    /// Answers `200` with a body that is not JSON.
    NotJson,
    /// Answers `200` with an honest `current` answer padded with spaces to `bytes` bytes, with
    /// its length declared, or chunked when `declared` is false.
    Padded {
        /// The body's length.
        bytes: usize,
        /// Whether `Content-Length` declares it.
        declared: bool,
    },
    /// Reads the question and never answers.
    Hang,
    /// Sends a `200` head declaring an honest `current` answer's length and half of the body,
    /// then nothing more.
    HangInBody,
    /// Closes the connection without answering.
    Close,
}

impl FakeReply {
    /// An honest `current` answer padded to one byte more than the cap, its length declared
    /// or chunked.
    pub fn oversized(declared: bool) -> Self {
        FakeReply::Padded {
            bytes: MAX_ANSWER_BYTES + 1,
            declared,
        }
    }
}

/// A request the fake read.
#[derive(Clone, Debug)]
pub struct Received {
    /// The request line and headers, as sent.
    pub head: String,
    /// The body.
    pub body: Vec<u8>,
}

impl Received {
    /// The request line, such as `POST /v1/currency HTTP/1.1`.
    pub fn request_line(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }

    /// The value of the header `name`, if the request had it.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
    }

    /// The body as a JSON object, if it is one.
    pub fn question(&self) -> Option<Map<String, Value>> {
        match serde_json::from_slice(&self.body) {
            Ok(Value::Object(object)) => Some(object),
            _ => None,
        }
    }
}

struct Shared {
    reply: Mutex<FakeReply>,
    received: Mutex<Vec<Received>>,
}

/// A local resolver answering as it is told, on a loopback port of its own. It runs on the
/// Tokio runtime it was started on, until that runtime ends.
pub struct FakeResolver {
    address: SocketAddr,
    tls: bool,
    shared: Arc<Shared>,
}

impl FakeResolver {
    /// A fake over plain HTTP, replying with `reply` until told otherwise.
    pub async fn start(reply: FakeReply) -> std::io::Result<Self> {
        Self::listen(None, reply).await
    }

    /// A fake over TLS with `config`, replying with `reply` until told otherwise.
    pub async fn start_tls(config: Arc<ServerConfig>, reply: FakeReply) -> std::io::Result<Self> {
        Self::listen(Some(TlsAcceptor::from(config)), reply).await
    }

    async fn listen(acceptor: Option<TlsAcceptor>, reply: FakeReply) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let tls = acceptor.is_some();
        let shared = Arc::new(Shared {
            reply: Mutex::new(reply),
            received: Mutex::new(Vec::new()),
        });
        let state = Arc::clone(&shared);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&state);
                match acceptor.clone() {
                    None => {
                        tokio::spawn(serve(stream, state));
                    }
                    Some(acceptor) => {
                        tokio::spawn(async move {
                            // A handshake the client abandons is no request.
                            if let Ok(stream) = acceptor.accept(stream).await {
                                serve(stream, state).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(Self {
            address,
            tls,
            shared,
        })
    }

    /// Replies to every later question with `reply`.
    pub fn set(&self, reply: FakeReply) {
        *self
            .shared
            .reply
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = reply;
    }

    /// The interface's base URL.
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.address)
    }

    /// A configuration naming this fake, with no CA file and no token file: right for a fake
    /// over plain HTTP.
    pub fn config(&self) -> ResolverConfig {
        ResolverConfig {
            url: self.url(),
            ..ResolverConfig::default()
        }
    }

    /// Every request read so far, in order.
    pub fn received(&self) -> Vec<Received> {
        self.shared
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Reads one request and replies as the fake is told.
async fn serve(mut stream: impl AsyncRead + AsyncWrite + Unpin, shared: Arc<Shared>) {
    let mut read = Vec::new();
    let mut buffer = [0_u8; 4096];
    let end = loop {
        if let Some(end) = read.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => read.extend_from_slice(&buffer[..count]),
        }
    };
    let head = String::from_utf8_lossy(&read[..end]).into_owned();
    let mut body = read[end + 4..].to_vec();
    let length = head
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while body.len() < length {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => body.extend_from_slice(&buffer[..count]),
        }
    }
    body.truncate(length);
    let question = match serde_json::from_slice(&body) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    };
    shared
        .received
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Received { head, body });
    let reply = *shared.reply.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(question) = question else {
        let _ = stream.write_all(&response(400, b"")).await;
        let _ = stream.shutdown().await;
        return;
    };
    let written = match reply {
        FakeReply::Answer(answer) => ok(&answered(&question, answer)),
        FakeReply::UnknownVersion(answer) => {
            let mut object = answered(&question, answer);
            object.insert("version".to_owned(), Value::from("v2"));
            ok(&object)
        }
        FakeReply::OtherQuestion(answer, member) => {
            let mut object = answered(&question, answer);
            let changed = match object.get(member.name()) {
                Some(Value::Number(number)) => Value::from(number.as_u64().unwrap_or(0) + 1),
                Some(Value::String(text)) => Value::from(format!("{text}-other")),
                _ => Value::from("other"),
            };
            object.insert(member.name().to_owned(), changed);
            ok(&object)
        }
        FakeReply::Edited(answer, edit) => {
            let mut object = answered(&question, answer);
            edit(&mut object);
            ok(&object)
        }
        FakeReply::Status(status) => {
            let body = serialize(&answered(&question, Answer::Current));
            response(status, &body)
        }
        FakeReply::NotJson => response(200, b"current"),
        FakeReply::Padded { bytes, declared } => {
            let mut body = serialize(&answered(&question, Answer::Current));
            body.resize(bytes.max(body.len()), b' ');
            if declared {
                response(200, &body)
            } else {
                chunked(&body)
            }
        }
        FakeReply::Hang => {
            std::future::pending::<()>().await;
            return;
        }
        FakeReply::HangInBody => {
            let body = serialize(&answered(&question, Answer::Current));
            let mut written = head_with_length(200, body.len());
            written.extend_from_slice(&body[..body.len() / 2]);
            let _ = stream.write_all(&written).await;
            std::future::pending::<()>().await;
            return;
        }
        FakeReply::Close => {
            let _ = stream.shutdown().await;
            return;
        }
    };
    let _ = stream.write_all(&written).await;
    let _ = stream.shutdown().await;
}

/// The question's own object with `answer` added, under this version.
fn answered(question: &Map<String, Value>, answer: Answer) -> Map<String, Value> {
    let mut object = question.clone();
    object.insert("version".to_owned(), Value::from(VERSION));
    object.insert("answer".to_owned(), Value::from(answer.as_str()));
    object
}

fn serialize(object: &Map<String, Value>) -> Vec<u8> {
    serde_json::to_vec(object).unwrap_or_default()
}

fn ok(object: &Map<String, Value>) -> Vec<u8> {
    response(200, &serialize(object))
}

fn head_with_length(status: u16, length: usize) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} Fake\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes()
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut written = head_with_length(status, body.len());
    written.extend_from_slice(body);
    written
}

/// A `200` with `body` in chunks of 4 KiB and no declared length.
fn chunked(body: &[u8]) -> Vec<u8> {
    let mut written = b"HTTP/1.1 200 Fake\r\nContent-Type: application/json\r\n\
        Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        .to_vec();
    for chunk in body.chunks(4096) {
        written.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        written.extend_from_slice(chunk);
        written.extend_from_slice(b"\r\n");
    }
    written.extend_from_slice(b"0\r\n\r\n");
    written
}
