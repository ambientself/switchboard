//! A request answered at the protocol layer, before any policy.

use std::fmt;

use http::header::{ALLOW, WWW_AUTHENTICATE};
use http::{HeaderValue, StatusCode};
use serde_json::{Value, json};

use crate::constants::{
    CHALLENGE, DENIAL_CODE, HEADER_MISMATCH, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND,
    MODERN, PARSE_ERROR, UNSUPPORTED_VERSION,
};
use crate::message::{Era, RequestId};
use crate::reply::{HttpResponse, error_response};

/// Why a request was answered without reaching the gateway's logic. For logs and tests; the
/// caller sees the status and the JSON-RPC error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectionKind {
    /// 405: not a POST.
    MethodNotAllowed,
    /// 415: the body is not declared as `application/json`.
    UnsupportedMediaType,
    /// 406: an `Accept` header that does not admit `application/json`.
    NotAcceptable,
    /// 413: the body is larger than the gateway reads. Built by the HTTP layer.
    PayloadTooLarge,
    /// 403: a `Host` the gateway is not configured to answer for. Built by the HTTP layer.
    ForbiddenHost,
    /// 403: an `Origin` the gateway is not configured to accept. Built by the HTTP layer.
    ForbiddenOrigin,
    /// 401: the caller's identity was not proved. Built by the HTTP layer.
    Unauthorized,
    /// 400, -32700: the body is not JSON.
    ParseError,
    /// 400, -32600: JSON, but not a single request or notification this endpoint takes: a
    /// batch, a response, a `null` identifier, a legacy request naming a version not served.
    InvalidRequest,
    /// -32602: the parameters, or the 2026-07-28 `_meta` fields, are missing or malformed.
    InvalidParams,
    /// 400, -32020: a 2026-07-28 header is missing, malformed, or disagrees with the body.
    HeaderMismatch,
    /// 400, -32022: a 2026-07-28 request for a version this endpoint does not serve.
    UnsupportedVersion,
    /// -32601: no such method in this era. 404 under 2026-07-28, 200 under 2025-06-18.
    MethodNotFound,
}

/// A request refused at the protocol layer: the HTTP status, the JSON-RPC error, and the
/// request's identifier when it could be read.
#[derive(Clone, Debug, PartialEq)]
pub struct Rejection {
    kind: RejectionKind,
    status: StatusCode,
    code: i64,
    message: String,
    data: Option<Value>,
    id: Option<RequestId>,
}

impl Rejection {
    fn new(kind: RejectionKind, status: StatusCode, code: i64, message: impl Into<String>) -> Self {
        Rejection {
            kind,
            status,
            code,
            message: message.into(),
            data: None,
            id: None,
        }
    }

    pub(crate) fn with_id(mut self, id: &RequestId) -> Self {
        self.id = Some(id.clone());
        self
    }

    pub(crate) fn method_not_allowed() -> Self {
        Rejection::new(
            RejectionKind::MethodNotAllowed,
            StatusCode::METHOD_NOT_ALLOWED,
            INVALID_REQUEST,
            "Method not allowed: this endpoint takes POST only",
        )
    }

    pub(crate) fn unsupported_media_type() -> Self {
        Rejection::new(
            RejectionKind::UnsupportedMediaType,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            INVALID_REQUEST,
            "Unsupported media type: the body must be application/json",
        )
    }

    pub(crate) fn not_acceptable() -> Self {
        Rejection::new(
            RejectionKind::NotAcceptable,
            StatusCode::NOT_ACCEPTABLE,
            INVALID_REQUEST,
            "Not acceptable: every answer is application/json",
        )
    }

    pub(crate) fn parse_error() -> Self {
        Rejection::new(
            RejectionKind::ParseError,
            StatusCode::BAD_REQUEST,
            PARSE_ERROR,
            "Parse error: the body is not JSON",
        )
    }

    pub(crate) fn invalid_request(message: impl Into<String>) -> Self {
        Rejection::new(
            RejectionKind::InvalidRequest,
            StatusCode::BAD_REQUEST,
            INVALID_REQUEST,
            message,
        )
    }

    /// Under 2026-07-28 a malformed request is a 400; under 2025-06-18 the request was read, so
    /// it is answered with 200 and the error, as other JSON-RPC errors are.
    pub(crate) fn invalid_params(era: Era, id: &RequestId, message: impl Into<String>) -> Self {
        let status = match era {
            Era::Modern => StatusCode::BAD_REQUEST,
            Era::Legacy => StatusCode::OK,
        };
        Rejection::new(
            RejectionKind::InvalidParams,
            status,
            INVALID_PARAMS,
            message,
        )
        .with_id(id)
    }

    pub(crate) fn header_mismatch(id: &RequestId, message: impl Into<String>) -> Self {
        Rejection::new(
            RejectionKind::HeaderMismatch,
            StatusCode::BAD_REQUEST,
            HEADER_MISMATCH,
            message,
        )
        .with_id(id)
    }

    pub(crate) fn unsupported_version(id: &RequestId, requested: &str) -> Self {
        let mut rejection = Rejection::new(
            RejectionKind::UnsupportedVersion,
            StatusCode::BAD_REQUEST,
            UNSUPPORTED_VERSION,
            "Unsupported protocol version",
        )
        .with_id(id);
        rejection.data = Some(json!({"supported": [MODERN], "requested": requested}));
        rejection
    }

    /// The spec requires 404 for an unknown method under 2026-07-28. Under 2025-06-18 it is 200,
    /// so a legacy client does not mistake the endpoint for a missing one.
    pub(crate) fn method_not_found(era: Era, id: &RequestId, method: &str) -> Self {
        let status = match era {
            Era::Modern => StatusCode::NOT_FOUND,
            Era::Legacy => StatusCode::OK,
        };
        Rejection::new(
            RejectionKind::MethodNotFound,
            status,
            METHOD_NOT_FOUND,
            format!("Method not found: {method} is not served under {era}"),
        )
        .with_id(id)
    }

    /// 413, for a body larger than the gateway reads.
    pub fn payload_too_large() -> Self {
        Rejection::new(
            RejectionKind::PayloadTooLarge,
            StatusCode::PAYLOAD_TOO_LARGE,
            INVALID_REQUEST,
            "Payload too large",
        )
    }

    /// 403, for a `Host` header the gateway does not answer for.
    pub fn forbidden_host() -> Self {
        Rejection::new(
            RejectionKind::ForbiddenHost,
            StatusCode::FORBIDDEN,
            INVALID_REQUEST,
            "Forbidden: host not allowed",
        )
    }

    /// 403, for an `Origin` header the gateway does not accept.
    pub fn forbidden_origin() -> Self {
        Rejection::new(
            RejectionKind::ForbiddenOrigin,
            StatusCode::FORBIDDEN,
            INVALID_REQUEST,
            "Forbidden: origin not allowed",
        )
    }

    /// 401 with a `Bearer` challenge, [`DENIAL_CODE`] and the given message, for an identity
    /// failure of any cause. Pass the core's one identity sentence, so the bytes are the same
    /// whatever the cause; the cause belongs in a log, never here.
    pub fn unauthorized(message: &str) -> Self {
        Rejection::new(
            RejectionKind::Unauthorized,
            StatusCode::UNAUTHORIZED,
            DENIAL_CODE,
            message,
        )
    }

    /// Why the request was refused.
    pub fn kind(&self) -> RejectionKind {
        self.kind
    }

    /// The HTTP status the refusal is sent with.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The JSON-RPC error code.
    pub fn code(&self) -> i64 {
        self.code
    }

    /// The JSON-RPC error message. Protocol text; never a policy sentence.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The JSON-RPC error's `data`, when there is one.
    pub fn data(&self) -> Option<&Value> {
        self.data.as_ref()
    }

    /// The request's identifier, when it could be read before the refusal. The answer's `id`
    /// is `null` otherwise.
    pub fn id(&self) -> Option<&RequestId> {
        self.id.as_ref()
    }

    /// The response to send.
    pub fn response(&self) -> HttpResponse {
        let mut response = error_response(
            self.status,
            self.id.as_ref(),
            self.code,
            &self.message,
            self.data.as_ref(),
        );
        match self.kind {
            RejectionKind::MethodNotAllowed => {
                response
                    .headers
                    .insert(ALLOW, HeaderValue::from_static("POST"));
            }
            RejectionKind::Unauthorized => {
                response
                    .headers
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static(CHALLENGE));
            }
            _ => {}
        }
        response
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for Rejection {}
