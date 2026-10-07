//! The protocol's fixed values: versions, error codes, header names and `_meta` keys.

/// The current MCP revision. A request that carries its protocol version is served as this.
pub const MODERN: &str = "2026-07-28";

/// The revision every `initialize` is answered with, whatever was asked, as Otto's gateway does.
pub const LEGACY: &str = "2025-06-18";

/// The JSON-RPC code for a policy denial, a scope refusal, an audit failure and an identity
/// failure, in both eras (decision 0007, owner answer Q1 for now).
pub const DENIAL_CODE: i64 = -32001;

/// `HeaderMismatch` (2026-07-28): a mirrored header is missing, malformed, or disagrees with
/// the body.
pub const HEADER_MISMATCH: i64 = -32020;

/// `UnsupportedProtocolVersion` (2026-07-28). Its `data` names the supported versions and the
/// requested one.
pub const UNSUPPORTED_VERSION: i64 = -32022;

/// JSON-RPC: the body is not JSON.
pub const PARSE_ERROR: i64 = -32700;

/// JSON-RPC: the body is JSON but not a single request or notification this endpoint takes.
pub const INVALID_REQUEST: i64 = -32600;

/// JSON-RPC: no such method in this era.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC: the method's parameters are missing or malformed.
pub const INVALID_PARAMS: i64 = -32602;

/// JSON-RPC: the gateway failed in a way that is not the caller's doing.
pub const INTERNAL_ERROR: i64 = -32603;

/// How long a client may cache `tools/list` and `server/discover`, in milliseconds. Zero for
/// now (owner answer Q8): a withdrawn tool must disappear at once.
pub const LIST_TTL_MS: u64 = 0;

/// The `WWW-Authenticate` challenge sent with every 401.
pub const CHALLENGE: &str = "Bearer realm=\"switchboard\"";

/// The header that mirrors the request's protocol version. Header names are matched without
/// regard to case; these are written in lower case, as `http` stores them.
pub const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// The header that mirrors the request's `method` (2026-07-28).
pub const METHOD_HEADER: &str = "mcp-method";

/// The header that mirrors `params.name` on a `tools/call` (2026-07-28).
pub const NAME_HEADER: &str = "mcp-name";

/// The session header of revisions up to 2025-11-25. Ignored when it arrives, never sent.
pub const SESSION_ID_HEADER: &str = "mcp-session-id";

/// The resumption header of revisions up to 2025-11-25. Ignored when it arrives.
pub const LAST_EVENT_ID_HEADER: &str = "last-event-id";

/// The `_meta` key carrying the request's protocol version (2026-07-28).
pub const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key carrying the client's capabilities, required on every 2026-07-28 request.
pub const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";

/// The `_meta` key a 2026-07-28 result names the server under.
pub const SERVER_INFO_META: &str = "io.modelcontextprotocol/serverInfo";

/// The `_meta` key Claude Code puts its tool-use identifier under on a `tools/call`.
pub const TOOL_USE_ID_META: &str = "claudecode/toolUseId";
