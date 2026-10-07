#!/bin/sh
# deploy/demo/workload.sh: the scripted workload of decision 0008. It is not a model: it makes
# fixed calls through the gateway and checks each answer exactly. Every check prints one PASS
# or FAIL line; the last line is the RESULT, and the exit status is 0 only if every check
# passed. Nothing is retried.
#
# Usage: workload.sh [MODE]
#   full           (default) initialize, tools/list, an allowed read, a denied read, a call that
#                  names no project, identity failures, and, when DIRECT_URL is set, the direct
#                  call to the server that network policy must stop
#   before-policy  call DIRECT_URL with this workload's own token; the server must answer 401
#   refused        this workload's own token must be refused (a ServiceAccount not in the
#                  team manifest)
#   audit-down     one allowed read while the audit database is unavailable; the gateway must
#                  refuse it with the audit-failure sentence
#   withdrawn      after docs__read_document is withdrawn from the registry: tools/list drops it
#                  and a call to it is refused
#
# Environment:
#   GATEWAY_URL      the surface's endpoint, e.g. http://gateway:8080/mcp/docs
#   TOKEN_FILE       a file holding this workload's token, or
#   TOKEN_URL        a URL that answers with this workload's token (the Compose dev issuer)
#   OWN_PROJECT      the project this workload's team may read
#   OTHER_PROJECT    the other team's project
#   BAD_TOKEN_FILES  space-separated files, each holding a real token the gateway must refuse
#   BAD_TOKEN_URLS   space-separated URLs, each answering with such a token
#   DIRECT_URL       the server's own address, bypassing the gateway
#   DIRECT_TIMEOUT   seconds to wait on DIRECT_URL, default 3
#
# The tool names and their arguments are the demo registry's (deploy/*/config/registry); the
# `plan` document and the projects `atlas` and `borealis` are the mock server's
# (crates/mock-docs-server). The sentences are the core's (crates/gateway-core/src/sentences.rs);
# crates/demo-checks tests that they still match.
set -u

MODE=${1:-full}
GW=${GATEWAY_URL:?GATEWAY_URL is required}
SURFACE=${GW##*/}
PROTOCOL=2025-06-18
LIST_TOOL=docs__list_documents
READ_TOOL=docs__read_document
DOCUMENT=plan

IDENTITY_FAILURE='The gateway could not verify who is calling, so the call was refused.'
AUDIT_FAILURE='The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.'

PASSES=0
FAILS=0
BODY=$(mktemp) || { echo "FAIL setup: cannot create a temporary file"; exit 1; }
trap 'rm -f "$BODY"' EXIT

pass() { PASSES=$((PASSES + 1)); echo "PASS $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL $1"; }
# check GOT WANT NAME
check() {
  if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1', want '$2')"; fi
}
note() { echo "     $1"; }
finish() {
  total=$((PASSES + FAILS))
  if [ "$FAILS" -eq 0 ] && [ "$total" -gt 0 ]; then
    echo "RESULT: PASS ($PASSES/$total)"
    exit 0
  fi
  echo "RESULT: FAIL ($FAILS of $total failed)"
  exit 1
}
setup_failed() { fail "setup: $1"; finish; }

# fetch URL: a token from the dev issuer, or nothing and a non-zero status.
fetch() { curl -fsS -m 10 "$1"; }

load_token() {
  if [ -n "${TOKEN_FILE:-}" ]; then
    TOKEN=$(cat "$TOKEN_FILE") || setup_failed "cannot read TOKEN_FILE $TOKEN_FILE"
  elif [ -n "${TOKEN_URL:-}" ]; then
    TOKEN=$(fetch "$TOKEN_URL") || setup_failed "cannot fetch a token from TOKEN_URL"
  else
    setup_failed "set TOKEN_FILE or TOKEN_URL"
  fi
  [ -n "$TOKEN" ] || setup_failed "the workload's token is empty"
}

# rpc TOKEN METHOD PARAMS: prints the HTTP status, or `curl exit N`; the body is in $BODY.
# An empty TOKEN sends no Authorization header.
rpc() {
  : >"$BODY"
  if [ -n "$1" ]; then
    set -- "$2" "$3" -H "Authorization: Bearer $1"
  else
    set -- "$2" "$3"
  fi
  method=$1
  params=$2
  shift 2
  if [ "${method#notifications/}" != "$method" ]; then
    payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params}"
  else
    payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
  fi
  status=$(curl -sS -m 10 -o "$BODY" -w '%{http_code}' "$GW" "$@" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H "MCP-Protocol-Version: $PROTOCOL" -d "$payload")
  code=$?
  if [ "$code" -ne 0 ]; then echo "curl exit $code"; else echo "$status"; fi
}
call() { rpc "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; }
# body FILTER: applies a jq filter to the last body; prints `invalid JSON` if it is not JSON.
body() { jq -r "$1" "$BODY" 2>/dev/null || echo "invalid JSON"; }

# An allowed call: HTTP 200, a result with isError exactly false, and some content.
expect_allowed() {
  check "$1" 200 "$2: HTTP status"
  check "$(body '.result.isError')" false "$2: isError"
  check "$(body '(.result.content // []) | length > 0')" true "$2: has content"
}
# A refused call: HTTP 200 and JSON-RPC error -32001.
expect_denied() {
  check "$1" 200 "$2: HTTP status"
  check "$(body '.error.code')" -32001 "$2: error code"
  note "sentence: $(body '.error.message')"
}
# An identity failure: HTTP 401, -32001 and the one opaque sentence.
expect_identity_failure() {
  check "$1" 401 "$2: HTTP status"
  check "$(body '.error.code')" -32001 "$2: error code"
  check "$(body '.error.message')" "$IDENTITY_FAILURE" "$2: sentence"
}

full() {
  load_token
  own_args="{\"project\":\"$OWN_PROJECT\",\"document\":\"$DOCUMENT\"}"
  other_args="{\"project\":\"$OTHER_PROJECT\",\"document\":\"$DOCUMENT\"}"

  status=$(rpc "$TOKEN" initialize "{\"protocolVersion\":\"$PROTOCOL\",\"capabilities\":{},\"clientInfo\":{\"name\":\"mock-workload\",\"version\":\"0\"}}")
  check "$status" 200 "initialize: HTTP status"
  check "$(body '.result.protocolVersion')" "$PROTOCOL" "initialize: protocol version"
  check "$(rpc "$TOKEN" notifications/initialized '{}')" 202 "notifications/initialized: HTTP status"

  status=$(rpc "$TOKEN" tools/list '{}')
  check "$status" 200 "tools/list: HTTP status"
  check "$(body '[.result.tools[].name] | sort | join(",")')" "$LIST_TOOL,$READ_TOOL" "tools/list: names"

  expect_allowed "$(call "$TOKEN" "$LIST_TOOL" "{\"project\":\"$OWN_PROJECT\"}")" "list own project $OWN_PROJECT"
  expect_allowed "$(call "$TOKEN" "$READ_TOOL" "$own_args")" "read own project $OWN_PROJECT"

  expect_denied "$(call "$TOKEN" "$READ_TOOL" "$other_args")" "read other project $OTHER_PROJECT"
  sentence=$(body '.error.message')
  check "$(printf '%s' "$sentence" | grep -c "^Tool \`$READ_TOOL\` names docs project \`$OTHER_PROJECT\`, which is outside what .*\. Name only resources within that limit\.$")" 1 \
    "read other project $OTHER_PROJECT: the resource-limit sentence"

  expect_denied "$(call "$TOKEN" "$READ_TOOL" "{\"document\":\"$DOCUMENT\"}")" "read naming no project"
  check "$(body '.error.message')" \
    "Tool \`$READ_TOOL\` reaches resources the gateway must check, and this call named none of them, so it cannot be allowed. Name the resource the call is for." \
    "read naming no project: the none-named sentence"

  expect_identity_failure "$(call "" "$LIST_TOOL" "{\"project\":\"$OWN_PROJECT\"}")" "identity failure (no token)"
  expect_identity_failure "$(call "not-a-token" "$LIST_TOOL" "{\"project\":\"$OWN_PROJECT\"}")" "identity failure (not a token)"
  for file in ${BAD_TOKEN_FILES:-}; do
    bad=$(cat "$file") || { fail "identity failure ($file): cannot read the file"; continue; }
    expect_identity_failure "$(call "$bad" "$LIST_TOOL" "{\"project\":\"$OWN_PROJECT\"}")" "identity failure ($file)"
  done
  for url in ${BAD_TOKEN_URLS:-}; do
    bad=$(fetch "$url") || { fail "identity failure ($url): cannot fetch the token"; continue; }
    expect_identity_failure "$(call "$bad" "$LIST_TOOL" "{\"project\":\"$OWN_PROJECT\"}")" "identity failure ($url)"
  done

  if [ -n "${DIRECT_URL:-}" ]; then
    # Network policy must drop the connection, so curl times out: exit 28. Any other failure
    # (a DNS miss, a refused port, a 401 from the server) proves nothing and fails the check.
    curl -sS -m "${DIRECT_TIMEOUT:-3}" -o /dev/null "$DIRECT_URL" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' 2>/dev/null
    check "$?" 28 "direct call to the server refused (curl exit 28 at $DIRECT_URL)"
    # The positive control, in the same pod: the gateway is reachable and still reaches the server.
    check "$(rpc "$TOKEN" ping '{}')" 200 "same pod still reaches the gateway"
    expect_allowed "$(call "$TOKEN" "$READ_TOOL" "$own_args")" "same pod's read through the gateway"
  fi
}

before_policy() {
  load_token
  : "${DIRECT_URL:?DIRECT_URL is required}"
  : >"$BODY"
  status=$(curl -sS -m "${DIRECT_TIMEOUT:-3}" -o "$BODY" -w '%{http_code}' "$DIRECT_URL" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}')
  code=$?
  check "$code" 0 "before policy: the direct call connects ($DIRECT_URL)"
  check "$status" 401 "before policy: the server refuses the workload's own token"
}

refused() {
  load_token
  expect_identity_failure "$(rpc "$TOKEN" tools/list '{}')" "identity failure (own token)"
}

audit_down() {
  load_token
  expect_denied "$(call "$TOKEN" "$READ_TOOL" "{\"project\":\"$OWN_PROJECT\",\"document\":\"$DOCUMENT\"}")" "read while the audit database is down"
  check "$(body '.error.message')" "$AUDIT_FAILURE" "read while the audit database is down: the audit-failure sentence"
}

withdrawn() {
  load_token
  status=$(rpc "$TOKEN" tools/list '{}')
  check "$status" 200 "tools/list after withdrawal: HTTP status"
  check "$(body '[.result.tools[].name] | sort | join(",")')" "$LIST_TOOL" "tools/list after withdrawal: names"
  expect_denied "$(call "$TOKEN" "$READ_TOOL" "{\"project\":\"$OWN_PROJECT\",\"document\":\"$DOCUMENT\"}")" "call to the withdrawn tool"
  check "$(body '.error.message')" \
    "Tool \`$READ_TOOL\` is not available on surface \`$SURFACE\`. Call \`tools/list\` to see the tools this surface serves." \
    "call to the withdrawn tool: the not-available sentence"
}

case "$MODE" in
  full) : "${OWN_PROJECT:?}" "${OTHER_PROJECT:?}"; full ;;
  before-policy) before_policy ;;
  refused) refused ;;
  audit-down) : "${OWN_PROJECT:?}"; audit_down ;;
  withdrawn) : "${OWN_PROJECT:?}"; withdrawn ;;
  *) echo "usage: $0 [full|before-policy|refused|audit-down|withdrawn]" >&2; exit 2 ;;
esac
finish
