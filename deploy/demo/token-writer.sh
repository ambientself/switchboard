#!/bin/sh
# deploy/demo/token-writer.sh: the kind demo's token writer (decision 0013, section 10). It runs
# as a sidecar in the gateway's pod (deploy/kind/base/gateway.yaml). For each ServiceAccount it
# is given, one per entry of the mock server in the registry, it asks the API server for a token
# by TokenRequest and writes it to a file the gateway reads as that entry's credential. The
# gateway itself holds no token the API server accepts and has no API-server client.
#
# Usage: token-writer.sh [once]
#   (none)  write every token, then again every TOKEN_REFRESH_SECONDS; after a failure, try again
#           in TOKEN_RETRY_SECONDS. Runs until stopped.
#   once    write every token once; exit 1 if any could not be written.
#
# Environment, every variable required:
#   TOKEN_SERVICE_ACCOUNTS    space-separated ServiceAccount names, e.g. "docs-team-a docs-team-b"
#   TOKEN_NAMESPACE           their namespace
#   TOKEN_AUDIENCE            the audience each token is for, the server's: mock-docs
#   TOKEN_EXPIRATION_SECONDS  how long each token is valid, 600 to 86400
#   TOKEN_REFRESH_SECONDS     how often each is written again, less than the expiration
#   TOKEN_RETRY_SECONDS       how soon after a failure
#   TOKEN_DIR                 where each token is written, as TOKEN_DIR/<ServiceAccount>
#   API_SERVER                the API server's URL, e.g. https://kubernetes.default.svc
#   API_TOKEN_FILE            this container's own token for the API server, read on every request
#   API_CA_FILE               the cluster's CA, which the API server's certificate must chain to
#
# It never prints a token. The API token goes to curl on its standard input, never on a command
# line, and each written token only into its file. Each file is written whole to a new file in
# TOKEN_DIR and renamed over the old one, so the gateway reads the old token or the new one,
# never part of either. A token that cannot be had leaves its file as it was. A setting that is
# missing or not a number exits 2 before anything is asked.
#
# Needs sh, curl, jq and mv. The demo image has them.
set -u
umask 077

MODE=${1:-run}

log() { echo "token-writer: $*"; }
bad_config() {
  log "bad configuration: $*" >&2
  exit 2
}

# number NAME VALUE MIN MAX: VALUE is a whole number from MIN to MAX, or the configuration is bad.
number() {
  case $2 in
    '' | *[!0-9]*) bad_config "$1 must be a whole number of seconds, not '$2'" ;;
  esac
  [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] || bad_config "$1 must be from $3 to $4, not $2"
}

for name in TOKEN_SERVICE_ACCOUNTS TOKEN_NAMESPACE TOKEN_AUDIENCE TOKEN_EXPIRATION_SECONDS \
  TOKEN_REFRESH_SECONDS TOKEN_RETRY_SECONDS TOKEN_DIR API_SERVER API_TOKEN_FILE API_CA_FILE; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || bad_config "$name is not set"
done
number TOKEN_EXPIRATION_SECONDS "$TOKEN_EXPIRATION_SECONDS" 600 86400
number TOKEN_REFRESH_SECONDS "$TOKEN_REFRESH_SECONDS" 1 $((TOKEN_EXPIRATION_SECONDS - 1))
number TOKEN_RETRY_SECONDS "$TOKEN_RETRY_SECONDS" 1 "$TOKEN_REFRESH_SECONDS"
case $API_SERVER in https://*) ;; *) bad_config "API_SERVER must be an https URL, not '$API_SERVER'" ;; esac
[ -d "$TOKEN_DIR" ] || bad_config "TOKEN_DIR $TOKEN_DIR is not a directory"
for account in $TOKEN_SERVICE_ACCOUNTS; do
  case $account in
    *[!a-z0-9.-]* | -* | '') bad_config "'$account' is not a ServiceAccount name" ;;
  esac
done
case $MODE in run | once) ;; *) bad_config "usage: $0 [once]" ;; esac

# The TokenRequest every token is asked with: the server's audience and the expiration only.
BODY=$(jq -cn --arg audience "$TOKEN_AUDIENCE" --argjson seconds "$TOKEN_EXPIRATION_SECONDS" \
  '{apiVersion: "authentication.k8s.io/v1", kind: "TokenRequest",
    spec: {audiences: [$audience], expirationSeconds: $seconds}}') ||
  bad_config "cannot build the TokenRequest"

# write ACCOUNT: asks for ACCOUNT's token and renames it into TOKEN_DIR/ACCOUNT. Returns non-zero,
# with the file left as it was, if it cannot.
write() {
  account=$1
  target=$TOKEN_DIR/$account
  next=$TOKEN_DIR/.$account.next
  api=$(cat "$API_TOKEN_FILE" 2>/dev/null) || api=""
  if [ -z "$api" ]; then
    log "$account: cannot read the API token in $API_TOKEN_FILE; keeping the previous token"
    return 1
  fi
  # The header comes from standard input, so the API token is on no command line. The answer is
  # kept in a variable and only the token is taken from it; neither is printed.
  answer=$(printf 'Authorization: Bearer %s\n' "$api" |
    curl -q -sS --fail -m 10 --cacert "$API_CA_FILE" -H @- \
      -H 'Content-Type: application/json' -H 'Accept: application/json' \
      -X POST --data-binary "$BODY" \
      "$API_SERVER/api/v1/namespaces/$TOKEN_NAMESPACE/serviceaccounts/$account/token")
  code=$?
  if [ "$code" -ne 0 ]; then
    log "$account: the TokenRequest failed (curl exit $code); keeping the previous token"
    return 1
  fi
  token=$(printf '%s' "$answer" | jq -er '.status.token | select(type == "string" and test("^[!-~]+$"))' 2>/dev/null) || token=""
  if [ -z "$token" ]; then
    log "$account: the answer holds no token; keeping the previous token"
    return 1
  fi
  if ! printf '%s\n' "$token" >"$next" || ! mv -f "$next" "$target"; then
    rm -f "$next"
    log "$account: cannot write $target; keeping the previous token"
    return 1
  fi
  log "$account: wrote a token for audience $TOKEN_AUDIENCE, valid for ${TOKEN_EXPIRATION_SECONDS}s"
}

# write_all: every account's token; non-zero if any could not be written.
write_all() {
  failed=0
  for account in $TOKEN_SERVICE_ACCOUNTS; do
    write "$account" || failed=1
  done
  return "$failed"
}

if [ "$MODE" = once ]; then
  write_all
  exit
fi

# Sleeps in the background so SIGTERM ends the wait at once: as PID 1 the shell gets no default
# action for it.
trap 'exit 0' TERM INT
while :; do
  if write_all; then wait_for=$TOKEN_REFRESH_SECONDS; else wait_for=$TOKEN_RETRY_SECONDS; fi
  sleep "$wait_for" &
  wait $!
done
