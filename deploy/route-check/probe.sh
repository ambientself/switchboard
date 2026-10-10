#!/bin/sh
# deploy/route-check/probe.sh: the probe of the route check (decision 0010, "The route check").
# The operator step (route-check.sh) starts it in a pod of the workload as an ephemeral
# container, so it has the pod's network; the image installs it as /usr/local/bin/route-probe.sh.
# It needs nothing from the agent's image, and it sends no credential: no attempt carries an
# Authorization header.
#
# First it POSTs to GATEWAY_URL. Any HTTP status (401 is expected) means the gateway was reached;
# if it was not, the probe fails before it tries any route. Then it tries each route in ROUTES:
# by name, unless the URL's host is an address literal, and by each address the row gives. The
# name is resolved with getent first, so a name that does not resolve, or whose lookup times
# out, is "could-not-probe", never "refused" at the server's address. A URL whose host is an
# address literal is tried only at that host, so the row's addresses must include it, or the
# row fails: a refusal at some other address would say nothing about the host. A host of digits
# and dots that is not an IPv4 literal (10.0.0.256) fails its row too: curl would look it up as
# a name, with no getent first.
#
# Environment:
#   ROUTES         the routes file's contents, with {{ADDR}} already replaced. Tab-separated
#                  columns: name, url, addresses, flags. addresses is a comma list of address
#                  literals, or `resolve` for the addresses the name resolves to in the pod (for
#                  a URL whose host is an address literal, that host). flags
#                  is empty or a comma list; reject_ok counts a refused connection as refused. A
#                  line starting with # is a comment.
#   GATEWAY_URL    the gateway's endpoint
#   EXPECT         refused (default): every attempt must be refused; open: every one must be open
#   PROBE_TIMEOUT  seconds each attempt may take, default 3
#
# Output, the interface route-check.sh reads: one line per attempt,
#   ROUTE <row> <name|address> <target> <refused|open|could-not-probe>
# where the target is the URL for a name and the address for an address, and a last line
# `RESULT: PASS` or `RESULT: FAIL`. The exit status is 0 on PASS and 1 on FAIL.
#
# Each attempt is classified from what curl saw:
#   an HTTP status, whatever it is          open: something answered
#   timed out before it connected           refused: dropped on the way to the address
#     (curl exit 28, no connection made)
#   connected, then timed out with no       could-not-probe: something took the connection, so
#     answer (curl exit 28)                 the route was not refused, but nothing answered
#   connection refused (curl exit 7)        refused for a row flagged reject_ok, where the route
#                                           is refused by a reset, if no connection was made;
#                                           could-not-probe otherwise, as a stopped server or a
#                                           wrong port looks the same, and a refusal after a
#                                           connection (curl retries on its own, as after an
#                                           HTTP/2 REFUSED_STREAM) means something was reached
#   a name that does not resolve (or 6)     could-not-probe
#   curl printed anything but one status    could-not-probe: the attempt was not one request
#     and one connection count
#   anything else                           could-not-probe
#
# One row is one request to each target: curl runs with globbing off, and a URL that holds a
# glob character ({, }, [ or ], other than the brackets of an IPv6 host) fails its row. Two
# requests in one curl run print two results and exit with the last one's status, so a refused
# second request could hide a first that connected.
#
# curl runs with proxies off (--noproxy '*'), whatever the environment says: through a proxy,
# an attempt would test the route to the proxy, not to the target.
#
# Needs sh, curl and getent.
set -u

TAB=$(printf '\t')
EXPECT=${EXPECT:-refused}
PROBE_TIMEOUT=${PROBE_TIMEOUT:-3}
GATEWAY_URL=${GATEWAY_URL:-}
ROUTES=${ROUTES:-}
# A harmless JSON-RPC request; what matters is whether anything answers it.
BODY='{"jsonrpc":"2.0","id":1,"method":"ping"}'

ATTEMPTS=0
WANTED=0
BROKEN=0

finish() {
  if [ "$BROKEN" -eq 0 ] && [ "$ATTEMPTS" -gt 0 ] && [ "$WANTED" -eq "$ATTEMPTS" ]; then
    echo "PASS every route $EXPECT ($ATTEMPTS attempts)"
    echo "RESULT: PASS"
    exit 0
  fi
  if [ "$ATTEMPTS" -eq 0 ]; then
    echo "FAIL no route was tried"
  elif [ "$WANTED" -ne "$ATTEMPTS" ]; then
    echo "FAIL $((ATTEMPTS - WANTED)) of $ATTEMPTS attempts were not $EXPECT"
  fi
  echo "RESULT: FAIL"
  exit 1
}

# stop REASON: fails the run before any route is tried.
stop() {
  echo "FAIL $1"
  echo "RESULT: FAIL"
  exit 1
}

case $EXPECT in refused | open) ;; *) stop "EXPECT is refused or open, not $EXPECT" ;; esac
case $PROBE_TIMEOUT in '' | *[!0-9]* | 0) stop "PROBE_TIMEOUT is a number of seconds, not $PROBE_TIMEOUT" ;; esac
[ -n "$GATEWAY_URL" ] || stop "GATEWAY_URL is not set"

# post URL [CURL OPTION...]: one POST with no credential. Prints the HTTP status (000 when
# nothing answered), a space and the number of connections curl made, and returns curl's exit
# status. Both a connect that times out and an answer that does not come in time are curl exit
# 28; only the count of connections tells them apart. -q keeps any .curlrc out; -g turns URL
# globbing off, so the URL is one request; --noproxy '*' keeps the proxy variables (http_proxy
# and the rest) from sending it through a proxy; the empty Authorization header keeps curl from
# adding one.
post() {
  post_url=$1
  shift
  curl -q -g -s --noproxy '*' -o /dev/null -w '%{http_code} %{num_connects}' -X POST \
    -H 'Authorization:' -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --connect-timeout "$PROBE_TIMEOUT" --max-time "$PROBE_TIMEOUT" \
    --data "$BODY" "$@" "$post_url" </dev/null 2>/dev/null
}

# one_transfer OUTPUT: whether OUTPUT is what post prints for exactly one request: three digits
# of HTTP status, a space and a number of connections. Sets transfer_code and transfer_connects.
# Two requests' results run together ("000 1000 0") are not one.
one_transfer() {
  transfer_code='' transfer_connects=''
  case $1 in
    [0-9][0-9][0-9]' '*) ;;
    *) return 1 ;;
  esac
  transfer_connects=${1#???' '}
  case $transfer_connects in '' | *[!0-9]*) return 1 ;; esac
  transfer_code=${1%%' '*}
}

# classify EXIT STATUS CONNECTIONS FLAGS: the result of one attempt.
classify() {
  case $2 in
    '' | 000) ;;
    *) echo open; return ;;
  esac
  case $1 in
    28)
      # Refused only when no connection was made. A connection that was made and then got no
      # answer in time was taken by something: that is not a refusal.
      case $3 in
        0) echo refused ;;
        *) echo could-not-probe ;;
      esac
      ;;
    7)
      # Refused only on a row flagged reject_ok, and only when no connection was made. curl
      # retries on its own (after an HTTP/2 REFUSED_STREAM, for one), so a refused retry can
      # follow a connection to a server that was reached.
      case ,$4,:$3 in
        *,reject_ok,*:0) echo refused ;;
        *) echo could-not-probe ;;
      esac
      ;;
    *) echo could-not-probe ;;
  esac
}

# record ROW BY TARGET RESULT [WHY]: prints the attempt's line and counts it.
record() {
  echo "ROUTE $1 $2 $3 $4"
  [ -z "${5:-}" ] || echo "NOTE $1 $2 $3: $5"
  ATTEMPTS=$((ATTEMPTS + 1))
  [ "$4" != "$EXPECT" ] || WANTED=$((WANTED + 1))
}

# attempt ROW BY TARGET URL FLAGS [CURL OPTION...]
attempt() {
  attempt_row=$1 attempt_by=$2 attempt_target=$3 attempt_url=$4 attempt_flags=$5
  shift 5
  attempt_out=$(post "$attempt_url" "$@")
  attempt_exit=$?
  if ! one_transfer "$attempt_out"; then
    record "$attempt_row" "$attempt_by" "$attempt_target" could-not-probe \
      "curl printed \"$attempt_out\", not one request's status (curl exit $attempt_exit)"
    return
  fi
  attempt_code=$transfer_code attempt_connects=$transfer_connects
  attempt_result=$(classify "$attempt_exit" "$attempt_code" "$attempt_connects" "$attempt_flags")
  if [ "$attempt_result" = could-not-probe ]; then
    attempt_why="curl exit $attempt_exit"
    if [ "$attempt_exit" -eq 28 ] && [ -n "$attempt_connects" ] && [ "$attempt_connects" != 0 ]; then
      attempt_why="connected, but nothing answered in ${PROBE_TIMEOUT}s (curl exit 28)"
    elif [ "$attempt_exit" -eq 7 ] && [ -n "$attempt_connects" ] && [ "$attempt_connects" != 0 ]; then
      attempt_why="connected, then a connection was refused (curl exit 7)"
    fi
    record "$attempt_row" "$attempt_by" "$attempt_target" "$attempt_result" "$attempt_why"
  else
    record "$attempt_row" "$attempt_by" "$attempt_target" "$attempt_result"
  fi
}

# resolve NAME: the addresses NAME resolves to, one per line; nothing if it does not resolve.
resolve() {
  getent ahosts "$1" 2>/dev/null | while read -r resolved _; do
    case $resolved in
      '' | *[!0-9a-fA-F.:]*) ;;
      *) echo "$resolved" ;;
    esac
  done | unique
}

# unique: its input's lines, each once, in order.
unique() {
  seen=" "
  while read -r line; do
    case $seen in *" $line "*) continue ;; esac
    seen="$seen$line "
    echo "$line"
  done
}

# literals ADDRESSES: whether each entry of a comma list is an address literal. One without a
# colon must be four decimal octets, 0 to 255, with no leading zero: curl looks up anything else
# (deadbeef, 10.0.0.256) as a name, and a lookup that times out would count as refused. One with
# a colon goes to curl in brackets, which curl takes only as an IPv6 literal, never as a name.
literals() {
  for literal_entry in $(IFS=,; for entry in $1; do echo "$entry"; done); do
    case $literal_entry in
      *:*) continue ;;
      *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    # shellcheck disable=SC2046 # split on the dots
    set -- $(IFS=.; for octet in $literal_entry; do echo "$octet"; done)
    [ $# -eq 4 ] || return 1
    for octet; do
      case $octet in 0) ;; 0* | ????*) return 1 ;; esac
      [ "$octet" -le 255 ] || return 1
    done
  done
}

# bracketed ADDRESS: an IPv6 literal in brackets, as a URL and curl's --resolve take it.
bracketed() {
  case $1 in *:*) echo "[$1]" ;; *) echo "$1" ;; esac
}

# --- 1. The gateway ---------------------------------------------------------------------------

out=$(post "$GATEWAY_URL")
status=$?
one_transfer "$out" || stop "gateway check: curl printed \"$out\", not one request's status (curl exit $status)"
code=$transfer_code
case $code in
  '' | 000) stop "gateway unreachable: $GATEWAY_URL (curl exit $status)" ;;
esac
echo "PASS gateway reached: $GATEWAY_URL answered HTTP $code"

# --- 2. The routes ----------------------------------------------------------------------------

# broken NUMBER WHY: a row the probe cannot try fails the run.
broken() {
  echo "FAIL routes line $1: $2"
  BROKEN=$((BROKEN + 1))
}

number=0
while IFS="$TAB" read -r row url addresses flags extra; do
  number=$((number + 1))
  case $row in '' | '#'*) continue ;; esac
  case $row$url$addresses$flags in
    *' '* | *"$(printf '\r')"*) broken "$number" "a column holds a space"; continue ;;
  esac
  [ -z "$extra" ] || { broken "$number" "more than four columns"; continue; }
  case $flags in
    '' | - | reject_ok) ;;
    *) broken "$number" "unknown flags $flags"; continue ;;
  esac
  case $url in
    http://*) scheme=http port=80 ;;
    https://*) scheme=https port=443 ;;
    *) broken "$number" "the URL is not http or https: $url"; continue ;;
  esac
  rest=${url#*://}
  authority=${rest%%[/?#]*}
  path=${rest#"$authority"}
  # The bracket is quoted: dash takes an unquoted [ as the start of a pattern and strips nothing.
  case $authority in
    *@*) broken "$number" "the URL carries a user name or password"; continue ;;
    '['*']') host=${authority#'['} host=${host%]} ;;
    '['*']:'*) host=${authority#'['} host=${host%%]*} port=${authority##*]:} ;;
    *:*) host=${authority%:*} port=${authority##*:} ;;
    *) host=$authority ;;
  esac
  # curl would expand a glob into several requests; the brackets of an IPv6 host are not one.
  glob_rest=$rest
  case $authority in '['*) glob_rest=${rest#*]} ;; esac
  case $glob_rest in
    *'{'* | *'}'* | *'['* | *']'*) broken "$number" "the URL holds a curl glob character: $url"; continue ;;
  esac
  case $port in '' | *[!0-9]*) broken "$number" "the URL's port is not a number"; continue ;; esac
  case $host in
    '' | *[!0-9a-zA-Z.:_-]*) broken "$number" "the URL's host is not a name or an address"; continue ;;
  esac
  # An address literal in the URL is tried by address only. curl takes a bracketed host only as
  # an IPv6 literal.
  literal=""
  case $authority in
    '['*)
      case $host in
        *[!0-9a-fA-F.:]*) ;;
        *:*) literal=1 ;;
      esac
      [ -n "$literal" ] || { broken "$number" "the URL has a bracketed host that is not an IPv6 address: $url"; continue; }
      ;;
    *)
      case $host in *[!0-9.]*) ;; *) literal=1 ;; esac
      # curl looks up a dotted host that is not an IPv4 literal (10.0.0.256) as a name, and a
      # lookup that times out would count as refused.
      if [ -n "$literal" ] && ! literals "$host"; then
        broken "$number" "the URL has a host of digits and dots that is not an IPv4 address: $url"
        continue
      fi
      ;;
  esac
  case $addresses in
    '') broken "$number" "no addresses"; continue ;;
    resolve) ;;
    *)
      case $addresses in
        *[!0-9a-fA-F.:,]* | ,* | *, | *,,*) broken "$number" "addresses are not address literals: $addresses"; continue ;;
      esac
      literals "$addresses" || { broken "$number" "addresses are not address literals: $addresses"; continue; }
      # The host of a URL with an address literal is tried only by address, so it must be one.
      if [ -n "$literal" ]; then
        case ,$addresses, in
          *,"$host",*) ;;
          *) broken "$number" "the host $host of the URL is not one of its addresses: $addresses"; continue ;;
        esac
      fi
      ;;
  esac

  if [ -n "$literal" ]; then
    # An address literal stands for itself: `resolve` tries the URL's own host.
    found=$host
  else
    found=$(resolve "$host")
  fi
  if [ -z "$literal" ]; then
    if [ -z "$found" ]; then
      record "$row" name "$url" could-not-probe "$host does not resolve"
    else
      pinned=""
      for address in $found; do
        pinned="$pinned${pinned:+,}$(bracketed "$address")"
      done
      # curl connects to the addresses just resolved, so a slow lookup cannot time out as a
      # refused connection.
      attempt "$row" name "$url" "$url" "$flags" --resolve "$host:$port:$pinned"
    fi
  fi
  if [ "$addresses" = resolve ]; then
    if [ -z "$found" ]; then
      record "$row" address "$host" could-not-probe "$host does not resolve, so it has no address to try"
      continue
    fi
    list=$found
  else
    list=$(IFS=,; for address in $addresses; do echo "$address"; done | unique)
  fi
  for address in $list; do
    attempt "$row" address "$address" "$scheme://$(bracketed "$address"):$port$path" "$flags"
  done
done <<EOF
$ROUTES
EOF

finish
