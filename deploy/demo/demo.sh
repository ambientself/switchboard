#!/usr/bin/env bash
# deploy/demo/demo.sh: the demo in one command.
#
#   demo.sh compose   build the image; start Postgres, the migration, the dev issuer, mock-docs
#                     and the gateway under Compose; run both teams' workloads; show a database
#                     outage and a withdrawn tool; check the audit rows
#   demo.sh kind      the same in the kind cluster switchboard-demo, with projected
#                     ServiceAccount tokens, network policy, the operator's permission checks,
#                     and the route check (deploy/route-check) before and after the policy
#   demo.sh down compose   stop Compose and delete its volumes; the cluster is left alone
#   demo.sh down kind      delete the kind cluster switchboard-demo; Compose is left alone
#   demo.sh down all       both
#
# A run leaves what it started running, so it can be looked at afterwards.
#
# Every check prints PASS or FAIL. The last line is the RESULT with the count, and the exit
# status is non-zero if any check failed or any step could not run. Nothing is retried and no
# failure is ignored.
#
# It never touches any cluster but switchboard-demo, and never ~/.kube/config. It refuses any
# other cluster name (otto-dev included), drops KUBECONFIG from its environment, and names its
# own kubeconfig file, .demo/kubeconfig, in every kubectl and kind call.
#
# Needs docker (with compose), kind, kubectl, jq, awk and tar on the host.
#
# What it reads, and where each comes from:
#   - the gateway's JSON log lines (crates/gateway): one `"event":"boot"` line per gate, with
#     `"identity":"enforce"` and `"audit":"postgres"`, and one `"event":"identity_failed"` line
#     per caller refused for identity;
#   - mock-docs' JSON log lines (crates/mock-docs-server): one per request, with
#     `bearer_sha256`, the first 12 hex digits of the bearer's SHA-256, and `accepted`, and for
#     a tools/call its `rpc_method`, `project` and, if the server refused the project,
#     `refused`. In kind the server runs in its JWT mode, and each line also has `caller`, the
#     verified subject of an accepted token, and `refusal`, why a token was refused;
#   - the audit table switchboard_audit.call_rows (crates/audit-postgres), read as
#     switchboard_reader;
#   - the gateway's GET /metrics, Prometheus text on its own listener (crates/gateway,
#     metrics.rs), read with curl inside the gateway's container: port 9090, on loopback in
#     Compose and on the pod's `metrics` port in kind.
set -euo pipefail
unset KUBECONFIG

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
# The demo's own cluster, and the only one it touches. SWITCHBOARD_DEMO_CLUSTER may name it
# again, but any other name is refused before any kind or kubectl call.
CLUSTER=switchboard-demo
if [ "${SWITCHBOARD_DEMO_CLUSTER:-$CLUSTER}" != "$CLUSTER" ]; then
  echo "demo.sh: refusing to touch the cluster ${SWITCHBOARD_DEMO_CLUSTER}; the demo uses only its own cluster, $CLUSTER" >&2
  exit 2
fi
DEMO_DIR=$ROOT/.demo
KCFG=$DEMO_DIR/kubeconfig
IMG=switchboard-demo:dev
IMG_RUN=$IMG
# Postgres, pinned by the digest of the tag's multi-arch index. Compose names the same reference;
# the kind manifest names only the tag, and load_images loads this digest under it.
# crates/demo-checks/tests/pins.rs holds every Postgres pin in the repository to one version and
# digest. Dependabot does not read this file: bump it by hand with the others (deploy/Dockerfile
# lists them), taking the digest from `docker buildx imagetools inspect postgres:<tag>`.
POSTGRES_IMAGE=postgres:17.11-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
COMPOSE_FILE=$ROOT/deploy/compose/compose.yaml
KIND_ISSUER=https://kubernetes.default.svc.cluster.local
# Where the kind gateway fetches that issuer's keys, with no token, and the cluster CA it trusts
# for it (deploy/kind/base: config/gateway.toml, gateway.yaml, issuer-discovery.yaml).
KIND_KEYS_URL=$KIND_ISSUER/openid/v1/jwks
KIND_CLUSTER_CA=/etc/switchboard/cluster-ca/ca.crt
# What the gateway logs at boot for each issuer whose keys it fetched (crates/gateway, start.rs).
KEYS_FETCHED_MESSAGE="fetched the issuer's keys from its keys URL"
# The mock server is registered once per team (deploy/*/config/registry): each team's entry is
# docs-<team>, which names its surface and the first part of its tools' names, and the gateway
# presents that entry's own credential on the team's calls. In kind each entry's identity is its
# ServiceAccount, whose token the gateway pod's token writer gets (deploy/kind/base); these are
# the only callers mock-docs accepts there. In Compose it is the entry's dummy credential.
KIND_ENTRY_SUBJECTS="system:serviceaccount:switchboard:docs-team-a system:serviceaccount:switchboard:docs-team-b"
COMPOSE_CREDENTIALS=$ROOT/deploy/compose/dummy-credentials
# The registries' revision, and the Compose withdrawal's (registry-withdrawn.toml).
REVISION=demo-3
WITHDRAWN_REVISION=demo-4
AUDIT_TABLE=switchboard_audit.call_rows
# The open-row query's view (crates/audit-postgres, sql/migrations/0005_open_rows.sql).
OPEN_ROWS_VIEW=switchboard_audit.open_call_rows
# The gateway's surfaces as the workloads reach them in kind, each at $KIND_GATEWAY_URL/<entry>
# (deploy/kind/base/workloads.yaml).
KIND_GATEWAY_URL=http://gateway.switchboard.svc.cluster.local:8080/mcp
# The route check (decision 0010): its operator step, the routes its probe tries in kind, and the
# one list of permissions that it and the operator checks ask about. The step runs as the
# ServiceAccount of deploy/kind/route-check/rbac.yaml, with that access and no more.
ROUTE_CHECK=$ROOT/deploy/route-check/route-check.sh
ROUTE_CHECK_ROUTES=$ROOT/deploy/route-check/routes/kind.tsv
PERMISSIONS=$ROOT/deploy/route-check/permissions.tsv
# The matcher of the RBAC rules bound to a ServiceAccount against that list, which the route
# check's operator step runs too (#60).
RBAC_MATCH=$ROOT/deploy/route-check/rbac-match.jq
ROUTE_CHECK_OPERATOR=system:serviceaccount:route-check:operator

PASSES=0
FAILS=0
FINISHED=""
CURRENT_STEP="start"
MODE=""
PAUSED=""
SINCE=""
# The same moment as SINCE, as an RFC 3339 time for `logs --since` and `logs --since-time`.
LOG_SINCE=""
# The database outage step's span, in the database's clock (epoch seconds); 0 to 0 if there was none.
OUTAGE_FROM=0
OUTAGE_TO=0
# The kind run's route checks: the last report written, and how many attempts the probe found
# open before the policy.
ROUTE_REPORT=""
OPEN_ATTEMPTS=""
GATEWAY_POD=""
# What the last fetch read.
FETCHED=""

k() { kubectl --kubeconfig "$KCFG" --context "kind-$CLUSTER" "$@"; }
# team_entry TEAM: TEAM's entry of the mock server, its surface. team_project TEAM: the project
# TEAM may read.
team_entry() { echo "docs-$1"; }
team_project() { case $1 in team-a) echo atlas ;; team-b) echo borealis ;; esac; }
# entry_sha TEAM: the SHA-256 of TEAM's entry's dummy credential in Compose.
entry_sha() { cat "$COMPOSE_CREDENTIALS/$(team_entry "$1")-credential.sha256"; }
dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

step() {
  CURRENT_STEP=$*
  printf '\n== %s\n' "$*"
}
pass() { PASSES=$((PASSES + 1)); echo "PASS $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL $1"; }
# check GOT WANT NAME
check() {
  if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1', want '$2')"; fi
}
# check_at_least GOT MIN NAME
check_at_least() {
  case "$1" in
    '' | *[!0-9]*) fail "$3 (got '$1', want a number of at least $2)" ;;
    *) if [ "$1" -ge "$2" ]; then pass "$3 ($1)"; else fail "$3 (got $1, want at least $2)"; fi ;;
  esac
}
# check_at_most GOT MAX NAME
check_at_most() {
  case "$1" in
    '' | *[!0-9]*) fail "$3 (got '$1', want a number of at most $2)" ;;
    *) if [ "$1" -le "$2" ]; then pass "$3 ($1)"; else fail "$3 (got $1, want at most $2)"; fi ;;
  esac
}
# count_lines PATTERN TEXT: how many lines of TEXT match the extended regex PATTERN.
count_lines() { printf '%s\n' "$2" | awk -v pattern="$1" '$0 ~ pattern { n++ } END { print n + 0 }'; }

# fetch WHAT COMMAND...: runs COMMAND and keeps what it printed in FETCHED. If COMMAND fails,
# fails the check "could not read WHAT" and returns non-zero, so the caller checks nothing from
# a read that may be short or empty: a log cut short can look like a shorter run that passed.
fetch() {
  local what=$1 status=0
  shift
  FETCHED=$("$@") || status=$?
  if [ "$status" -ne 0 ]; then
    fail "could not read $what (exit $status)"
    return 1
  fi
}

# result_total LINE: how many checks a RESULT line counts, as workload.sh and route-check.sh
# print it: `RESULT: PASS (P/T)` or `RESULT: FAIL (F of T failed)`. Nothing for any other line.
result_total() {
  printf '%s\n' "$1" | sed -nE 's/^RESULT: (PASS \([0-9]+\/([0-9]+)\)|FAIL \([0-9]+ of ([0-9]+) failed\))$/\2\3/p'
}

# tally_workload LABEL STATUS OUTPUT: adds a workload's PASS and FAIL lines to the count. It
# must have checked something, and its last RESULT line must count exactly the PASS and FAIL
# lines tallied, so a log cut short does not pass as a shorter run. That is the last RESULT
# line, not the last line: `dc run --rm` may print after it. Its exit status must agree with
# its lines.
tally_workload() {
  local label=$1 status=$2 output=$3 passed failed result total
  printf '%s\n' "$output" | sed 's/^/    /'
  passed=$(count_lines '^PASS ' "$output")
  failed=$(count_lines '^FAIL ' "$output")
  PASSES=$((PASSES + passed))
  FAILS=$((FAILS + failed))
  result=$(printf '%s\n' "$output" | awk '/^RESULT: / { last = $0 } END { print last }')
  total=$(result_total "$result")
  if [ "$passed" -eq 0 ] && [ "$failed" -eq 0 ]; then
    fail "$label: the workload ran no checks (exit $status)"
  elif [ -z "$result" ]; then
    fail "$label: the workload printed no RESULT line (exit $status)"
  elif [ "$total" != "$((passed + failed))" ]; then
    fail "$label: the workload's RESULT counts ${total:-no number of} checks, but $((passed + failed)) PASS and FAIL lines were read ($result)"
  elif [ "$status" -ne 0 ] && [ "$failed" -eq 0 ]; then
    fail "$label: the workload exited $status without a FAIL line"
  elif [ "$status" -eq 0 ] && [ "$failed" -ne 0 ]; then
    fail "$label: the workload exited 0 despite $failed FAIL lines"
  fi
}

# result STATUS: prints the RESULT line and exits; non-zero unless every check passed and the
# run finished.
result() {
  local status=$1 total
  if [ "$status" -ne 0 ] && [ -z "$FINISHED" ]; then
    fail "step '$CURRENT_STEP' could not complete (exit $status)"
  fi
  total=$((PASSES + FAILS))
  if [ "$FAILS" -eq 0 ] && [ "$total" -gt 0 ] && [ -n "$FINISHED" ]; then
    printf '\nRESULT: PASS (%s/%s)\n' "$PASSES" "$total"
    exit 0
  fi
  printf '\nRESULT: FAIL (%s of %s failed)\n' "$FAILS" "$total"
  exit 1
}

on_exit() {
  local status=$?
  trap - EXIT
  if [ -n "$PAUSED" ]; then
    echo "unpausing postgres after the interrupted outage step" >&2
    dc unpause postgres >&2 || echo "could not unpause postgres; run: docker compose -f $COMPOSE_FILE unpause postgres" >&2
  fi
  result "$status"
}

# psql_reader ARGS...: psql as switchboard_reader, in whichever deployment is running.
psql_reader() {
  case "$MODE" in
    compose) dc exec -T postgres psql -X -v ON_ERROR_STOP=1 -U switchboard_reader -d switchboard "$@" ;;
    kind) k -n switchboard exec -i deploy/postgres -- psql -X -v ON_ERROR_STOP=1 -U switchboard_reader -d switchboard "$@" ;;
  esac
}
psql_superuser() {
  case "$MODE" in
    compose) dc exec -T postgres psql -X -v ON_ERROR_STOP=1 -U postgres -d switchboard "$@" ;;
    kind) k -n switchboard exec -i deploy/postgres -- psql -X -v ON_ERROR_STOP=1 -U postgres -d switchboard "$@" ;;
  esac
}
audit_count() { psql_reader -Atc "select count(*) from $AUDIT_TABLE where begun_at >= to_timestamp($SINCE) and $1"; }
# open_count CONDITION: how many of this run's rows the open-row view shows that meet CONDITION.
open_count() { psql_reader -Atc "select count(*) from $OPEN_ROWS_VIEW where begun_at >= to_timestamp($SINCE) and $1"; }

mark_start() {
  local mark
  mark=$(psql_superuser -AtF ' ' -c "select extract(epoch from now()),
    to_char(now() at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
  SINCE=${mark% *}
  LOG_SINCE=${mark#* }
  echo "audit rows and mock-docs requests from this run start at epoch $SINCE ($LOG_SINCE)"
}

# mock_docs_log: mock-docs' log lines from this run's start. A run that follows another without
# `down` can reuse the same server, whose whole log holds the earlier run's requests too. The
# mark is Postgres' clock, which is the clock Docker and the kubelet stamp log lines with: all
# run on the same Docker host.
mock_docs_log() {
  case "$MODE" in
    compose) dc logs --no-log-prefix --since "$LOG_SINCE" mock-docs ;;
    kind) k -n mock-docs logs --since-time "$LOG_SINCE" deploy/mock-docs ;;
  esac
}

# project_json NAME: the `resources` column of a call that named only the docs project NAME.
project_json() { printf '[{"system":"docs","kind":"project","identifier":"%s"}]' "$1"; }

# row_resources_json: every row from this run, as one JSON array of what check_row_resources
# and check_list_rows read.
row_resources_json() {
  psql_reader -Atc "select coalesce(json_agg(json_build_object('kind', kind, 'team', proved_team,
      'tool', tool, 'decision', decision, 'reason', reason, 'sentence', sentence,
      'resources', resources, 'revision', policy_revision, 'listed', listed_tools,
      'omitted', listed_omitted)
      order by begun_at), '[]') from $AUDIT_TABLE where begun_at >= to_timestamp($SINCE)"
}

# check_row_resources ROWS: every row records what its call named. ROWS is a JSON array of
# {kind, team, tool, decision, reason, sentence, resources, ...}. Each row of kind `call` is
# matched to the demo's call that made it, and its resources must be what that call named:
#   - an allowed call: its team's own project (team-a atlas, team-b borealis);
#   - a call denied for naming no project: none, [];
#   - a call denied for its project: the other team's project;
#   - a call to a tool the gateway does not know: "unknown", since no adapter read the call.
# A row of kind `list` records a tools/list, which names no resources: its resources are null.
# check_list_rows counts those rows and checks what they name. A row that matches none of the
# demo's calls or lists fails the check too.
check_row_resources() {
  local rows=$1 total lists wrong
  # shellcheck disable=SC2016 # jq's own variables
  if ! wrong=$(printf '%s' "$rows" | jq -c '
      def project($name): [{system: "docs", kind: "project", identifier: $name}];
      def own: {"team-a": "atlas", "team-b": "borealis"}[.team // ""];
      def other: {"team-a": "borealis", "team-b": "atlas"}[.team // ""];
      def named:
        if .kind == "list" then null
        elif .kind != "call" then "no call of the demo makes this row"
        elif .decision == "allow" then project(own)
        elif .reason == "unknown_tool" then "unknown"
        elif .reason == "resource_outside_limit" and (.sentence // "" | contains("named none of them")) then []
        elif .reason == "resource_outside_limit" then project(other)
        else "no call of the demo makes this row" end;
      .[] | select(.resources != named) | {kind, team, tool, decision, reason, resources, named: named}') \
    || ! total=$(printf '%s' "$rows" | jq -e 'length') \
    || ! lists=$(printf '%s' "$rows" | jq -e '[.[] | select(.kind == "list")] | length'); then
    fail "audit: every row records the resources its call named (the rows are not a JSON array)"
    return
  fi
  if [ -n "$wrong" ]; then
    printf '%s\n' "$wrong" | sed 's/^/    wrong: /'
  fi
  if [ "$total" -eq 0 ]; then
    fail "audit: every row records the resources its call named (there are no rows)"
  else
    check "$(count_lines . "$wrong")" 0 \
      "audit: every row records the resources its call named ($total rows: $((total - lists)) calls, $lists lists)"
  fi
}

# check_list_rows ROWS EXPECTED: the rows of kind `list` are the workloads' tools/list calls,
# exactly EXPECTED of them: one per tools/list a workload made (decision 0009). An identity
# failure writes no row, so a refused caller's list leaves none. Each list row was made by
# team-a or team-b and names the tools that caller was shown on its own surface under the row's
# policy revision: its own entry's two tools under $REVISION, and only its list tool under
# $WITHDRAWN_REVISION, after each team's read tool is withdrawn. None is left out. ROWS is what
# row_resources_json prints.
check_list_rows() {
  local rows=$1 expected=$2 lists wrong
  # shellcheck disable=SC2016 # jq's own variables
  if ! lists=$(printf '%s' "$rows" | jq -e '[.[] | select(.kind == "list")] | length') \
    || ! wrong=$(printf '%s' "$rows" | jq -c --arg revision "$REVISION" --arg withdrawn "$WITHDRAWN_REVISION" '
        def entry: {"team-a": "docs-team-a", "team-b": "docs-team-b"}[.team // ""];
        def shown: if entry == null then null
          else {($revision): [entry + "__list_documents", entry + "__read_document"],
                ($withdrawn): [entry + "__list_documents"]}[.revision // ""] end;
        .[] | select(.kind == "list")
        | select(((.team == "team-a" or .team == "team-b")
            and shown != null and (.listed | type) == "array"
            and (.listed | sort) == (shown | sort)
            and .omitted == 0) | not)
        | {team, revision, listed, omitted, shown: shown}'); then
    fail "audit: one list row for each of the workloads' tools/list calls (the rows are not a JSON array)"
    return
  fi
  if [ -n "$wrong" ]; then
    printf '%s\n' "$wrong" | sed 's/^/    wrong: /'
  fi
  check "$lists" "$expected" "audit: one list row for each of the workloads' $expected tools/list calls"
  check "$(count_lines . "$wrong")" 0 "audit: each list row names the tools its caller was shown"
}

# The columns are crates/audit-postgres's (sql/migrations/0001_call_rows.sql and
# 0004_list_rows.sql). `resources` is a JSON array of the {system, kind, identifier} each call
# named, or "unknown"; the listing shows each as system/kind/identifier. A row of kind `list`
# has no tool or resources; the listing shows the tools it listed in the tool column.
#
# audit_rows LISTS: checks this run's rows, LISTS of them of kind `list`: one per tools/list
# the workloads made.
audit_rows() {
  local lists=$1
  step "audit rows from this run"
  psql_reader -c "select to_char(begun_at, 'HH24:MI:SS') as at, kind, proved_subject, proved_team as team,
      coalesce(tool, 'listed: ' || coalesce((select string_agg(t, ',')
          from jsonb_array_elements_text(listed_tools) as t), 'nothing')) as tool,
      coalesce((select string_agg(concat_ws('/', r->>'system', r->>'kind', r->>'identifier'), ',')
          from jsonb_array_elements(case when jsonb_typeof(resources) = 'array' then resources
                                         else '[]'::jsonb end) as r), resources #>> '{}') as resources,
      decision, reason, outcome, latency_ms as ms, policy_revision as rev
    from $AUDIT_TABLE where begun_at >= to_timestamp($SINCE) order by begun_at"
  local team own other read
  for team in team-a team-b; do
    if [ "$team" = team-a ]; then own=atlas other=borealis; else own=borealis other=atlas; fi
    read=$(team_entry "$team")__read_document
    check_at_least "$(audit_count "proved_team = '$team' and tool = '$read' and decision = 'allow'
        and outcome = 'ok' and resources = '$(project_json "$own")'::jsonb")" 1 \
      "audit: $team's read of $own is an allow row naming $own, with outcome ok"
    check_at_least "$(audit_count "proved_team = '$team' and tool = '$read' and decision = 'deny'
        and reason = 'resource_outside_limit' and resources = '$(project_json "$other")'::jsonb
        and sentence like '%\`$other\`%'")" 1 \
      "audit: $team's read of $other is a deny row naming $other and the resource limit"
    check "$(audit_count "proved_team = '$team' and decision = 'allow'
        and resources @> '$(project_json "$other")'::jsonb")" 0 \
      "audit: no allowed row of $team names $other"
    check_at_least "$(audit_count "proved_team = '$team' and resources = '[]'::jsonb
        and sentence like '%named none of them%'")" 1 \
      "audit: $team's call that named no project records none"
  done
  local rows
  rows=$(row_resources_json)
  check_row_resources "$rows"
  check_list_rows "$rows" "$lists"
  # The open-row view shows an allowed call row with no outcome only once its deadline has
  # passed, by the database's clock: before then it may still be completed. So wait for the
  # deadline of this run's last allowed call row, at most a minute, and the view then sees
  # every row of the run.
  local wait
  wait=$(psql_reader -Atc "select ceil(greatest(0, extract(epoch from max(deadline) - clock_timestamp())))::int
    from $AUDIT_TABLE where begun_at >= to_timestamp($SINCE) and kind = 'call' and decision = 'allow'")
  check_at_most "$wait" 60 "audit: this run's last allowed call row is due within a minute"
  case "$wait" in
    '' | *[!0-9]*) ;;
    *) if [ "$wait" -le 60 ]; then
      echo "    waiting ${wait}s for this run's last allowed call row to reach its deadline"
      sleep $((wait + 1))
    fi ;;
  esac
  # A begin that ran past its budget may still commit: the store asks the server to cancel the
  # insert, but a paused server cannot act on that before it commits. The store then tries to
  # complete such a row as error until its finish deadline, and one it could not complete by
  # then stays open (decision 0009), so the outage step's one refused call may leave its row
  # open. No other allowed row may. The view never shows a denial or a list row, which are
  # never completed; the outage step makes no list.
  local outage="begun_at between to_timestamp($OUTAGE_FROM) and to_timestamp($OUTAGE_TO)"
  check "$(open_count "not ($outage)")" 0 \
    "audit: the open-row query finds no row outside the database outage"
  check_at_most "$(open_count "$outage")" 1 \
    "audit: the open-row query finds at most the database outage's refused call's row"
  check "$(audit_count "proved_subject like '%stranger%'")" 0 "audit: no row for the ServiceAccount outside the manifest"
}

# check_boot LOGS: the gateway says at boot that identity is enforced and audit is in Postgres.
check_boot() {
  printf '%s\n' "$1" | grep -E '"event":"boot"' | sed 's/^/    /' || echo "    (no boot lines)"
  check_at_least "$(count_lines '"identity":"enforce"' "$1")" 1 "the gateway enforces identity"
  check_at_least "$(count_lines '"audit":"postgres"' "$1")" 1 "the gateway writes audit rows to Postgres"
  check "$(count_lines '"identity":"disabled"|"audit":"disabled"' "$1")" 0 "the gateway disabled neither identity nor audit"
}

# check_keys_fetched LOGS ISSUER: the gateway says at boot, exactly once, that it fetched
# ISSUER's keys from its keys URL, and how many. A gateway that read a keys file logs no such
# line, and one whose fetch failed did not start.
check_keys_fetched() {
  local counts
  # shellcheck disable=SC2016 # jq's own variables
  counts=$(printf '%s\n' "$1" | jq -rR --arg issuer "$2" --arg message "$KEYS_FETCHED_MESSAGE" \
    'fromjson? | .fields? // empty
      | select(.event == "boot" and .message == $message and .keys_issuer == $issuer) | .keys')
  check "$(count_lines . "$counts")" 1 "the gateway fetched the keys of $2 from its keys URL at boot"
  check_at_least "$(printf '%s\n' "$counts" | head -n 1)" 1 "the keys it fetched"
}

# metric SERIES TEXT: the value of the one sample of TEXT, Prometheus text, written exactly as
# SERIES, its name and any labels; nothing if there is none.
metric() { printf '%s\n' "$2" | awk -v series="$1" '$1 == series { print $2; exit }'; }

# metric_total NAME TEXT: the sum of every sample of the family NAME, whatever its labels, as a
# whole number; nothing if there is none.
metric_total() {
  printf '%s\n' "$2" | awk -v name="$1" '
    $1 == name || index($1, name "{") == 1 { sum += $2; found = 1 }
    END { if (found) printf "%d\n", sum }'
}

# check_metrics OUTAGE TEXT: what the gateway's GET /metrics answered (crates/gateway, metrics.rs).
# Telemetry dropped is exported, and the last open-row poll found at most one row open: with
# OUTAGE=outage, the outage's refused call's. With OUTAGE=outage, the database outage's refused call is counted as a begin failure and
# as an answer with the audit-failure sentence.
check_metrics() {
  local outage=$1 text=$2
  printf '%s\n' "$text" \
    | grep -E '^switchboard_(audit_(begin_failures_total|failure_answers_total|open_rows|open_rows_poll_failures_total|finishes_in_flight)|telemetry_dropped_total)' \
    | sed 's/^/    /' || echo "    (no samples)"
  check_at_least "$(metric switchboard_telemetry_dropped_total "$text")" 0 \
    "metrics: telemetry dropped is exported"
  # Only the Compose run has a database outage; the kind run's message does not name one.
  local open="one row"
  [ "$outage" != outage ] || open="the database outage's refused call's row"
  check_at_most "$(metric switchboard_audit_open_rows "$text")" 1 \
    "metrics: the last open-row poll found at most $open open"
  if [ "$outage" = outage ]; then
    check_at_least "$(metric_total switchboard_audit_begin_failures_total "$text")" 1 \
      "metrics: the database outage's refused call counted as a begin failure"
    check_at_least "$(metric switchboard_audit_failure_answers_total "$text")" 1 \
      "metrics: the database outage's refused call counted as an audit-failure answer"
  fi
}

# check_server_bearers LOGS SHA256S CALLS SCOPE: what mock-docs received this run. Every request
# it accepted carried one of the gateway's credentials, one for each entry of mock-docs in the
# registry, whose SHA-256s are the space-separated SHA256S; with SCOPE=all, so did every request
# carrying any bearer. CALLS is exactly how many calls the gateway allowed so far: one more means
# a call it denied reached the server, one fewer that an allowed call did not, or that the log is
# short. Requests with no bearer (the health checks) are not counted. check_server_entries checks
# that each team's calls carried its own entry's credential.
check_server_bearers() {
  local logs=$1 shas=$2 calls=$3 scope=$4 lines sha shown=""
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(.bearer_sha256 != null)
    | "\(if .accepted == true then "accepted" else "refused" end) \(.bearer_sha256)"')
  for sha in $shas; do shown="$shown ${sha:0:12}..."; done
  echo "    requests seen by mock-docs, by answer and bearer sha256 prefix (the gateway's are$shown):"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  local good bad stray ours
  # shellcheck disable=SC2016 # awk's own variables
  ours='function ours(prefix,  n, i, sha) {
      n = split(shas, sha, " ")
      for (i = 1; i <= n; i++) if (length(prefix) >= 8 && index(sha[i], prefix) == 1) return 1
      return 0
    }'
  good=$(printf '%s\n' "$lines" | awk -v shas="$shas" "$ours"'$1 == "accepted" && ours($2) { count++ } END { print count + 0 }')
  bad=$(printf '%s\n' "$lines" | awk -v shas="$shas" "$ours"'$1 == "accepted" && !ours($2) { count++ } END { print count + 0 }')
  stray=$(printf '%s\n' "$lines" | awk -v shas="$shas" "$ours"'NF == 2 && !ours($2) { count++ } END { print count + 0 }')
  check "$good" "$calls" "mock-docs accepted the gateway's credentials on exactly the $calls calls the gateway allowed"
  check "$bad" 0 "mock-docs accepted no other bearer"
  if [ "$scope" = all ]; then
    check "$stray" 0 "mock-docs never received any bearer but the gateway's"
  fi
}

# check_server_callers LOGS SUBJECTS CALLS REFUSALS PROBES: what mock-docs received this run in
# its JWT mode, where each log line names the verified caller of an accepted token, or why a token
# was refused. Every request it accepted came from one of SUBJECTS, space-separated: the
# ServiceAccounts of mock-docs' entries in the registry, whose tokens the gateway presents. CALLS
# is exactly how many calls the gateway allowed so far: one more means a call it denied reached
# the server, one fewer that an allowed call did not, or that the log is short. A request
# accepted with any other caller, or with none (a static token), fails the check.
# check_server_entries checks that each team's calls came under its own entry's. Exactly
# REFUSALS requests were refused as wrong_audience: a token the cluster signed for another
# audience, the workloads' own on their direct calls before the policy. Exactly PROBES were
# refused as no_bearer: the route check's probe before the policy, which sends no credential,
# one request per attempt it found open. Any other refusal fails.
check_server_callers() {
  local logs=$1 subjects=$2 calls=$3 refusals=$4 probes=$5 lines
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(has("accepted"))
    | if .accepted == true then "accepted \(.caller // "none")" else "refused \(.refusal // "none")" end')
  echo "    requests seen by mock-docs, by answer and verified caller or refusal:"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  local gateway other audience bearerless refused
  # shellcheck disable=SC2016 # awk's own variables
  local ours='BEGIN { n = split(subjects, list, " "); for (i = 1; i <= n; i++) entry[list[i]] = 1 }
    '
  gateway=$(printf '%s\n' "$lines" | awk -v subjects="$subjects" "$ours"'$1 == "accepted" && ($2 in entry) && NF == 2 { count++ } END { print count + 0 }')
  other=$(printf '%s\n' "$lines" | awk -v subjects="$subjects" "$ours"'$1 == "accepted" && !(($2 in entry) && NF == 2) { count++ } END { print count + 0 }')
  audience=$(printf '%s\n' "$lines" | awk '$0 == "refused wrong_audience" { n++ } END { print n + 0 }')
  bearerless=$(printf '%s\n' "$lines" | awk '$0 == "refused no_bearer" { n++ } END { print n + 0 }')
  refused=$(printf '%s\n' "$lines" | awk '$1 == "refused" { n++ } END { print n + 0 }')
  check "$gateway" "$calls" "mock-docs accepted the entries' tokens ($subjects) on exactly the $calls calls the gateway allowed"
  check "$other" 0 "mock-docs accepted no other caller, and no token without one"
  check "$audience" "$refusals" "mock-docs refused the $refusals direct calls' tokens as meant for another audience"
  check "$bearerless" "$probes" "mock-docs refused the route check's $probes open attempts before the policy, which carried no bearer"
  check "$refused" "$((refusals + probes))" "mock-docs refused nothing else"
}

# check_server_entries LOGS CALLS WHO...: each team's calls reached mock-docs under its own
# entry's identity, and only for its own project. Each WHO is TEAM=IDENTITY, the identity of
# TEAM's entry as mock-docs logs it: in kind the entry's ServiceAccount, the verified `caller`; in
# Compose the SHA-256 of the entry's credential, whose prefix is logged as `bearer_sha256`. Of
# the tools/call requests mock-docs accepted, exactly CALLS came under each team's identity, and
# each of those named the team's own project and was answered: none named another project, which
# mock-docs refuses for that identity.
check_server_entries() {
  local logs=$1 calls=$2 who team identity own lines mine other
  shift 2
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(.accepted == true and .rpc_method == "tools/call")
    | "\(.caller // .bearer_sha256 // "none") \(.project // "none" | tostring | gsub(" "; "_")) \(if has("refused") then "refused" else "answered" end)"')
  echo "    tools/call requests mock-docs accepted, by identity, project and answer:"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  # shellcheck disable=SC2016 # awk's own variables
  local under='function under(logged) {
      if (length(identity) == 64 && identity !~ /[^0-9a-f]/) return length(logged) >= 8 && index(identity, logged) == 1
      return logged == identity
    }'
  for who in "$@"; do
    team=${who%%=*} identity=${who#*=}
    own=$(team_project "$team")
    mine=$(printf '%s\n' "$lines" | awk -v identity="$identity" -v own="$own" "$under"'under($1) && $2 == own && $3 == "answered" { count++ } END { print count + 0 }')
    other=$(printf '%s\n' "$lines" | awk -v identity="$identity" -v own="$own" "$under"'NF == 3 && under($1) && !($2 == own && $3 == "answered") { count++ } END { print count + 0 }')
    check "$mine" "$calls" "mock-docs answered $team's $calls allowed calls under $team's own entry's identity, each for $own"
    check "$other" 0 "no call under $team's entry's identity named another project"
  done
}

# --- Compose --------------------------------------------------------------------------------

compose_workload() { # LABEL MODE TEAM: runs the workload service once
  local label=$1 mode=$2 team=$3 own other output status
  if [ "$team" = team-a ]; then own=atlas other=borealis; else own=borealis other=atlas; fi
  local issuer=http://dev-issuer:8090/token
  if output=$(dc run --rm --no-deps -T \
      -e "GATEWAY_URL=http://gateway:8080/mcp/$(team_entry "$team")" \
      -e "TOKEN_URL=$issuer?subject=workload:$team:mock-workload&audience=switchboard" \
      -e "OWN_PROJECT=$own" -e "OTHER_PROJECT=$other" \
      -e "BAD_TOKEN_URLS=$issuer?subject=workload:$team:stranger&audience=switchboard $issuer?subject=workload:$team:mock-workload&audience=not-switchboard" \
      workload workload.sh "$mode" 2>&1); then
    status=0
  else
    status=$?
  fi
  tally_workload "$label" "$status" "$output"
}

# mock_docs_requests: how many requests mock-docs has accepted. Its health checks carry no bearer
# and are not accepted, so they do not count.
mock_docs_requests() {
  dc logs --no-log-prefix mock-docs | jq -cR 'fromjson? | select(.accepted == true)' | awk 'END { print NR }'
}

swap_registry() { # FILE: replaces the mounted registry file in one rename
  cp "$1" "$DEMO_DIR/compose-registry/.registry.toml.new"
  mv "$DEMO_DIR/compose-registry/.registry.toml.new" "$DEMO_DIR/compose-registry/registry.toml"
}

# compose_registry: the gateway reads a copy of the registry, so withdrawing a tool never edits
# the repository. The directory is kept from run to run and only its file replaced: a rerun
# without `down` can reuse the gateway's container, whose mount still names the directory it
# started with, and would never see a new one.
compose_registry() {
  mkdir -p "$DEMO_DIR/compose-registry"
  swap_registry "$ROOT/deploy/compose/config/registry/registry.toml"
}

compose_run() {
  MODE=compose
  step "build the image; start Postgres, the migration, the dev issuer, mock-docs and the gateway"
  mkdir -p "$DEMO_DIR"
  compose_registry
  export SWITCHBOARD_REGISTRY_DIR=$DEMO_DIR/compose-registry
  # Naming the gateway starts everything it depends on; --wait then accepts the migration
  # having exited 0, which it does not when the migration is named itself.
  dc up -d --build --wait --wait-timeout 300 gateway
  dc ps
  mark_start

  step "the gateway's boot lines"
  if fetch "the gateway's log" dc logs --no-log-prefix gateway; then
    check_boot "$FETCHED"
  fi

  step "team-a and team-b workloads"
  compose_workload "team-a workload" full team-a
  compose_workload "team-b workload" full team-b

  step "the server never saw a workload token, no denied call reached it, and each team's calls carried its own entry's credential"
  # Each team's full run is allowed two calls, its list and its read; its other calls are denied.
  if fetch "mock-docs' log" mock_docs_log; then
    check_server_bearers "$FETCHED" "$(entry_sha team-a) $(entry_sha team-b)" 4 all
    check_server_entries "$FETCHED" 2 "team-a=$(entry_sha team-a)" "team-b=$(entry_sha team-b)"
  fi

  step "database unavailable: the call is refused and nothing runs"
  local before after
  before=$(mock_docs_requests)
  OUTAGE_FROM=$(psql_superuser -Atc "select extract(epoch from now())")
  PAUSED=1
  dc pause postgres
  compose_workload "read while the database is paused" audit-down team-a
  dc unpause postgres
  PAUSED=""
  after=$(mock_docs_requests)
  check "$after" "$before" "mock-docs received nothing while the database was down"
  # An insert the pause held commits as soon as the server runs again, well within 2 s.
  OUTAGE_TO=$(psql_superuser -Atc "select extract(epoch from now() + interval '2 seconds')")

  step "withdraw each team's read tool from the registry (the gateway polls every 2 s)"
  swap_registry "$ROOT/deploy/compose/config/registry-withdrawn.toml"
  sleep 4
  compose_workload "after the withdrawal" withdrawn team-a
  swap_registry "$ROOT/deploy/compose/config/registry/registry.toml"
  # The gateway no longer knows the tool, so no adapter read the call: its resources are
  # unknown, not none.
  check_at_least "$(audit_count "tool = '$(team_entry team-a)__read_document' and decision = 'deny'
      and policy_revision = '$WITHDRAWN_REVISION' and reason = 'unknown_tool' and resources = '\"unknown\"'::jsonb")" 1 \
    "audit: the call to the withdrawn tool is a deny row under revision $WITHDRAWN_REVISION, its resources unknown"
  # Let the gateway load the restored registry before anything else runs against it.
  sleep 4

  step "the gateway's metrics (GET /metrics on its own listener, loopback in the container, unpublished)"
  if fetch "the gateway's metrics" dc exec -T gateway curl -sS --fail http://127.0.0.1:9090/metrics; then
    check_metrics outage "$FETCHED"
  fi

  # Three lists: each team's full run, and the run after the withdrawal.
  audit_rows 3
  FINISHED=1
}

# --- kind -----------------------------------------------------------------------------------

# start_job NAMESPACE CRONJOB MODE: starts a new Job, so a new pod, from the suspended CronJob's
# template with MODE as the workload's argument. Sets JOB.
start_job() {
  local ns=$1 cron=$2 mode=$3
  JOB="$cron-$mode-$(date +%s)"
  k -n "$ns" get cronjob "$cron" -o json \
    | jq --arg name "$JOB" --arg mode "$mode" '{
        apiVersion: "batch/v1", kind: "Job",
        metadata: {name: $name, namespace: .metadata.namespace, labels: .spec.jobTemplate.metadata.labels},
        spec: (.spec.jobTemplate.spec | .template.spec.containers[0].args = [$mode])}' \
    | k apply -f - >/dev/null
}

# wait_job NAMESPACE NAME TIMEOUT: waits until the Job has succeeded or failed. Sets JOB_STATUS
# to 0 or 1; returns non-zero only if it did neither within TIMEOUT seconds.
wait_job() {
  local ns=$1 name=$2 timeout=$3 waited=0 succeeded failed
  while :; do
    succeeded=$(k -n "$ns" get job "$name" -o jsonpath='{.status.succeeded}')
    failed=$(k -n "$ns" get job "$name" -o jsonpath='{.status.failed}')
    if [ "${succeeded:-0}" -ge 1 ]; then JOB_STATUS=0; return 0; fi
    if [ "${failed:-0}" -ge 1 ]; then JOB_STATUS=1; return 0; fi
    if [ "$waited" -ge "$timeout" ]; then
      echo "job $ns/$name did not finish within ${timeout}s" >&2
      k -n "$ns" describe job "$name" >&2
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

# kind_workload LABEL NAMESPACE CRONJOB MODE: runs the workload as a new Job and tallies its log.
# A log that cannot be read fails as that, whatever part of it was printed.
kind_workload() {
  local label=$1 ns=$2 cron=$3 mode=$4
  start_job "$ns" "$cron" "$mode"
  wait_job "$ns" "$JOB" 180
  if fetch "$label's log (job $ns/$JOB)" k -n "$ns" logs "job/$JOB"; then
    tally_workload "$label" "$JOB_STATUS" "$FETCHED"
  fi
}

# start_idle NAMESPACE: starts a new Job of the team's workload in its idle mode, a new pod with
# the workload's labels and ServiceAccount that makes no call, and waits until the pod runs.
# Sets JOB; returns non-zero if the pod is not running within 120 s.
start_idle() {
  local ns=$1 waited=0 phase
  start_job "$ns" mock-workload idle
  while :; do
    phase=$(k -n "$ns" get pods -l "job-name=$JOB" -o jsonpath='{.items[*].status.phase}')
    if [ "$phase" = Running ]; then return 0; fi
    if [ "$waited" -ge 120 ]; then
      echo "the idle pod of job $ns/$JOB is not running within 120 s (phase '$phase')" >&2
      k -n "$ns" describe pods -l "job-name=$JOB" >&2
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

# stop_idle NAMESPACE NAME: deletes the idle Job and waits until its pod is gone. The pod ends
# on the SIGTERM its deletion sends.
stop_idle() {
  k -n "$1" delete job "$2" --cascade=foreground --wait=true --timeout=120s
}

# route_check NAMESPACE EXPECT JOB: the route check's operator step (deploy/route-check), run as
# the route-check operator with only its own access, against the running pod of the idle Job JOB
# in NAMESPACE. Its probe expects every route of routes/kind.tsv to be EXPECT, by name and by
# address. Its PASS and FAIL lines count as this run's, and any FAIL fails the run. The report
# goes to .demo: route-check-<team>-<UTC time>.json for the check after the policy, with `open`
# before the time for the control before it. Sets ROUTE_REPORT.
route_check() {
  local ns=$1 expect=$2 job=$3 when output status
  when=$(date -u +%Y%m%dT%H%M%SZ)
  if [ "$expect" = open ]; then
    ROUTE_REPORT=$DEMO_DIR/route-check-$ns-open-$when.json
  else
    ROUTE_REPORT=$DEMO_DIR/route-check-$ns-$when.json
  fi
  if output=$("$ROUTE_CHECK" --kubeconfig "$KCFG" --context "kind-$CLUSTER" --as "$ROUTE_CHECK_OPERATOR" \
      --namespace "$ns" --selector "app=mock-workload,job-name=$job" --gateway-ns switchboard \
      --server-ns mock-docs --server-service mock-docs/mock-docs --server-audience mock-docs \
      --routes "$ROUTE_CHECK_ROUTES" --gateway-url "$KIND_GATEWAY_URL/$(team_entry "$ns")" --expect "$expect" \
      --probe-image "$IMG_RUN" --report "$ROUTE_REPORT" --environment "first slice, kind" 2>&1); then
    status=0
  else
    status=$?
  fi
  tally_workload "route check in $ns, every route $expect" "$status" "$output"
  echo "    report: $ROUTE_REPORT"
}

# open_route_attempts REPORT: how many of the probe's attempts in REPORT were open, each a
# request mock-docs answered; nothing if the report cannot be read.
open_route_attempts() {
  jq -er '[.routes[] | select(.result == "open")] | length' "$1" 2>/dev/null || true
}

# gateway_pod: the gateway's pod of its Deployment's current ReplicaSet, by the ReplicaSet's
# pod-template-hash. After a rollout the previous pod can still be running out its grace period,
# and the Deployment's log may be read from that one, whose boot lines are the previous build's. Sets
# GATEWAY_POD; returns non-zero unless exactly one such pod runs.
gateway_pod() {
  local revision sets hash pods
  revision=$(k -n switchboard get deploy/gateway -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')
  sets=$(k -n switchboard get replicasets -l app=gateway -o json)
  # shellcheck disable=SC2016 # jq's own variables
  hash=$(jq -r --arg revision "$revision" '[.items[]
      | select(.metadata.annotations["deployment.kubernetes.io/revision"] == $revision)
      | .metadata.labels["pod-template-hash"] // empty]
    | if length == 1 then .[0] else empty end' <<<"$sets")
  if [ -z "$revision" ] || [ -z "$hash" ]; then
    echo "cannot find the gateway's ReplicaSet of revision '$revision'" >&2
    return 1
  fi
  pods=$(k -n switchboard get pods -l "app=gateway,pod-template-hash=$hash" -o json \
    | jq -r '[.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null)
        | .metadata.name] | join(" ")')
  case "$pods" in
    '' | *' '*)
      echo "want one running gateway pod of ReplicaSet $hash (revision $revision), got '$pods'" >&2
      return 1
      ;;
  esac
  GATEWAY_POD=$pods
}

# can_i_no_as USER WHO ARGS...: the answer to `kubectl auth can-i ARGS` as USER, checked to be
# no, in a check named for WHO.
can_i_no_as() {
  local user=$1 who=$2 answer status=0 last
  shift 2
  # can-i exits 1 when the answer is no; the answer itself, its last line, is what is checked.
  # A kubectl that fails (it cannot reach the cluster, or may not impersonate) ends with
  # neither: its whole message goes in the FAIL line, and the run goes on.
  answer=$(k auth can-i "$@" --as="$user" 2>&1) || status=$?
  # can-i looks the resource up in the API's discovery. One it cannot find is still asked, as a
  # core-group resource of the whole name. That is not what the API server checks, so the
  # answer, yes or no, says nothing about the permission. Its warning fails the check.
  case "$answer" in
    *"doesn't have a resource type"*) answer="a resource the API does not serve: ${answer%%$'\n'*}" ;;
    *)
      last=${answer##*$'\n'}
      case "$last" in
        yes | no) answer=$last ;;
        *) answer="no answer (kubectl exit $status): $(printf '%s' "$answer" | tr '\n' ' ')" ;;
      esac
      ;;
  esac
  check "$answer" no "$who may not: $*"
}

# can_i_no TEAM ARGS...: can_i_no_as for TEAM's workload.
can_i_no() {
  local team=$1
  shift
  can_i_no_as "system:serviceaccount:$team:mock-workload" "$team's workload" "$@"
}

# sar_no TEAM VERB GROUP RESOURCE [SUBRESOURCE [NAMESPACE]]: as can_i_no, across the cluster or
# in NAMESPACE, for what can-i cannot name. The API server checks impersonating a UID as `uids`
# and an extra as `userextras/<key>`, both in authentication.k8s.io, which serves neither as a
# resource. can-i would warn and ask about a core resource of the whole name instead (see
# can_i_no_as). A SubjectAccessReview names the group, resource and subresource as the API
# server asks them, for the user and groups `--as` gives a ServiceAccount. A kubectl that fails
# gives no answer: its message goes in the FAIL line, and the run goes on.
sar_no() {
  local team=$1 verb=$2 group=$3 resource=$4 subresource=${5:-} namespace=${6:-} allowed answer status=0
  # shellcheck disable=SC2016 # jq's own variables
  allowed=$(jq -cn --arg team "$team" --arg verb "$verb" --arg group "$group" \
      --arg resource "$resource" --arg subresource "$subresource" --arg namespace "$namespace" '{
        apiVersion: "authorization.k8s.io/v1", kind: "SubjectAccessReview",
        spec: {user: "system:serviceaccount:\($team):mock-workload",
               groups: ["system:serviceaccounts", "system:serviceaccounts:\($team)", "system:authenticated"],
               resourceAttributes: {verb: $verb, group: $group, resource: $resource, subresource: $subresource}}}
        | if $namespace == "" then . else .spec.resourceAttributes.namespace = $namespace end' \
    | k create -f - -o jsonpath='{.status.allowed}' 2>&1) || status=$?
  case "$status:$allowed" in
    0:false) answer=no ;;
    0:true) answer=yes ;;
    *) answer="no answer (kubectl exit $status): $(printf '%s' "$allowed" | tr '\n' ' ')" ;;
  esac
  check "$answer" no "$team's workload may not: $verb $group/$resource${subresource:+/$subresource}${namespace:+ -n $namespace}"
}

# operator_checks: what each team's workload may not do through the cluster API (decision 0010,
# control 1). Reading the gateway's or the server's secrets, or the gateway's configuration,
# would reach the server without the gateway. So would anything that yields a pod or a token
# that holds a credential: starting pods, or a controller that starts them (Deployments,
# ReplicaSets, StatefulSets, DaemonSets, Jobs and CronJobs); minting a ServiceAccount's token;
# impersonating a user, group, ServiceAccount, UID or extra; and binding or escalating a role,
# or creating a binding. So would the API server's own routes to a pod, a Service or a node:
# exec, attach, port-forward, the proxies, and ephemeral containers. Their traffic comes from
# the API server, not the workload's pod, so the network policy does not stop it.
#
# What is asked is every row of deploy/route-check/permissions.tsv, the list the route check's
# operator step asks too, so there is one list. Reading is asked as get, list and watch, since
# list and watch return a Secret's data too. Each route is asked with both verbs a request
# through it can use, and an ephemeral container with both that add one.
#
# A row's scope means what it means to route-check.sh. A `namespaced` row is asked in mock-docs,
# in the gateway's namespace, in the team's own and across the cluster; a `cluster` row is asked
# across the cluster only. Across the cluster is a can-i with no namespace, as the checks asked
# it before they read the list (binding ClusterRoles among them). can-i then asks in the
# kubeconfig's namespace, `default`, and warns for a resource that has none. RBAC counts that
# namespace's RoleBindings as well as ClusterRoleBindings, so a no there holds across the
# cluster too, and covers more than --all-namespaces, which counts only ClusterRoleBindings.
# A list that cannot be read fails the step; nothing is asked from a list of its own.
#
# A can-i names no resource, so it cannot see a rule limited by resourceNames: a workload able
# to mint tokens for one named ServiceAccount answers no. So the checks also read the RBAC rules
# bound to each team's workload, in every namespace, with deploy/route-check/rbac-match.jq,
# the matcher the route check's operator step runs (operator_rbac).
operator_checks() {
  local rows team verb resource subresource scope ns
  if ! rows=$(awk -F'\t' '/^#/ || NF == 0 { next }
      NF != 4 || ($4 != "namespaced" && $4 != "cluster") { bad = 1; next }
      { print }
      END { exit bad }' "$PERMISSIONS") || [ -z "$rows" ]; then
    fail "operator checks: every row of $PERMISSIONS is read (a row is not verb, resource, subresource and scope, or there is none)"
    return
  fi
  for team in team-a team-b; do
    while IFS=$'\t' read -r verb resource subresource scope <&3; do
      if [ "$scope" = cluster ]; then
        operator_ask "$team" "$verb" "$resource" "$subresource" ""
      else
        for ns in mock-docs switchboard "$team" all; do
          operator_ask "$team" "$verb" "$resource" "$subresource" "$ns"
        done
      fi
    done 3<<<"$rows"
  done
  operator_rbac
}

# operator_rbac: for each team's workload, that no RBAC rule bound to its ServiceAccount or its
# groups grants a row of permissions.tsv, whatever its resourceNames. It reads the ClusterRoles,
# the ClusterRoleBindings, and the Roles and RoleBindings in every namespace, and runs
# rbac-match.jq for each team. Every namespace, not only those a team's can-i checks ask in
# (mock-docs, the gateway's, the team's own, and default for across the cluster): a RoleBinding
# in kube-system or in the other team's namespace can bind the workload or its groups too, and
# no can-i asks there. Where can-i does ask, in default among them, it still misses a rule
# limited by resourceNames. A list that cannot be read or parsed fails the step, and nothing
# is matched.
operator_rbac() {
  local lists what list team verdicts verdict row detail status
  lists=$(mktemp)
  status=0
  for what in clusterroles clusterrolebindings; do
    if ! list=$(k get "$what" -o json) ||
      ! jq -ce --arg what "$what" 'if type == "object" then {what: $what, list: .} else error end' <<<"$list" >>"$lists"; then
      fail "operator checks: the RBAC rules bound to each team's workload (could not read the $what)"
      status=1
      break
    fi
  done
  for what in roles rolebindings; do
    [ "$status" -eq 0 ] || break
    if ! list=$(k get "$what" -A -o json) ||
      ! jq -ce --arg what "$what" 'if type == "object" then {what: $what, list: .} else error end' <<<"$list" >>"$lists"; then
      fail "operator checks: the RBAC rules bound to each team's workload (could not read the $what in every namespace)"
      status=1
    fi
  done
  if [ "$status" -eq 0 ]; then
    for team in team-a team-b; do
      if ! verdicts=$(jq -n -r --rawfile permissions "$PERMISSIONS" --arg namespace "$team" --arg name mock-workload \
        -f "$RBAC_MATCH" <"$lists" 2>&1); then
        fail "$team's workload is bound to no RBAC rule for a row of $PERMISSIONS (${verdicts%%$'\n'*})"
        continue
      fi
      while IFS=$'\t' read -r verdict row detail; do
        if [ "$verdict" = PASS ]; then
          pass "$team's workload is bound to no RBAC rule for: $row, whatever its resourceNames ($detail)"
        else
          fail "$team's workload is bound to no RBAC rule for: $row, whatever its resourceNames ($detail)"
        fi
      done <<<"$verdicts"
    done
  fi
  rm -f "$lists"
}

# operator_ask TEAM VERB RESOURCE SUBRESOURCE WHERE: one row of permissions.tsv for TEAM's
# workload. WHERE is a namespace, or `all` or empty for across the cluster (see operator_checks).
# RESOURCE is written as can-i takes it, `name.group` outside the core group, and SUBRESOURCE is
# `-` for none. Impersonating a UID or an extra is asked by SubjectAccessReview (see sar_no).
operator_ask() {
  local team=$1 verb=$2 resource=$3 subresource=$4 where=$5 args
  if [ "$verb" = impersonate ] && [ "${resource#*.}" = authentication.k8s.io ]; then
    [ "$subresource" != - ] || subresource=""
    [ "$where" != all ] || where=""
    sar_no "$team" "$verb" authentication.k8s.io "${resource%%.*}" "$subresource" "$where"
    return
  fi
  args=("$verb" "$resource")
  [ "$subresource" = - ] || args+=("--subresource=$subresource")
  case "$where" in
    '' | all) ;;
    *) args+=(-n "$where") ;;
  esac
  can_i_no "$team" "${args[@]}"
}

# token_grants: what ServiceAccount gateway may do with ServiceAccount tokens, the grant its
# pod's token writer uses (deploy/kind/base/gateway-tokens.yaml): create them for docs-team-a and
# docs-team-b, named, and for no other ServiceAccount, its own and a workload's among them, nor
# without a name.
token_grants() {
  local gateway=system:serviceaccount:switchboard:gateway entry answer
  for entry in docs-team-a docs-team-b; do
    answer=$(k auth can-i create "serviceaccounts/$entry" --subresource=token -n switchboard --as="$gateway" 2>&1) || true
    check "${answer##*$'\n'}" yes "the gateway may create tokens for $entry"
  done
  can_i_no_as "$gateway" "the gateway" create serviceaccounts/gateway --subresource=token -n switchboard
  can_i_no_as "$gateway" "the gateway" create serviceaccounts/migrate --subresource=token -n switchboard
  can_i_no_as "$gateway" "the gateway" create serviceaccounts --subresource=token -n switchboard
  can_i_no_as "$gateway" "the gateway" create serviceaccounts/mock-workload --subresource=token -n team-a
}

# before_policy_probes: before the network policy, a new pod of each team calls mock-docs
# directly. The call must connect and the server must refuse the workload's own token. The same
# pod then reads its team's project through the gateway, and the gateway's call to the same
# server must succeed. Each team's later check that its direct call is dropped then has its own
# control in the same run. The Job is the team's CronJob template with only the argument
# changed (start_job), so it has the template's OWN_PROJECT (deploy/kind/base/workloads.yaml).
before_policy_probes() {
  kind_workload "team-a before policy" team-a mock-workload before-policy
  kind_workload "team-b before policy" team-b mock-workload before-policy
}

# route_checks_before_policy: the route check's positive control. Every check that shows a route
# refused shows, in the same run, one that works (decision 0010, "Evidence"). Before the
# network policy, from a new idle team-a pod, every route on the list must be open, by name and
# by address: the probe reaches mock-docs, and mock-docs answers. Sets OPEN_ATTEMPTS: how many
# attempts the probe found open, each a request mock-docs refused for carrying no bearer.
route_checks_before_policy() {
  local job
  # The operator runs with its own access and no more: no Secret data, no exec, no pod of its
  # own, and no probe outside the teams' namespaces.
  can_i_no_as "$ROUTE_CHECK_OPERATOR" "the route-check operator" get secrets -n mock-docs
  can_i_no_as "$ROUTE_CHECK_OPERATOR" "the route-check operator" create pods --subresource=exec -n team-a
  can_i_no_as "$ROUTE_CHECK_OPERATOR" "the route-check operator" create pods -n team-a
  can_i_no_as "$ROUTE_CHECK_OPERATOR" "the route-check operator" patch pods --subresource=ephemeralcontainers -n mock-docs
  start_idle team-a
  job=$JOB
  route_check team-a open "$job"
  OPEN_ATTEMPTS=$(open_route_attempts "$ROUTE_REPORT")
  check_at_least "$OPEN_ATTEMPTS" 1 "the route check before the policy found routes open"
  stop_idle team-a "$job"
}

# route_checks_after_policy: after the policy and its settle, a new idle pod of each team, then
# 10 s more, since a new pod is briefly outside its policy; then the route check from each, with
# every route refused. Each report records the network plugin and the kind version.
route_checks_after_policy() {
  local team jobs=() i=0
  for team in team-a team-b; do
    start_idle "$team"
    jobs+=("$JOB")
  done
  sleep 10
  for team in team-a team-b; do
    route_check "$team" refused "${jobs[$i]}"
    check_route_report "$team" "$ROUTE_REPORT"
    i=$((i + 1))
  done
  i=0
  for team in team-a team-b; do
    stop_idle "$team" "${jobs[$i]}"
    i=$((i + 1))
  done
}

# check_route_report TEAM REPORT: the route check's report names the network plugin it read
# enforcement from, kindnet, and the kind release whose kindnetd that is.
check_route_report() {
  local team=$1 report=$2 plugin kind
  plugin=$(jq -r '.network_plugin' "$report" 2>/dev/null || true)
  kind=$(jq -r '.kind_version' "$report" 2>/dev/null || true)
  check "$plugin" kindnet "the route check's report for $team records the network plugin"
  case "$kind" in
    'kind v'[0-9]*) pass "the route check's report for $team records the kind version ($kind)" ;;
    *) fail "the route check's report for $team records the kind version (got '$kind')" ;;
  esac
}

# run_image: tags the image just built with its own ID and sets IMG_RUN to that tag. The
# manifests name $IMG; the cluster runs the image under this tag instead, so a run on an
# existing cluster replaces every pod that runs it. With one fixed tag, kubectl apply would see
# no change and leave the previous build's pods running.
run_image() {
  local image_id
  image_id=$(docker image inspect --format '{{.Id}}' "$IMG")
  image_id=${image_id#sha256:}
  case "$image_id" in
    '' | *[!0-9a-f]*)
      echo "cannot read the ID of the image $IMG (got '$image_id')" >&2
      return 1
      ;;
  esac
  IMG_RUN=${IMG%:*}:${image_id:0:12}
  docker tag "$IMG" "$IMG_RUN"
}

# apply_base: applies the base manifests with every pod that runs $IMG on this run's tag, and
# Postgres's pod template annotated with the digest it runs. The manifest names Postgres's tag
# alone, so the annotation is what changes when only the digest does, and rolls the pod.
apply_base() {
  k kustomize "$ROOT/deploy/kind/base" \
    | sed -e "s|image: $IMG\$|image: $IMG_RUN|" \
      -e "s|switchboard.io/image-digest: .*|switchboard.io/image-digest: ${POSTGRES_IMAGE#*@}|" \
    | k apply -f -
}

# load_images: loads this run's image and Postgres into the cluster. Postgres goes in under its
# tag alone, which is what the kind manifest names: the archive holds this platform's manifest,
# not the tag's multi-arch index, so a pod naming the index digest would miss it and pull.
load_images() {
  local arch postgres_tag=${POSTGRES_IMAGE%@*}
  arch=$(docker version --format '{{.Server.Arch}}')
  docker image inspect "$POSTGRES_IMAGE" >/dev/null 2>&1 || docker pull "$POSTGRES_IMAGE"
  # Tagged from the pinned digest, so the tag is that image whatever it named here before.
  docker tag "$POSTGRES_IMAGE" "$postgres_tag"
  # `kind load docker-image` fails on Docker's containerd image store with multi-platform
  # images, so save this platform's images to an archive and load that.
  docker save --platform "linux/$arch" -o "$DEMO_DIR/images.tar" "$IMG_RUN" "$postgres_tag"
  kind load image-archive "$DEMO_DIR/images.tar" --name "$CLUSTER"
  rm -f "$DEMO_DIR/images.tar"
}

# check_postgres_image: the Postgres pod runs the pinned digest. That digest names a multi-arch
# index the node never sees: the archive kind loads holds this platform's manifest, which
# Docker's classic image store writes anew when it saves the image, and kind's load wraps it in
# an index of its own. What reaches the node unchanged is the image's config, and the config's
# digest is the ID the node gives a container's image. Docker's own image ID cannot stand in for
# it: the classic store gives the config's digest, the containerd store the manifest's. So this
# reads the config's digest of the pinned image for this platform from what `docker save`
# writes, which is the same on both stores, and requires the pod's container to run the image
# with that ID.
check_postgres_image() {
  local arch want pods node container got
  arch=$(docker version --format '{{.Server.Arch}}')
  # manifest.json names the config blobs/sha256/<hex>, or <hex>.json before Docker 25.
  want=$(docker save --platform "linux/$arch" "$POSTGRES_IMAGE" | tar -xOf - manifest.json |
    jq -r '.[0].Config | capture("^(blobs/sha256/)?(?<hex>[0-9a-f]{64})(\\.json)?$").hex | "sha256:" + .') || want=''
  pods=$(k -n switchboard get pods -l app=postgres \
    -o jsonpath='{range .items[*]}{.spec.nodeName} {.status.containerStatuses[0].containerID}{"\n"}{end}') || pods=''
  if [ "$(count_lines . "$pods")" -ne 1 ]; then
    fail "Postgres runs the pinned digest (want one pod, got '$pods')"
    return
  fi
  read -r node container <<<"$pods"
  if [ -z "$container" ]; then
    fail "Postgres runs the pinned digest (its pod on $node has no container yet)"
    return
  fi
  case "$want" in
    sha256:*) ;;
    *)
      fail "Postgres runs the pinned digest (cannot read the config of $POSTGRES_IMAGE for linux/$arch: got '$want')"
      return
      ;;
  esac
  # The CRI's imageRef for a listed container is its image's ID.
  got=$(docker exec "$node" crictl ps -o json --id "${container#*://}" | jq -r '.containers[].imageRef') || got=''
  if [ "$got" = "$want" ]; then
    pass "Postgres runs the pinned digest (${POSTGRES_IMAGE#*@}: linux/$arch config $want)"
  else
    fail "Postgres runs the pinned digest (its container ${container#*://} runs image '$(printf '%s' "$got" | tr '\n' ' ')', want $want)"
  fi
}

kind_run() {
  MODE=kind
  step "cluster $CLUSTER (own kubeconfig $KCFG; otto-dev and ~/.kube/config untouched)"
  mkdir -p "$DEMO_DIR"
  if kind get clusters | grep -qx "$CLUSTER"; then
    kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KCFG"
  else
    kind create cluster --name "$CLUSTER" --kubeconfig "$KCFG" --config "$ROOT/deploy/kind/cluster.yaml" --wait 120s
  fi

  step "build the image and load it into the cluster"
  docker build -t "$IMG" -f "$ROOT/deploy/Dockerfile" --build-arg REQUIRE_ALL_BINS=true "$ROOT"
  run_image
  echo "this run's image: $IMG_RUN"
  load_images

  step "the cluster's issuer and keys (the gateway fetches its own; mock-docs gets a copy)"
  local issuer
  issuer=$(k get --raw /.well-known/openid-configuration | jq -r .issuer)
  check "$issuer" "$KIND_ISSUER" "the cluster's issuer is the one the gateway trusts"
  k get --raw /openid/v1/jwks >"$DEMO_DIR/cluster-jwks.json"
  check_at_least "$(jq '.keys | length' "$DEMO_DIR/cluster-jwks.json")" 1 "the cluster published its signing keys"
  k apply -f "$ROOT/deploy/kind/base/namespaces.yaml"
  # mock-docs, a test double, verifies the gateway's tokens with a copy of these keys, made once.
  # The gateway fetches its own from the API server (deploy/kind/base/config/gateway.toml); a copy
  # an earlier run left in its namespace is removed.
  k -n mock-docs create configmap cluster-issuer-keys --from-file=jwks.json="$DEMO_DIR/cluster-jwks.json" \
    --dry-run=client -o yaml | k apply -f -
  k -n switchboard delete configmap cluster-issuer-keys --ignore-not-found

  step "deploy Postgres, the migration, mock-docs and the gateway, with no network policy"
  # A run on an existing cluster starts from no policy, or the first probe below would mean nothing.
  k delete -k "$ROOT/deploy/kind/policy" --ignore-not-found
  k -n switchboard delete job migrate --ignore-not-found
  k -n team-a delete job -l app=mock-workload --ignore-not-found
  k -n team-a delete job -l app=stranger-workload --ignore-not-found
  k -n team-b delete job -l app=mock-workload --ignore-not-found
  apply_base
  # The route check's operator: its ServiceAccount and only the access its step needs.
  k apply -f "$ROOT/deploy/kind/route-check/rbac.yaml"
  k -n switchboard rollout status deploy/postgres --timeout=120s
  check_postgres_image
  wait_job switchboard migrate 180
  k -n switchboard logs job/migrate | sed 's/^/    /'
  check "$JOB_STATUS" 0 "the migration completed"
  k -n mock-docs rollout status deploy/mock-docs --timeout=120s
  k -n switchboard rollout status deploy/gateway --timeout=240s
  check "$(k -n switchboard get deploy/gateway -o jsonpath='{.spec.template.spec.containers[0].image}')" \
    "$IMG_RUN" "the gateway runs this run's image"
  check "$(k -n mock-docs get deploy/mock-docs -o jsonpath='{.spec.template.spec.containers[0].image}')" \
    "$IMG_RUN" "mock-docs runs this run's image"
  mark_start

  step "the gateway's boot lines (its pod of the current ReplicaSet)"
  gateway_pod
  echo "    pod $GATEWAY_POD"
  if fetch "the gateway's log (pod $GATEWAY_POD)" k -n switchboard logs "pod/$GATEWAY_POD"; then
    check_boot "$FETCHED"
    check_keys_fetched "$FETCHED" "$KIND_ISSUER"
  fi

  step "the API server gives its issuer's keys, and nothing else, to a caller with no token (decision 0013, section 10)"
  # Asked from the gateway's container, which mounts no token the API server accepts, with the
  # cluster CA the gateway trusts. The base binds this ClusterRole, and only it, to
  # system:unauthenticated (deploy/kind/base/issuer-discovery.yaml).
  if fetch "the issuer-discovery ClusterRole" k get clusterrole system:service-account-issuer-discovery -o json; then
    check "$(jq -c '[.rules[] | {verbs, nonResourceURLs, resources, apiGroups}]' <<<"$FETCHED")" \
      '[{"verbs":["get"],"nonResourceURLs":["/.well-known/openid-configuration","/.well-known/openid-configuration/","/openid/v1/jwks","/openid/v1/jwks/"],"resources":null,"apiGroups":null}]' \
      "the issuer-discovery ClusterRole grants only get on the issuer's discovery document and keys"
  fi
  if fetch "the issuer's keys with no token (pod $GATEWAY_POD)" k -n switchboard exec "pod/$GATEWAY_POD" -c gateway -- \
    curl -sS --fail --cacert "$KIND_CLUSTER_CA" "$KIND_KEYS_URL"; then
    check "$(jq -c '[.keys[].kid] | sort' <<<"$FETCHED")" "$(jq -c '[.keys[].kid] | sort' "$DEMO_DIR/cluster-jwks.json")" \
      "an unauthenticated read of $KIND_KEYS_URL gets the cluster's keys"
  fi
  if fetch "a ConfigMap with no token (pod $GATEWAY_POD)" k -n switchboard exec "pod/$GATEWAY_POD" -c gateway -- \
    curl -sS -o /dev/null -w '%{http_code}' --cacert "$KIND_CLUSTER_CA" \
    "$KIND_ISSUER/api/v1/namespaces/switchboard/configmaps/registry"; then
    check "$FETCHED" 403 "an unauthenticated read of a ConfigMap is refused"
  fi

  step "before the policy: each team's direct call to mock-docs connects, the server refuses the workload's own token, and the gateway's call to mock-docs succeeds"
  before_policy_probes

  step "before the policy: the route check, as the route-check operator, from a new idle team-a pod; every route to mock-docs is open, by name and by address (its positive control)"
  route_checks_before_policy

  step "apply the network policy; new pods from here on; settle 10 s"
  k apply -k "$ROOT/deploy/kind/policy"
  sleep 10

  step "team-a and team-b workloads (new pods)"
  kind_workload "team-a workload" team-a mock-workload full
  kind_workload "team-b workload" team-b mock-workload full

  step "identity: a ServiceAccount not in the team manifest"
  kind_workload "stranger" team-a stranger-workload refused

  step "after the policy: the route check, as the route-check operator, from a new idle pod of each team, 10 s after it started; every route to mock-docs is refused, by name and by address"
  route_checks_after_policy

  step "the gateway's token grant (gateway-tokens.yaml): it may create tokens for docs-team-a and docs-team-b, and for no other ServiceAccount"
  token_grants

  step "operator checks: every row of deploy/route-check/permissions.tsv, for each team's workload, in mock-docs, the gateway's namespace, its own and across the cluster: neither may start pods or the controllers that start them, mint tokens, impersonate, exec, attach, port-forward, proxy, add an ephemeral container, bind or escalate a role or create, update or patch a binding, nor get, list or watch secrets or configuration; and no RBAC rule bound to either grants any of these, whatever its resourceNames"
  operator_checks

  step "mock-docs accepted only the entries' identities, no denied call reached it, and each team's calls came under its own entry's identity"
  # Every request the server accepted carried the token of one of its entries' ServiceAccounts,
  # docs-team-a or docs-team-b, for audience mock-docs, which the gateway pod's token writer got.
  # Each team's came under its own entry's. Each team is allowed four calls, so 2 x 4 = 8:
  # before the policy, the read through the gateway after its direct call; after it, its full
  # run's list and read, and the same pod's read after its direct call times out. Its other calls
  # are denied, and the stranger is refused. The two direct calls before the policy, one per
  # team, carried the workloads' own projected tokens, for audience switchboard, and were
  # refused (401) as wrong_audience. The route check's probe before the policy sent no
  # credential, and each attempt it found open was refused as no_bearer. After the policy no
  # direct call reaches the server.
  if fetch "mock-docs' log" mock_docs_log; then
    check_server_callers "$FETCHED" "$KIND_ENTRY_SUBJECTS" 8 2 "$OPEN_ATTEMPTS"
    check_server_entries "$FETCHED" 4 "team-a=${KIND_ENTRY_SUBJECTS%% *}" "team-b=${KIND_ENTRY_SUBJECTS##* }"
  fi

  step "the gateway's view of identity failures (operators only; no audit rows)"
  local gateway_logs
  # Only this run's lines: a run on an existing cluster may reuse the gateway's pod.
  gateway_logs=$(k -n switchboard logs --since-time "$LOG_SINCE" "pod/$GATEWAY_POD")
  printf '%s\n' "$gateway_logs" | grep 'identity_failed' | sed 's/^/    /' || echo "    (none)"
  # Two teams refused three ways each (no token, not a token, a projected token for another
  # audience), and the stranger once.
  check_at_least "$(count_lines '"event":"identity_failed"' "$gateway_logs")" 7 "the gateway logged every identity failure"

  step "the gateway's metrics (GET /metrics on its own port, which the teams cannot reach)"
  # The kind run has no database outage.
  if fetch "the gateway's metrics (pod $GATEWAY_POD)" k -n switchboard exec "pod/$GATEWAY_POD" -c gateway -- \
    curl -sS --fail http://localhost:9090/metrics; then
    check_metrics none "$FETCHED"
  fi

  # Two lists: each team's full run. The probes before the policy make none, and the
  # stranger's is refused for identity, which writes no row.
  audit_rows 2
  FINISHED=1
}

down_compose() { dc --profile demo down -v --remove-orphans; }
down_kind() { kind delete cluster --name "$CLUSTER" --kubeconfig "$KCFG"; }

# Sourcing defines the functions and runs nothing; the tests use that.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
  return 0
fi

case "${1:-}" in
  compose)
    trap on_exit EXIT
    compose_run
    ;;
  kind)
    trap on_exit EXIT
    kind_run
    ;;
  down)
    # What to take down is always named, so stopping Compose never deletes the cluster.
    case "${2:-}" in
      compose) down_compose ;;
      kind) down_kind ;;
      all) down_compose && down_kind ;;
      *)
        echo "usage: $0 down compose|kind|all" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "usage: $0 compose|kind|down compose|kind|all" >&2
    exit 2
    ;;
esac
