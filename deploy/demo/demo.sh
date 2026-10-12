#!/usr/bin/env bash
# deploy/demo/demo.sh: the demo in one command.
#
#   demo.sh compose   build the image; start Postgres, the migration, the dev issuer, mock-docs
#                     and the gateway under Compose; run both teams' workloads; show a database
#                     outage and a withdrawn tool; show #11's demonstrations (an undeclared
#                     argument, a registry refused at load, a hanging server, an overload and
#                     drift); check the audit rows
#   demo.sh kind      the same in the kind cluster switchboard-demo, with projected
#                     ServiceAccount tokens, network policy, the operator's permission checks,
#                     and the route check (deploy/route-check) before and after the policy, and
#                     with no database outage or withdrawn registry file
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
#     `"identity":"enforce"` and `"audit":"postgres"`, and the caps, deadlines and drift
#     interval; one `"event":"identity_failed"` line per caller refused for identity; and the
#     registry's reloads (`policy_reloaded`, `policy_reload_refused`) and the drift pass's
#     withdrawals (`tool_withdrawn`, `policy_withdrawal_cleared`), each with its fields;
#   - mock-docs' JSON log lines (crates/mock-docs-server): one per request, with
#     `bearer_sha256`, the first 12 hex digits of the bearer's SHA-256, `accepted` and, for a
#     JSON-RPC request, its `rpc_method`, and for a tools/call its `project` and, if the server
#     refused the project, `refused`. The gateway's own tools/list requests are its drift pass,
#     which reads each entry's tool list every 10 s with that entry's credential; they are not
#     calls, and the call counts leave them out. In kind the server runs in its JWT mode, and
#     each line also has `caller`, the verified subject of an accepted token, and `refusal`, why
#     a token was refused. Its admin endpoint's requests are logged as `"event":"admin"`;
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
# The SHA-256 of `not-a-token`, the malformed bearer of the gateway's drift probe
# (connector_proxy::MALFORMED_CREDENTIAL).
PROBE_MALFORMED_SHA=ce6f21ae951df0ba38d6ce0e0175465bf5e9882edcf2ba677bca63b296f17ce7
# The registries' revision, and the Compose withdrawal's (registry-withdrawn.toml).
REVISION=demo-7
WITHDRAWN_REVISION=demo-8
# The revisions of the registry variants the demonstrations make from the registry served, at
# run time, start with this one, above every revision a file names, so a row or log line under
# a variant is never taken for one under a file's revision. Each adds what it is and when.
VARIANT_REVISION=demo-9
# #11's demonstrations (demonstrations, below) rely on the gateway's defaults for the caps and
# the call deadline, which the demos' deployment files leave alone, and on the drift interval
# they set. TEAM_CAP is decision 0014's cap on calls in flight from one team to one proxied
# server, CALL_DEADLINE its call deadline in seconds, and DRIFT_INTERVAL the deployment files'
# `[drift] interval_seconds`. Each run checks the gateway's boot lines give these
# (check_bounds), and crates/demo-checks holds them to the code and the files.
TEAM_CAP=8
CALL_DEADLINE=5
DRIFT_INTERVAL=10
# How long past CALL_DEADLINE the hanging-server step's client may wait for its answer, in ms.
# The deadline holds the call to the server; the client also waits for what comes before and
# after it: the token check, the policy, the audit row's begin and finish, each one Postgres
# write, and the hops through Docker's or the cluster's network. 1.5 s covers those on a busy
# laptop, and is far short of the 10 s after which mock-docs answers slow-doc, so a gateway that
# waits for the server, or holds the call 2 s past its deadline, fails.
HANG_ALLOWANCE_MS=1500
# The drift step has mock-docs serve this description of list_documents in place of the one
# approved. Both entries list it, so both entries' list tools are withdrawn, and the revision
# served is then this one, the literal derived revision of decision 0013, section 6.
DRIFTED_DESCRIPTION="List the names of the documents in one project, and whatever else it holds."
DRIFTED_REVISION="$REVISION+withdrawn:docs-team-a__list_documents,docs-team-b__list_documents"
# mock-docs' admin endpoint (deploy/compose/compose.yaml, deploy/kind/base/mock-docs.yaml). It
# listens on loopback in mock-docs' own container, so only an exec into that container reaches
# it: no Service, published port or other pod can.
MOCK_ADMIN_URL=http://127.0.0.1:9091
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
# The last step_mark, in epoch seconds and as an RFC 3339 time; and the gateway's log lines the
# last wait_for_events selected.
MARK_EPOCH=""
MARK_TIME=""
EVENTS=""
# What the last workload tallied printed.
WORKLOAD_OUTPUT=""
# The workload start_workload started, its label, and in Compose the file its output goes to.
BACKGROUND=""
BACKGROUND_LABEL=""
BACKGROUND_OUTPUT=""
# While a demonstration has changed what the gateway serves: the registry file to put back, and
# whether mock-docs serves the drifted description. on_exit undoes both if the run stops early.
RESTORE_REGISTRY=""
DRIFTED=""
# Set from the drift step's change until the gateway serves the re-approval: the gateway may hold
# withdrawals of both list tools in its memory, which only a new approval or a restart clears.
# on_exit says so and how to clear them, and restarts nothing: the gateway is left as it was, to
# be looked at.
WITHDRAWAL_HELD=""

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
  WORKLOAD_OUTPUT=$output
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
  if [ -n "$DRIFTED" ]; then
    echo "serving list_documents' approved description again after the interrupted drift step" >&2
    mock_admin DELETE /admin/definitions/list_documents >&2 || echo "could not; mock-docs still serves the drifted description" >&2
  fi
  if [ -n "$RESTORE_REGISTRY" ]; then
    echo "putting back the registry the gateway served before the interrupted step" >&2
    install_registry "$RESTORE_REGISTRY" >&2 || echo "could not; the next run puts it back" >&2
  fi
  if [ -n "$WITHDRAWAL_HELD" ]; then
    echo "the gateway may still hold the drift step's withdrawals of docs-team-a__list_documents and docs-team-b__list_documents in memory; until it restarts, a run against it fails" >&2
    case "$MODE" in
      compose) echo "to clear them, stop Compose and start afresh: $0 down compose" >&2 ;;
      kind) echo "to clear them, restart the gateway: kubectl --kubeconfig $KCFG --context kind-$CLUSTER -n switchboard rollout restart deploy/gateway" >&2 ;;
    esac
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
# $WITHDRAWN_REVISION, after each team's read tool is withdrawn. Under a revision the drift pass
# derived from $REVISION, `$REVISION+withdrawn:` and the withdrawn tools, they are its two tools
# less those; and under a re-approval's, `$VARIANT_REVISION-reapproved-` and the time, its two
# tools.
# None is left out. ROWS is what row_resources_json prints.
check_list_rows() {
  local rows=$1 expected=$2 lists wrong
  # shellcheck disable=SC2016 # jq's own variables
  if ! lists=$(printf '%s' "$rows" | jq -e '[.[] | select(.kind == "list")] | length') \
    || ! wrong=$(printf '%s' "$rows" | jq -c --arg revision "$REVISION" --arg withdrawn "$WITHDRAWN_REVISION" --arg variant "$VARIANT_REVISION" '
        def entry: {"team-a": "docs-team-a", "team-b": "docs-team-b"}[.team // ""];
        def both: [entry + "__list_documents", entry + "__read_document"];
        def shown: if entry == null then null
          elif .revision == $revision or ((.revision // "") | test("^" + $variant + "-reapproved-[0-9]{8}T[0-9]{6}Z$")) then both
          elif .revision == $withdrawn then [entry + "__list_documents"]
          elif ((.revision // "") | startswith($revision + "+withdrawn:")) then
            ((.revision | ltrimstr($revision + "+withdrawn:") | split(",")) as $gone | both - $gone)
          else null end;
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
# short. Requests with no bearer (the health checks) are not counted, and neither are the
# gateway's drift polls: its own tools/list requests, with its own credentials. Nor are its drift
# probes' bearers (decision 0013, section 9), the malformed one and the probe's dummy, which are
# no workload's; mock-docs must refuse them, so one it accepted still fails.
# check_server_entries checks that each team's calls carried its own entry's credential.
check_server_bearers() {
  local logs=$1 shas=$2 calls=$3 scope=$4 lines sha shown=""
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(.bearer_sha256 != null)
    | "\(if .accepted == true then "accepted" else "refused" end) \(.bearer_sha256) \(.rpc_method // "none")"')
  for sha in $shas; do shown="$shown ${sha:0:12}..."; done
  echo "    requests seen by mock-docs, by answer, bearer sha256 prefix and method (the gateway's are$shown):"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  local good bad stray ours
  # shellcheck disable=SC2016 # awk's own variables
  ours='function ours(prefix,  n, i, sha) {
      n = split(shas, sha, " ")
      for (i = 1; i <= n; i++) if (length(prefix) >= 8 && index(sha[i], prefix) == 1) return 1
      return 0
    }'
  good=$(printf '%s\n' "$lines" | awk -v shas="$shas" "$ours"'$1 == "accepted" && ours($2) && $3 != "tools/list" { count++ } END { print count + 0 }')
  bad=$(printf '%s\n' "$lines" | awk -v shas="$shas" "$ours"'$1 == "accepted" && !ours($2) { count++ } END { print count + 0 }')
  local probe_shas
  probe_shas="$PROBE_MALFORMED_SHA $(cat "$COMPOSE_CREDENTIALS/registry-probe-credential.sha256")"
  stray=$(printf '%s\n' "$lines" | awk -v shas="$shas $probe_shas" "$ours"'NF == 3 && !ours($2) { count++ } END { print count + 0 }')
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
# The gateway's drift polls, its own tools/list requests under the entries' identities, are not
# calls and are not counted. check_server_entries checks that each team's calls came under its
# own entry's. Exactly REFUSALS requests were refused as wrong_audience: a token the cluster
# signed for another audience, the workloads' own on their direct calls before the policy.
# Exactly PROBES were refused as no_bearer: the route check's probe before the policy, which
# sends no credential, one request per attempt it found open. Each drift poll's probe of an entry
# (decision 0013, section 9) adds three refusals, one each of no_bearer, malformed and
# wrong_subject, so one malformed refusal counts one gateway probe. Only wrong_subject shows that
# the third call carried registry-probe's token, valid for mock-docs' audience but for a subject
# outside the gateway's identities (decision 0010), so there must be exactly as many of those as
# of malformed. A refusal for any other reason, or one more of any of these, fails.
check_server_callers() {
  local logs=$1 subjects=$2 calls=$3 refusals=$4 probes=$5 lines
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(has("accepted"))
    | if .accepted == true then "accepted \(.caller // "none") \(.rpc_method // "none")" else "refused \(.refusal // "none")" end')
  echo "    requests seen by mock-docs, by answer and verified caller and method, or refusal:"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  local gateway other audience bearerless third refused drift_probes
  drift_probes=$(printf '%s\n' "$lines" | awk '$0 == "refused malformed" { n++ } END { print n + 0 }')
  # shellcheck disable=SC2016 # awk's own variables
  local ours='BEGIN { n = split(subjects, list, " "); for (i = 1; i <= n; i++) entry[list[i]] = 1 }
    '
  gateway=$(printf '%s\n' "$lines" | awk -v subjects="$subjects" "$ours"'$1 == "accepted" && ($2 in entry) && NF == 3 && $3 != "tools/list" { count++ } END { print count + 0 }')
  other=$(printf '%s\n' "$lines" | awk -v subjects="$subjects" "$ours"'$1 == "accepted" && !(($2 in entry) && NF == 3) { count++ } END { print count + 0 }')
  audience=$(printf '%s\n' "$lines" | awk '$0 == "refused wrong_audience" { n++ } END { print n + 0 }')
  bearerless=$(printf '%s\n' "$lines" | awk '$0 == "refused no_bearer" { n++ } END { print n + 0 }')
  third=$(printf '%s\n' "$lines" | awk '$0 == "refused wrong_subject" { n++ } END { print n + 0 }')
  refused=$(printf '%s\n' "$lines" | awk '$1 == "refused" { n++ } END { print n + 0 }')
  check "$gateway" "$calls" "mock-docs accepted the entries' tokens ($subjects) on exactly the $calls calls the gateway allowed"
  check "$other" 0 "mock-docs accepted no other caller, and no token without one"
  check "$audience" "$refusals" "mock-docs refused the $refusals direct calls' tokens as meant for another audience"
  check "$bearerless" "$((probes + drift_probes))" "mock-docs refused the route check's $probes open attempts before the policy, which carried no bearer, and the gateway's $drift_probes probes' calls with none"
  check "$third" "$drift_probes" "mock-docs refused the gateway's $drift_probes probes' calls with registry-probe's token as wrong_subject"
  check "$refused" "$((refusals + probes + 3 * drift_probes))" "mock-docs refused nothing else"
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

# --- #11's demonstrations, in both runs -------------------------------------------------------

# check_bounds LOGS: the gateway's boot lines in LOGS give what the demonstrations rely on: a cap
# of TEAM_CAP calls in flight from each team to each server, the default CALL_DEADLINE s
# deadline on each entry's calls, and a DRIFT_INTERVAL s drift interval. The gateway logs a
# server's bounds only when the deployment file sets them, so an entry with no such line has
# the default. A gateway that started more than once (a Compose container started again) is
# read at its last start.
check_bounds() {
  local boot entry
  boot=$(printf '%s\n' "$1" | jq -cR 'fromjson? | .fields? // empty | select(.event == "boot")' 2>/dev/null) || boot=""
  check "$(jq -rs '[.[] | .per_team_per_server_in_flight // empty] | last // empty' <<<"$boot")" "$TEAM_CAP" \
    "the gateway caps each team at $TEAM_CAP calls in flight to each server (decision 0014)"
  for entry in docs-team-a docs-team-b; do
    # shellcheck disable=SC2016 # jq's own variables
    check "$(jq -rs --arg entry "$entry" '[.[] | select(.server == $entry) | .deadline_seconds // empty] | last // "the default"' <<<"$boot")" \
      "the default" "entry $entry's calls have the default deadline, $CALL_DEADLINE s: the deployment file sets none (decision 0014)"
  done
  check "$(jq -rs '[.[] | .drift_interval_seconds // empty] | last // empty' <<<"$boot")" "$DRIFT_INTERVAL" \
    "the drift pass reads each entry's tool list every $DRIFT_INTERVAL s"
}

# workload LABEL TEAM MODE [ARGS...]: runs TEAM's workload once in MODE, in whichever
# deployment is running, and tallies it.
workload() {
  local label=$1 team=$2 mode=$3
  shift 3
  case "$MODE" in
    compose) compose_workload "$label" "$mode" "$team" "$@" ;;
    kind) kind_workload "$label" "$team" mock-workload "$mode" "$@" ;;
  esac
}

# start_workload LABEL TEAM MODE [ARGS...]: starts TEAM's workload in MODE and returns at once.
# finish_workload waits for it and tallies it. One runs at a time.
start_workload() {
  local team=$2 mode=$3
  BACKGROUND_LABEL=$1
  shift 3
  case "$MODE" in
    compose)
      BACKGROUND_OUTPUT=$DEMO_DIR/background-workload.log
      compose_workload_output "$mode" "$team" "$@" >"$BACKGROUND_OUTPUT" 2>&1 &
      BACKGROUND=$!
      ;;
    kind)
      start_job "$team" mock-workload "$mode" "$@"
      BACKGROUND=$team/$JOB
      ;;
  esac
}
finish_workload() {
  local status=0
  case "$MODE" in
    compose)
      wait "$BACKGROUND" || status=$?
      tally_workload "$BACKGROUND_LABEL" "$status" "$(cat "$BACKGROUND_OUTPUT")"
      ;;
    kind)
      wait_job "${BACKGROUND%%/*}" "${BACKGROUND#*/}" 300
      if fetch "$BACKGROUND_LABEL's log (job $BACKGROUND)" k -n "${BACKGROUND%%/*}" logs "job/${BACKGROUND#*/}"; then
        tally_workload "$BACKGROUND_LABEL" "$JOB_STATUS" "$FETCHED"
      fi
      ;;
  esac
  BACKGROUND=""
}

# step_mark: sets MARK_EPOCH and MARK_TIME to now by the database's clock, as mark_start sets
# SINCE and LOG_SINCE, so a step reads only its own rows and log lines.
step_mark() {
  local mark
  mark=$(psql_superuser -AtF ' ' -c "select extract(epoch from now()),
    to_char(now() at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
  MARK_EPOCH=${mark% *}
  MARK_TIME=${mark#* }
}

# step_rows SINCE: every row begun since SINCE (epoch seconds), as one JSON array in the order
# begun, with what the demonstrations' checks read. `begun` and `finished` are epoch seconds.
step_rows() {
  psql_reader -Atc "select coalesce(json_agg(json_build_object('kind', kind, 'team', proved_team,
      'tool', tool, 'decision', decision, 'reason', reason, 'outcome', outcome,
      'error_kind', error_kind, 'outcome_sentence', outcome_sentence, 'latency_ms', latency_ms,
      'revision', policy_revision, 'listed', listed_tools,
      'begun', extract(epoch from begun_at), 'finished', extract(epoch from finished_at))
      order by begun_at), '[]') from $AUDIT_TABLE where begun_at >= to_timestamp($1)"
}

# gateway_log SINCE: the gateway's log lines from SINCE, an RFC 3339 time.
gateway_log() {
  case "$MODE" in
    compose) dc logs --no-log-prefix --since "$1" gateway ;;
    kind) k -n switchboard logs --since-time "$1" -c gateway "pod/$GATEWAY_POD" ;;
  esac
}

# gateway_metrics: what the gateway's GET /metrics answers now.
gateway_metrics() {
  case "$MODE" in
    compose) dc exec -T gateway curl -sS --fail http://127.0.0.1:9090/metrics ;;
    kind) k -n switchboard exec "pod/$GATEWAY_POD" -c gateway -- curl -sS --fail http://localhost:9090/metrics ;;
  esac
}

# events LOG FILTER: the gateway's JSON log lines in LOG that the jq FILTER selects, each as its
# fields with its `timestamp` beside them, one compact JSON object a line.
events() {
  printf '%s\n' "$1" | jq -cR "fromjson? | . as \$line | (.fields? // empty) | . + {timestamp: \$line.timestamp} | $2"
}

# wait_for_events WHAT TIMEOUT COUNT SINCE FILTER: reads the gateway's log from SINCE every 2 s
# until FILTER selects at least COUNT of its lines, for at most TIMEOUT seconds, and passes WHAT,
# or fails it if they did not come in time. Sets EVENTS to the lines selected.
wait_for_events() {
  local what=$1 timeout=$2 count=$3 since=$4 filter=$5 waited=0 log
  EVENTS=""
  while :; do
    if log=$(gateway_log "$since" 2>/dev/null); then
      EVENTS=$(events "$log" "$filter" 2>/dev/null) || EVENTS=""
    fi
    if [ "$(count_lines . "$EVENTS")" -ge "$count" ]; then
      pass "$what (seen within $waited s)"
      return 0
    fi
    if [ "$waited" -ge "$timeout" ]; then
      fail "$what (not seen within $timeout s: $(count_lines . "$EVENTS") of $count log lines)"
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

# mock_admin METHOD PATH [BODY]: one request to mock-docs' admin endpoint, MOCK_ADMIN_URL, from
# inside mock-docs' own container: the endpoint listens on that container's loopback and nowhere
# else. It has no credential of its own, so it accepts mock-docs' callers (crates/mock-docs-server):
# the request carries docs-team-a's credential, in Compose its dummy credential and in kind a
# short-lived token of its ServiceAccount for audience mock-docs, which the demo's own
# kubeconfig asks the cluster for.
mock_admin() {
  local method=$1 path=$2 bearer request
  case "$MODE" in
    compose) bearer=$(cat "$COMPOSE_CREDENTIALS/docs-team-a-credential") ;;
    kind) bearer=$(k -n switchboard create token docs-team-a --audience mock-docs --duration 10m) ;;
  esac
  request=(curl -sS --fail -w '\n' -X "$method" -H "Authorization: Bearer $bearer" "$MOCK_ADMIN_URL$path")
  if [ $# -ge 3 ]; then
    request+=(-H 'Content-Type: application/json' -d "$3")
  fi
  case "$MODE" in
    compose) dc exec -T mock-docs "${request[@]}" ;;
    kind) k -n mock-docs exec deploy/mock-docs -c mock-docs -- "${request[@]}" ;;
  esac
}

# accepted_calls LOG: how many tools/call requests mock-docs accepted in LOG, its log lines. Its
# admin requests and the gateway's drift polls are not calls.
accepted_calls() {
  printf '%s\n' "$1" | jq -cR 'fromjson? | select(.event == "request" and .accepted == true and .rpc_method == "tools/call")' \
    | awk 'END { print NR }'
}

# served_registry: the registry file the gateway serves now: Compose's copy under .demo, or kind's
# ConfigMap `registry`.
served_registry() {
  case "$MODE" in
    compose) cat "$DEMO_DIR/compose-registry/registry.toml" ;;
    kind) k -n switchboard get configmap registry -o jsonpath='{.data.registry\.toml}' ;;
  esac
}

# install_registry FILE: puts FILE where the gateway reads its registry. In kind the kubelet
# updates the mounted ConfigMap when it next syncs the gateway's pod, up to a minute or more
# away; a change to the pod's annotations makes it sync now.
install_registry() {
  case "$MODE" in
    compose) swap_registry "$1" ;;
    kind)
      k -n switchboard create configmap registry --from-file=registry.toml="$1" --dry-run=client -o yaml \
        | k apply -f - >/dev/null
      k -n switchboard annotate --overwrite "pod/$GATEWAY_POD" "switchboard.io/registry-installed=$(date +%s)" >/dev/null
      ;;
  esac
}

# reload_wait: how long a registry change may take to reach the gateway: its 2 s poll in
# Compose, and the kubelet's update of the ConfigMap in kind as well.
reload_wait() {
  case "$MODE" in
    compose) echo 30 ;;
    kind) echo 240 ;;
  esac
}

# reach_variant REVISION: the registry on standard input, with revision REVISION and team-b
# admitted to docs-team-a's surface beside team-a. docs-team-a's entry narrows nothing and
# reaches atlas, which team-b's limit does not hold, so the loader must refuse it (decision 0011,
# rule 5). Fails, and the output is not to be used, unless it changed exactly those two lines.
reach_variant() {
  awk -v revision="$1" '
    /^\[/ { table = $0; surface = "" }
    table == "" && /^revision = "/ { print "revision = \"" revision "\""; revised++; next }
    table == "[[surfaces]]" && $0 == "name = \"docs-team-a\"" { surface = "docs-team-a" }
    surface == "docs-team-a" && $0 == "teams = [\"team-a\"]" { print "teams = [\"team-a\", \"team-b\"]"; widened++; next }
    { print }
    END { exit !(revised == 1 && widened == 1) }'
}

# reapproval_variant REVISION APPROVED_AT TOOL...: the registry on standard input, with revision
# REVISION and each TOOL approved again at APPROVED_AT. Nothing else changes: not the definition
# approved, its hash or the binding. A new approved_at is a new approval, which clears a
# standing withdrawal of the tool (decision 0013, section 6). Fails, and the output is not to be
# used, unless it changed the revision and one approved_at for each TOOL.
reapproval_variant() {
  local revision=$1 approved_at=$2
  shift 2
  awk -v revision="$revision" -v approved_at="$approved_at" -v tools="$*" '
    BEGIN { n = split(tools, list, " "); for (i = 1; i <= n; i++) wanted["name = \"" list[i] "\""] = 1 }
    /^\[/ { table = $0; tool = "" }
    table == "" && /^revision = "/ { print "revision = \"" revision "\""; revised++; next }
    table == "[[tools]]" && ($0 in wanted) { tool = $0 }
    tool != "" && /^approved_at = / { print "approved_at = " approved_at; approved++; tool = ""; next }
    { print }
    END { exit !(revised == 1 && approved == n && n > 0) }'
}

# number_or_none VALUE: VALUE if it is a whole number, or `none`.
number_or_none() {
  case "$1" in
    '' | *[!0-9]*) echo none ;;
    *) echo "$1" ;;
  esac
}

# check_undeclared ROWS BEFORE AFTER: team-a's read with an argument its approval does not
# declare (workload.sh undeclared). ROWS are the step's rows (step_rows): exactly one, team-a's
# read, allowed and completed as error of the kind invalid_arguments, since the argument check
# runs inside the audited run and sends nothing. BEFORE and AFTER are how many tools/call
# requests mock-docs had accepted before and after the step: the same.
check_undeclared() {
  local rows=$1 read
  read=$(team_entry team-a)__read_document
  case "$(number_or_none "$2") $(number_or_none "$3")" in
    *none*) fail "mock-docs received no call for the read with an undeclared argument (its calls could not be counted: '$2' before, '$3' after)" ;;
    *) check "$3" "$2" "mock-docs received no call for the read with an undeclared argument (its calls before and after)" ;;
  esac
  check "$(jq -c '[.[] | {team, tool, decision, outcome, error_kind}]' <<<"$rows" 2>/dev/null)" \
    "[{\"team\":\"team-a\",\"tool\":\"$read\",\"decision\":\"allow\",\"outcome\":\"error\",\"error_kind\":\"invalid_arguments\"}]" \
    "audit: the step's one row is team-a's read, allowed and completed as error of the kind invalid_arguments"
}

# check_meanwhile ROWS WHAT: team-b's steady reads went on while team-a's calls in ROWS were held:
# at least one of team-b's rows began after the first of team-a's began, and finished, ok,
# before the last of team-a's finished. Team-b's calls go to its own entry, so neither cap of
# docs-team-a's holds them; this shows the gateway answered them meanwhile.
check_meanwhile() {
  check_at_least "$(jq -r '[.[] | select(.team == "team-a")] as $a
      | ($a | map(.begun) | min) as $from | ($a | map(.finished) | max) as $to
      | [.[] | select(.team == "team-b" and .decision == "allow" and .outcome == "ok"
          and $from != null and $to != null and .begun > $from and .finished != null
          and .finished < $to)] | length' <<<"$1" 2>/dev/null)" 1 \
    "audit: team-b's reads were answered while $2"
}

# check_hang ROWS OUTPUT: team-a's read of slow-doc (workload.sh hang). Of the step's rows,
# team-a's is exactly one: that read, allowed and completed as error of the kind
# oversized_or_late_read, its connector abandoned at the call deadline, within a second of it.
# The row's latency ends before its audit completes, so it does not show when the caller was
# answered: OUTPUT, what the workload printed, does. Its client got the answer no sooner than
# the deadline and no later than HANG_ALLOWANCE_MS after it. Team-b's reads went on meanwhile.
check_hang() {
  local rows=$1 output=$2 read deadline=$((CALL_DEADLINE * 1000)) elapsed
  read=$(team_entry team-a)__read_document
  check "$(jq -c '[.[] | select(.team == "team-a") | {tool, decision, outcome, error_kind}]' <<<"$rows" 2>/dev/null)" \
    "[{\"tool\":\"$read\",\"decision\":\"allow\",\"outcome\":\"error\",\"error_kind\":\"oversized_or_late_read\"}]" \
    "audit: team-a's one row is its read, allowed and completed as error of the kind oversized_or_late_read"
  # shellcheck disable=SC2016 # jq's own variables
  check "$(jq -r --argjson ms "$deadline" '[.[] | select(.team == "team-a" and .latency_ms >= $ms and .latency_ms < $ms + 1000)] | length' <<<"$rows" 2>/dev/null)" 1 \
    "audit: it was answered at the $CALL_DEADLINE s deadline, within a second ($(jq -r '[.[] | select(.team == "team-a") | .latency_ms] | map(tostring) | join(",")' <<<"$rows" 2>/dev/null) ms)"
  elapsed=$(printf '%s\n' "$output" | sed -nE "s/^ *read of slow-doc: answered after ([0-9]+|unknown) ms by the client's clock\$/\\1/p" | tail -n 1)
  local within="team-a's client was answered between the $CALL_DEADLINE s deadline and $HANG_ALLOWANCE_MS ms after it, by its own clock"
  if [ "$(number_or_none "$elapsed")" = none ]; then
    fail "$within (got '${elapsed:-no time}' from the workload)"
  elif [ "$elapsed" -ge "$deadline" ] && [ "$elapsed" -le $((deadline + HANG_ALLOWANCE_MS)) ]; then
    pass "$within ($elapsed ms)"
  else
    fail "$within (got $elapsed ms)"
  fi
  check_meanwhile "$rows" "team-a's read was held until its deadline"
}

# check_overload ROWS SHED OUTPUT: team-a's TEAM_CAP + 1 reads of slow-doc at once (workload.sh
# overload). Of the step's rows, team-a's are those reads, each allowed: TEAM_CAP completed as
# error of the kind oversized_or_late_read, and one completed as refused, its row recording the
# team-capacity sentence (decision 0014, section 2: refused, not error, which keeps no sentence).
# Each of the TEAM_CAP was held until the deadline and no longer, as check_hang holds its one
# read: its row's latency is within a second of the deadline, and OUTPUT, what the workload
# printed, gives its client's answer between the deadline and HANG_ALLOWANCE_MS after it. SHED
# is how many calls the gateway counted shed with scope team over the step: that one. Team-b's
# reads went on meanwhile.
check_overload() {
  local rows=$1 shed=$2 output=$3 entry read calls=$((TEAM_CAP + 1)) deadline=$((CALL_DEADLINE * 1000))
  entry=$(team_entry team-a)
  read=${entry}__read_document
  local sentence="Your team already has as many calls in flight to server \`$entry\` from this gateway as it allows, so this call to tool \`$read\` was not sent. Try it again shortly."
  # shellcheck disable=SC2016 # jq's own variables
  check "$(jq -r --arg read "$read" '[.[] | select(.team == "team-a")] | "\(length) rows, \([.[] | select(.tool == $read and .decision == "allow")] | length) allowed reads"' <<<"$rows" 2>/dev/null)" \
    "$calls rows, $calls allowed reads" "audit: team-a's $calls reads each have a row, allowed, and the step has no other of team-a's"
  check "$(jq -r '[.[] | select(.team == "team-a" and .outcome == "error" and .error_kind == "oversized_or_late_read")] | length' <<<"$rows" 2>/dev/null)" \
    "$TEAM_CAP" "audit: $TEAM_CAP completed as error of the kind oversized_or_late_read"
  # shellcheck disable=SC2016 # jq's own variables
  check "$(jq -r --argjson ms "$deadline" '[.[] | select(.team == "team-a" and .error_kind == "oversized_or_late_read"
      and .latency_ms >= $ms and .latency_ms < $ms + 1000)] | length' <<<"$rows" 2>/dev/null)" "$TEAM_CAP" \
    "audit: each was answered at the $CALL_DEADLINE s deadline, within a second ($(jq -r '[.[] | select(.team == "team-a" and .error_kind == "oversized_or_late_read") | .latency_ms] | map(tostring) | join(",")' <<<"$rows" 2>/dev/null) ms)"
  local times elapsed held=0 outside=0
  local within="team-a's client was answered on each of the $TEAM_CAP held reads between the $CALL_DEADLINE s deadline and $HANG_ALLOWANCE_MS ms after it, by its own clock"
  times=$(printf '%s\n' "$output" | sed -nE "s/^ *read [0-9]+ of slow-doc, held: answered after ([0-9]+|unknown) ms by the client's clock\$/\\1/p")
  for elapsed in $times; do
    held=$((held + 1))
    if [ "$(number_or_none "$elapsed")" = none ] || [ "$elapsed" -lt "$deadline" ] ||
      [ "$elapsed" -gt $((deadline + HANG_ALLOWANCE_MS)) ]; then
      outside=$((outside + 1))
    fi
  done
  times=$(printf '%s\n' "$times" | paste -sd, -)
  if [ "$held" -eq "$TEAM_CAP" ] && [ "$outside" -eq 0 ]; then
    pass "$within ($times ms)"
  else
    fail "$within (got $held times from the workload, $outside of them outside: '$times')"
  fi
  # shellcheck disable=SC2016 # jq's own variables
  check "$(jq -r --arg sentence "$sentence" '[.[] | select(.team == "team-a" and .outcome == "refused" and .outcome_sentence == $sentence)] | length' <<<"$rows" 2>/dev/null)" \
    1 "audit: one was over the cap of $TEAM_CAP, completed as refused with the team-capacity sentence"
  check "$shed" 1 "metrics: the gateway counted one call shed with scope team"
  check_meanwhile "$rows" "team-a's reads filled its cap"
}

# check_refused_at_load EVENTS VARIANT: the gateway's reload lines (policy_reloaded and
# policy_reload_refused) since the variant of revision VARIANT was installed. The first refuses
# it for rule 5, naming docs-team-a's surface, the atlas it reaches and team-b, and says the
# policy served is still REVISION's; no line says the variant was served.
check_refused_at_load() {
  local events=$1 variant=$2 first reason
  first=$(printf '%s\n' "$events" | head -n 1)
  check "$(jq -r '.event' <<<"$first" 2>/dev/null)" policy_reload_refused "the gateway refused the registry that admits team-b to docs-team-a's surface"
  reason=$(jq -r '.reason' <<<"$first" 2>/dev/null) || reason=""
  case "$reason" in
    *"rule 5: surface \`docs-team-a\` serves tool \`docs-team-a__"*"\`, whose entry reaches \`docs / project / atlas\`, to team \`team-b\`, whose limit does not hold it"*)
      pass "its reason is rule 5: the entry reaches atlas, which team-b's limit does not hold" ;;
    *) fail "its reason is rule 5: the entry reaches atlas, which team-b's limit does not hold (got '$reason')" ;;
  esac
  check "$(jq -r '.served' <<<"$first" 2>/dev/null)" "$REVISION" "the policy served is still revision $REVISION"
  # shellcheck disable=SC2016 # jq's own variables
  check "$(printf '%s\n' "$events" | jq -c --arg variant "$variant" 'select(.event == "policy_reloaded" and (.revision | startswith($variant)))' 2>/dev/null | awk 'END { print NR }')" \
    0 "the gateway never served revision $variant"
}

# check_withdrawal EVENTS CHANGED: the tool_withdrawn lines since mock-docs began serving the
# drifted description at CHANGED (epoch seconds). Each list tool, docs-team-a's and
# docs-team-b's, was withdrawn once, for a changed definition, from base REVISION, within the
# drift interval plus the call deadline of CHANGED (decision 0013, section 5); and the revision
# served after the last withdrawal is DRIFTED_REVISION, the literal derived one (section 6).
check_withdrawal() {
  local events=$1 changed=${2%.*} tool at
  for tool in docs-team-a__list_documents docs-team-b__list_documents; do
    # shellcheck disable=SC2016 # jq's own variables
    check "$(printf '%s\n' "$events" | jq -r --arg tool "$tool" 'select(.tool == $tool) | "\(.cause) from \(.base)"' 2>/dev/null | sort | uniq -c | awk '{ $1 = $1 " x"; print }')" \
      "1 x definition changed from $REVISION" "the gateway withdrew $tool once, for a changed definition, from revision $REVISION"
    # shellcheck disable=SC2016 # jq's own variables
    at=$(printf '%s\n' "$events" | jq -r --arg tool "$tool" 'select(.tool == $tool) | .timestamp | sub("\\.[0-9]+"; "") | fromdateiso8601' 2>/dev/null | head -n 1)
    case "$at:$changed" in
      [0-9]*:[0-9]*) check_at_most "$((at - changed))" $((DRIFT_INTERVAL + CALL_DEADLINE)) \
        "it was withdrawn within the $DRIFT_INTERVAL s interval plus the $CALL_DEADLINE s deadline of the change (seconds)" ;;
      *) fail "it was withdrawn within the $DRIFT_INTERVAL s interval plus the $CALL_DEADLINE s deadline of the change (got '$at' and '$changed')" ;;
    esac
  done
  check "$(printf '%s\n' "$events" | tail -n 1 | jq -r '.revision' 2>/dev/null)" "$DRIFTED_REVISION" \
    "the revision served after both withdrawals is the literal derived one"
}

# check_drift_rows ROWS REVISION LISTED CALL: team-a's rows from one workload run of the drift
# step: its tools/list, a row of kind list under REVISION naming exactly LISTED (its tools,
# comma-separated, sorted), then its call to its list tool under REVISION, CALL being its
# decision and its reason or outcome: `deny unknown_tool` while the tool is withdrawn, `allow ok`
# while it is served.
check_drift_rows() {
  local rows=$1 revision=$2 listed=$3 call=$4 want
  # shellcheck disable=SC2016 # jq's own variables
  want=$(jq -cn --arg revision "$revision" --arg listed "$listed" --arg call "$call" \
    --arg tool "$(team_entry team-a)__list_documents" '[
      {kind: "list", revision: $revision, listed: ($listed | split(","))},
      {kind: "call", revision: $revision, tool: $tool, call: $call}]')
  check "$(jq -c '[.[] | select(.team == "team-a")
      | if .kind == "list" then {kind, revision, listed: (.listed | sort)}
        else {kind, revision, tool, call: "\(.decision) \(.reason // .outcome)"} end]' <<<"$rows" 2>/dev/null)" \
    "$want" "audit: team-a's list and call are recorded under revision $revision, listing $listed, the call $call"
}

# check_reapproval EVENTS REVISION: the gateway's lines since the registry approving both list
# tools again, under REVISION, was installed (policy_reloaded, policy_withdrawal_cleared and
# tool_withdrawn). It served REVISION itself, with no withdrawal derived from it, and dropped
# both list tools' withdrawals as approved again; it withdrew nothing.
check_reapproval() {
  local events=$1 revision=$2
  check "$(printf '%s\n' "$events" | jq -r 'select(.event == "policy_reloaded") | .revision' 2>/dev/null | head -n 1)" \
    "$revision" "the gateway serves revision $revision, with no withdrawal"
  check "$(printf '%s\n' "$events" | jq -r 'select(.event == "policy_withdrawal_cleared") | "\(.tool): \(.reason)"' 2>/dev/null | sort | paste -sd ';' -)" \
    "docs-team-a__list_documents: approved again;docs-team-b__list_documents: approved again" \
    "both list tools' withdrawals cleared as approved again"
  check "$(printf '%s\n' "$events" | jq -c 'select(.event == "tool_withdrawn")' 2>/dev/null | awk 'END { print NR }')" 0 \
    "the drift pass withdrew nothing since"
}

# drift_polls TEXT: the drift pass's successful reads of each entry's tool list so far, from the
# metrics TEXT, as `A B`.
drift_polls() {
  echo "$(metric 'switchboard_drift_polls_total{server="docs-team-a",result="ok"}' "$1") $(metric 'switchboard_drift_polls_total{server="docs-team-b",result="ok"}' "$1")"
}

# wait_for_polls N: waits until the drift pass has read each entry's tool list N more times,
# so N polls of each began after the wait did, at most N intervals plus a call deadline and 10 s.
wait_for_polls() {
  local polls=$1 limit=$(($1 * DRIFT_INTERVAL + CALL_DEADLINE + 10)) waited=0 from now a b
  fetch "the gateway's metrics" gateway_metrics || return 0
  from=$(drift_polls "$FETCHED")
  case "$from" in
    *[!0-9\ ]* | ' '* | *' ') fail "the drift pass's polls are counted (got '$from')"; return 0 ;;
  esac
  while :; do
    sleep 2
    waited=$((waited + 2))
    fetch "the gateway's metrics" gateway_metrics || return 0
    now=$(drift_polls "$FETCHED")
    read -r a b <<<"$now"
    if [ "$(number_or_none "$a")" != none ] && [ "$(number_or_none "$b")" != none ] &&
      [ "$a" -ge $((${from% *} + polls)) ] && [ "$b" -ge $((${from#* } + polls)) ]; then
      pass "the drift pass read each entry's tool list $polls more times (polls $from, then $now, within $waited s)"
      return 0
    fi
    if [ "$waited" -ge "$limit" ]; then
      fail "the drift pass read each entry's tool list $polls more times (polls $from, then $now, after $waited s)"
      return 0
    fi
  done
}

# undeclared_step: decision 0011, section 1, and its Consequences: an undeclared argument is
# refused before forwarding.
undeclared_step() {
  step "an undeclared argument: team-a's read with an argument its approval does not declare is refused before it is forwarded, and mock-docs receives nothing"
  local before after
  step_mark
  if fetch "mock-docs' log" mock_docs_log; then before=$(accepted_calls "$FETCHED"); fi
  workload "team-a, an undeclared argument" team-a undeclared
  if fetch "mock-docs' log" mock_docs_log; then after=$(accepted_calls "$FETCHED"); fi
  check_undeclared "$(step_rows "$MARK_EPOCH")" "${before:-}" "${after:-}"
}

# refused_at_load_step: decision 0011's Consequences: a registry admitting team-b to
# docs-team-a's surface, whose entry reaches atlas, which team-b's limit does not hold, is
# refused at load. The variant is made from the registry served, at run time.
refused_at_load_step() {
  step "refused at load: a registry admitting team-b to docs-team-a's surface, whose entry reaches atlas, is refused for rule 5 and revision $REVISION stays served"
  local served=$DEMO_DIR/registry-served.toml variant=$DEMO_DIR/registry-variant.toml revision
  revision=$VARIANT_REVISION-reach-$(date -u +%Y%m%dT%H%M%SZ)
  served_registry >"$served"
  if ! reach_variant "$revision" <"$served" >"$variant"; then
    fail "the registry served admits team-a alone to docs-team-a's surface, so the variant can be made from it"
    return 0
  fi
  step_mark
  RESTORE_REGISTRY=$served
  install_registry "$variant"
  if wait_for_events "the gateway read the variant" "$(reload_wait)" 1 "$MARK_TIME" \
    'select(.event == "policy_reloaded" or .event == "policy_reload_refused")'; then
    check_refused_at_load "$EVENTS" "$revision"
  fi
  step_mark
  install_registry "$served"
  wait_for_events "the gateway reloaded the registry served before, revision $REVISION" "$(reload_wait)" 1 "$MARK_TIME" \
    "select(.event == \"policy_reloaded\" and .revision == \"$REVISION\")" || true
  RESTORE_REGISTRY=""
}

# isolation_steps: decision 0014, sections 1 and 2: a hanging server and an overload, each held
# to team-a's own calls while team-b's go on.
isolation_steps() {
  local reads stream hang burst before after
  case "$MODE" in
    compose) reads=30 ;;
    kind) reads=60 ;;
  esac
  step "team-b reads its own project once a second, $reads times, through the next two steps"
  step_mark
  stream=$MARK_EPOCH
  start_workload "team-b, steady reads" team-b steady "$reads"
  local waited=0
  until [ "$(psql_reader -Atc "select count(*) from $AUDIT_TABLE where begun_at >= to_timestamp($stream)
      and proved_team = 'team-b' and outcome = 'ok'")" -ge 1 ] || [ "$waited" -ge 120 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  echo "    team-b's reads began after ${waited} s"

  step "a hanging server: team-a reads slow-doc, which mock-docs answers after 10 s, and the gateway answers at the $CALL_DEADLINE s call deadline"
  step_mark
  hang=$MARK_EPOCH
  WORKLOAD_OUTPUT=""
  workload "team-a, a read past its deadline" team-a hang
  check_hang "$(step_rows "$hang")" "$WORKLOAD_OUTPUT"

  step "overload: team-a starts $((TEAM_CAP + 1)) reads of slow-doc at once, one over its cap of $TEAM_CAP calls in flight to its server"
  step_mark
  burst=$MARK_EPOCH
  if fetch "the gateway's metrics" gateway_metrics; then
    before=$(metric 'switchboard_calls_shed_total{scope="team"}' "$FETCHED")
  fi
  WORKLOAD_OUTPUT=""
  workload "team-a, overload" team-a overload $((TEAM_CAP + 1))
  if fetch "the gateway's metrics" gateway_metrics; then
    after=$(metric 'switchboard_calls_shed_total{scope="team"}' "$FETCHED")
  fi
  local shed=unreadable
  if [ "$(number_or_none "${before:-}")" != none ] && [ "$(number_or_none "${after:-}")" != none ]; then
    shed=$((after - before))
  fi
  check_overload "$(step_rows "$burst")" "$shed" "$WORKLOAD_OUTPUT"

  step "team-b's steady reads: every one allowed and answered ok"
  finish_workload
  check "$(psql_reader -Atc "select count(*) from $AUDIT_TABLE where begun_at >= to_timestamp($stream)
      and proved_team = 'team-b' and not (kind = 'call' and decision = 'allow' and outcome = 'ok')")" 0 \
    "audit: every team-b row since its reads began is an allowed read answered ok"
}

# drift_steps: decision 0013, sections 5 to 7 and the acceptance scenarios of section 11: a
# changed definition withdrawn within the interval plus the deadline, rows under the literal
# derived revision, the withdrawal standing after the definition is restored, and a new approval
# of the same definition clearing it. Nothing here approves a changed definition.
drift_steps() {
  local list
  list=$(team_entry team-a)__list_documents
  step "drift: mock-docs serves another description of list_documents, which both entries list; the gateway withdraws both list tools within the $DRIFT_INTERVAL s interval plus the $CALL_DEADLINE s deadline"
  step_mark
  local changed=$MARK_EPOCH changed_at=$MARK_TIME
  DRIFTED=1
  WITHDRAWAL_HELD=1
  mock_admin PUT /admin/definitions/list_documents "{\"description\": \"$DRIFTED_DESCRIPTION\"}" | sed 's/^/    mock-docs: /'
  if wait_for_events "the gateway withdrew both list tools" $((DRIFT_INTERVAL + CALL_DEADLINE + 30)) 2 "$changed_at" \
    'select(.event == "tool_withdrawn")'; then
    printf '%s\n' "$EVENTS" | sed 's/^/    /'
    check_withdrawal "$EVENTS" "$changed"
  fi
  step_mark
  workload "team-a after the withdrawal" team-a withdrawn list
  check_drift_rows "$(step_rows "$MARK_EPOCH")" "$DRIFTED_REVISION" "$(team_entry team-a)__read_document" "deny unknown_tool"

  step "drift: mock-docs serves the approved description again; the list tools stay withdrawn until they are approved again (decision 0013, section 7)"
  step_mark
  local restored_at=$MARK_TIME
  mock_admin DELETE /admin/definitions/list_documents | sed 's/^/    mock-docs: /'
  DRIFTED=""
  wait_for_polls 2
  step_mark
  workload "team-a after the description is restored" team-a withdrawn list
  check_drift_rows "$(step_rows "$MARK_EPOCH")" "$DRIFTED_REVISION" "$(team_entry team-a)__read_document" "deny unknown_tool"
  if fetch "the gateway's log" gateway_log "$restored_at"; then
    check "$(events "$FETCHED" 'select(.event == "policy_reloaded" or .event == "policy_withdrawal_cleared")' | awk 'END { print NR }')" 0 \
      "nothing cleared the withdrawals since"
  fi

  local served=$DEMO_DIR/registry-served.toml variant=$DEMO_DIR/registry-variant.toml stamp revision
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  revision=$VARIANT_REVISION-reapproved-$stamp
  step "drift: both list tools approved again, unchanged, with a new approved_at, under revision $revision; the withdrawals clear and the next polls leave them served"
  served_registry >"$served"
  if ! reapproval_variant "$revision" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$list" "$(team_entry team-b)__list_documents" <"$served" >"$variant"; then
    fail "the registry served approves both list tools, so the variant can be made from it"
    return 0
  fi
  step_mark
  local approved_at=$MARK_TIME
  RESTORE_REGISTRY=$served
  install_registry "$variant"
  if wait_for_events "the gateway served revision $revision" "$(reload_wait)" 1 "$approved_at" \
    "select(.event == \"policy_reloaded\" and (.revision | startswith(\"$revision\")))"; then
    # A new approval clears a standing withdrawal (decision 0013, section 6).
    WITHDRAWAL_HELD=""
  fi
  wait_for_polls 2
  if fetch "the gateway's log" gateway_log "$approved_at"; then
    check_reapproval "$(events "$FETCHED" 'select(.event == "policy_reloaded" or .event == "policy_withdrawal_cleared" or .event == "tool_withdrawn")')" "$revision"
  fi
  step_mark
  workload "team-a after the new approval" team-a served
  check_drift_rows "$(step_rows "$MARK_EPOCH")" "$revision" "$list,$(team_entry team-a)__read_document" "allow ok"

  step "drift: the registry served before, revision $REVISION, back in place; both list tools served"
  step_mark
  install_registry "$served"
  wait_for_events "the gateway served revision $REVISION" "$(reload_wait)" 1 "$MARK_TIME" \
    "select(.event == \"policy_reloaded\" and .revision == \"$REVISION\")" || true
  RESTORE_REGISTRY=""
  step_mark
  workload "team-a under revision $REVISION" team-a served
  check_drift_rows "$(step_rows "$MARK_EPOCH")" "$REVISION" "$list,$(team_entry team-a)__read_document" "allow ok"
}

# demonstrations: #11's demonstrations, in order, in whichever deployment is running.
demonstrations() {
  undeclared_step
  refused_at_load_step
  isolation_steps
  drift_steps
}

# --- Compose --------------------------------------------------------------------------------

compose_workload_output() { # MODE TEAM [ARGS...]: runs the workload service once, and prints what it printed
  local mode=$1 team=$2 own other
  shift 2
  if [ "$team" = team-a ]; then own=atlas other=borealis; else own=borealis other=atlas; fi
  local issuer=http://dev-issuer:8090/token
  dc run --rm --no-deps -T \
      -e "GATEWAY_URL=http://gateway:8080/mcp/$(team_entry "$team")" \
      -e "TOKEN_URL=$issuer?subject=workload:$team:mock-workload&audience=switchboard" \
      -e "OWN_PROJECT=$own" -e "OTHER_PROJECT=$other" \
      -e "BAD_TOKEN_URLS=$issuer?subject=workload:$team:stranger&audience=switchboard $issuer?subject=workload:$team:mock-workload&audience=not-switchboard" \
      workload workload.sh "$mode" "$@" 2>&1
}

compose_workload() { # LABEL MODE TEAM [ARGS...]: runs the workload service once and tallies it
  local label=$1 output status
  shift
  if output=$(compose_workload_output "$@"); then
    status=0
  else
    status=$?
  fi
  tally_workload "$label" "$status" "$output"
}

# mock_docs_requests: how many requests mock-docs has accepted, other than tools/list. Its health
# checks carry no bearer and are not accepted, so they do not count. The gateway's drift pass
# reads each entry's tool list every 10 s whatever the database is doing, so its tools/list
# requests do not count either: no call is a tools/list.
mock_docs_requests() {
  dc logs --no-log-prefix mock-docs | jq -cR 'fromjson? | select(.accepted == true and .rpc_method != "tools/list")' | awk 'END { print NR }'
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
    check_bounds "$FETCHED"
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

  demonstrations

  step "the gateway's metrics (GET /metrics on its own listener, loopback in the container, unpublished)"
  if fetch "the gateway's metrics" dc exec -T gateway curl -sS --fail http://127.0.0.1:9090/metrics; then
    check_metrics outage "$FETCHED"
  fi

  # Seven lists: each team's full run, the run after the withdrawal, and team-a's four in the
  # drift steps.
  audit_rows 7
  FINISHED=1
}

# --- kind -----------------------------------------------------------------------------------

# start_job NAMESPACE CRONJOB MODE [ARGS...]: starts a new Job, so a new pod, from the suspended
# CronJob's template with MODE and ARGS as the workload's arguments. Sets JOB.
start_job() {
  local ns=$1 cron=$2 mode=$3
  shift 3
  JOB="$cron-$mode-$(date +%s)"
  k -n "$ns" get cronjob "$cron" -o json \
    | jq --arg name "$JOB" '{
        apiVersion: "batch/v1", kind: "Job",
        metadata: {name: $name, namespace: .metadata.namespace, labels: .spec.jobTemplate.metadata.labels},
        spec: (.spec.jobTemplate.spec | .template.spec.containers[0].args = $ARGS.positional)}' \
      --args "$mode" "$@" \
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

# kind_workload LABEL NAMESPACE CRONJOB MODE [ARGS...]: runs the workload as a new Job and
# tallies its log. A log that cannot be read fails as that, whatever part of it was printed.
kind_workload() {
  local label=$1 ns=$2 cron=$3 mode=$4
  shift 4
  start_job "$ns" "$cron" "$mode" "$@"
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
# in the gateway's namespace, in the team's own and across the cluster; a `gateway` row in
# mock-docs and the gateway's namespace only, so a team may read its own ConfigMaps (#104); a
# `cluster` row is asked across the cluster only. Across the cluster is a can-i with no
# namespace, as the checks asked it before they read the list (binding ClusterRoles among
# them). can-i then asks in the kubeconfig's namespace, `default`, and warns for a resource
# that has none. RBAC counts that namespace's RoleBindings as well as ClusterRoleBindings, so a
# no there holds across the cluster too, and covers more than --all-namespaces, which counts
# only ClusterRoleBindings.
# A list that cannot be read fails the step; nothing is asked from a list of its own.
#
# A can-i names no resource, so it cannot see a rule limited by resourceNames: a workload able
# to mint tokens for one named ServiceAccount answers no. So the checks also read the RBAC rules
# bound to each team's workload, in every namespace, with deploy/route-check/rbac-match.jq,
# the matcher the route check's operator step runs (operator_rbac).
operator_checks() {
  local rows team verb resource subresource scope ns
  if ! rows=$(awk -F'\t' '/^#/ || NF == 0 { next }
      NF != 4 || ($4 != "namespaced" && $4 != "gateway" && $4 != "cluster") { bad = 1; next }
      { print }
      END { exit bad }' "$PERMISSIONS") || [ -z "$rows" ]; then
    fail "operator checks: every row of $PERMISSIONS is read (a row is not verb, resource, subresource and scope, or there is none)"
    return
  fi
  for team in team-a team-b; do
    while IFS=$'\t' read -r verb resource subresource scope <&3; do
      if [ "$scope" = cluster ]; then
        operator_ask "$team" "$verb" "$resource" "$subresource" ""
      elif [ "$scope" = gateway ]; then
        for ns in mock-docs switchboard; do
          operator_ask "$team" "$verb" "$resource" "$subresource" "$ns"
        done
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
        --argjson gateway_namespaces '["switchboard", "mock-docs"]' -f "$RBAC_MATCH" <"$lists" 2>&1); then
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
# pod's token writer uses (deploy/kind/base/gateway-tokens.yaml): create them for docs-team-a,
# docs-team-b and registry-probe, the drift probe's, named, and for no other ServiceAccount, its
# own and a workload's among them, nor without a name.
token_grants() {
  local gateway=system:serviceaccount:switchboard:gateway entry answer
  for entry in docs-team-a docs-team-b registry-probe; do
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
    check_bounds "$FETCHED"
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

  step "the gateway's token grant (gateway-tokens.yaml): it may create tokens for docs-team-a, docs-team-b and registry-probe, and for no other ServiceAccount"
  token_grants

  step "operator checks: every row of deploy/route-check/permissions.tsv, for each team's workload, in mock-docs, the gateway's namespace, its own and across the cluster: neither may start pods or the controllers that start them, mint tokens, impersonate, exec, attach, port-forward, proxy, add an ephemeral container, bind or escalate a role or create, update or patch a binding, nor get, list or watch secrets, or ConfigMaps in mock-docs or the gateway's namespace; and no RBAC rule bound to either grants any of these, whatever its resourceNames"
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

  demonstrations

  step "the gateway's metrics (GET /metrics on its own port, which the teams cannot reach)"
  # The kind run has no database outage.
  if fetch "the gateway's metrics (pod $GATEWAY_POD)" k -n switchboard exec "pod/$GATEWAY_POD" -c gateway -- \
    curl -sS --fail http://localhost:9090/metrics; then
    check_metrics none "$FETCHED"
  fi

  # Six lists: each team's full run, and team-a's four in the drift steps. The probes before
  # the policy make none, and the stranger's is refused for identity, which writes no row.
  audit_rows 6
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
