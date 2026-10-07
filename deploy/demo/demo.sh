#!/usr/bin/env bash
# deploy/demo/demo.sh: the demo in one command.
#
#   demo.sh compose   build the image; start Postgres, the migration, the dev issuer, mock-docs
#                     and the gateway under Compose; run both teams' workloads; show a database
#                     outage and a withdrawn tool; check the audit rows
#   demo.sh kind      the same in the kind cluster switchboard-demo, with projected
#                     ServiceAccount tokens, network policy and the operator's permission checks
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
# It never touches the cluster otto-dev or ~/.kube/config. It refuses a cluster named otto-dev,
# drops KUBECONFIG from its environment, and names its own kubeconfig file, .demo/kubeconfig,
# in every kubectl and kind call.
#
# Needs docker (with compose), kind, kubectl, jq and awk on the host.
#
# What it reads, and where each comes from:
#   - the gateway's JSON log lines (crates/gateway): one `"event":"boot"` line per gate, with
#     `"identity":"enforce"` and `"audit":"postgres"`, and one `"event":"identity_failed"` line
#     per caller refused for identity;
#   - mock-docs' JSON log lines (crates/mock-docs-server): one per request, with
#     `bearer_sha256`, the first 12 hex digits of the bearer's SHA-256, and `accepted`;
#   - the audit table switchboard_audit.call_rows (crates/audit-postgres), read as
#     switchboard_reader.
set -euo pipefail
unset KUBECONFIG

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
CLUSTER=${SWITCHBOARD_DEMO_CLUSTER:-switchboard-demo}
if [ "$CLUSTER" = "otto-dev" ]; then
  echo "demo.sh: refusing to touch the cluster otto-dev; the demo uses its own cluster" >&2
  exit 2
fi
DEMO_DIR=$ROOT/.demo
KCFG=$DEMO_DIR/kubeconfig
IMG=switchboard-demo:dev
IMG_RUN=$IMG
COMPOSE_FILE=$ROOT/deploy/compose/compose.yaml
KIND_ISSUER=https://kubernetes.default.svc.cluster.local
AUDIT_TABLE=switchboard_audit.call_rows
READ_TOOL=docs__read_document

PASSES=0
FAILS=0
FINISHED=""
CURRENT_STEP="start"
MODE=""
PAUSED=""
SINCE=""

k() { kubectl --kubeconfig "$KCFG" --context "kind-$CLUSTER" "$@"; }
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
# count_lines PATTERN TEXT: how many lines of TEXT match the extended regex PATTERN.
count_lines() { printf '%s\n' "$2" | awk -v pattern="$1" '$0 ~ pattern { n++ } END { print n + 0 }'; }

# tally_workload LABEL STATUS OUTPUT: adds a workload's PASS and FAIL lines to the count. Its
# exit status must agree with its lines, and it must have checked something.
tally_workload() {
  local label=$1 status=$2 output=$3 passed failed
  printf '%s\n' "$output" | sed 's/^/    /'
  passed=$(count_lines '^PASS ' "$output")
  failed=$(count_lines '^FAIL ' "$output")
  PASSES=$((PASSES + passed))
  FAILS=$((FAILS + failed))
  if [ "$passed" -eq 0 ] && [ "$failed" -eq 0 ]; then
    fail "$label: the workload ran no checks (exit $status)"
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

mark_start() {
  SINCE=$(psql_superuser -Atc "select extract(epoch from now())")
  echo "audit rows from this run start at epoch $SINCE"
}

# project_json NAME: the `resources` column of a call that named only the docs project NAME.
project_json() { printf '[{"system":"docs","kind":"project","identifier":"%s"}]' "$1"; }

# The columns are crates/audit-postgres's (sql/migrations/0001_call_rows.sql). `resources` is a
# JSON array of the {system, kind, identifier} each call named, or "unknown"; the listing shows
# each as system/kind/identifier.
audit_rows() {
  step "audit rows from this run"
  psql_reader -c "select to_char(begun_at, 'HH24:MI:SS') as at, proved_subject, proved_team as team,
      tool, coalesce((select string_agg(concat_ws('/', r->>'system', r->>'kind', r->>'identifier'), ',')
          from jsonb_array_elements(case when jsonb_typeof(resources) = 'array' then resources
                                         else '[]'::jsonb end) as r), resources #>> '{}') as resources,
      decision, reason, outcome, latency_ms as ms, policy_revision as rev
    from $AUDIT_TABLE where begun_at >= to_timestamp($SINCE) order by begun_at"
  local team own other
  for team in team-a team-b; do
    if [ "$team" = team-a ]; then own=atlas other=borealis; else own=borealis other=atlas; fi
    check_at_least "$(audit_count "proved_team = '$team' and tool = '$READ_TOOL' and decision = 'allow'
        and outcome = 'ok' and resources = '$(project_json "$own")'::jsonb")" 1 \
      "audit: $team's read of $own is an allow row naming $own, with outcome ok"
    check_at_least "$(audit_count "proved_team = '$team' and tool = '$READ_TOOL' and decision = 'deny'
        and reason = 'resource_outside_limit' and resources = '$(project_json "$other")'::jsonb
        and sentence like '%\`$other\`%'")" 1 \
      "audit: $team's read of $other is a deny row naming $other and the resource limit"
    check "$(audit_count "proved_team = '$team' and decision = 'allow'
        and resources @> '$(project_json "$other")'::jsonb")" 0 \
      "audit: no allowed row of $team names $other"
  done
  check "$(audit_count "resources is null")" 0 "audit: every row records the resources its call named"
  # A begin that ran past its budget may still commit; the store then completes the row as
  # error, because the call was refused and nothing ran (decision 0009).
  check "$(audit_count "decision = 'allow' and outcome is null")" 0 "audit: no allowed row is left without an outcome"
  check "$(audit_count "proved_subject like '%stranger%'")" 0 "audit: no row for the ServiceAccount outside the manifest"
}

# check_boot LOGS: the gateway says at boot that identity is enforced and audit is in Postgres.
check_boot() {
  printf '%s\n' "$1" | grep -E '"event":"boot"' | sed 's/^/    /' || echo "    (no boot lines)"
  check_at_least "$(count_lines '"identity":"enforce"' "$1")" 1 "the gateway enforces identity"
  check_at_least "$(count_lines '"audit":"postgres"' "$1")" 1 "the gateway writes audit rows to Postgres"
  check "$(count_lines '"identity":"disabled"|"audit":"disabled"' "$1")" 0 "the gateway disabled neither identity nor audit"
}

# check_server_bearers LOGS SHA256 MIN SCOPE: what mock-docs received. Every request it accepted
# carried the gateway's credential, which is SHA256; with SCOPE=all, so did every request carrying
# any bearer. MIN is the fewest accepted requests the run must have made. Requests with no bearer
# (the health checks) are not counted.
check_server_bearers() {
  local logs=$1 sha=$2 min=$3 scope=$4 lines
  lines=$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(.bearer_sha256 != null)
    | "\(if .accepted == true then "accepted" else "refused" end) \(.bearer_sha256)"')
  echo "    requests seen by mock-docs, by answer and bearer sha256 prefix (the gateway's is ${sha:0:12}...):"
  printf '%s\n' "$lines" | sort | uniq -c | sed 's/^/    /'
  local good bad stray
  good=$(printf '%s\n' "$lines" | awk -v sha="$sha" '$1 == "accepted" && length($2) >= 8 && index(sha, $2) == 1 { n++ } END { print n + 0 }')
  bad=$(printf '%s\n' "$lines" | awk -v sha="$sha" '$1 == "accepted" && !(length($2) >= 8 && index(sha, $2) == 1) { n++ } END { print n + 0 }')
  stray=$(printf '%s\n' "$lines" | awk -v sha="$sha" 'NF == 2 && !(length($2) >= 8 && index(sha, $2) == 1) { n++ } END { print n + 0 }')
  check_at_least "$good" "$min" "mock-docs accepted the gateway's credential"
  check "$bad" 0 "mock-docs accepted no other bearer"
  if [ "$scope" = all ]; then
    check "$stray" 0 "mock-docs never received any bearer but the gateway's"
  fi
}

# --- Compose --------------------------------------------------------------------------------

compose_workload() { # LABEL MODE TEAM: runs the workload service once
  local label=$1 mode=$2 team=$3 own other output status
  if [ "$team" = team-a ]; then own=atlas other=borealis; else own=borealis other=atlas; fi
  local issuer=http://dev-issuer:8090/token
  if output=$(dc run --rm --no-deps -T \
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

compose_run() {
  MODE=compose
  step "build the image; start Postgres, the migration, the dev issuer, mock-docs and the gateway"
  mkdir -p "$DEMO_DIR"
  # The gateway reads a copy of the registry, so withdrawing a tool never edits the repository.
  rm -rf "$DEMO_DIR/compose-registry"
  cp -R "$ROOT/deploy/compose/config/registry" "$DEMO_DIR/compose-registry"
  export SWITCHBOARD_REGISTRY_DIR=$DEMO_DIR/compose-registry
  # Naming the gateway starts everything it depends on; --wait then accepts the migration
  # having exited 0, which it does not when the migration is named itself.
  dc up -d --build --wait --wait-timeout 300 gateway
  dc ps
  mark_start

  step "the gateway's boot lines"
  check_boot "$(dc logs --no-log-prefix gateway)"

  step "team-a and team-b workloads"
  compose_workload "team-a workload" full team-a
  compose_workload "team-b workload" full team-b

  step "the server never saw a workload token"
  check_server_bearers "$(dc logs --no-log-prefix mock-docs)" \
    "$(cat "$ROOT/deploy/compose/dummy-credentials/docs-credential.sha256")" 4 all

  step "database unavailable: the call is refused and nothing runs"
  local before after
  before=$(mock_docs_requests)
  PAUSED=1
  dc pause postgres
  compose_workload "read while the database is paused" audit-down team-a
  dc unpause postgres
  PAUSED=""
  after=$(mock_docs_requests)
  check "$after" "$before" "mock-docs received nothing while the database was down"

  step "withdraw $READ_TOOL from the registry (the gateway polls every 2 s)"
  swap_registry "$ROOT/deploy/compose/config/registry-withdrawn.toml"
  sleep 4
  compose_workload "after the withdrawal" withdrawn team-a
  swap_registry "$ROOT/deploy/compose/config/registry/registry.toml"
  check_at_least "$(audit_count "tool = '$READ_TOOL' and decision = 'deny' and policy_revision = 'demo-2'")" 1 \
    "audit: the call to the withdrawn tool is a deny row under revision demo-2"
  # Let the gateway load the restored registry before anything else runs against it.
  sleep 4

  audit_rows
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

kind_workload() { # LABEL NAMESPACE CRONJOB MODE
  local label=$1 ns=$2 cron=$3 mode=$4
  start_job "$ns" "$cron" "$mode"
  wait_job "$ns" "$JOB" 180
  tally_workload "$label" "$JOB_STATUS" "$(k -n "$ns" logs "job/$JOB")"
}

# can_i ARGS...: the answer to `kubectl auth can-i ARGS` for team-a's workload, checked to be no.
can_i_no() {
  local answer
  # can-i exits 1 when the answer is no; the answer itself is what is checked.
  if answer=$(k auth can-i "$@" --as=system:serviceaccount:team-a:mock-workload 2>/dev/null); then :; fi
  check "$answer" no "team-a's workload may not: $*"
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

# apply_base: applies the base manifests with every pod that runs $IMG on this run's tag.
apply_base() {
  k kustomize "$ROOT/deploy/kind/base" | sed "s|image: $IMG\$|image: $IMG_RUN|" | k apply -f -
}

load_images() {
  local arch
  arch=$(docker version --format '{{.Server.Arch}}')
  docker image inspect postgres:17-alpine >/dev/null 2>&1 || docker pull postgres:17-alpine
  # `kind load docker-image` fails on Docker's containerd image store with multi-platform
  # images, so save this platform's images to an archive and load that.
  docker save --platform "linux/$arch" -o "$DEMO_DIR/images.tar" "$IMG_RUN" postgres:17-alpine
  kind load image-archive "$DEMO_DIR/images.tar" --name "$CLUSTER"
  rm -f "$DEMO_DIR/images.tar"
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

  step "the cluster's issuer and keys (copied once, not rotated or fetched)"
  local issuer
  issuer=$(k get --raw /.well-known/openid-configuration | jq -r .issuer)
  check "$issuer" "$KIND_ISSUER" "the cluster's issuer is the one the gateway trusts"
  k get --raw /openid/v1/jwks >"$DEMO_DIR/cluster-jwks.json"
  check_at_least "$(jq '.keys | length' "$DEMO_DIR/cluster-jwks.json")" 1 "the cluster published its signing keys"
  k apply -f "$ROOT/deploy/kind/base/namespaces.yaml"
  k -n switchboard create configmap cluster-issuer-keys --from-file=jwks.json="$DEMO_DIR/cluster-jwks.json" \
    --dry-run=client -o yaml | k apply -f -

  step "deploy Postgres, the migration, mock-docs and the gateway, with no network policy"
  # A run on an existing cluster starts from no policy, or the first probe below would mean nothing.
  k delete -k "$ROOT/deploy/kind/policy" --ignore-not-found
  k -n switchboard delete job migrate --ignore-not-found
  k -n team-a delete job -l app=mock-workload --ignore-not-found
  k -n team-a delete job -l app=stranger-workload --ignore-not-found
  k -n team-b delete job -l app=mock-workload --ignore-not-found
  apply_base
  k -n switchboard rollout status deploy/postgres --timeout=120s
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

  step "the gateway's boot lines"
  check_boot "$(k -n switchboard logs deploy/gateway)"

  step "before the policy: a direct call to mock-docs connects, and the server refuses the workload's own token"
  kind_workload "before policy" team-a mock-workload before-policy

  step "apply the network policy; new pods from here on; settle 10 s"
  k apply -k "$ROOT/deploy/kind/policy"
  sleep 10

  step "team-a and team-b workloads (new pods)"
  kind_workload "team-a workload" team-a mock-workload full
  kind_workload "team-b workload" team-b mock-workload full

  step "identity: a ServiceAccount not in the team manifest"
  kind_workload "stranger" team-a stranger-workload refused

  step "operator checks: the workload holds nothing that reaches the server"
  can_i_no get secrets -n switchboard
  can_i_no get secrets -n mock-docs
  can_i_no get configmaps -n switchboard
  can_i_no create pods -n team-a
  can_i_no create pods --subresource=exec -n mock-docs
  can_i_no create serviceaccounts --subresource=token -n switchboard

  step "the server never saw a workload token through the gateway"
  # The one direct call before the policy carried the workload's token and was refused (401);
  # every request the server accepted carried the gateway's credential.
  check_server_bearers "$(k -n mock-docs logs deploy/mock-docs)" \
    "$(cat "$ROOT/deploy/kind/base/dummy-credentials/docs-credential.sha256")" 4 accepted

  step "the gateway's view of identity failures (operators only; no audit rows)"
  local gateway_logs
  gateway_logs=$(k -n switchboard logs deploy/gateway)
  printf '%s\n' "$gateway_logs" | grep 'identity_failed' | sed 's/^/    /' || echo "    (none)"
  # Two teams refused three ways each (no token, not a token, the default API token), and the
  # stranger once.
  check_at_least "$(count_lines '"event":"identity_failed"' "$gateway_logs")" 7 "the gateway logged every identity failure"

  audit_rows
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
