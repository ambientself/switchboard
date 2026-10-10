#!/usr/bin/env bash
# deploy/route-check/route-check.sh: the operator step of the route check (decision 0010, "The
# route check"). It runs outside the workload, picks one running pod of it, checks what that pod
# could use to go around the gateway, and starts the probe in the pod as an ephemeral container.
#
#   route-check.sh --kubeconfig FILE --context NAME [--as USER]
#       --namespace NS --selector LABELS --gateway-ns NS
#       --server-ns NS [--server-ns NS ...]
#       --server-service NS/NAME [--server-service NS/NAME ...]
#       --server-audience AUDIENCE [--server-audience AUDIENCE ...]
#       --routes FILE --gateway-url URL [--expect refused|open]
#       --probe-image IMAGE [--probe-wait SECONDS] --report FILE --environment NAME
#
# Every kubectl call names --kubeconfig and --context, and --as when given; KUBECONFIG is ignored.
#
# It checks, and prints PASS or FAIL for each:
#   (a) the network plugin, from the DaemonSets in kube-system, and for kindnet that it enforces
#       network policy, as read from the kindnet pod on the probed pod's node: its flags, the
#       default of its kindnetd image when no flag is set, and its log. Any other plugin is not
#       read, so it fails;
#   (b) that the pod mounts no Secret and takes no variable from one, that no literal variable
#       and no ConfigMap it reads holds a string in a format in token-patterns.txt, and that no
#       projected ServiceAccount token in it is for a server's audience (--server-audience);
#   (c) by SubjectAccessReview, that the pod's ServiceAccount holds none of the permissions in
#       permissions.tsv, in the workload's, the gateway's and each server's namespace, and across
#       the cluster. The reviews are SubjectAccessReview objects created with `kubectl create`,
#       so the step needs no impersonation;
#   (d) the cloud identity annotations on the ServiceAccount. They are recorded for the owner to
#       check and never fail the run;
#   (e) the probe: route-probe.sh in --probe-image, started with `kubectl debug` as an ephemeral
#       container under the restricted profile. Its routes are --routes with each {{ADDR}}
#       replaced by the addresses of the --server-service the row's URL names: the Service's
#       ClusterIP and its endpoint IPs. The step waits at most --probe-wait seconds (default 60)
#       in all for the probe to end, then reads its log: one ROUTE line per attempt and a RESULT
#       line. It requires exactly one ROUTE line for each attempt the routes ask for: by name,
#       unless the URL's host is an address literal, and by each address; a row whose
#       addresses are `resolve` needs at least one address line. A missing, extra or repeated
#       line fails the run.
#
# Anything it cannot read is a FAIL ("could not read"), never a PASS, and so is anything it read
# but could not parse: kubectl output that is not one JSON object, or a field of it in a shape jq
# cannot take. The last line is the RESULT. The report goes to --report as JSON, and the exit
# status is non-zero on any FAIL.
#
# The access it needs, and no more (deploy/kind/route-check/rbac.yaml): get and list on what it
# reads, create on subjectaccessreviews, and patch on pods/ephemeralcontainers in the workload's
# namespace. It reads pod specs, never Secret data, and needs no exec.
#
# The probe's interface (route-probe.sh, from probe.sh beside this file): the environment
# variables ROUTES (the routes file's contents), GATEWAY_URL and EXPECT; the lines
# `ROUTE <row> <name|address> <target> <result>`, with the URL as a name's target and result
# refused, open or could-not-probe; and a last line `RESULT: PASS` or `RESULT: FAIL`. The routes
# file's columns are name, url, addresses and flags, tab-separated.
#
# Needs bash, kubectl, jq, grep and awk.
set -euo pipefail
unset KUBECONFIG

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
PERMISSIONS=$HERE/permissions.tsv
TOKEN_PATTERNS=$HERE/token-patterns.txt
PROBE_COMMAND=/usr/local/bin/route-probe.sh
# The ServiceAccount annotations that bind a cloud identity, recorded for the owner to check.
CLOUD_IDENTITY_ANNOTATIONS='["eks.amazonaws.com/role-arn","iam.gke.io/gcp-service-account","azure.workload.identity/client-id"]'

usage() {
  echo "route-check.sh: $*" >&2
  echo "usage: see the comment at the top of deploy/route-check/route-check.sh" >&2
  exit 2
}

KCFG="" CONTEXT="" AS="" NAMESPACE="" SELECTOR="" GATEWAY_NS="" ROUTES_FILE="" GATEWAY_URL=""
EXPECT=refused PROBE_IMAGE="" REPORT="" ENVIRONMENT="" PROBE_WAIT=60
SERVER_NS=() SERVER_SERVICES=() SERVER_AUDIENCES=()
while [ $# -gt 0 ]; do
  case $1 in
    --*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}" ;;
  esac
  [ $# -ge 2 ] || usage "$1 needs a value"
  case $1 in
    --kubeconfig) KCFG=$2 ;;
    --context) CONTEXT=$2 ;;
    --as) AS=$2 ;;
    --namespace) NAMESPACE=$2 ;;
    --selector) SELECTOR=$2 ;;
    --gateway-ns) GATEWAY_NS=$2 ;;
    --server-ns) SERVER_NS+=("$2") ;;
    --server-service) SERVER_SERVICES+=("$2") ;;
    --server-audience) SERVER_AUDIENCES+=("$2") ;;
    --routes) ROUTES_FILE=$2 ;;
    --gateway-url) GATEWAY_URL=$2 ;;
    --expect) EXPECT=$2 ;;
    --probe-image) PROBE_IMAGE=$2 ;;
    --probe-wait) PROBE_WAIT=$2 ;;
    --report) REPORT=$2 ;;
    --environment) ENVIRONMENT=$2 ;;
    *) usage "unknown argument $1" ;;
  esac
  shift 2
done
for required in KCFG:--kubeconfig CONTEXT:--context NAMESPACE:--namespace SELECTOR:--selector \
  GATEWAY_NS:--gateway-ns ROUTES_FILE:--routes GATEWAY_URL:--gateway-url \
  PROBE_IMAGE:--probe-image REPORT:--report ENVIRONMENT:--environment; do
  variable=${required%%:*}
  [ -n "${!variable}" ] || usage "${required#*:} is required"
done
[ ${#SERVER_NS[@]} -gt 0 ] || usage "--server-ns is required"
[ ${#SERVER_SERVICES[@]} -gt 0 ] || usage "--server-service is required"
[ ${#SERVER_AUDIENCES[@]} -gt 0 ] || usage "--server-audience is required"
for service in "${SERVER_SERVICES[@]}"; do
  case $service in
    */*/* | /* | */) usage "--server-service takes NAMESPACE/NAME, not $service" ;;
    */*) ;;
    *) usage "--server-service takes NAMESPACE/NAME, not $service" ;;
  esac
done
case $EXPECT in refused | open) ;; *) usage "--expect is refused or open, not $EXPECT" ;; esac
case $PROBE_WAIT in
  '' | *[!0-9]*) usage "--probe-wait takes a number of seconds, not $PROBE_WAIT" ;;
esac
[ "$PROBE_WAIT" -ge 1 ] && [ "$PROBE_WAIT" -le 3600 ] || usage "--probe-wait is 1 to 3600 seconds"
[ -r "$ROUTES_FILE" ] || usage "cannot read the routes file $ROUTES_FILE"

TMP=$(mktemp -d)
CHECKS=$TMP/checks.jsonl
ROUTE_LINES=$TMP/routes.jsonl
: >"$CHECKS"
: >"$ROUTE_LINES"

DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PASSES=0
FAILS=0
FINISHED=""
CURRENT_STEP="start"
KUBERNETES_VERSION="could not read"
KIND_VERSION="unknown"
NODE_IMAGE="could not read"
PLUGIN="could not read"
ENFORCEMENT="could not read"
POD="" NODE="" SA=""
CLOUD_IDENTITY="{}"
AUDIENCES="[]"
PROBE_CONTAINER=""
PROBE_RESULT=""
# How long one kubectl call may take. The wait for the probe shrinks it to the time left.
REQUEST_TIMEOUT=30s

k() {
  if [ -n "$AS" ]; then
    kubectl --kubeconfig "$KCFG" --context "$CONTEXT" --as="$AS" --request-timeout="$REQUEST_TIMEOUT" "$@"
  else
    kubectl --kubeconfig "$KCFG" --context "$CONTEXT" --request-timeout="$REQUEST_TIMEOUT" "$@"
  fi
}

step() {
  CURRENT_STEP=$*
  printf '\n== %s\n' "$*"
}
# record RESULT NAME: one check in the report.
record() { jq -nc --arg result "$1" --arg name "$2" '{name: $name, result: $result}' >>"$CHECKS"; }
pass() { PASSES=$((PASSES + 1)); echo "PASS $1"; record PASS "$1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL $1"; record FAIL "$1"; }
note() { echo "NOTE $1"; }
# json_object TEXT: true when TEXT is exactly one JSON object. kubectl output that is empty, cut
# short or more than one value is not read, since jq would take it as nothing to check.
json_object() { jq -se 'length == 1 and (.[0] | type) == "object"' >/dev/null 2>&1 <<<"$1"; }

# finish STATUS: writes the report, prints the RESULT line and exits; non-zero unless every check
# passed and the run finished.
finish() {
  local status=$1 total result
  trap - EXIT
  if [ "$status" -ne 0 ] && [ -z "$FINISHED" ]; then
    fail "step '$CURRENT_STEP' could not complete (exit $status)"
  fi
  total=$((PASSES + FAILS))
  if [ "$FAILS" -eq 0 ] && [ "$total" -gt 0 ] && [ -n "$FINISHED" ]; then
    result=PASS
  else
    result=FAIL
  fi
  if ! jq -n \
    --arg date "$DATE" --arg environment "$ENVIRONMENT" \
    --arg kubernetes "$KUBERNETES_VERSION" --arg kind "$KIND_VERSION" --arg node_image "$NODE_IMAGE" \
    --arg plugin "$PLUGIN" --arg enforcement "$ENFORCEMENT" \
    --arg pod "$POD" --arg node "$NODE" --arg sa "$SA" \
    --argjson cloud_identity "$CLOUD_IDENTITY" --argjson audiences "$AUDIENCES" \
    --arg expect "$EXPECT" --arg probe_container "$PROBE_CONTAINER" --arg probe_result "$PROBE_RESULT" \
    --arg result "$result" \
    --slurpfile checks "$CHECKS" --slurpfile routes "$ROUTE_LINES" \
    '{
      date: $date,
      environment: $environment,
      kubernetes_version: $kubernetes,
      kind_version: $kind,
      node_image: $node_image,
      network_plugin: $plugin,
      enforcement: $enforcement,
      pod: $pod,
      node: $node,
      service_account: $sa,
      cloud_identity: $cloud_identity,
      token_audiences: $audiences,
      expect: $expect,
      probe_container: $probe_container,
      checks: $checks,
      routes: $routes,
      probe_result: (if $probe_result == "" then null else $probe_result end),
      result: $result
    }' >"$REPORT"; then
    echo "FAIL could not write the report to $REPORT"
    result=FAIL
  fi
  rm -rf "$TMP"
  if [ "$result" = PASS ]; then
    printf '\nRESULT: PASS (%s/%s)\n' "$PASSES" "$total"
    exit 0
  fi
  printf '\nRESULT: FAIL (%s of %s failed)\n' "$FAILS" "$total"
  exit 1
}
trap 'finish $?' EXIT

# --- The pod -----------------------------------------------------------------------------------

pick_pod() {
  step "the pod: a running pod in $NAMESPACE matching $SELECTOR"
  # It runs as an `if` condition, so set -e is off here: every read is checked.
  local pods
  if ! pods=$(k get pods -n "$NAMESPACE" -l "$SELECTOR" -o json) || ! json_object "$pods" ||
    ! POD_JSON=$(jq -c '[.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null)]
      | sort_by(.metadata.name) | .[0] // empty' <<<"$pods"); then
    fail "a running pod matches $SELECTOR in $NAMESPACE: could not read the pods"
    return 1
  fi
  if [ -z "$POD_JSON" ]; then
    fail "a running pod matches $SELECTOR in $NAMESPACE: there is none"
    return 1
  fi
  if ! POD_NAME=$(jq -er '.metadata.name | strings' <<<"$POD_JSON") ||
    ! NODE=$(jq -r '.spec.nodeName // ""' <<<"$POD_JSON") ||
    ! SA_NAME=$(jq -r '.spec.serviceAccountName // "default"' <<<"$POD_JSON"); then
    fail "a running pod matches $SELECTOR in $NAMESPACE: could not read the pods"
    return 1
  fi
  POD=$NAMESPACE/$POD_NAME
  SA=$NAMESPACE/$SA_NAME
  pass "a running pod matches $SELECTOR in $NAMESPACE: $POD on node ${NODE:-?}, ServiceAccount $SA_NAME"
}

versions() {
  local version node
  if version=$(k version -o json 2>/dev/null) && json_object "$version" &&
    version=$(jq -er '.serverVersion.gitVersion' <<<"$version"); then
    KUBERNETES_VERSION=$version
  else
    fail "the Kubernetes version is recorded: could not read"
  fi
  if [ -n "$NODE" ] && node=$(k get node "$NODE" -o json) && json_object "$node" &&
    node=$(jq -er '.status.nodeInfo | select(.osImage != null) | "\(.osImage), kubelet \(.kubeletVersion), \(.containerRuntimeVersion)"' <<<"$node"); then
    NODE_IMAGE=$node
  else
    fail "the node image of ${NODE:-its node} is recorded: could not read"
  fi
  echo "Kubernetes $KUBERNETES_VERSION; node $NODE: $NODE_IMAGE"
}

# --- (a) The network plugin --------------------------------------------------------------------

# kindnetd_default_on TAG: the kind release that ships kindnetd image TAG, when that kindnetd
# enforces network policy with no flag set; nothing otherwise. Each tag is checked against kind's
# source before it is added. Kind v0.32.0 (deploy/kind/cluster.yaml) ships
# kindest/kindnetd:v20260528-9350166c, whose images/kindnetd/cmd/kindnetd/main.go starts the
# kube-network-policies controller with no flag to turn it off.
kindnetd_default_on() {
  case $1 in
    v20260528-9350166c) echo "kind v0.32.0" ;;
  esac
}

network_plugin() {
  step "(a) the network plugin and its enforcement"
  local daemonsets plugins
  if ! daemonsets=$(k get daemonsets -n kube-system -o json) || ! json_object "$daemonsets" ||
    ! plugins=$(jq -r '[.items[].metadata.name
        | if startswith("kindnet") then "kindnet"
          elif startswith("calico") then "calico"
          elif startswith("cilium") then "cilium"
          elif . == "aws-node" then "aws-node"
          else empty end] | unique | join(",")' <<<"$daemonsets"); then
    fail "network policy enforcement: could not read the DaemonSets in kube-system"
    return
  fi
  PLUGIN=${plugins:-unknown}
  if [ "$PLUGIN" != kindnet ]; then
    ENFORCEMENT=unknown
    fail "network policy enforcement: unknown for plugin $PLUGIN; only kindnet's is read"
    return
  fi
  kindnet_enforcement "$daemonsets"
}

# kindnet_enforcement DAEMONSETS: reads the kindnet pod on the probed pod's node.
kindnet_enforcement() {
  local daemonsets=$1 selector agents agent agent_name container image tag flags line value
  local state="" why="" release
  if ! selector=$(jq -r '[.items[] | select(.metadata.name | startswith("kindnet"))][0].spec.selector.matchLabels // {}
    | to_entries | map("\(.key)=\(.value)") | join(",")' <<<"$daemonsets"); then
    why="could not read the kindnet DaemonSet"
  elif [ -z "$selector" ]; then
    why="the kindnet DaemonSet has no label selector"
  elif ! agents=$(k get pods -n kube-system -l "$selector" -o json) || ! json_object "$agents" ||
    ! agent=$(jq -c --arg node "$NODE" '[.items[] | select(.spec.nodeName == $node and .status.phase == "Running")][0] // empty' <<<"$agents"); then
    why="could not read the kindnet pods"
  elif [ -z "$agent" ]; then
    why="no running kindnet pod on node $NODE"
  fi
  if [ -z "$why" ]; then
    if ! agent_name=$(jq -er '.metadata.name | strings' <<<"$agent") ||
      ! container=$(jq -c '[.spec.containers[] | select(.image | contains("kindnetd"))][0] // empty' <<<"$agent"); then
      why="could not read the kindnet pods"
    elif [ -z "$container" ]; then
      why="pod $agent_name runs no kindnetd image"
    fi
  fi
  # The flag, from the command, the arguments and the environment. A Go bool flag given with no
  # value is true; a variable whose value comes from elsewhere cannot be read.
  if [ -z "$why" ] && ! flags=$(jq -r '((.command // []) + (.args // []))[],
      ((.env // [])[] | "\(.name)=\(.value // "<from elsewhere>")")' <<<"$container"); then
    why="could not read the kindnetd container of $agent_name"
  fi
  if [ -z "$why" ]; then
    image=$(jq -r .image <<<"$container")
    image=${image%%@*}
    tag=""
    case ${image##*/} in *:*) tag=${image##*:} ;; esac
    flags=$(grep -Ei 'network.?polic' <<<"$flags" || true)
    if [ -n "$flags" ]; then
      state=on
      while IFS= read -r line; do
        case $line in *=*) value=${line#*=} ;; *) value=true ;; esac
        case $(printf '%s' "$value" | tr '[:upper:]' '[:lower:]') in
          true | 1 | t) ;;
          false | 0 | f) state=off ;;
          *) [ "$state" = off ] || { state=""; why="pod $agent_name sets $line"; } ;;
        esac
      done <<<"$flags"
      [ -z "$state" ] || ENFORCEMENT="$state by flag ($(tr '\n' ' ' <<<"$flags" | sed 's/ $//'))"
    else
      release=$(kindnetd_default_on "$tag")
      if [ -n "$release" ]; then
        state=on
        KIND_VERSION=$release
        ENFORCEMENT="default-on (kindnetd $tag, $release)"
      else
        why="pod $agent_name sets no network-policy flag, and the default of kindnetd ${tag:-with no tag} is not known"
      fi
    fi
  fi
  # The agent's own log: it must have started its policy controller and not skipped it.
  if [ "$state" = on ]; then
    local log
    if ! log=$(k logs -n kube-system "pod/$agent_name" -c "$(jq -r .name <<<"$container")"); then
      state="" why="could not read the log of $agent_name"
    elif grep -q 'skipping network policies' <<<"$log"; then
      state=off ENFORCEMENT="$ENFORCEMENT, but $agent_name logged that it skipped network policies"
    elif ! grep -q '"Starting controller" name="kube-network-policies"' <<<"$log"; then
      state="" why="the log of $agent_name does not show its network policy controller starting"
    fi
  fi
  [ -n "$state" ] || ENFORCEMENT="could not read"
  case $state in
    on) pass "network policy is enforced: kindnet, $ENFORCEMENT" ;;
    off) fail "network policy is not enforced: kindnet, $ENFORCEMENT" ;;
    *) fail "network policy enforcement: could not read ($why)" ;;
  esac
}

# --- (b) No credential in the pod --------------------------------------------------------------

# The pod's containers of every kind, as jq takes them.
CONTAINERS='[(.spec.containers // [])[], (.spec.initContainers // [])[], (.spec.ephemeralContainers // [])[]]'
# A volume's projected sources, as jq takes them: none for a volume that is not projected, and an
# error, never nothing, when the sources are not a list of objects.
SOURCES='def sources: if .projected == null then empty
  elif (.projected | type) != "object" then error("projected is not an object")
  elif .projected.sources == null then empty
  elif (.projected.sources | type) != "array" then error("projected sources are not a list")
  else .projected.sources[] | if type == "object" then . else error("a projected source is not an object") end end;'

credentials() {
  step "(b) no credential in the pod"
  local found
  # Each check fails, never passes, when jq cannot take the pod's spec (pipefail keeps its status).
  local check
  check="no Secret volume"
  if ! found=$(jq -r "$SOURCES"'(.spec.volumes // [])[]
      | select(.secret or any(sources; .secret) or (.csi.driver == "secrets-store.csi.k8s.io"))
      | .name' <<<"$POD_JSON" | paste -sd, -); then
    fail "$check: could not read the pod's volumes"
  elif [ -n "$found" ]; then fail "$check: $found"; else pass "$check"; fi

  check="no variable from a Secret (secretKeyRef)"
  if ! found=$(jq -r "$CONTAINERS"'[] | .name as $c | (.env // [])[] | select(.valueFrom.secretKeyRef) | "\($c)/\(.name)"' <<<"$POD_JSON" | paste -sd, -); then
    fail "$check: could not read the pod's variables"
  elif [ -n "$found" ]; then fail "$check: $found"; else pass "$check"; fi

  check="no variables from a Secret (envFrom secretRef)"
  if ! found=$(jq -r "$CONTAINERS"'[] | .name as $c | (.envFrom // [])[] | select(.secretRef) | "\($c)/\(.secretRef.name)"' <<<"$POD_JSON" | paste -sd, -); then
    fail "$check: could not read the pod's envFrom"
  elif [ -n "$found" ]; then fail "$check: $found"; else pass "$check"; fi

  token_scan
  token_audiences
}

# token_scan: the literal variables and every ConfigMap the pod reads, against token-patterns.txt.
# Each value is a file; the report names the file's source and the pattern's line, not the value.
token_scan() {
  local items=$TMP/items literals count i configmaps name cm keys unreadable="" n=0 patterns line number files
  local matches=()
  mkdir -p "$items"
  : >"$TMP/where"
  # The literal variables.
  if ! literals=$(jq -c "$CONTAINERS"' | map(.name as $c | (.env // [])[] | select(.value != null) | {where: "variable \($c)/\(.name)", value})' <<<"$POD_JSON") ||
    ! count=$(jq length <<<"$literals"); then
    fail "no string in a token format: could not read the pod's variables"
    return
  fi
  for ((i = 0; i < count; i++)); do
    jq -j --argjson i "$i" '.[$i].value' <<<"$literals" >"$items/$n"
    printf '%s\t%s\n' "$n" "$(jq -r --argjson i "$i" '.[$i].where' <<<"$literals")" >>"$TMP/where"
    n=$((n + 1))
  done
  # Every ConfigMap it mounts, takes variables from, or takes one variable from.
  if ! configmaps=$(jq -r "$SOURCES"'[((.spec.volumes // [])[] | .configMap.name // empty, (sources | .configMap.name // empty)),
      ('"$CONTAINERS"'[] | ((.envFrom // [])[] | .configMapRef.name // empty), ((.env // [])[] | .valueFrom.configMapKeyRef.name // empty))]
      | unique[]' <<<"$POD_JSON"); then
    fail "no string in a token format: could not read which ConfigMaps the pod reads"
    return
  fi
  # Each ConfigMap's keys are read into a variable first and jq's status checked: one it cannot
  # parse is unreadable, never a ConfigMap with nothing in it.
  for name in $configmaps; do
    if ! cm=$(k get configmap "$name" -n "$NAMESPACE" -o json) || ! json_object "$cm" ||
      ! keys=$(jq -r '((.data // {}) | keys[] | "data\t\(.)"), ((.binaryData // {}) | keys[] | "binaryData\t\(.)")' <<<"$cm"); then
      unreadable="$unreadable${unreadable:+,}$name"
      continue
    fi
    [ -n "$keys" ] || continue
    while IFS= read -r line; do
      if ! jq -j --arg key "${line#*$'\t'}" --arg kind "${line%%$'\t'*}" \
        'if $kind == "data" then .data[$key] else (.binaryData[$key] | @base64d) end' <<<"$cm" >"$items/$n"; then
        unreadable="$unreadable${unreadable:+,}$name"
        break
      fi
      printf '%s\tConfigMap %s key %s\n' "$n" "$name" "${line#*$'\t'}" >>"$TMP/where"
      n=$((n + 1))
    done <<<"$keys"
  done
  if [ -n "$unreadable" ]; then
    fail "no string in a token format: could not read ConfigMap $unreadable in $NAMESPACE"
    return
  fi
  patterns=$(grep -cvE '^(#|$)' "$TOKEN_PATTERNS" || true)
  if [ "${patterns:-0}" -eq 0 ]; then
    fail "no string in a token format: could not read a pattern from token-patterns.txt"
    return
  fi
  if [ "$n" -gt 0 ]; then
    number=0
    while IFS= read -r line || [ -n "$line" ]; do
      number=$((number + 1))
      case $line in '' | '#'*) continue ;; esac
      if files=$(grep -lE -e "$line" -- "$items"/*); then
        for file in $files; do
          matches+=("$(awk -F'\t' -v n="${file##*/}" '$1 == n { print $2 }' "$TMP/where") (token-patterns.txt:$number)")
        done
      elif [ $? -ne 1 ]; then
        fail "no string in a token format: token-patterns.txt:$number is not a pattern grep -E takes"
        return
      fi
    done <"$TOKEN_PATTERNS"
  fi
  if [ ${#matches[@]} -gt 0 ]; then
    fail "no string in a token format: $(printf '%s; ' "${matches[@]}" | sed 's/; $//')"
  else
    pass "no string in a token format ($n values, $patterns patterns)"
  fi
}

# token_audiences: every projected ServiceAccount token's audience. One for a server would be a
# credential for that server.
token_audiences() {
  local audiences count audience server bad=()
  if ! AUDIENCES=$(jq -c "$SOURCES"'[(.spec.volumes // [])[] | .name as $v | sources
      | select(.serviceAccountToken) | {volume: $v, audience: (.serviceAccountToken.audience // "")}]' <<<"$POD_JSON") ||
    ! count=$(jq length <<<"$AUDIENCES") || ! audiences=$(jq -r '.[].audience' <<<"$AUDIENCES"); then
    AUDIENCES=null
    fail "no projected token for a server's audience: could not read the pod's projected volumes"
    return
  fi
  if [ "$count" -gt 0 ]; then
    while IFS= read -r audience; do
      echo "projected token for audience: ${audience:-(none set: the API server)}"
      for server in "${SERVER_AUDIENCES[@]}"; do
        if [ "$audience" = "$server" ]; then bad+=("$audience"); fi
      done
    done <<<"$audiences"
  fi
  if [ ${#bad[@]} -gt 0 ]; then
    fail "no projected token for a server's audience: $(printf '%s,' "${bad[@]}" | sed 's/,$//')"
  else
    pass "no projected token for a server's audience ($count projected)"
  fi
}

# --- (c) SubjectAccessReviews ------------------------------------------------------------------

permissions() {
  step "(c) what $SA may do through the cluster API (permissions.tsv)"
  local namespaces requests answers verdicts verdict row
  namespaces=$(printf '%s\n' "$NAMESPACE" "$GATEWAY_NS" "${SERVER_NS[@]}" | awk 'NF && !seen[$0]++' | jq -R . | jq -sc .)
  # One review per row and scope, for the ServiceAccount's user and groups.
  if ! requests=$(jq -R -s -c --arg user "system:serviceaccount:$NAMESPACE:$SA_NAME" --arg sans "$NAMESPACE" \
    --argjson namespaces "$namespaces" '
      split("\n") | map(select(length > 0 and (startswith("#") | not)) | split("\t"))
      | map(if length == 4 and (.[3] == "namespaced" or .[3] == "cluster") then .
            else error("bad row: \(join(" "))") end)
      | map(. as [$verb, $resource, $sub, $scope]
        | ($resource | index(".")) as $dot
        | {label: ("\($verb) \($resource)" + (if $sub == "-" then "" else "/\($sub)" end)),
           verb: $verb,
           resource: (if $dot then $resource[:$dot] else $resource end),
           group: (if $dot then $resource[$dot + 1:] else "" end),
           subresource: (if $sub == "-" then "" else $sub end),
           scopes: (if $scope == "namespaced" then $namespaces + [""] else [""] end)})
      | {rows: ., list: {apiVersion: "v1", kind: "List", items: [.[] as $row | $row.scopes[] as $ns
          | {apiVersion: "authorization.k8s.io/v1", kind: "SubjectAccessReview",
             spec: {user: $user,
                    groups: ["system:serviceaccounts", "system:serviceaccounts:\($sans)", "system:authenticated"],
                    resourceAttributes: ({verb: $row.verb, group: $row.group, resource: $row.resource}
                      + (if $row.subresource == "" then {} else {subresource: $row.subresource} end)
                      + (if $ns == "" then {} else {namespace: $ns} end))}}]}}' "$PERMISSIONS"); then
    fail "$SA may do none of control 1: could not read permissions.tsv"
    return
  fi
  if [ "$(jq '.rows | length' <<<"$requests")" -eq 0 ]; then
    fail "$SA may do none of control 1: permissions.tsv lists nothing"
    return
  fi
  jq -c .list <<<"$requests" >"$TMP/reviews.json"
  if ! answers=$(k create -f - -o json <"$TMP/reviews.json"); then
    fail "$SA may do none of control 1: could not create the SubjectAccessReviews"
    return
  fi
  # Each answer, by what it was asked: true, false, or missing when there is no clear answer. A
  # review that is not allowed but carries an evaluationError was not settled (an authorizer
  # failed, and might have allowed it), so it counts as missing.
  if ! verdicts=$(jq -s -r --arg user "system:serviceaccount:$NAMESPACE:$SA_NAME" --argjson requests "$requests" '
      def key: [.verb, (.group // ""), .resource, (.subresource // ""), (.namespace // "")] | join("|");
      (map(if .kind == "List" then .items[] else . end)
        | map(select(.spec.user == $user and (.status.allowed | type) == "boolean"
                     and (.status.allowed or (.status.evaluationError // "") == ""))
              | {key: (.spec.resourceAttributes | key), value: .status.allowed})
        | from_entries) as $answers
      | $requests.rows[]
      | . as $row
      | [$row.scopes[] | {scope: (if . == "" then "cluster" else . end),
            answer: $answers[{verb: $row.verb, group: $row.group, resource: $row.resource,
                              subresource: $row.subresource, namespace: .} | key]}] as $asked
      | [$asked[] | select(.answer == true) | .scope] as $yes
      | [$asked[] | select(.answer != true and .answer != false) | .scope] as $unread
      | if ($yes | length) > 0 then "FAIL\t\($row.label): it may, in \($yes | join(","))"
        elif ($unread | length) > 0 then "FAIL\t\($row.label): could not read the answer for \($unread | join(","))"
        else "PASS\t\($row.label) (\([$asked[] | .scope] | join(",")))" end' <<<"$answers"); then
    fail "$SA may do none of control 1: could not read the SubjectAccessReviews' answers"
    return
  fi
  while IFS=$'\t' read -r verdict row; do
    if [ "$verdict" = PASS ]; then pass "$SA may not $row"; else fail "$SA may not $row"; fi
  done <<<"$verdicts"
}

# --- (d) Cloud identity ------------------------------------------------------------------------

cloud_identity() {
  step "(d) cloud identity bound to $SA, for the owner to check"
  local sa identity
  if ! sa=$(k get serviceaccount "$SA_NAME" -n "$NAMESPACE" -o json) || ! json_object "$sa" ||
    ! identity=$(jq -c --argjson keys "$CLOUD_IDENTITY_ANNOTATIONS" \
      '(.metadata.annotations // {}) as $a | [$keys[] | select($a[.] != null) | {key: ., value: $a[.]}] | from_entries' <<<"$sa"); then
    fail "cloud identity of $SA: could not read the ServiceAccount"
    return
  fi
  CLOUD_IDENTITY=$identity
  if [ "$CLOUD_IDENTITY" = "{}" ]; then
    note "no cloud identity annotation on $SA"
  else
    jq -r 'to_entries[] | "NOTE cloud identity for the owner to check: \(.key)=\(.value)"' <<<"$CLOUD_IDENTITY"
  fi
}

# --- (e) The probe -----------------------------------------------------------------------------

# server_addresses: one line per --server-service, `NAME.NAMESPACE<TAB>address,address...`, with
# the Service's ClusterIPs and its endpoints' addresses.
server_addresses() {
  local service ns name svc slices addresses
  for service in "${SERVER_SERVICES[@]}"; do
    ns=${service%%/*} name=${service#*/}
    if ! svc=$(k get service "$name" -n "$ns" -o json) || ! json_object "$svc" ||
      ! slices=$(k get endpointslices -n "$ns" -l "kubernetes.io/service-name=$name" -o json) ||
      ! json_object "$slices" ||
      ! addresses=$(jq -rn --argjson svc "$svc" --argjson slices "$slices" '
        [($svc.spec.clusterIPs // [$svc.spec.clusterIP // empty])[],
         ($slices.items | if type == "array" then .[] else error("items are not a list") end
          | .endpoints | if . == null then empty elif type == "array" then .[] else error("endpoints are not a list") end
          | .addresses | if type == "array" then .[] else error("addresses are not a list") end
          | if type == "string" then . else error("an address is not a string") end)]
        | map(select(. != "None" and . != "")) | unique | join(",")'); then
      echo "could not read Service $service or its EndpointSlices" >&2
      return 1
    fi
    if [ -z "$addresses" ]; then
      echo "Service $service has no ClusterIP and no endpoint address" >&2
      return 1
    fi
    printf '%s.%s\t%s\n' "$name" "$ns" "$addresses"
  done
}

probe() {
  step "(e) the probe in $POD"
  local addresses routes wanted mismatch custom deadline left pod_now state="" unread=1 log exit_code last bad
  if ! addresses=$(server_addresses); then
    fail "the probe ran: could not read the servers' addresses"
    return
  fi
  # Each {{ADDR}} in the addresses column, from the --server-service its URL's host names.
  if ! routes=$(ADDRESSES=$addresses awk -F'\t' -v OFS='\t' '
      BEGIN {
        n = split(ENVIRON["ADDRESSES"], entries, "\n")
        for (i = 1; i <= n; i++) { split(entries[i], kv, "\t"); addr[kv[1]] = kv[2] }
      }
      /^#/ || NF == 0 { print; next }
      index($3, "{{ADDR}}") {
        host = $2; sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", host); sub(/[\/?#].*$/, "", host); sub(/:[0-9]+$/, "", host)
        found = ""
        for (key in addr) if (host == key || host == key ".svc" || index(host, key ".svc.") == 1) found = addr[key]
        if (found == "") { print "row " $1 ": no --server-service for host " host > "/dev/stderr"; bad = 1; next }
        out = ""; rest = $3
        while ((at = index(rest, "{{ADDR}}")) > 0) { out = out substr(rest, 1, at - 1) found; rest = substr(rest, at + 8) }
        $3 = out rest
      }
      { print }
      END { exit bad }' "$ROUTES_FILE"); then
    fail "the probe ran: a row of $ROUTES_FILE has {{ADDR}} but no --server-service for its host"
    return
  fi
  if awk '!/^#/ && index($0, "{{ADDR}}") { found = 1 } END { exit !found }' <<<"$routes"; then
    fail "the probe ran: {{ADDR}} is left outside the addresses column of $ROUTES_FILE"
    return
  fi
  # The attempts the routes ask for, each [row, by, target]: by name unless the URL's host is an
  # address literal, as the probe does, and by each address. A `resolve` row's addresses are
  # found in the pod, so it asks for at least one address line, whatever its target.
  if ! wanted=$(jq -R -s -c '
      split("\n") | map(select(length > 0 and (startswith("#") | not)) | split("\t")
        | if length >= 3 and (.[0] | length) > 0 and (.[2] | length) > 0 then . else error("bad row") end
        | .[0] as $row | .[1] as $url | .[2] as $addresses
        | ($url | sub("^[a-zA-Z][a-zA-Z0-9+.-]*://"; "") | sub("[/?#].*$"; "")) as $authority
        | ($authority | startswith("[") or (sub(":[0-9]+$"; "") | test("^[0-9.]+$"))) as $literal
        | {exact: [(if $literal then empty else [$row, "name", $url] end),
                   (if $addresses == "resolve" then empty else ($addresses | split(",")[] | [$row, "address", .]) end)],
           resolve: (if $addresses == "resolve" then [$row] else [] end)})
      | {exact: (map(.exact[]) | unique), resolve: (map(.resolve[]) | unique)}' <<<"$routes"); then
    fail "the probe ran: could not read the rows of $ROUTES_FILE"
    return
  fi
  # kubectl debug's --env splits its value at commas, and the routes hold commas, so the
  # variables go in a partial container spec (--custom).
  custom=$TMP/probe-env.json
  jq -n --arg routes "$routes" --arg url "$GATEWAY_URL" --arg expect "$EXPECT" \
    '{env: [{name: "ROUTES", value: $routes}, {name: "GATEWAY_URL", value: $url}, {name: "EXPECT", value: $expect}]}' >"$custom"
  PROBE_CONTAINER=route-probe-$(date -u +%Y%m%d%H%M%S)
  if ! k debug "pod/$POD_NAME" -n "$NAMESPACE" --image="$PROBE_IMAGE" --profile=restricted \
    -c "$PROBE_CONTAINER" --custom="$custom" -- "$PROBE_COMMAND" >&2; then
    fail "the probe ran: kubectl debug could not start $PROBE_CONTAINER"
    return
  fi
  # Wait for it to end, at most --probe-wait seconds in all: each read may take only the time
  # left, and an end seen after the deadline does not count.
  deadline=$((SECONDS + PROBE_WAIT))
  # A read that fails or cannot be parsed is tried again; if the last one did, or none was made,
  # the wait fails as could not read.
  while :; do
    left=$((deadline - SECONDS))
    if [ "$left" -le 0 ]; then break; fi
    [ "$left" -le 30 ] || left=30
    if pod_now=$(REQUEST_TIMEOUT=${left}s k get pod "$POD_NAME" -n "$NAMESPACE" -o json 2>/dev/null) && json_object "$pod_now" &&
      state=$(jq -c --arg c "$PROBE_CONTAINER" \
        '[(.status.ephemeralContainerStatuses // [])[] | select(.name == $c) | .state.terminated // empty][0] // empty' <<<"$pod_now"); then
      unread=""
      if [ -n "$state" ]; then
        [ "$SECONDS" -le "$deadline" ] || state=""
        break
      fi
    else
      state="" unread=1
    fi
    sleep 1
  done
  if [ -n "$unread" ]; then
    fail "the probe ended within $PROBE_WAIT s: could not read pod $POD_NAME"
    return
  fi
  if [ -z "$state" ]; then
    fail "the probe ended within $PROBE_WAIT s: $PROBE_CONTAINER had not"
    return
  fi
  exit_code=$(jq -r '.exitCode // "?"' <<<"$state")
  pass "the probe ended within $PROBE_WAIT s (exit $exit_code)"
  if ! log=$(k logs "pod/$POD_NAME" -n "$NAMESPACE" -c "$PROBE_CONTAINER"); then
    fail "the probe passed: could not read the log of $PROBE_CONTAINER"
    return
  fi
  printf '%s\n' "$log" | sed 's/^/    /'
  printf '%s\n' "$log" | awk '$1 == "ROUTE" { print }' |
    jq -R -c 'split(" ") | {line: join(" "), row: .[1], by: .[2], target: .[3], result: .[4],
      well_formed: (length == 5 and (.[2] == "name" or .[2] == "address")
        and (.[4] == "refused" or .[4] == "open" or .[4] == "could-not-probe"))}' >>"$ROUTE_LINES"
  last=$(printf '%s\n' "$log" | awk 'NF { line = $0 } END { print line }')
  case $last in
    'RESULT: PASS') PROBE_RESULT=PASS ;;
    'RESULT: FAIL') PROBE_RESULT=FAIL ;;
    *) PROBE_RESULT="" ;;
  esac
  local want
  if [ "$EXPECT" = open ]; then want=open; else want=refused; fi
  bad=$(jq -s --arg want "$want" '[.[] | select(.well_formed | not)] | length' "$ROUTE_LINES")
  if [ -z "$PROBE_RESULT" ]; then
    fail "the probe passed: its last line is not a RESULT line"
  elif [ "$PROBE_RESULT" != PASS ]; then
    fail "the probe passed: RESULT: $PROBE_RESULT (exit $exit_code)"
  elif [ "$exit_code" != 0 ]; then
    fail "the probe passed: RESULT: PASS, but it exited $exit_code"
  elif [ "$(jq -s length "$ROUTE_LINES")" -eq 0 ]; then
    fail "the probe passed: it tried no route"
  elif [ "$bad" -ne 0 ]; then
    fail "the probe passed: $bad ROUTE lines are not in the probe's format"
  elif [ "$(jq -s --arg want "$want" '[.[] | select(.result != $want)] | length' "$ROUTE_LINES")" -ne 0 ]; then
    fail "the probe passed: RESULT: PASS, but not every route was $want"
  elif ! mismatch=$(jq -s -r --argjson wanted "$wanted" '
      map([.row, .by, .target]) as $got
      | ([$wanted.exact[] | . as $w | select(any($got[]; . == $w) | not) | join(" ")]
         + [$wanted.resolve[] | . as $r | select(any($got[]; .[0] == $r and .[1] == "address") | not)
            | "\($r) address (resolved in the pod)"]) as $missing
      | [$got[] | . as $g
         | select(any($wanted.exact[]; . == $g) or ($g[1] == "address" and any($wanted.resolve[]; . == $g[0])) | not)
         | join(" ")] as $extra
      | [$got | group_by(.)[] | select(length > 1) | .[0] | join(" ")] as $repeated
      | [if $missing == [] then empty else "missing \($missing | join(", "))" end,
         if $extra == [] then empty else "not asked for \($extra | join(", "))" end,
         if $repeated == [] then empty else "repeated \($repeated | join(", "))" end] | join("; ")' "$ROUTE_LINES"); then
    fail "the probe passed: could not compare its ROUTE lines with the routes"
  elif [ -n "$mismatch" ]; then
    fail "the probe passed: one ROUTE line per attempt the routes ask for: $mismatch"
  else
    pass "the probe passed: every route $want ($(jq -s length "$ROUTE_LINES") attempts, EXPECT=$EXPECT)"
  fi
}

# --- Running -----------------------------------------------------------------------------------

echo "route check: $ENVIRONMENT, $DATE (context $CONTEXT${AS:+, as $AS})"
if pick_pod; then
  versions
  network_plugin
  credentials
  permissions
  cloud_identity
  probe
fi
FINISHED=1
