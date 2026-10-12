# Deploying the demo

The first-slice demo (#14) runs in two places, each with one command from the repository root:

```sh
deploy/demo/demo.sh compose   # Tier A: Postgres, the gateway, mock-docs and the dev issuer
deploy/demo/demo.sh kind      # Tier B: the cluster switchboard-demo, with network policy
deploy/demo/demo.sh down compose   # stop Compose and delete its volumes; the cluster stays
deploy/demo/demo.sh down kind      # delete the cluster; Compose stays
deploy/demo/demo.sh down all       # both
```

Every check prints PASS or FAIL. The last line counts them, and the script exits non-zero if
any check failed or any step could not run. Nothing is retried. It needs docker with compose,
kind, kubectl, jq, awk and tar.

A run leaves what it started running, so it can be looked at afterwards. `down` takes down
only what it names: stopping Compose never deletes the cluster.

`demo.sh kind` never touches the cluster `otto-dev` or `~/.kube/config`. It refuses a cluster
named `otto-dev`, drops `KUBECONFIG`, and names `.demo/kubeconfig` in every kubectl and kind
call. To use the cluster by hand:

```sh
kubectl --kubeconfig .demo/kubeconfig --context kind-switchboard-demo get pods -A
```

If the cluster exists but `.demo/kubeconfig` does not (another checkout created it), the script
writes it with `kind export kubeconfig`.

Every password and static credential under `deploy/` is a dummy value for the demo. In kind the
gateway holds no static credential for mock-docs: it presents a ServiceAccount token for each
entry of mock-docs in the registry (below).

## One entry of mock-docs per team

The registry lists mock-docs twice, once per team (decisions 0010 and 0013, section 10):

| Entry | Team | Surface | Tools | Credential reference | kind identity | Compose credential |
| --- | --- | --- | --- | --- | --- | --- |
| `docs-team-a` | `team-a` | `/mcp/docs-team-a` | `docs-team-a__list_documents`, `docs-team-a__read_document` | `docs-team-a-credential` | ServiceAccount `switchboard/docs-team-a` | `compose/dummy-credentials/docs-team-a-credential` |
| `docs-team-b` | `team-b` | `/mcp/docs-team-b` | `docs-team-b__list_documents`, `docs-team-b__read_document` | `docs-team-b-credential` | ServiceAccount `switchboard/docs-team-b` | `compose/dummy-credentials/docs-team-b-credential` |

Both entries have mock-docs' one address and identity. Each surface admits its own team only.
The gateway presents an entry's own credential on every call to that entry's tools, and
mock-docs limits each credential to its team's project, `docs-team-a`'s to `atlas` and
`docs-team-b`'s to `borealis`. So a call through one team's entry cannot reach the other team's
project at the server, whatever the gateway decided. Both demos read mock-docs' log to show
that each team's calls came under its own entry's identity, for its own project.

In kind each entry's identity is a ServiceAccount whose token comes by TokenRequest. The gateway
pod runs a native sidecar, `token-writer` (`demo/token-writer.sh`), which asks the API server
for each entry's token, and for that of `registry-probe`, the drift probe's ServiceAccount, for
audience `mock-docs` and valid for 600 s, and writes it to `/var/run/switchboard/tokens/<name>`,
again every 300 s, always to a new file renamed into place. A token it cannot get leaves the
previous file and is tried again in 5 s. It never prints a token. The gateway reads each entry's
file as that entry's credential on every call, and the probe's on every probe, so it has no
API-server client. `kind/base/gateway-tokens.yaml` lets ServiceAccount `gateway` create tokens
for `docs-team-a`, `docs-team-b` and `registry-probe`, by name, and for no other ServiceAccount.
Both containers run as that ServiceAccount, but only the token writer mounts a token the API
server accepts (a projected token with no audience); the gateway container mounts no API token
and reads the tokens directory read-only. No workload mounts an API token either. The kind run
asks the API server that the gateway may create tokens for the two entries and the probe, and
for no other ServiceAccount, and `crates/demo-checks` holds the manifests to all of it.

In kind the gateway fetches the cluster issuer's keys from the API server with no token
(decision 0013, section 10). A projected token would not help: every one authenticates as the
pod's ServiceAccount, and it is the ServiceAccount, not a container, that holds the pod's
grants, so a token the API server accepts would carry them all. Instead `kind/base/issuer-discovery.yaml`
binds the ClusterRole `system:service-account-issuer-discovery`, which grants only `get` on the
issuer's discovery document and keys, to the group `system:unauthenticated`, and the gateway
trusts only the cluster CA in ConfigMap `kube-root-ca.crt`. The kind run checks that a caller
with no token gets the keys from the gateway's pod and is refused a ConfigMap.

## The drift pass

The gateway reads each entry's tool list from mock-docs, with that entry's own credential, once
during boot before it binds its listener and then every `[drift] interval_seconds` (decision
0013, section 5). Both demos set 10 s, so a run sees it; decision 0013 sets 300 s, the default,
for real deployments, and the gateway refuses an interval below 5 or above 900. An approved
tool whose served definition no longer hashes to its approval's `definition_sha256`, or that
mock-docs no longer lists, is withdrawn from every surface in that replica until it is approved
again or the replica restarts, with a `"event":"tool_withdrawn"` line at `ERROR`. A poll that
fails keeps the entry's tools served and logs `"event":"drift_poll_failed"` at `WARN`. These
tools/list requests reach mock-docs every 10 s under the entries' identities; they are not calls,
and the runs' call counts leave them out. Neither run changes a definition: the demos show that
the pass runs and withdraws nothing while mock-docs serves what was approved.

## What is here

| Path | What it is |
| --- | --- |
| `Dockerfile` | One image for every role: the workspace's binaries, `workload.sh`, `migrate.sh`, `token-writer.sh` and `roles.sql`. The audit migrations are inside `switchboard`. `BINS` lists the binaries; `REQUIRE_ALL_BINS=true` refuses to build without all of them. |
| `compose/compose.yaml` | `postgres` (not published), `migrate`, `dev-issuer`, `mock-docs`, `gateway` on `127.0.0.1:18080`, and `workload` under `profiles: [demo]`. |
| `compose/config/` | The gateway's deployment file, the team manifest, the registry directory it polls, and the registry with each team's read tool withdrawn. |
| `compose/dummy-credentials/` | Each entry's dummy credential and its SHA-256, and `mock-docs-callers`, the two SHA-256s each with its team's project, which mock-docs reads. |
| `kind/cluster.yaml` | One node, kindnet, the node image kind v0.32.0 uses. |
| `kind/base/` | Namespaces `switchboard`, `mock-docs`, `team-a`, `team-b`; ServiceAccounts, `docs-team-a` and `docs-team-b` among them; the token grant (`gateway-tokens.yaml`); Postgres; the migration Job; mock-docs, which accepts only the entries' ServiceAccounts, each for its team's project; the gateway, with the token writer beside it and the cluster CA; `issuer-discovery.yaml`, which lets a caller with no token read the cluster issuer's keys; suspended CronJobs holding each workload's Job template. No network policy. |
| `kind/policy/` | The network policies: mock-docs admits only the gateway, Postgres only the gateway and the migration, the gateway only the two teams. |
| `kind/route-check/rbac.yaml` | The route check's operator: ServiceAccount `route-check/operator`, `get` and `list` on what it reads, among them Roles, ClusterRoles, RoleBindings and ClusterRoleBindings across the cluster, `create` on SubjectAccessReviews, and `patch` on `pods/ephemeralcontainers` in `team-a` and `team-b` only. Not part of the base; the kind run applies it. |
| `route-check/` | The route check (decision 0010): `route-check.sh`, its operator step; `probe.sh`, its probe, which the image installs as `route-probe.sh`; `permissions.tsv`, the one list of control 1's permissions; `rbac-match.jq`, which finds the RBAC rules bound to a ServiceAccount that grant a row of that list; `token-patterns.txt`; and `routes/kind.tsv`, the routes the probe tries in kind. |
| `demo/workload.sh` | The scripted workload (decision 0008). Modes `full`, `before-policy`, `refused`, `audit-down`, `withdrawn`, and `idle`, which makes no call and holds a running pod for the route check until SIGTERM, at most 600 s. |
| `demo/token-writer.sh` | The kind gateway pod's token writer (above). `token-writer.sh once` writes each token once. |
| `demo/migrate.sh`, `demo/roles.sql` | Creates the roles and database as the superuser, runs `switchboard migrate` as `switchboard_owner`, and lets `switchboard_reader` read the audit schema. |
| `demo/demo.sh` | The driver. |

`crates/demo-checks` tests the scripts and manifests: the workload against a fake gateway that
misbehaves one way at a time, the driver with fake docker, kind and kubectl, and the manifests'
claims (only the gateway is published, the policy admits only the gateway, Compose's dummy
credentials' hashes match, and in kind: only the token writer mounts an API token and the token
grant names exactly the two entries' ServiceAccounts and the probe's; mock-docs' settings name
only the entries', each for its team's project; each workload calls its own team's surface; the
gateway fetches the issuer's keys with the cluster CA and no token; and the discovery binding
names one ClusterRole and one group). It runs `token-writer.sh` against a fake API server too.

## Network policy in kind

kindnet in kind v0.32.0 (node image v1.36.1) enforces NetworkPolicy. This was checked on
2026-10-06 with a throwaway test: before a policy, two new pods reached an nginx pod; after an
ingress policy admitting one label, a new pod without it timed out (by Service IP and by pod IP)
and a new pod with it still connected. Kubelet's readiness probes still pass under a deny-all
ingress policy. No Calico was needed.

The demo still checks this every run, for each team: before the policy, a new pod's direct call
must connect and get 401 from the server, and the same pod must get an allowed read through the
gateway, whose call to the server succeeds; after it, a new pod's direct call must time out
before it connects (curl exit 28 with no connection made), and the same pod must still reach
the gateway and get an allowed read through it. curl also exits 28 when it connected and no
answer came in time, from a stalled server or a tarpit; that is not a dropped route, and it
fails the check (#83).

Network policy does not see what reaches a pod through the API server: exec, attach,
port-forward, ephemeral containers, and the pod, Service and node proxy routes. The operator
checks ask about each team's workload and require `no` (decision 0010, control 1). They ask
every row of `route-check/permissions.tsv`, the list the route check's operator step asks too,
so there is one list. A `namespaced` row is asked in `mock-docs`, `switchboard`, the team's own
namespace and across the cluster; a `gateway` row in `mock-docs` and `switchboard` only; a
`cluster` row across the cluster only. Across the cluster is a can-i with no namespace: it asks
in the kubeconfig's namespace, `default`, so RBAC counts that namespace's RoleBindings as well
as ClusterRoleBindings. The list covers reading Secrets (`get`, `list` and `watch`, since list
and watch return the data too), and the same on ConfigMaps as `gateway` rows: the gateway's
ConfigMap names the file that holds its credential, not the credential, so a team may read its
own namespace's ConfigMaps (#104), but not the gateway's or a server's; creating pods and
`create`, `update` and `patch` on Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs and
CronJobs; `create` and `get` on exec, attach, port-forward and the pod, Service and node
proxies; `patch` and `update` on ephemeral containers; minting a ServiceAccount's token;
impersonating users, groups, ServiceAccounts, UIDs and extras (`userextras/scopes`); `bind` and
`escalate` on roles and cluster roles; and `create`, `update` and `patch` on role and cluster
role bindings. That is 42 namespaced rows, 3 gateway rows and 10 cluster rows, 184 checks per
team. They are asked with `kubectl auth can-i --as`, except UIDs and extras, which the API
server checks in `authentication.k8s.io` though it serves no such resource: can-i cannot name
them, so those are asked as SubjectAccessReviews. A query kubectl cannot answer is a FAIL with
kubectl's message, and the run goes on.

can-i and a SubjectAccessReview name no resource, so neither sees a rule limited by
`resourceNames`: a workload able to mint tokens for one named ServiceAccount answers no (#60).
So the checks also read the RBAC objects, with `route-check/rbac-match.jq`, the matcher the
route check's operator step runs too. They read the ClusterRoles, the ClusterRoleBindings, and
the Roles and RoleBindings in every namespace (`kubectl get -A`), not only in those a team's
can-i checks ask in: `mock-docs`, `switchboard`, the team's own, and `default` for across the
cluster. A RoleBinding in `kube-system` or the other team's namespace can bind the workload too,
and no can-i asks there. Where can-i does ask, in `default` among them, it still misses a rule
limited by `resourceNames`. A binding counts when a subject is the team's ServiceAccount, as a
ServiceAccount or as the user `system:serviceaccount:<team>:mock-workload`, or one of its groups
(`system:serviceaccounts`, `system:serviceaccounts:<team>`, `system:authenticated`). A
RoleBinding counts the Role or ClusterRole it binds. A rule grants a row when its verbs, API
groups and resources match the row's, `*` matching anything and `*/<sub>` any resource's
subresource, whatever its `resourceNames`. A `namespaced` row counts the RoleBindings, in
whatever namespace, and the ClusterRoleBindings; a `gateway` row the RoleBindings in `mock-docs`
and `switchboard`, to a Role or a ClusterRole, and the ClusterRoleBindings; a `cluster` row only
the ClusterRoleBindings. That is one more check per row, 55 per team. A list that cannot be read
or parsed fails, and nothing is matched. No grant is allowed in code. The issuer-discovery
binding to `system:unauthenticated` is read too and counts for no team: a workload's token is
authenticated, so that group is not one of its groups, and the ClusterRole names only URLs,
which grant no row.

## The route check in kind

`demo.sh kind` is the route check's first user (decision 0010, "The kind run"). It applies
`kind/route-check/rbac.yaml` and runs `route-check/route-check.sh` as
`system:serviceaccount:route-check:operator`, through kubectl's `--as`, so the step has that
ServiceAccount's access and no more. Before it, four checks ask that the operator may not get
`mock-docs`' Secrets, exec into or create a pod in `team-a`, or add an ephemeral container in
`mock-docs`.

- **Before the policy,** a new idle Job in `team-a` (`workload.sh idle`: the workload's
  labels and ServiceAccount, and no call) gives the step a running pod. The step runs with
  `--expect open`: every route in `routes/kind.tsv` must be open, by name and by each address
  (mock-docs' ClusterIP and its pod's IP). This is the positive control: the probe can reach
  the server, and the server answers. Each open attempt carries no credential, and mock-docs
  refuses it as `no_bearer`; the server check counts them.
- **After the policy** and its 10 s settle, a new idle pod of each team gets 10 s more, since
  a new pod is briefly outside its policy. The step then runs with `--expect refused` for each
  team: every route must be refused, which for the probe means curl timed out with no
  connection made.

Each step deletes its idle Jobs. The step's PASS and FAIL lines count as the run's, so any FAIL
fails the run. Its reports go to `.demo/route-check-<team>-<UTC time>.json` (and
`route-check-team-a-open-<UTC time>.json` for the control), with the network plugin, how its
enforcement was read, and the kind version; the run checks that each report after the policy
names kindnet and a kind release. The step reads kindnet's enforcement from its flags, or from
the default of the pinned kindnetd when it sets none. kindnet's log is only the fallback, since
the kubelet rotates it: on `switchboard-demo` the line of its policy controller starting is
gone after about a week.

A pass shows that the routes on the list were refused, not that no route exists. There is no
schedule and no alert: decision 0010 leaves both to the first real cluster. The kind claim
holds only while the evidence log in `docs/route-exceptions.md` has a passing run from the last
seven days.

## Metrics

Decision 0009 leaves where telemetry goes to whoever runs logging (Still open 3); until then it
is the gateway's structured events and counters. The default, until a sink is chosen, is
Prometheus text on a listener of the gateway's own: `[metrics] listen` in the deployment file
serves `GET /metrics` there, and nothing else. Left out, nothing listens. It may not take the
MCP port, and it runs no host, origin or identity check, so it belongs where only a scraper
reaches it. In Compose it listens on the container's loopback, `127.0.0.1:9090`, and is not
published. In kind it is the pod's `metrics` port, 9090: the Service does not expose it, and
the `gateway-from-teams` policy admits the teams on 8080 only. Both runs read it with curl
inside the gateway's container.

The signals of design section 11, all from the gateway's own counters: begin failures by cause
(`switchboard_audit_begin_failures_total{cause}`; see `pool_timeout` below), the audit-failure
answers they cause (`switchboard_audit_failure_answers_total`, for `tools/call` and
`tools/list`), answers released before finish, finishes given up by cause, failed begins never
committed, finishes in flight, open rows and the oldest open row's deadline (polled every 15 s
through the open-row view; a failed poll is counted and keeps the last count), begin and finish
latency histograms, the begin and finish pools' connections in use, open and maximum, and
telemetry events and drops. Each proxied server's drift polls by result, the tools the drift
pass withdrew from it, and how many tools are withdrawn now
(`switchboard_drift_polls_total{server,result}`, `switchboard_drift_withdrawals_total{server}`,
`switchboard_tools_withdrawn`). Receipts in `unknown` arrive with receipts (#10 stage 2). The
Compose run checks that its database outage counted a begin failure and an audit-failure answer;
both runs check that telemetry dropped is exported and that at most one row is open. No alert
thresholds or paging: those wait for the first production deployment (Still open 9).

A begin failure's `pool_timeout` means no connection was obtained in time, whether waiting for
a pool permit or opening a new connection. So three different things count there: a database
that never answers, such as one behind a blackholed address; a reconnect after a transient
error, such as a broken connection, that runs past the begin budget; and a begin pool too small
for the load. The count does not say which, so a rise in it does not by itself mean the pool is
too small. A database that refuses connections counts as `database_error` instead. A signal
that tells an unreachable database from a small pool is #155.

Each gateway instance opens at most 21 connections to the audit database: 16 for begins and list
rows, 4 for finishes, and 1 for the open-row poll. The poll has its connection to itself, so a
poll held up for its full 2 s never takes a connection a finish could use (#140). The pool
metrics cover the begin and finish pools; the poll's connection is not among them.

## Stopping the gateway

Decision 0009 says an instance that is told to stop first fails its readiness check, then stops
accepting calls, and lets running calls and their finishes complete. On SIGTERM the gateway's
`GET /readyz` turns from 200 to 503, and the gateway goes on serving for its readiness removal,
8 s, before it stops taking connections. In kind the readiness probe asks `/readyz` every 2 s
and takes the pod out of the Service after 3 failures, 6 s, inside that window. `/readyz` runs
no host, origin or identity check, since the kubelet probes it by the pod's IP, and it answers
one word. Compose has no probe, but the gateway still waits out the removal there.

The termination grace period must be longer than the readiness removal plus the begin budget,
the call deadline, the finish deadline and one answer budget (the last attempt to complete a
failed begin's row is made at the finish deadline), or a stop can leave open rows: 8 s + 2 s +
5 s + 30 s + 2 s, 47 s. No call starts after the removal: a request on a connection still open
whose body arrives later is answered 503 and nothing runs. The gateway's 30 s wait for open
connections after the removal fits inside the same 47 s. Both manifests give the gateway 50 s: `terminationGracePeriodSeconds` in
`kind/base/gateway.yaml` and `stop_grace_period` in `compose/compose.yaml`, in place of 30 s and
10 s. `crates/demo-checks` holds both to the code's budgets and the probe to the removal.

## Loading images into kind

`kind load docker-image` fails on this machine's Docker (containerd image store) for images
pulled with several platforms (`ctr: content digest ... not found`). The driver saves this
platform's images to an archive and loads that with `kind load image-archive` instead.

The manifests name `switchboard-demo:dev`. In kind the driver deploys the image under a tag
taken from its own ID (`switchboard-demo:<12 hex digits>`) and checks that the gateway and
mock-docs run that tag. With one fixed tag, a run on an existing cluster would leave the
previous build's pods running, because `kubectl apply` sees no change.

Postgres is pinned by tag and digest (`postgres:<tag>@sha256:<digest>`) in
`compose/compose.yaml` and in the driver's `POSTGRES_IMAGE`. The archive holds this platform's
manifest, not the tag's multi-arch index, so a pod naming the index digest does not find the
loaded image and pulls it from Docker Hub instead (checked on kind v0.32.0: with
`imagePullPolicy: Never`, such a pod stops at `ErrImageNeverPull`). So `kind/base/postgres.yaml`
names the tag alone, and the driver pulls the pinned digest, tags it with that tag and loads it.
The pod has `imagePullPolicy: Never` too, so it never pulls whatever the tag names today. Its
template carries the digest as the annotation `switchboard.io/image-digest`, which the driver
fills in when it applies the manifests: a new digest under the same tag changes the template, and
the pod is replaced. After the rollout the driver checks that the pod runs the pinned digest.
The node never has that digest, and with Docker's classic image store not even this platform's
manifest: kind's load wraps the archive in an index of its own, and the classic store writes a
new manifest when it saves the image. Nor can Docker's image ID stand in for it: that is the
config's digest on the classic store and the manifest's on the containerd store. What reaches
the node unchanged is the image's config. So
the driver reads the config's digest of the pinned image for this platform from what
`docker save` writes, the same on both stores, and requires the pod's container to run the image
with that ID, as `crictl ps` lists it on the node.

`crates/demo-checks/tests/pins.rs` holds every Postgres pin in the repository to one release,
and every one but CI's to one digest. CI's service container runs the Debian variant of the same
release, pinned by a digest of its own.

## What runs

Every command and file below is the real one; `crates/demo-checks` and the gateway's own tests
check that the deployment files load.

| Piece | How it runs |
| --- | --- |
| Binaries | `switchboard` (crates/gateway), `switchboard-dev` (crates/gateway-dev) and `mock-docs-server` (crates/mock-docs-server). `Dockerfile` builds `switchboard` on its own with `cargo build --release --locked -p gateway --bin switchboard`, then the other two with `cargo build --release --locked -p gateway-dev -p mock-docs-server --bins`. Build `switchboard` for deployment the same way: a workspace build turns on gateway-dev's `test-support` feature, which exempts the gateway from the receipt-store gate (decision 0009). `switchboard` links nothing from the testkit. |
| Gateway | `switchboard --config=<file>`. The deployment file (`compose/config/gateway.toml`, `kind/base/config/gateway.toml`; format in `crates/gateway/src/deployment.rs`) gives the listen address, the allowed hosts, the registry file and how often it is read again (2 s), each trusted issuer with where its keys come from and its team manifest (`teams.toml`), the audit store (`mode = "postgres"`, URL from `SWITCHBOARD_DATABASE_URL`) and the file holding the gateway's credential for each registry server, and `[metrics] listen`, where `GET /metrics` is served (above), and `[drift] interval_seconds`, how often each entry's tool list is read and the entry probed (10 s; the drift pass, above), and `[drift.probe_credentials]`, the file holding what each entry's probe presents on its third call (kind: `registry-probe`'s token; Compose: the dummy `registry-probe-credential`). Missing, partial or unknown fields refuse to start, except `listen`, which is `127.0.0.1:8080` (loopback only) if left out, `[metrics]`, which serves nothing if left out, and `[drift] interval_seconds`, 300 s if left out. A probe credential is required for each entry the registry names, so `[drift]` itself cannot be left out while the registry names one. Compose's issuer has a keys file, which the dev issuer writes. kind's has `keys_url`, the API server's `/openid/v1/jwks` on the issuer's own origin, fetched at boot and every 60 s with no token and with `keys_ca_file` from ConfigMap `kube-root-ca.crt`; the gateway logs `fetched the issuer's keys from its keys URL` at boot, which the kind run checks. |
| Gateway logs | JSON lines. One `"event":"boot"` line per gate: `"identity":"enforce"` with `issuers` and `subjects`; `"audit":"postgres"` with `role` and `"role_check":"passed"` (the audit store's boot checks); `"metrics"`, the address `GET /metrics` is served on, or `"off"`; and the policy served: the `registry_revision`, and the `revision` and `tools` served once the first drift pass has run, with how many it `withdrawn`. One `"event":"identity_failed"` line per caller refused for identity, with its `cause`. `"event":"policy_reloaded"` or `"policy_reload_refused"` when the registry file changes. A boot line with `drift_interval_seconds`; `"event":"tool_withdrawn"` at `ERROR` for each tool the drift pass withdraws, `"event":"drift_poll_failed"` at `WARN` for each tool list it could not read, `"event":"server_open"` at `ERROR` for each probe that found an entry open, naming the calls it dispatched (its tools stay listed), `"event":"probe_not_shown"` at `WARN` for each probe that found an entry neither open nor refused, such as one that could not connect, and `"event":"policy_withdrawal_cleared"` when a reload drops a withdrawal. One `"event":"audit_row_given_up"` line at `ERROR` for each audit row whose completion the store stopped trying to write, with the `row`, the `outcome` not written and the `cause`. |
| Registry | `gateway-registry`'s TOML (`compose/config/registry/registry.toml`, `kind/base/config/registry/registry.toml`; the kind one is the registry crate's demo file). Revision `demo-7`; `compose/config/registry-withdrawn.toml` is revision `demo-8` without either team's read tool. A new version that changes a server or a tool's route is refused until a restart. |
| Migrations | `migrate.sh` creates the roles and database as the superuser (`demo/roles.sql`), then runs `switchboard migrate` as `switchboard_owner`, which applies `crates/audit-postgres`'s migrations and records them in `switchboard_audit.migrations`. |
| Dev issuer | `switchboard-dev issuer --listen=0.0.0.0:8090 --issuer=https://dev-issuer.switchboard.test --keys-out=/shared/issuer/jwks.json --subject=...`. `GET /token?subject=<s>&audience=<a>` answers with the bare token for a listed subject, 403 otherwise. Workload subjects are `workload:<team>:mock-workload`. Not published: it signs for anyone who can reach it. A restart makes a new key, so restart the gateway after it. |
| mock-docs | `mock-docs-server`, configured by environment. In Compose: `MOCK_DOCS_LISTEN` and `MOCK_DOCS_TOKEN_SHA256_FILE` (each entry's credential's hash with its team's project, never the credential). In kind, its JWT mode: `MOCK_DOCS_JWT_ISSUER` (the cluster's issuer), `MOCK_DOCS_JWT_AUDIENCE` (`mock-docs`), `MOCK_DOCS_JWT_SUBJECTS` (`docs-team-a`'s ServiceAccount for `atlas`, `docs-team-b`'s for `borealis`) and `MOCK_DOCS_JWKS_FILE` (the cluster's keys, from ConfigMap `mock-docs/cluster-issuer-keys`, which `demo.sh` copies once, for mock-docs only: the gateway fetches its own). `POST /mcp`; tools `list_documents {project}` and `read_document {project, document}`; document `plan` in projects `atlas` and `borealis`; 401 for any other bearer, from the headers alone; one JSON log line per request with `bearer_sha256` (a hex prefix) and `accepted`, and in kind `caller` (the verified subject) and `refusal` (why a token was refused). No admin endpoint, and `slow-doc`'s default delay: no step uses either. Each run checks that it accepted exactly the gateway's allowed calls (4 in Compose, 8 in kind), each team's under its own entry's credential or ServiceAccount and for its own project. The kind run checks that it refused only the two direct calls before the policy, as `wrong_audience`, the route check's open attempts before the policy, as `no_bearer`, and the three calls of each of the gateway's drift probes, as `no_bearer`, `malformed` and `wrong_subject` (`registry-probe`'s token). The Compose run leaves the probes' two bearers out of its count and still fails if mock-docs accepted either. |
| Audit schema | Table `switchboard_audit.call_rows` (`crates/audit-postgres/sql/migrations/`), with `begun_at`, `kind`, `proved_subject`, `proved_team`, `tool`, `resources`, `decision`, `reason`, `sentence`, `outcome`, `latency_ms`, `policy_revision`, `listed_tools` and `listed_omitted`, read by the driver as `switchboard_reader`. `resources` is a JSON array of the `{system, kind, identifier}` each call named (`[]` for none), or `"unknown"` when nobody could read what the call named, as for a tool the gateway does not know; the driver lists each as `docs/project/atlas`. It checks that each team's allowed read names its own project, that its denied read names the other's, that its call naming no project records `[]`, and that no allowed row names the other team's project. It matches every row of kind `call` to the demo call that made it and checks that the row records what that call named; in Compose, the call to the withdrawn tool records `"unknown"`. A row of kind `list` records one workload's `tools/list`, with no tool or resources; the listing shows the tools it listed. The driver counts these apart, 3 in Compose and 2 in kind, and checks that each names the tools its caller was shown under its policy revision, with none left out. It reads the open rows through the view `switchboard_audit.open_call_rows` (migration 0005). |
| Sentences | The core's, from `crates/gateway-core/src/sentences.rs`; `crates/demo-checks` fails if the workload's copies drift. |

## What a run shows that is not settled

- **A refused call can still leave a row open.** In the database outage
  step the gateway refuses the call after its 2 s begin budget, and nothing runs. The store
  asks Postgres to cancel the insert, but a paused server cannot act on that; once it is
  unpaused the insert commits. Decision 0009 allows this: a begin reported as failed may still
  have written its row. The store tries to complete such a row as `error` until its finish
  deadline, and one it could not complete stays open, so the listing may show an `allow` row
  with no outcome inside the outage. The gateway chooses each row's identifier, and a repeated
  begin with it writes no second row. Each `tools/list` writes a row of kind `list` before it
  answers. The open-row query is built: the view `switchboard_audit.open_call_rows` shows the
  allowed rows of kind `call` with no outcome past their deadline, by the database's clock.
  The driver waits for the deadline of the run's last allowed call row, then checks through
  the view that no row outside the outage is open, and at most that one row inside it.
- **Decisions 0009 and 0010 ask more of the slice than it has.** In kind the gateway presents
  each entry's ServiceAccount token to mock-docs, which accepts only those identities, each for
  its team's project.
  The route check runs in every kind run (above). The signals of section 11 are exported
  (above), but no sink is chosen, and receipts in `unknown` wait for #10. Compose has no cluster
  issuer, so there mock-docs still recognises each entry by a static dummy credential checked
  into this repository, compared by its SHA-256.

## Findings

[docs/first-slice-findings.md](../docs/first-slice-findings.md) holds what the runs measured
(#14k). It covers audit begin and finish latency over 200 calls, a paused or stopped
database, and how long a registry change takes to show: up to 2 s in Compose, and 33 to 88 s
in kind, where kubelet updates the mounted ConfigMap. It also says what the kind run proved,
what it did not, and the gaps.
