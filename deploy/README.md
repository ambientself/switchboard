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
kind, kubectl, jq and awk.

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
gateway holds no static credential for mock-docs: it presents a projected token of its own
ServiceAccount.

## What is here

| Path | What it is |
| --- | --- |
| `Dockerfile` | One image for every role: the workspace's binaries, `workload.sh`, `migrate.sh` and `roles.sql`. The audit migrations are inside `switchboard`. `BINS` lists the binaries; `REQUIRE_ALL_BINS=true` refuses to build without all of them. |
| `compose/compose.yaml` | `postgres` (not published), `migrate`, `dev-issuer`, `mock-docs`, `gateway` on `127.0.0.1:18080`, and `workload` under `profiles: [demo]`. |
| `compose/config/` | The gateway's deployment file, the team manifest, the registry directory it polls, and the registry with `docs__read_document` withdrawn. |
| `kind/cluster.yaml` | One node, kindnet, the node image kind v0.32.0 uses. |
| `kind/base/` | Namespaces `switchboard`, `mock-docs`, `team-a`, `team-b`; ServiceAccounts; Postgres; the migration Job; mock-docs, which accepts only the gateway's ServiceAccount; the gateway, with a projected token for audience `mock-docs`; suspended CronJobs holding each workload's Job template. No network policy. |
| `kind/policy/` | The network policies: mock-docs admits only the gateway, Postgres only the gateway and the migration, the gateway only the two teams. |
| `kind/route-check/rbac.yaml` | The route check's operator: ServiceAccount `route-check/operator`, `get` and `list` on what it reads, `create` on SubjectAccessReviews, and `patch` on `pods/ephemeralcontainers` in `team-a` and `team-b` only. Not part of the base; the kind run applies it. |
| `route-check/` | The route check (decision 0010): `route-check.sh`, its operator step; `probe.sh`, its probe, which the image installs as `route-probe.sh`; `permissions.tsv`, the one list of control 1's permissions; `token-patterns.txt`; and `routes/kind.tsv`, the routes the probe tries in kind. |
| `demo/workload.sh` | The scripted workload (decision 0008). Modes `full`, `before-policy`, `refused`, `audit-down`, `withdrawn`, and `idle`, which makes no call and holds a running pod for the route check until SIGTERM, at most 600 s. |
| `demo/migrate.sh`, `demo/roles.sql` | Creates the roles and database as the superuser, runs `switchboard migrate` as `switchboard_owner`, and lets `switchboard_reader` read the audit schema. |
| `demo/demo.sh` | The driver. |

`crates/demo-checks` tests the scripts and manifests: the workload against a fake gateway that
misbehaves one way at a time, the driver with fake docker, kind and kubectl, and the manifests'
claims (only the gateway is published, the policy admits only the gateway, Compose's dummy
credential's hash matches, and in kind the gateway mounts only a projected token for
`mock-docs`, whose settings name only the gateway's ServiceAccount).

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
namespace and across the cluster; a `cluster` row across the cluster only. Across the cluster
is a can-i with no namespace: it asks in the kubeconfig's namespace, `default`, so RBAC counts
that namespace's RoleBindings as well as ClusterRoleBindings. The list covers reading Secrets
and ConfigMaps (`get`, `list` and `watch`, since list and watch return the data too); creating
pods and `create`, `update` and `patch` on Deployments, ReplicaSets, StatefulSets, DaemonSets,
Jobs and CronJobs; `create` and `get` on exec, attach, port-forward and the pod, Service and
node proxies; `patch` and `update` on ephemeral containers; minting a ServiceAccount's token;
impersonating users, groups, ServiceAccounts, UIDs and extras (`userextras/scopes`); `bind` and
`escalate` on roles and cluster roles; and creating role and cluster role bindings. That is 43
namespaced rows and 8 cluster rows, 180 checks per team. They are asked with `kubectl auth
can-i --as`, except UIDs and extras, which the API server checks in `authentication.k8s.io`
though it serves no such resource: can-i cannot name them, so those are asked as
SubjectAccessReviews. A query kubectl cannot answer is a FAIL with kubectl's message, and the
run goes on.

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

## What runs

Every command and file below is the real one; `crates/demo-checks` and the gateway's own tests
check that the deployment files load.

| Piece | How it runs |
| --- | --- |
| Binaries | `switchboard` (crates/gateway), `switchboard-dev` (crates/gateway-dev) and `mock-docs-server` (crates/mock-docs-server). `Dockerfile` builds `switchboard` on its own with `cargo build --release --locked -p gateway --bin switchboard`, then the other two with `cargo build --release --locked -p gateway-dev -p mock-docs-server --bins`. Build `switchboard` for deployment the same way: a workspace build turns on gateway-dev's `test-support` feature, which exempts the gateway from the receipt-store gate (decision 0009). `switchboard` links nothing from the testkit. |
| Gateway | `switchboard --config=<file>`. The deployment file (`compose/config/gateway.toml`, `kind/base/config/gateway.toml`; format in `crates/gateway/src/deployment.rs`) gives the listen address, the allowed hosts, the registry file and how often it is read again (2 s), each trusted issuer with its keys file and team manifest (`teams.toml`), the audit store (`mode = "postgres"`, URL from `SWITCHBOARD_DATABASE_URL`) and the file holding the gateway's credential for each registry server. Missing, partial or unknown fields refuse to start, except `listen`, which is `127.0.0.1:8080` (loopback only) if left out. |
| Gateway logs | JSON lines. One `"event":"boot"` line per gate: `"identity":"enforce"` with `issuers` and `subjects`; `"audit":"postgres"` with `role` and `"role_check":"passed"` (the audit store's boot checks); and the registry's `revision`. One `"event":"identity_failed"` line per caller refused for identity, with its `cause`. `"event":"policy_reloaded"` or `"policy_reload_refused"` when the registry file changes. One `"event":"audit_row_given_up"` line at `ERROR` for each audit row whose completion the store stopped trying to write, with the `row`, the `outcome` not written and the `cause`. |
| Registry | `gateway-registry`'s TOML (`compose/config/registry/registry.toml`, `kind/base/config/registry/registry.toml`; the kind one is the registry crate's demo file). Revision `demo-1`; `compose/config/registry-withdrawn.toml` is revision `demo-2` without `docs__read_document`. A new version that changes a server or a tool's route is refused until a restart. |
| Migrations | `migrate.sh` creates the roles and database as the superuser (`demo/roles.sql`), then runs `switchboard migrate` as `switchboard_owner`, which applies `crates/audit-postgres`'s migrations and records them in `switchboard_audit.migrations`. |
| Dev issuer | `switchboard-dev issuer --listen=0.0.0.0:8090 --issuer=https://dev-issuer.switchboard.test --keys-out=/shared/issuer/jwks.json --subject=...`. `GET /token?subject=<s>&audience=<a>` answers with the bare token for a listed subject, 403 otherwise. Workload subjects are `workload:<team>:mock-workload`. Not published: it signs for anyone who can reach it. A restart makes a new key, so restart the gateway after it. |
| mock-docs | `mock-docs-server`, configured by environment. In Compose: `MOCK_DOCS_LISTEN` and `MOCK_DOCS_TOKEN_SHA256_FILE` (the gateway credential's hash, never the credential). In kind, its JWT mode: `MOCK_DOCS_JWT_ISSUER` (the cluster's issuer), `MOCK_DOCS_JWT_AUDIENCE` (`mock-docs`), `MOCK_DOCS_JWT_SUBJECT` (`system:serviceaccount:switchboard:gateway`) and `MOCK_DOCS_JWKS_FILE` (the cluster's keys, from ConfigMap `mock-docs/cluster-issuer-keys`, which `demo.sh` copies once). `POST /mcp`; tools `list_documents {project}` and `read_document {project, document}`; document `plan` in projects `atlas` and `borealis`; 401 for any other bearer, from the headers alone; one JSON log line per request with `bearer_sha256` (a hex prefix) and `accepted`, and in kind `caller` (the verified subject) and `refusal` (why a token was refused). The kind run checks that it accepted exactly the gateway's 8 allowed calls, all from the gateway's ServiceAccount, and refused only the two direct calls before the policy, as `wrong_audience`, and the route check's open attempts before the policy, as `no_bearer`. |
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
  a projected token of its own ServiceAccount to mock-docs, which accepts only that identity.
  The route check runs in every kind run (above). The signals of section 11 are not exported
  yet (#47). Compose has no cluster
  issuer, so there mock-docs still recognises the gateway by a static dummy credential checked
  into this repository, compared by its SHA-256.

## Findings

[docs/first-slice-findings.md](../docs/first-slice-findings.md) holds what the runs measured
(#14k). It covers audit begin and finish latency over 200 calls, a paused or stopped
database, and how long a registry change takes to show: up to 2 s in Compose, and 33 to 88 s
in kind, where kubelet updates the mounted ConfigMap. It also says what the kind run proved,
what it did not, and the gaps.
