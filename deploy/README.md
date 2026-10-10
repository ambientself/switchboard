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
| `demo/workload.sh` | The scripted workload (decision 0008). Modes `full`, `before-policy`, `refused`, `audit-down`, `withdrawn`. |
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
(curl exit 28), and the same pod must still reach the gateway and get an allowed read through
it.

Network policy does not see what reaches a pod through the API server: exec, attach,
port-forward, ephemeral containers, and the pod, Service and node proxy routes. The operator
checks ask `kubectl auth can-i` about each team's workload and require `no` (decision 0010,
control 1). In `mock-docs`, `switchboard` and the team's own namespace, they ask about each
route (`create` and `get` on exec, attach, port-forward and the pod and Service proxies;
`patch` and `update` on ephemeral containers), creating pods, minting a ServiceAccount's token,
impersonating a ServiceAccount, `bind` and `escalate` on roles, creating role bindings, and
`create`, `update` and `patch` on Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs and
CronJobs: 36 checks each. Across the cluster they ask about the node proxy (`create` and
`get`), impersonating users, groups, UIDs and extras (`userextras/scopes`), `bind` and
`escalate` on cluster roles, and creating cluster role bindings: 9 checks. can-i cannot name
UIDs and extras, which the API server checks in `authentication.k8s.io` though it serves no
such resource, so those two are asked as SubjectAccessReviews. Last, neither workload may get,
list or watch the two namespaces' secrets or the gateway's configuration (list and watch return a
Secret's data too): 9 checks. That is 126 checks per team.

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
| mock-docs | `mock-docs-server`, configured by environment. In Compose: `MOCK_DOCS_LISTEN` and `MOCK_DOCS_TOKEN_SHA256_FILE` (the gateway credential's hash, never the credential). In kind, its JWT mode: `MOCK_DOCS_JWT_ISSUER` (the cluster's issuer), `MOCK_DOCS_JWT_AUDIENCE` (`mock-docs`), `MOCK_DOCS_JWT_SUBJECT` (`system:serviceaccount:switchboard:gateway`) and `MOCK_DOCS_JWKS_FILE` (the cluster's keys, from ConfigMap `mock-docs/cluster-issuer-keys`, which `demo.sh` copies once). `POST /mcp`; tools `list_documents {project}` and `read_document {project, document}`; document `plan` in projects `atlas` and `borealis`; 401 for any other bearer, from the headers alone; one JSON log line per request with `bearer_sha256` (a hex prefix) and `accepted`, and in kind `caller` (the verified subject) and `refusal` (why a token was refused). The kind run checks that it accepted exactly the gateway's 8 allowed calls, all from the gateway's ServiceAccount, and refused only the two direct calls before the policy, as `wrong_audience`. |
| Audit schema | Table `switchboard_audit.call_rows` (`crates/audit-postgres/sql/migrations/`), with `begun_at`, `kind`, `proved_subject`, `proved_team`, `tool`, `resources`, `decision`, `reason`, `sentence`, `outcome`, `latency_ms`, `policy_revision`, `listed_tools` and `listed_omitted`, read by the driver as `switchboard_reader`. `resources` is a JSON array of the `{system, kind, identifier}` each call named (`[]` for none), or `"unknown"` when nobody could read what the call named, as for a tool the gateway does not know; the driver lists each as `docs/project/atlas`. It checks that each team's allowed read names its own project, that its denied read names the other's, that its call naming no project records `[]`, and that no allowed row names the other team's project. It matches every row of kind `call` to the demo call that made it and checks that the row records what that call named; in Compose, the call to the withdrawn tool records `"unknown"`. A row of kind `list` records one workload's `tools/list`, with no tool or resources; the listing shows the tools it listed. The driver counts these apart, 3 in Compose and 2 in kind, and checks that each names the tools its caller was shown under its policy revision, with none left out. |
| Sentences | The core's, from `crates/gateway-core/src/sentences.rs`; `crates/demo-checks` fails if the workload's copies drift. |

## What a run shows that is not settled

- **A refused call can still leave a row, and nothing completes it.** In the database outage
  step the gateway refuses the call after its 2 s begin budget, and nothing runs. The store
  asks Postgres to cancel the insert, but a paused server cannot act on that; once it is
  unpaused the insert commits. Decision 0009 allows this: a begin reported as failed may still
  have written its row. Completing such a row as `error` is not built (design section 17), so
  the listing may show an `allow` row with no outcome inside the outage. The driver checks that
  the outage left at most that one row open, and that every other allowed row has an outcome.
  The gateway now chooses each row's identifier, and a repeated begin with it writes no second
  row. Each `tools/list` writes a row of kind `list` before it answers. The rest of decision
  0009's row work (retrying begin by identifier, a deadline column, the open-row query) is
  not built.
- **Decisions 0009 and 0010 ask more of the slice than it has.** In kind the gateway presents
  a projected token of its own ServiceAccount to mock-docs, which accepts only that identity.
  There is no route-check program and no section 11 signals yet (#47). Compose has no cluster
  issuer, so there mock-docs still recognises the gateway by a static dummy credential checked
  into this repository, compared by its SHA-256.

## Findings

[docs/first-slice-findings.md](../docs/first-slice-findings.md) holds what the runs measured
(#14k). It covers audit begin and finish latency over 200 calls, a paused or stopped
database, and how long a registry change takes to show: up to 2 s in Compose, and 33 to 88 s
in kind, where kubelet updates the mounted ConfigMap. It also says what the kind run proved,
what it did not, and the gaps.
