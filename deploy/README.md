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

Every password and credential under `deploy/` is a dummy value for the demo.

## What is here

| Path | What it is |
| --- | --- |
| `Dockerfile` | One image for every role: the workspace's binaries, `workload.sh`, `migrate.sh` and `roles.sql`. The audit migrations are inside `switchboard`. `BINS` lists the binaries; `REQUIRE_ALL_BINS=true` refuses to build without all of them. |
| `compose/compose.yaml` | `postgres` (not published), `migrate`, `dev-issuer`, `mock-docs`, `gateway` on `127.0.0.1:18080`, and `workload` under `profiles: [demo]`. |
| `compose/config/` | The gateway's deployment file, the team manifest, the registry directory it polls, and the registry with `docs__read_document` withdrawn. |
| `kind/cluster.yaml` | One node, kindnet, the node image kind v0.32.0 uses. |
| `kind/base/` | Namespaces `switchboard`, `mock-docs`, `team-a`, `team-b`; ServiceAccounts; Postgres; the migration Job; mock-docs; the gateway; suspended CronJobs holding each workload's Job template. No network policy. |
| `kind/policy/` | The network policies: mock-docs admits only the gateway, Postgres only the gateway and the migration, the gateway only the two teams. |
| `demo/workload.sh` | The scripted workload (decision 0008). Modes `full`, `before-policy`, `refused`, `audit-down`, `withdrawn`. |
| `demo/migrate.sh`, `demo/roles.sql` | Creates the roles and database as the superuser, runs `switchboard migrate` as `switchboard_owner`, and lets `switchboard_reader` read the audit schema. |
| `demo/demo.sh` | The driver. |

`crates/demo-checks` tests the scripts and manifests: the workload against a fake gateway that
misbehaves one way at a time, the driver with fake docker, kind and kubectl, and the manifests'
claims (only the gateway is published, the policy admits only the gateway, each dummy
credential's hash matches).

## Network policy in kind

kindnet in kind v0.32.0 (node image v1.36.1) enforces NetworkPolicy. This was checked on
2026-10-06 with a throwaway test: before a policy, two new pods reached an nginx pod; after an
ingress policy admitting one label, a new pod without it timed out (by Service IP and by pod IP)
and a new pod with it still connected. Kubelet's readiness probes still pass under a deny-all
ingress policy. No Calico was needed.

The demo still checks this every run: before the policy, the direct call must connect and get
401 from the server; after it, a new pod's direct call must time out (curl exit 28), and the
same pod must still reach the gateway and get an allowed read through it.

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
| Binaries | `switchboard` (crates/gateway), `switchboard-dev` (crates/gateway-dev) and `mock-docs-server` (crates/mock-docs-server), built by `cargo build --release --workspace --bins`. `switchboard` links nothing from the testkit. |
| Gateway | `switchboard --config=<file>`. The deployment file (`compose/config/gateway.toml`, `kind/base/config/gateway.toml`; format in `crates/gateway/src/deployment.rs`) gives the listen address, the allowed hosts, the registry file and how often it is read again (2 s), each trusted issuer with its keys file and team manifest (`teams.toml`), the audit store (`mode = "postgres"`, URL from `SWITCHBOARD_DATABASE_URL`) and the file holding the gateway's credential for each registry server. Missing, partial or unknown fields refuse to start. |
| Gateway logs | JSON lines. One `"event":"boot"` line per gate: `"identity":"enforce"` with `issuers` and `subjects`; `"audit":"postgres"` with `role` and `"role_check":"passed"` (the audit store's boot checks); and the registry's `revision`. One `"event":"identity_failed"` line per caller refused for identity, with its `cause`. `"event":"policy_reloaded"` or `"policy_reload_refused"` when the registry file changes. |
| Registry | `gateway-registry`'s TOML (`compose/config/registry/registry.toml`, `kind/base/config/registry/registry.toml`; the kind one is the registry crate's demo file). Revision `demo-1`; `compose/config/registry-withdrawn.toml` is revision `demo-2` without `docs__read_document`. A new version that changes a server or a tool's route is refused until a restart. |
| Migrations | `migrate.sh` creates the roles and database as the superuser (`demo/roles.sql`), then runs `switchboard migrate` as `switchboard_owner`, which applies `crates/audit-postgres`'s migrations and records them in `switchboard_audit.migrations`. |
| Dev issuer | `switchboard-dev issuer --listen=0.0.0.0:8090 --issuer=https://dev-issuer.switchboard.test --keys-out=/shared/issuer/jwks.json --subject=...`. `GET /token?subject=<s>&audience=<a>` answers with the bare token for a listed subject, 403 otherwise. Workload subjects are `workload:<team>:mock-workload`. Not published: it signs for anyone who can reach it. A restart makes a new key, so restart the gateway after it. |
| mock-docs | `mock-docs-server`, configured by environment: `MOCK_DOCS_LISTEN` and `MOCK_DOCS_TOKEN_SHA256_FILE` (the gateway credential's hash, never the credential). `POST /mcp`; tools `list_documents {project}` and `read_document {project, document}`; document `plan` in projects `atlas` and `borealis`; 401 for any other bearer; one JSON log line per request with `bearer_sha256` (a hex prefix) and `accepted`. |
| Audit schema | Table `switchboard_audit.call_rows` (`crates/audit-postgres/sql/migrations/`), with `begun_at`, `proved_subject`, `proved_team`, `tool`, `resources`, `decision`, `reason`, `sentence`, `outcome`, `latency_ms` and `policy_revision`, read by the driver as `switchboard_reader`. `resources` is a JSON array of the `{system, kind, identifier}` each call named (`[]` for none), or `"unknown"`; the driver lists each as `docs/project/atlas`. It checks that each team's allowed read names its own project, that its denied read names the other's, and that no allowed row names the other team's project. |
| Sentences | The core's, from `crates/gateway-core/src/sentences.rs`; `crates/demo-checks` fails if the workload's copies drift. |

## What a run shows that is not settled

- **A refused call can still leave a row, completed as `error`.** In the database outage
  step the gateway refuses the call after its 2 s begin budget, and nothing runs. The store
  asks Postgres to cancel the insert, but a paused server cannot act on that; once it is
  unpaused the insert commits. The store is still waiting for the insert's answer, so it
  completes that row as `error` with latency 0, as decision 0009 says: a row may overstate
  what ran, never understate it. The listing shows it as an `allow` row with outcome `error`
  inside the outage, and the driver checks that no allowed row is left without an outcome.
  The rest of decision 0009's row work (gateway-assigned identifiers, a deadline column, the
  open-row query, `tools/list` rows) is not built.
- **It runs from an unmerged branch.** `agent/first-slice` stacks #25 (the harness's latest
  head, PR #35), #26, #10, #14 and #9 work that has not been merged, on top of main with #29
  and #30.

## Not done here

- Measuring how long a ConfigMap edit takes to reach the gateway in kind (planDemo.md, Tier C).
  Compose shows the withdrawal live.
- The latency findings over 200 calls (#14k).
