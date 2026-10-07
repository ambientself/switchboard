# Deploying the demo

The first-slice demo (#14) runs in two places, each with one command from the repository root:

```sh
deploy/demo/demo.sh compose   # Tier A: Postgres, the gateway, mock-docs and the dev issuer
deploy/demo/demo.sh kind      # Tier B: the cluster switchboard-demo, with network policy
deploy/demo/demo.sh down      # stop Compose and delete the cluster
```

Every check prints PASS or FAIL. The last line counts them, and the script exits non-zero if
any check failed or any step could not run. Nothing is retried. It needs docker with compose,
kind, kubectl, jq and awk.

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
| Audit schema | Table `switchboard_audit.call_rows` (`crates/audit-postgres/sql/migrations/`), with `begun_at`, `proved_subject`, `proved_team`, `tool`, `decision`, `reason`, `sentence`, `outcome`, `latency_ms` and `policy_revision`, read by the driver as `switchboard_reader`. Its `resources` column stays empty until the core's audit record carries resources (PR #30), so the driver checks a denial by its sentence, which names the project. |
| Sentences | The core's, from `crates/gateway-core/src/sentences.rs`; `crates/demo-checks` fails if the workload's copies drift. |

## What a run shows that is not settled

- **A row can outlive a refused call.** In the database outage step the gateway refuses the
  call after its 2 s begin budget, and nothing runs. The store cancels its insert, but the
  cancel cannot reach a paused server either; once Postgres is unpaused the insert commits.
  The table then holds an `allow` row with no outcome for a call that was refused and never
  ran (`at` within the outage, `outcome` empty). Decision 0009's open-row work (a deadline
  column, gateway-assigned identifiers) is what tells such a row apart; it is deferred until
  #29 and #30 merge.
- **It runs from an unmerged branch.** `agent/first-slice` stacks #25, #26, #10, #14 and #9
  work that has not been merged. It does not contain the #25 harness's latest head or #29.

## Not done here

- Measuring how long a ConfigMap edit takes to reach the gateway in kind (planDemo.md, Tier C).
  Compose shows the withdrawal live.
- The latency findings over 200 calls (#14k).
