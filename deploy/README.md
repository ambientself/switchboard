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
| `Dockerfile` | One image for every role: the workspace's binaries, `workload.sh`, `migrate.sh`, `roles.sql` and the audit migrations. `BINS` lists the binaries; `REQUIRE_ALL_BINS=true` refuses to build without all of them. |
| `compose/compose.yaml` | `postgres` (not published), `migrate`, `dev-issuer`, `mock-docs`, `gateway` on `127.0.0.1:18080`, and `workload` under `profiles: [demo]`. |
| `compose/config/` | The gateway's config, the registry directory it polls, and the registry with `docs__read_document` withdrawn. |
| `kind/cluster.yaml` | One node, kindnet, the node image kind v0.32.0 uses. |
| `kind/base/` | Namespaces `switchboard`, `mock-docs`, `team-a`, `team-b`; ServiceAccounts; Postgres; the migration Job; mock-docs; the gateway; suspended CronJobs holding each workload's Job template. No network policy. |
| `kind/policy/` | The network policies: mock-docs admits only the gateway, Postgres only the gateway and the migration, the gateway only the two teams. |
| `demo/workload.sh` | The scripted workload (decision 0008). Modes `full`, `before-policy`, `refused`, `audit-down`, `withdrawn`. |
| `demo/migrate.sh`, `demo/roles.sql` | Creates the roles and database as the superuser, applies each migration once as `switchboard_owner`, and lets `switchboard_reader` read the audit schema. |
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

## Interfaces the demo assumes

The binaries are being written alongside this. Each assumption below is marked
`TODO(integration)` where it is used; `grep -rn 'TODO(integration)' deploy` lists them.

| Piece | Assumed |
| --- | --- |
| Binaries | `switchboard` (#26), `switchboard-dev` (#26), `mock-docs-server` (#14a), built by `cargo build --release --workspace --bins`. |
| Gateway | `switchboard --config=<file>`; listens on `0.0.0.0:8080`; serves `POST /mcp/docs`; config fields as in `compose/config/gateway.toml`; database URL from `SWITCHBOARD_DATABASE_URL`; registry directory polled every 2 s. |
| Gateway logs | JSON lines. A boot line with `"identity":"enforce"` and one with `"audit":"postgres"`; one line containing `identity_failed` per identity failure. |
| Registry | TOML as in `compose/config/registry/registry.toml`: servers, tools with definitions and a resource adapter, surfaces, profiles, limits, profile-selection rules, revision `demo-1` (`demo-2` once withdrawn). |
| Dev issuer | `switchboard-dev issuer --listen=0.0.0.0:8090 --issuer=https://dev-issuer.switchboard.test --keys-out=/shared/issuer/jwks.json`; `GET /token?subject=<s>&audience=<a>` answers with the bare token. Workload subjects are `workload:<team>:mock-workload`. |
| mock-docs | `mock-docs-server --listen=0.0.0.0:8080 --accept-token-sha256-file=<file>`; `POST /mcp`; tools `list_documents {project}` and `read_document {project, document}`; document `plan` in projects `atlas` and `borealis`; 401 for any other bearer; one JSON log line per request with `bearer_sha256` (a hex prefix) and `status`. |
| Audit schema | SQL files under `crates/*/migrations/`, applied in name order as `switchboard_owner`; table `switchboard_audit.call_rows` with `begun_at`, `proved_subject`, `proved_team`, `tool`, `resources` (jsonb), `decision`, `reason`, `outcome`, `latency_ms`, `policy_revision`. |
| Sentences | The core's, from `crates/gateway-core/src/sentences.rs`; `crates/demo-checks` fails if the workload's copies drift. |

## Not done here

- Measuring how long a ConfigMap edit takes to reach the gateway in kind (planDemo.md, Tier C).
  Compose shows the withdrawal live.
- The latency findings over 200 calls (#14k).
