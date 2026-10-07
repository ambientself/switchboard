# syntax=docker/dockerfile:1
#
# The demo image: every Switchboard binary the workspace builds, the scripted workload, and the
# migration runner. One image serves every role in Compose and kind; each service picks its
# command. Built from the repository root:
#
#     docker build -f deploy/Dockerfile -t switchboard-demo:dev .
#
# BINS lists the binaries to copy into the image. A listed binary the workspace does not build
# yet is left out with a warning, unless REQUIRE_ALL_BINS=true, which demo.sh and Compose set:
# the demo must not start with a binary missing.
# TODO(integration): the binary names follow the plans: `switchboard` (crates/gateway, #26),
# `switchboard-dev` (crates/gateway-dev, #26, which also runs the Compose dev issuer) and
# `mock-docs-server` (crates/mock-docs-server, #14a).

ARG RUST_IMAGE=rust:1.99.0-slim-trixie
ARG RUNTIME_IMAGE=debian:trixie-slim

FROM ${RUST_IMAGE} AS build
ARG BINS="switchboard switchboard-dev mock-docs-server"
ARG REQUIRE_ALL_BINS=false
WORKDIR /src
COPY . .
# The registry and target caches persist between builds on this machine only.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eu; \
    cargo build --release --locked --workspace --bins; \
    mkdir -p /out/bin /out/migrations; \
    for bin in ${BINS}; do \
      if [ -x "target/release/${bin}" ]; then \
        cp "target/release/${bin}" /out/bin/; \
      elif [ "${REQUIRE_ALL_BINS}" = "true" ]; then \
        echo "binary ${bin} is not built by this workspace" >&2; exit 1; \
      else \
        echo "warning: binary ${bin} is not built by this workspace; left out" >&2; \
      fi; \
    done; \
    # TODO(integration): the audit schema migrations (#10a) are assumed to be plain SQL files
    # under crates/*/migrations/, applied in file-name order.
    find crates -path '*/migrations/*.sql' -type f -exec cp {} /out/migrations/ \; ; \
    ls -l /out/bin /out/migrations

FROM ${RUNTIME_IMAGE}
# curl and jq for the workload and health checks, psql for the migration runner and the audit
# query, ca-certificates for any TLS upstream.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl jq postgresql-client; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin switchboard; \
    # The Compose dev issuer writes its key set here; a new named volume takes this ownership.
    install -d -o 10001 -g 10001 /shared/issuer
COPY --from=build /out/bin/ /usr/local/bin/
COPY --from=build /out/migrations/ /usr/share/switchboard/migrations/
COPY deploy/demo/workload.sh deploy/demo/migrate.sh /usr/local/bin/
COPY deploy/demo/roles.sql /usr/share/switchboard/roles.sql
USER 10001:10001
WORKDIR /tmp
CMD ["workload.sh"]
