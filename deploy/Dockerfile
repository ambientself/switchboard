# syntax=docker/dockerfile:1
#
# The demo image: the Switchboard binaries, the scripted workload, and the migration runner. One
# image serves every role in Compose and kind; each service picks its command. Built from the
# repository root:
#
#     docker build -f deploy/Dockerfile -t switchboard-demo:dev .
#
# BINS lists the binaries to copy into the image: `switchboard` (crates/gateway: the gateway, and
# `switchboard migrate`, which carries the audit migrations), `switchboard-dev`
# (crates/gateway-dev: `switchboard-dev issuer` is the Compose development issuer) and
# `mock-docs-server` (crates/mock-docs-server). A listed binary the workspace does not build is
# left out with a warning, unless REQUIRE_ALL_BINS=true, which demo.sh and Compose set: the demo
# must not start with a binary missing. `switchboard` itself links nothing from the testkit;
# crates/gateway/tests/dependencies.rs holds it to that.
#
# `switchboard` is the release build, built on its own with `-p gateway` and no features, and
# copied out before anything else is built. Built with the workspace, it would take the
# `test-support` feature that crates/gateway-dev turns on (Cargo unifies features across the
# packages of one build), and a `test-support` build serves tools not classified `read` with no
# receipt store (decision 0009). crates/demo-checks/tests/release.rs pins the line, and CI runs
# the same command and checks the binary refuses such a tool.

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
    mkdir -p /out/bin /out/release; \
    cargo build --release --locked -p gateway --bin switchboard; \
    cp target/release/switchboard /out/release/switchboard; \
    cargo build --release --locked -p gateway-dev -p mock-docs-server --bins; \
    for bin in ${BINS}; do \
      if [ "${bin}" = switchboard ]; then \
        cp /out/release/switchboard /out/bin/; \
      elif [ -x "target/release/${bin}" ]; then \
        cp "target/release/${bin}" /out/bin/; \
      elif [ "${REQUIRE_ALL_BINS}" = "true" ]; then \
        echo "binary ${bin} is not built by this workspace" >&2; exit 1; \
      else \
        echo "warning: binary ${bin} is not built by this workspace; left out" >&2; \
      fi; \
    done; \
    ls -l /out/bin

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
COPY deploy/demo/workload.sh deploy/demo/migrate.sh /usr/local/bin/
COPY deploy/demo/roles.sql /usr/share/switchboard/roles.sql
USER 10001:10001
WORKDIR /tmp
CMD ["workload.sh"]
