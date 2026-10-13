# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
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
#
# Every image is pinned by the digest of its tag's multi-arch index: the frontend in the syntax
# line above and both base images below. The rust tag is rust-toolchain.toml's channel, and
# crates/demo-checks/tests/driver.rs holds it there. Dependabot proposes new digests for the base
# images and never a new rust version (.github/dependabot.yml); it does not read the syntax line.
# To bump a pin by hand, keep the tag and take the new digest from
#
#     docker buildx imagetools inspect <image>:<tag>
#
# Postgres is not in this image, but the demo pins it the same way, and its pins are bumped
# together, by hand: deploy/demo/demo.sh (POSTGRES_IMAGE), deploy/compose/compose.yaml, the
# commands in CONTRIBUTING.md and in crates/audit-postgres/src/lib.rs's documentation, the tag in
# deploy/kind/base/postgres.yaml, and CI's service container in .github/workflows/ci.yml, which
# is the Debian variant of the same release and has a digest of its own.
# crates/demo-checks/tests/pins.rs fails until they agree.
#
# The apt packages below are not pinned.

FROM rust:1.99.0-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS build
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

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# curl and jq for the workload, the kind demo's token writer and health checks, psql for the
# migration runner and the audit query, ca-certificates for any TLS upstream.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl jq postgresql-client; \
    rm -rf /var/lib/apt/lists/*; \
    useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin switchboard; \
    # The Compose dev issuer writes its key set here, and the reach-token service the registry's
    # token; a new named volume takes this ownership.
    install -d -o 10001 -g 10001 /shared/issuer /shared/reach
COPY --from=build /out/bin/ /usr/local/bin/
COPY deploy/demo/workload.sh deploy/demo/migrate.sh deploy/demo/token-writer.sh /usr/local/bin/
COPY deploy/demo/roles.sql /usr/share/switchboard/roles.sql
# The route check's probe (decision 0010), which route-check.sh starts in a workload's pod as an
# ephemeral container from this image, and the routes it tries.
COPY --chmod=0755 deploy/route-check/probe.sh /usr/local/bin/route-probe.sh
COPY deploy/route-check/routes/ /usr/share/switchboard/routes/
USER 10001:10001
WORKDIR /tmp
CMD ["workload.sh"]
