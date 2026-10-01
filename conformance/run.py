#!/usr/bin/env python3
"""Build the pinned, unmodified Otto gateway and test it with disposable services."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--otto-source", type=Path, required=True,
                        help="local agentrunner clone containing the pinned commit")
    parser.add_argument("--test", default=".", help="Go test name filter")
    args = parser.parse_args()
    pin = json.loads((ROOT / "baseline.json").read_text())
    source = args.otto_source.resolve()
    commit = run(["git", "-C", str(source), "rev-parse", pin["commit"] + "^{commit}"],
                 capture_output=True).stdout.strip()
    if commit != pin["commit"]:
        raise RuntimeError("source did not resolve to the pinned commit")

    # Do not pass gateway flags, vendor credentials or proxy settings from the shell.
    env = {k: v for k, v in os.environ.items()
           if k in {"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "DOCKER_HOST", "DOCKER_CONTEXT"}}
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    env.update(GOTOOLCHAIN=pin["go_toolchain"], GOCACHE=str(cache / "go-build"),
               GOWORK="off")
    print(f"Otto baseline: {commit}", flush=True)
    container = None
    with tempfile.TemporaryDirectory(prefix="switchboard-conformance-") as temp:
        temp = Path(temp)
        archive = temp / "otto.tar"
        with archive.open("wb") as out:
            subprocess.run(["git", "-C", str(source), "archive", commit],
                           check=True, stdout=out)
        checkout = temp / "otto"
        checkout.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(checkout, filter="data")
        binary = temp / "otto-gateway"
        run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary),
             "./cmd/otto-gateway"], cwd=checkout, env=env)
        try:
            # No volume, no host database, and only an ephemeral loopback port.
            container = run([
                "docker", "run", "--detach", "--rm",
                "--label", "switchboard.conformance=true",
                "--publish", "127.0.0.1::5432",
                "--env", "POSTGRES_USER=conformance",
                "--env", "POSTGRES_PASSWORD=local-conformance-only",
                "--env", "POSTGRES_DB=conformance", pin["postgres_image"],
            ], capture_output=True, env=env).stdout.strip()
            deadline = time.monotonic() + 45
            while True:
                probe = subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1",
                                        "-U", "conformance", "-d", "conformance"],
                                       capture_output=True, env=env)
                if probe.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("disposable Postgres did not become ready")
                time.sleep(0.2)
            port = run(["docker", "port", container, "5432/tcp"],
                       capture_output=True, env=env).stdout.strip().split(":")[-1]
            env.update(
                OTTO_TEST_BINARY=str(binary),
                OTTO_TEST_AUDIT_SQL=str(checkout / "internal/schema/sql/0013_gateway_audit.sql"),
                OTTO_TEST_DATABASE_URL=(f"postgres://conformance:local-conformance-only@"
                                        f"127.0.0.1:{port}/conformance?sslmode=disable"),
            )
            run(["go", "test", "-mod=readonly", "-race", "-count=1", "-timeout=3m",
                 "-v", "-run", args.test, "./..."], cwd=ROOT, env=env)
        finally:
            if container:
                run(["docker", "rm", "--force", container], capture_output=True, env=env)


if __name__ == "__main__":
    main()
