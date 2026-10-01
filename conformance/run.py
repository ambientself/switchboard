#!/usr/bin/env python3
"""Build the pinned, unmodified Otto gateway and test it with disposable services."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent

# Otto's schema names its owner and component roles, so the disposable database
# uses Otto's own names. Each test clones TEMPLATE_DB; nothing connects to it
# after the migration.
OWNER = "otto"
OWNER_PASSWORD = "local-conformance-only"
TEMPLATE_DB = "otto"
ROLE_PASSWORD = "local-conformance-role"
ROLE_PASSWORD_VARS = ("EGRESS_PROXY_PASSWORD", "MODEL_BROKER_PASSWORD", "GATEWAY_PASSWORD",
                      "RECEIPT_PASSWORD", "REPLIER_PASSWORD", "FEEDBACK_REPORT_PASSWORD",
                      "SESSION_PASSWORD", "EXECUTION_PASSWORD")


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    # Said plainly, because the failure otherwise is a TypeError from tarfile:
    # `python3` can resolve to an older system interpreter depending on the
    # directory the shell is in.
    if sys.version_info < (3, 12):
        raise SystemExit(f"run.py needs Python 3.12 or newer; this is {sys.version.split()[0]} "
                         f"at {sys.executable}")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--otto-source", type=Path, required=True,
                        help="local clone of the otto repository containing the pinned commit")
    parser.add_argument("--test", default=".", help="Go test name filter")
    parser.add_argument("--gateway-binary", type=Path,
                        help="test this gateway binary instead of building the pinned one; "
                             "for checking that a test fails against a deliberately broken build")
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
        # The gateway, the key custodian it asks for GitHub tokens, and the
        # session service, which is the only binary that migrates the schema.
        binaries = {}
        for name in ("otto-gateway", "otto-github-custodian", "otto-session"):
            binaries[name] = temp / name
            run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binaries[name]),
                 "./cmd/" + name], cwd=checkout, env=env)
        try:
            # No volume, no host database, and only an ephemeral loopback port.
            container = run([
                "docker", "run", "--detach", "--rm",
                "--label", "switchboard.conformance=true",
                "--publish", "127.0.0.1::5432",
                "--env", "POSTGRES_USER=" + OWNER,
                "--env", "POSTGRES_PASSWORD=" + OWNER_PASSWORD,
                "--env", "POSTGRES_DB=" + TEMPLATE_DB, pin["postgres_image"],
            ], capture_output=True, env=env).stdout.strip()
            deadline = time.monotonic() + 45
            while True:
                probe = subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1",
                                        "-U", OWNER, "-d", TEMPLATE_DB],
                                       capture_output=True, env=env)
                if probe.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("disposable Postgres did not become ready")
                time.sleep(0.2)
            port = run(["docker", "port", container, "5432/tcp"],
                       capture_output=True, env=env).stdout.strip().split(":")[-1]
            # Otto's own bootstrap creates the component roles, run inside the
            # container the way Otto's `make db-roles` runs it. The gateway
            # refuses to start as the owner, so it needs its own role.
            script = "/tmp/otto-db-bootstrap.sh"
            run(["docker", "cp", str(checkout / "deploy/eks/broker-db-bootstrap.sh"),
                 f"{container}:{script}"], capture_output=True, env=env)
            role_env = {"MASTER_DSN": f"postgres://{OWNER}@127.0.0.1:5432/{TEMPLATE_DB}?sslmode=disable",
                        "PGPASSWORD": OWNER_PASSWORD, "DB_NAME": TEMPLATE_DB, "DB_USER": OWNER}
            role_env.update({name: ROLE_PASSWORD for name in ROLE_PASSWORD_VARS})
            flags = [f for k, v in role_env.items() for f in ("--env", f"{k}={v}")]
            out = run(["docker", "exec", *flags, container, "sh", script],
                      capture_output=True, env=env).stdout
            if out.strip().splitlines()[-1] != "BOOTSTRAP_OK":
                raise RuntimeError("Otto's role bootstrap did not finish:\n" + out)
            owner = f"postgres://{OWNER}:{OWNER_PASSWORD}@127.0.0.1:{port}"
            # The schema comes from the same commit as the gateway, applied by
            # the pinned migrator rather than by loading SQL files here.
            run([str(binaries["otto-session"]), "migrate", "-database-url",
                 f"{owner}/{TEMPLATE_DB}?sslmode=disable"],
                env={"PATH": env["PATH"]}, capture_output=True)
            env.update(
                OTTO_TEST_BINARY=str(args.gateway_binary.resolve() if args.gateway_binary
                                     else binaries["otto-gateway"]),
                OTTO_TEST_CUSTODIAN_BINARY=str(binaries["otto-github-custodian"]),
                OTTO_TEST_ADMIN_URL=f"{owner}/postgres?sslmode=disable",
                OTTO_TEST_TEMPLATE_DB=TEMPLATE_DB,
                OTTO_TEST_GATEWAY_ROLE_PASSWORD=ROLE_PASSWORD,
            )
            run(["go", "test", "-mod=readonly", "-race", "-count=1", "-timeout=5m",
                 "-v", "-run", args.test, "./..."], cwd=ROOT, env=env)
        finally:
            if container:
                run(["docker", "rm", "--force", container], capture_output=True, env=env)


if __name__ == "__main__":
    main()
