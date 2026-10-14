#!/usr/bin/env python3
"""Check that conformance tests can fail: break one guard in the pinned Otto gateway at a
time, and require the test named for that guard to fail against the broken build."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent

# (name, file, text to find exactly once, replacement, test that must fail)
MUTATIONS = [
    ("grant_tool_check", "cmd/otto-gateway/main.go",
     "if len(c.Tools) > 0 && !slices.Contains(c.Tools, tool.Name) {",
     "if false && len(c.Tools) > 0 && !slices.Contains(c.Tools, tool.Name) {",
     "TestToolOutsideTheGrantIsRefused"),
    ("team_mismatch", "cmd/otto-gateway/main.go",
     "if authed != nil && authed.Team.ID != c.Team {",
     "if false && authed != nil && authed.Team.ID != c.Team {",
     "TestGrantTeamMustMatchProvedTeam"),
    ("finish_budget", "cmd/otto-gateway/main.go",
     "budget := time.NewTimer(finishResponseBudget)",
     "budget := time.NewTimer(0)",
     "TestAnswerFollowsAuditFinish"),
    ("refused_outcome", "cmd/otto-gateway/main.go",
     "outcome := gateway.HandlerOutcome(herr)",
     "outcome := gateway.OutcomeError; _ = gateway.HandlerOutcome(herr)",
     "TestScopeRefusalsAndArgumentErrors"),
    ("draft_pr", "internal/gateway/githubtools.go",
     "Body: params.Body, Draft: !c.createReadyPRs})",
     "Body: params.Body, Draft: false})",
     "TestOriginalToolsAndBrokeredCredentials"),
    ("grant_signature", "internal/turngrant/grant.go",
     'if !hmac.Equal(got, sign(key.key, version+"."+kid+"."+encoded)) {',
     'if false && !hmac.Equal(got, sign(key.key, version+"."+kid+"."+encoded)) {',
     "TestTurnGrantIsRequiredAndVerified"),
    # The newer tools and grant key rotation. These guards were written from what the
    # gateway says and does over HTTP; where only a sentence was found to break, the guard
    # changes that sentence, and the test that pins it must notice.
    ("grant_key_retirement", "internal/turngrant/grant.go",
     ".Before(", ".After(",
     "TestGrantKeyRotation"),
    ("grant_previous_key_needs_instant", "cmd/otto-gateway/grant.go",
     "is set without -turn-grant-previous-until", "is set alone",
     "TestBootRefusals"),
    ("check_annotation_bound", "internal/gateway/githubchecks.go",
     "= 10", "= 100",
     "TestReleasesIssuesAndChecks"),
    ("job_log_redirect_refusal", "internal/gateway/githubjoblog.go",
     "will not be followed", "is ignored",
     "TestJobLogFollowsOnlyItsPinnedHost"),
    ("repo_config_codeowners", "internal/gateway/repoconfig.go",
     '".github/CODEOWNERS"', '".github/MUTATED"',
     "TestTemplateAndConventionsComeFromTheDefaultBranch"),
    ("propose_draft", "internal/gateway/githubpropose.go",
     "Draft: true", "Draft: false",
     "TestProposeChange"),
    ("propose_atlantis_path", "internal/gateway/githubpropose.go",
     '"atlantis.yaml"', '"atlantis.mutated"',
     "TestNewerToolsRefuseBeforeAnyRequest"),
    ("amend_commit_message", "internal/gateway/githubamend.go",
     "Amend pull request #%d", "Amended #%d",
     "TestAmendChange"),
    ("declare_claim_bound", "internal/gateway/declareclaim.go",
     "1000", "2000",
     "TestDeclareUnverifiedClaim"),
    ("skill_body_unpinned", "internal/gateway/githubskillbody.go",
     "no skill set has been pinned for this turn", "no skills pinned",
     "TestSkillBodyNeedsAPinnedSkillSet"),
    ("jira_project_scope", "internal/gateway/jiratools.go",
     '"project in ("', '"project not in ("',
     "TestJiraSearch"),
    ("jira_restricted_comments", "internal/gateway/jiratools.go",
     'json:"visibility"', 'json:"visibility_mutated"',
     "TestJiraGetIssue"),
    ("jira_comment_attribution", "internal/gateway/jiratools.go",
     "posted by Otto, requested by", "posted, requested by",
     "TestJiraComment"),
]


def main():
    if sys.version_info < (3, 12):
        raise SystemExit(f"mutation_check.py needs Python 3.12 or newer; this is "
                         f"{sys.version.split()[0]} at {sys.executable}")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--otto-source", type=Path, required=True,
                        help="local clone of the otto repository containing the pinned commit")
    parser.add_argument("--only", help="run one mutation by name")
    args = parser.parse_args()
    pin = json.loads((ROOT / "baseline.json").read_text())
    source = args.otto_source.resolve()
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "TMPDIR"}}
    cache = ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    env.update(GOTOOLCHAIN=pin["go_toolchain"], GOCACHE=str(cache / "go-build"), GOWORK="off")
    survived = []
    with tempfile.TemporaryDirectory(prefix="switchboard-mutation-") as temp:
        temp = Path(temp)
        archive = temp / "otto.tar"
        with archive.open("wb") as out:
            subprocess.run(["git", "-C", str(source), "archive", pin["commit"]],
                           check=True, stdout=out)
        checkout = temp / "otto"
        checkout.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(checkout, filter="data")
        for name, path, old, new, test in MUTATIONS:
            if args.only and args.only != name:
                continue
            target = checkout / path
            original = target.read_text()
            # A pattern that no longer matches means Otto moved; that is a
            # failure of this check, never a pass.
            if original.count(old) != 1:
                survived.append(f"{name}: guard text found {original.count(old)} times in {path}")
                continue
            target.write_text(original.replace(old, new))
            binary = temp / name
            try:
                subprocess.run(["go", "build", "-mod=readonly", "-o", str(binary),
                                "./cmd/otto-gateway"], cwd=checkout, env=env, check=True)
            finally:
                target.write_text(original)
            result = subprocess.run(
                [sys.executable, str(ROOT / "run.py"), "--otto-source", str(source),
                 "--gateway-binary", str(binary), "--test", f"^{test}$"],
                capture_output=True, text=True)
            log = result.stdout + result.stderr
            failed = f"--- FAIL: {test}" in log
            passed = any(line.startswith("ok ") for line in log.splitlines())
            if result.returncode != 0 and failed:
                print(f"caught    {name}: {test} failed against the broken build", flush=True)
            elif result.returncode == 0 and passed:
                survived.append(f"{name}: {test} PASSED against the broken build")
            else:
                survived.append(f"{name}: the runner gave no verdict (exit {result.returncode}):\n"
                                + log[-600:])
    for line in survived:
        print("NOT CAUGHT " + line, flush=True)
    if survived:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
