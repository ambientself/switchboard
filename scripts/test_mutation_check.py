#!/usr/bin/env python3
"""Checks the mutation check's own steps, with cargo replaced by a stub that records each run.

    python3 scripts/test_mutation_check.py

Needs Python 3.12 or later, like the script, and runs no cargo.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

SPEC = importlib.util.spec_from_file_location("mutation_check", Path(__file__).resolve().parent / "mutation_check.py")
check = importlib.util.module_from_spec(SPEC)
sys.modules["mutation_check"] = check
SPEC.loader.exec_module(check)

GUARDED = "crates/a/src/lib.rs"
PRISTINE = "fn guard() -> bool { true }\n"
MUTATED = "fn guard() -> bool { false }\n"

# Package a holds the edited file and b depends on it; c does neither. So the mutation's first
# step is [a], its second is [b], and neither is the whole workspace.
A, B = frozenset({"a"}), frozenset({"b"})
PACKAGES = check.Packages(
    directories={"a": "crates/a/", "b": "crates/b/", "c": "crates/c/"},
    dependents={"a": B, "b": frozenset(), "c": frozenset()},
)
MUTATION = check.Mutation("probe", "the guard always refuses", (check.Edit(GUARDED, PRISTINE, MUTATED),))

Answer = Callable[[frozenset[str] | None, str], tuple[int | None, str]]


def passes(chosen: frozenset[str] | None, held: str) -> tuple[int | None, str]:
    return 0, ""


class Run:
    """main() over the one mutation, with every cargo run answered by `answer`. Each run is
    recorded as the packages it tested (None for the whole workspace), whether it stopped at the
    first failure, and whether the guarded file was pristine or mutated at the time."""

    def __init__(self, answer: Answer, *arguments: str, database: bool = True) -> None:
        self.runs: list[tuple[frozenset[str] | None, bool, str]] = []

        def run_tests(workspace: Path, target: Path, chosen: frozenset[str] | None = None, *,
                      fail_fast: bool = False) -> tuple[int | None, str]:
            held = {PRISTINE: "pristine", MUTATED: "mutated"}[(workspace / GUARDED).read_text()]
            self.runs.append((chosen, fail_fast, held))
            return answer(chosen, held)

        def copy_workspace(destination: Path) -> None:
            (destination / GUARDED).parent.mkdir(parents=True)
            (destination / GUARDED).write_text(PRISTINE)

        output = io.StringIO()
        with (
            mock.patch.object(check, "MUTATIONS", [MUTATION]),
            mock.patch.object(check, "sentence_mutations", lambda source: None),
            mock.patch.object(check, "copy_workspace", copy_workspace),
            mock.patch.object(check, "read_packages", lambda workspace: PACKAGES),
            mock.patch.object(check, "run_tests", run_tests),
            mock.patch.object(sys, "argv", ["mutation_check.py", *arguments]),
            mock.patch.dict(os.environ),
            contextlib.redirect_stdout(output),
        ):
            if database:
                os.environ[check.DATABASE_VARIABLE] = "postgres://unused"
            else:
                os.environ.pop(check.DATABASE_VARIABLE, None)
            self.status = check.main()
        self.output = output.getvalue()


class Steps(unittest.TestCase):
    def test_a_mutation_that_passes_both_steps_is_run_against_the_whole_workspace(self) -> None:
        run = Run(passes)
        self.assertEqual(run.runs, [
            (None, False, "pristine"),  # the baseline
            (A, True, "pristine"),  # [a] unmutated, the first time it is needed
            (A, True, "mutated"),  # the first step
            (B, True, "pristine"),  # [b] unmutated: the mutation is taken out first
            (B, True, "mutated"),  # the second step: the mutation is put back
            (None, False, "mutated"),  # the whole workspace, before SURVIVED
        ])
        self.assertIn("baseline for [b] passes", run.output)
        self.assertRegex(run.output, r"SURVIVED +probe .*\[a then b then workspace\]")
        self.assertEqual(run.status, 1)

    def test_a_catch_in_the_first_step_ends_the_mutation(self) -> None:
        def answer(chosen: frozenset[str] | None, held: str) -> tuple[int | None, str]:
            return (101, "test a::guard ... FAILED\n") if held == "mutated" else (0, "")

        run = Run(answer)
        self.assertEqual(run.runs, [(None, False, "pristine"), (A, True, "pristine"), (A, True, "mutated")])
        self.assertRegex(run.output, r"CAUGHT +probe .*\[a\]  a::guard")
        self.assertEqual(run.status, 0)

    def test_a_set_that_fails_unmutated_is_replaced_by_the_whole_workspace_and_shows_why(self) -> None:
        def answer(chosen: frozenset[str] | None, held: str) -> tuple[int | None, str]:
            if chosen == B and held == "pristine":
                return 101, "test b::alone ... FAILED\nthe end of b's own output\n"
            return 0, ""

        run = Run(answer)
        self.assertEqual(run.runs, [
            (None, False, "pristine"),
            (A, True, "pristine"),
            (A, True, "mutated"),
            (B, True, "pristine"),
            (None, True, "mutated"),  # in place of [b]; it passed the whole workspace, so no retry
        ])
        self.assertIn("the end of b's own output\n", run.output)
        self.assertIn("baseline for [b] FAILS unmutated", run.output)
        self.assertRegex(run.output, r"SURVIVED +probe .*\[a then workspace\]")

    def test_all_catchers_runs_both_steps_at_once(self) -> None:
        run = Run(passes, "--all-catchers")
        self.assertEqual(run.runs, [
            (None, False, "pristine"),
            (A | B, True, "pristine"),
            (A | B, False, "mutated"),
            (None, False, "mutated"),
        ])

    def test_a_missing_database_is_warned_about_once(self) -> None:
        warning = f"warning: {check.DATABASE_VARIABLE} is not set"
        self.assertEqual(Run(passes, database=False).output.count(warning), 1)
        self.assertNotIn(warning, Run(passes).output)


if __name__ == "__main__":
    unittest.main()
