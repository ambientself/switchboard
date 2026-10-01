# 0005: Build without a comparison first

Date: 2026-10-01. Status: accepted.

## Context

A design review recommended a two-week comparison before any Rust is written: extend Otto's
Go gateway, adopt an open-source MCP gateway, or build this one, judged against one
acceptance list. The plan never made that comparison, and the review considered a rewrite of
a working security boundary the highest-risk option.

## Decision

Build it, without the comparison. The purpose includes finding out what such a gateway looks
like in Rust, and that is worth doing even if the result is not adopted.

## What keeps this safe

- Otto's Go gateway stays in service and stays Otto's MCP path until a separate cutover
  decision. Nothing depends on this project succeeding.
- The first slice serves one non-Otto workload and a read-only server
  ([design.md](../design.md), section 17), so the earliest production exposure is small and
  reversible.
- [Decision 0002](0002-replace-ottos-mcp-gateway.md) remains the intent, and its cutover is
  staged: comparison alongside Otto first, then reads, then writes.

## Consequences

- The question the comparison would have answered stays open. If the first slice shows the
  core is not worth continuing, stopping is an acceptable outcome and should be said plainly.
- Evidence for or against continuing comes from the slice: latency with synchronous audit,
  how much of the policy model survives a real workload, and how long a change takes to
  verify.
