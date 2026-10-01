# 0002: Replace Otto's MCP gateway

Date: 2026-09-30. Status: accepted.

## Context

The company-wide gateway must become Otto's MCP path as well as serve other callers.
Otto already has a working Go gateway and a security and behavioral contract to preserve.

## Decision

The Rust gateway replaces Otto's Go MCP gateway. Otto will be reconfigured to call it
directly after the conformance suite passes. The Go gateway remains Otto's MCP path until
that cutover, after which it no longer serves Otto's MCP calls.

Otto retains responsibility for `/repo-config` and model brokering. Their separation from
the existing gateway is a migration requirement, outside this project's MCP implementation.

## Consequences

- The conformance suite is the first deliverable and establishes the existing Go behavior.
- Otto's headers, team manifest, audit-table contract, denial behavior and tool protections
  remain compatibility requirements.
- Endpoint and tool-name changes are handled explicitly by reconfiguring Otto and mapping
  the corresponding conformance requests, without weakening their assertions.
- The new gateway does not forward Otto's MCP calls through the old gateway, and Otto does
  not keep an independent MCP authorization path after cutover.
