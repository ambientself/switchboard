# 0001: Build the proxy on axum and the MCP SDK, not on Pingora

Date: 2026-09-30. Status: accepted.

## Context

The gateway will be written in Rust. [Pingora](https://github.com/cloudflare/pingora) is
Cloudflare's Rust framework for building HTTP proxies, and it was the first candidate for the
data plane.

## Decision

Build the proxy as an ordinary HTTP service on `axum` (`hyper` and `tower` underneath), using
`rmcp`, the official Rust MCP SDK, as an MCP server towards agents and an MCP client towards
downstream servers.

## Why

The gateway terminates MCP; it does not relay HTTP. Its work sits above the layer Pingora is
built for:

- **Many calls have no upstream to proxy to.** Built-in connectors call vendor APIs as an HTTP
  client. Pingora's `ProxyHttp` trait is built around choosing an upstream peer for each
  request.
- **Where there are upstreams, one request can reach several.** `tools/list` on a tool
  surface merges the tools of every connector and proxied server in it.
- **Decisions depend on the body.** Authorization needs the JSON-RPC method and the tool name,
  which are in the request body, not the headers or the path.
- **The load does not call for it.** DoorDash reports millions of calls a week, which is tens
  of requests per second, and Otto serves about 450 people. Pingora's advantages are connection reuse at
  very high request rates, zero-downtime reloads and custom load balancing.

## Consequences

- TLS termination, load balancing and connection draining are left to whatever already fronts
  the service (a cloud load balancer, Envoy, or Pingora itself as an edge).
- The proxy must handle graceful shutdown of long-lived response streams itself.
- If the gateway later needs to relay non-MCP traffic at high volume, this decision should be
  revisited for that path only.
