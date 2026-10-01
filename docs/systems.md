# Target systems

Date: 2026-09-30. Status: first pass. The systems the gateway must reach, as named on
2026-09-30: GitHub, Atlassian, New Relic, Sumo Logic, Akamai, AWS, and MCP servers TKWW teams
build themselves.

For each system there are two ways to connect it (see [design.md](design.md), section 13):

- **Built-in connector:** gateway code that calls the vendor's API with a brokered credential.
- **Proxied server:** a separate MCP server the gateway forwards to, the vendor's or a team's.

Three rules narrow the choice. Team service identities bind Otto and internal services;
employees may use per-user grants where permissions or authorship require them. Shared
identities may serve employee reads only for data explicitly approved for those employees.
Production mutation is denied for all profiles initially.

1. **Team service identities.** A vendor MCP server that works only with a per-user login
   cannot serve Otto as it stands.
2. **No production mutation.** A tool that changes production is destructive, whichever way
   the system is connected.
3. **Brokering for API-shaped systems, minting for CLI-shaped ones.**

## First pass

The "leaning" column is a starting position, not a finding. Nothing in the "to verify" column
has been checked yet.

| System | What agents need it for | Leaning | To verify |
| --- | --- | --- | --- |
| GitHub | Search, read files and pull requests, open pull requests, comment. | Built-in. It exists in the Go gateway with five tools and a GitHub App credential. | Nothing; this is the parity target. |
| Atlassian | Jira search, read, comment and transition; presumably Confluence reads. | Built-in. Otto already plans Jira this way. | Whether Atlassian's own MCP server accepts a service identity, or only a per-user login. Whether Confluence is wanted. |
| New Relic | Querying metrics, traces and alerts while investigating. | Either. Read-only and key-authenticated, so a good first proxied vendor server if one fits. | Whether New Relic's MCP server takes a brokered key and can be limited to reads. |
| Sumo Logic | Log search while investigating. | Either, for the same reasons as New Relic. | Whether a vendor MCP server exists in a usable form. Query cost and result-size limits. |
| Akamai | Reading configuration and delivery data. | Built-in, reads only. Activating a configuration or purging a cache changes production. | Which read operations are wanted. Request signing means the credential cannot be a plain header. |
| AWS | Inspecting resources; running `aws` in the sandbox. | Minting, deferred. Short-lived, read-only, per-team credentials; subsequent CLI calls do not pass through the gateway as tools. | How issuance is correlated with downstream action audit records; permitted accounts/resources, expiry and revocation limits. Resolve before enabling minting. |
| Self-built | Whatever a TKWW team exposes. | Proxied, by definition. | How a team's server proves the gateway is its caller. Who assigns each tool's classification. |

## What this list changes

- **Proxying is required, not optional.** Self-built servers cannot be built-in connectors,
  so the connector trait needs its proxied implementation for the gateway to be useful beyond
  GitHub and Jira.
- **AWS is a third mechanism.** Minting credentials is neither a built-in connector nor a
  proxied server, and it raises an audit question the other two do not: the gateway sees the
  credential being issued, but not what is done with it.
- **Seven systems share one rate-limit and failure story.** Per-team queues and circuit
  breakers, which Otto defers, become necessary as soon as there are several vendors with
  their own limits.

## Next step

Fill in the "to verify" column from each vendor's current documentation, one system at a time,
and record the result here with its date and source.
