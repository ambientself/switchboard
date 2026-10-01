# Target systems

Date: 2026-09-30, revised 2026-10-01 against Otto `752395a`. Status: first pass. The systems the gateway must reach, as named on
2026-09-30: GitHub, Atlassian, New Relic, Sumo Logic, Akamai, AWS, and MCP servers Org teams
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
| GitHub | Search; read files, releases, pull requests, issues, checks and job logs; open and amend draft pull requests; comment. | Built-in. Otto's Go gateway has fourteen GitHub tools as of `752395a`, with the App key held by a separate custodian process. | Which of the fourteen depend on Otto-owned state, and, for each, whether that state arrives in the turn grant or through an interface Otto exposes (decision 0003). |
| Atlassian | Jira search, read and comment; presumably Confluence reads. | Built-in. Otto's Go gateway has three Jira tools on one shared Atlassian account, limited to an allowlist of projects. | Whether one shared account is acceptable company-wide. Whether Atlassian's own MCP server accepts a service identity. Whether Confluence is wanted. |
| New Relic | Querying metrics, traces and alerts while investigating. | Either. Read-only and key-authenticated, so a good first proxied vendor server if one fits. | Whether New Relic's MCP server takes a brokered key and can be limited to reads. |
| Sumo Logic | Log search while investigating. | Either, for the same reasons as New Relic. | Whether a vendor MCP server exists in a usable form. Query cost and result-size limits. |
| Akamai | Reading configuration and delivery data. | Built-in, reads only. Activating a configuration or purging a cache changes production. | Which read operations are wanted. Request signing means the credential cannot be a plain header. |
| AWS | Inventory questions across accounts. | Built-in, brokered, read-only tools. Otto's draft decision 0016 plans an AWS Config query tool first and Steampipe queries second; an Otto sandbox cannot run `aws` at all. Minting is not planned. | That decision is a draft. Read access across 55 accounts is not something every employee has, so these reads need a per-team opt-in; see "What this list changes". |
| Self-built | Whatever an Org team exposes. | Proxied, by definition. | How a team's server proves the gateway is its caller. Who assigns each tool's classification. |

## What this list changes

- **Proxying is required, not optional.** Self-built servers cannot be built-in connectors,
  so the connector trait needs its proxied implementation for the gateway to be useful beyond
  GitHub and Jira.
- **A read is not always safe.** AWS inventory is classified `read` but shows more than most
  employees can see themselves. Classification alone cannot gate it, so the read tier needs a
  breadth setting per team or group. This applies to the employee profile as much as to Otto.
- **Minting is not needed by any listed system.** An earlier pass had AWS as minted
  credentials. With AWS brokered, every call passes through the gateway and is audited there,
  at the cost that AWS's own logs show the platform and not the person who asked.
- **Seven systems share one rate-limit and failure story.** Per-team queues and circuit
  breakers, which Otto defers, become necessary as soon as there are several vendors with
  their own limits.

## Next step

Fill in the "to verify" column from each vendor's current documentation, one system at a time,
and record the result here with its date and source.
