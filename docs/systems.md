# Target systems

Date: 2026-09-30, revised 2026-10-01 against Otto `752395a`. Status: researched from vendor
sources on 2026-10-01. Nothing here has been tested against a live account.

The systems the gateway must reach were named on 2026-09-30: GitHub, Atlassian, New Relic,
Sumo Logic, Akamai, AWS, and MCP servers Org teams build themselves. On 2026-10-01 the scope
widened to Slack, Salesforce and MongoDB Atlas ([issue 7](https://github.com/ambientself/switchboard/issues/7)).
This page records, for each, whether the vendor offers an MCP server the gateway could use,
how that server authenticates, and whether it can be held to reads.

For each system there are two ways to connect it (see [design.md](design.md), section 13):

- **Built-in connector:** gateway code that calls the vendor's API with a brokered credential.
- **Proxied server:** a separate MCP server the gateway forwards to, the vendor's or a team's.

## Rules that narrow the choice

Team service identities bind Otto and internal services; employees may use per-user grants
where permissions or authorship require them. Shared identities may serve employee reads only
for data explicitly approved for those employees. Production mutation is denied for all
profiles initially.

1. **Team service identities.** Service callers (Otto and internal automations) need a service
   identity: an API key, service account, app installation or OAuth client credentials. A
   vendor MCP server that works only with a per-user login cannot serve them as it stands.
   Employees' own agents may use per-user OAuth grants held by the gateway.
2. **No production mutation.** A tool that changes production is `write` or `destructive`,
   according to its effect, whichever way the system is connected. Both are denied in every
   profile (the 2026-10-04 amendment to
   [decision 0006](decisions/0006-what-the-decision-function-sees.md)). So the first question
   is read access, and whether a credential or a server can be limited to reads.
3. **Brokering for API-shaped systems, minting for CLI-shaped ones.**
4. **A proxied server is exposed only if the gateway can limit it.** Either the gateway
   understands the tool's arguments, or the server's credential and route limit it to exactly
   the permitted resources (design.md, section 13). Under
   [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md), a proxied
   tool's credential must reach nothing outside its callers' limits and must not be able to
   write. Its section's dated "To confirm" test is recorded before approval, and its reach is
   re-checked on a schedule.
5. **Short-lived beats long-lived.** Where a vendor supports workload federation or
   short-lived credentials, prefer that to holding a key (design.md, section 9).

The gateway proxies HTTP only. A server that speaks only stdio has to be wrapped in an HTTP
server before it can be registered.

## How to read this page

- Every fact carries its source and the date it was read. All pages were read on 2026-10-01.
- "The vendor documents this" means the vendor's own page says it. It does not mean it works
  for Org. No credential was created and no server was called.
- "Not verified" means no primary source was found, or the sources disagree.
- Counts of tools are taken from the vendor's own lists on that date. They change often.

## Summary

| System | What agents need it for | Recommendation | Service identity | Read-only |
| --- | --- | --- | --- | --- |
| GitHub | Search; read files, releases, pull requests, issues, checks, job logs; draft pull requests; comment. | Built-in. Official server is an option later. | Yes, documented, not tested. | Yes. |
| Atlassian | Jira search, read, comment. Confluence search and read. | Built-in now. Proxy the hosted server after a test. | Yes, service account API key. | Yes, by scope. |
| Sumo Logic | Log search while investigating. | Proxy the vendor's hosted server. | Yes, OAuth client credentials. | Yes, by scope. |
| New Relic | Metrics, traces, alerts while investigating. | Built-in (NerdGraph), unless an API-key test passes. | Not verified. | Yes. No write tools listed. |
| Slack | Search and read channels and threads. | Not yet. | No for the hosted server. | Yes, by scope. |
| AWS | Inventory questions across accounts. | Built-in, brokered, read-only tools. | Yes, IAM role. | Yes, by IAM policy. |
| Akamai | Configuration and delivery data. | Built-in, reads only. | Yes, EdgeGrid API client. | Yes, per API. |
| Salesforce | Read records. | Not yet. | No for the hosted server. Yes for the REST API. | Yes. |
| MongoDB Atlas | Read cluster and collection data. | Proxy the vendor's hosted server. | Yes, service account. | Yes. |
| Self-built | Whatever an Org team exposes. | Proxied, by definition. | How a team's server proves the gateway is its caller is open. | Each tool's classification is assigned by a person. |

"Service identity: yes" is what the vendor documents. It stays unproven until the test named in
each section has been run.

## GitHub

**The vendor documents this**

- An official server exists: [github/github-mcp-server](https://github.com/github/github-mcp-server),
  MIT licence, written in Go (GitHub repository metadata, 2026-10-01).
- It is hosted at `https://api.githubcopilot.com/mcp/`
  ([README](https://github.com/github/github-mcp-server/blob/main/README.md), 2026-10-01). The
  remote server went generally available on 4 September 2025
  ([changelog](https://github.blog/changelog/2025-09-04-remote-github-mcp-server-is-now-generally-available/), 2026-10-01).
- GitHub Enterprise Cloud with data residency uses a `copilot-api.<subdomain>.ghe.com/mcp`
  URL. GitHub Enterprise Server has no remote server
  ([README](https://github.com/github/github-mcp-server/blob/main/README.md), 2026-10-01).
- It is also self-hostable: a binary or Docker image run over stdio, or with an `http`
  command ([GitHub App authentication](https://github.com/github/github-mcp-server/blob/main/docs/github-app-auth.md), 2026-10-01).
  The remote server is configured with `type: http`. Whether it also serves legacy SSE is not
  verified.
- **Authentication.** The server does not authenticate anyone itself: "The Remote GitHub MCP
  Server itself does not provide Authentication services." It requires a token in the
  `Authorization` header, and "you may also supply any valid access token", for example a
  personal access token ([host integration guide](https://github.com/github/github-mcp-server/blob/main/docs/host-integration.md), 2026-10-01).
- **App installation tokens.** The governance guide lists, for the remote server, "GitHub App
  Installation Tokens: Uses a signed JWT to request installation access tokens (similar to
  the OAuth 2.0 client credentials flow) to operate as the application itself"
  ([policies and governance](https://github.com/github/github-mcp-server/blob/main/docs/policies-and-governance.md), 2026-10-01).
  The local stdio server can also be given an App id, installation id and private key and will
  mint and refresh its own installation token. The same page says that mode "is not available
  for the `http` command. HTTP clients must continue to provide their own `Authorization`
  token" ([GitHub App authentication](https://github.com/github/github-mcp-server/blob/main/docs/github-app-auth.md), 2026-10-01).
- **Installation tokens are narrowable and short.** A token request may name up to 500
  repositories and a subset of the App's permissions, and the token expires after one hour
  ([GitHub docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app), 2026-10-01).
- **Read-only.** Remote: add `/readonly` to the URL, or send the `X-MCP-Readonly` header
  ([remote server guide](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md), 2026-10-01).
  Local: `--read-only` or `GITHUB_READ_ONLY=1`; read-only wins over `--tools`
  ([README](https://github.com/github/github-mcp-server/blob/main/README.md), 2026-10-01).
- **Tools.** The README lists about 90 tools in 27 toolsets (counted from the README on
  2026-10-01). The default set is `context`, `repos`, `issues`, `pull_requests` and `users`.
  Filtering is by `X-MCP-Toolsets` and `X-MCP-Tools` headers on the remote server, and
  `--toolsets` and `--tools` locally. A "lockdown" mode hides issue content from users without
  push access; GitHub calls it "a best-effort content filter, not a security boundary"
  ([remote server guide](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md), 2026-10-01).
- **Limits.** Calls count against GitHub API limits for the credential used. An installation
  token has at least 5,000 requests an hour, scaling to 12,500, or 15,000 on Enterprise Cloud
  ([GitHub docs](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), 2026-10-01).

**Not verified**

- Whether the remote server accepts an installation token end to end, and whether it needs a
  Copilot licence on the account behind it. The governance guide says it does accept one; no
  worked example was found.
- Whether the remote server serves legacy SSE as well as HTTP.
- The governance guide's line "Currently available only on GitHub Enterprise Cloud (GHEC)" for
  the remote server sits oddly beside the README, which shows it working on github.com. It is
  unclear whether github.com organisations count.

**What the official server would add.** Otto's Go gateway already implements GitHub as a
built-in connector with a GitHub App, fourteen tools as of `752395a`, with the key held by a
separate custodian process. The official server would add breadth: Actions, code scanning,
security advisories, projects, discussions and more, with read-only and toolset filters ready
made. It would not add credential custody; the gateway would still have to obtain and present an
installation token. Its tools take `owner` and `repo` arguments, so a gateway adapter could
check them, and the token request can name the repositories. Neither the hosted nor the
self-hosted server removes the work of classifying each tool.

**Recommendation: built-in.** It is the parity target (open-questions, Q7), it already narrows
tokens and limits every call to one organisation before a request leaves, and Otto's behaviour
is the thing milestone 4 must match. Revisit the official server, self-hosted over `http` with
the gateway supplying a per-call token, if Org wants more than the built-in tools.
To confirm: mint a read-only, single-repository installation token, send it to the hosted server
at `/x/repos/readonly`, and check that a call to a repository outside the token fails.

## Atlassian (Jira and Confluence)

**The vendor documents this**

- An official hosted server exists: the Atlassian MCP server, URL
  `https://mcp.atlassian.com/v2/mcp`. It covers Jira, Jira Service Management, Confluence,
  Bitbucket, Projects, Goals and Loom ([getting started](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/), 2026-10-01).
  Version 1 is being retired: from 1 March 2027 existing v1 use starts to expose v2 tools (same
  page). It is described as released; no preview label was found on the pages read. No self-hostable Atlassian server was found
  on Atlassian's own pages.
- Transport is HTTP (the setup commands on the same page use `--transport http`). Legacy SSE: not
  verified.
- **For gateways, a flat tool list.** By default the server exposes a few tools (`discover`,
  `executeRead`, `executeWrite`, `executeDestructive`) and loads the rest on demand. For a
  gateway Atlassian says to use `https://mcp.atlassian.com/v2/mcp?tools=all`, "a paginated
  flat list of tools" ([supported tools](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/), 2026-10-01).
  Without it, the gateway would see only generic executor tools whose arguments name the real
  tool, which it could not classify.
- **Authentication.** Two ways. OAuth 2.1 is "the primary authentication mechanism" for
  "interactive, user-driven scenarios". For "non-interactive or machine-to-machine scenarios"
  there is API token authentication: a personal token sent as `Authorization: Basic
  <base64(email:token)>`, or a **service account API key** sent as `Authorization: Bearer
  <api_key>`, which "an Atlassian admin" creates ([API token guide](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-authentication-via-api-token/), 2026-10-01).
- API token authentication must be switched on by an organisation admin (Atlassian
  Administration, Rovo, Rovo MCP server, Authentication) ([admin settings](https://support.atlassian.com/security-and-access-policies/docs/control-atlassian-rovo-mcp-server-settings/), 2026-10-01).
  Atlassian says it suits "service-style or non-interactive tools". Tokens used this way skip
  the domain allowlist and are "governed by your IP allowlist configuration and the scopes
  granted to their tokens or API keys" (same page).
- **Read-only by scope.** Tools are grouped into permission groups, each with its own scope:
  `read:jira:agent-interface`, `write:jira:agent-interface`, `search:jira:agent-interface`,
  `read:confluence:agent-interface`, `write:confluence:agent-interface`,
  `search:confluence:agent-interface`, and so on. The Jira and Confluence read, write and
  search groups are all listed as available with API token authentication. `delete_jira` and
  `manage_jira` are
  "disabled by default" until an admin enables them ([supported tools](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/), 2026-10-01).
  A service account key created with only the read and search scopes would be a read-only
  credential; the page tells the admin to create the key "with the required scopes".
- **Tools.** The Jira read group has 27 tools and the Confluence read group 25 (counted from
  the supported-tools page). The ones that matter: `searchJiraIssuesUsingJql`, `getJiraIssue`,
  `listJiraIssueComments`, `getConfluenceContent` and `searchConfluence` (CQL). Writes include
  `addOrEditJiraIssueComment`, `createJiraIssue`, `transitionJiraIssue`.
- **Limits that matter.**
  - Tokens used this way "are not bound to a specific cloudId"; the client passes it per call
    ([API token guide](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/configuring-authentication-via-api-token/), 2026-10-01).
  - Some tools are missing under API token authentication because their scopes cannot be
    granted to API keys yet. Examples: some Compass tools, and `search_code`, `read_teams` and
    `write_teams`, which are listed as OAuth only.
  - Calls that retrieve data through the search and Teamwork Graph tools use Rovo credits from
    a shared pool; `search` "may consume up to 10 Rovo credits" ([getting started](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/), 2026-10-01).
  - No request-rate limit was found.

**Not verified**

- Whether a service account can be limited to an allowlist of Jira projects, so that its key
  can reach only those. Jira permissions would normally decide this; no Atlassian page says it
  for MCP.
- Rate limits for the hosted server, and its data-residency and plan requirements.

**Smallest useful surface.** Jira: `searchJiraIssuesUsingJql`, `getJiraIssue`,
`listJiraIssueComments`, plus one comment write (`addOrEditJiraIssueComment`). That matches the
three tools Otto has today. The comment write is classified `write`, not `propose`: it
comments on issues the gateway did not create, it can edit comments the gateway did not
create, and a comment can act as a command. It is denied in every profile, and as a proxied
tool that is not `read` it is refused at load. It gets no exception: Otto's built-in
`jira_comment` has a narrow one for Otto's callers
([decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md), section 9), and
this tool does not. A Jira comment proposal therefore stays built-in. If employees will use this
server's entry, its test adds a restricted issue or page as a canary that must not be
visible.

Confluence is in use and wanted (confirmed 2026-10-01): `searchConfluence` and
`getConfluenceContent`. Otto's gateway has no Confluence tools, so there is nothing built-in to
carry over. That makes Confluence the stronger reason to test the hosted server: if a service
account can be limited to chosen spaces, Confluence reads can be proxied without writing a
connector. The test below should cover a space limit as well as a project limit.

**Recommendation: built-in now, then test the hosted server.** Otto's built-in Jira tools limit
calls to an allowlist of projects. A proxied server cannot enforce that unless the gateway
parses the JQL or the service account can see only those projects, and the second is not
verified. The hosted server does look usable as a read-only proxy: it has a service credential
and scoped read groups.
To confirm: create a service account that can see one project, issue a key with the read and
search scopes only, call `?tools=all` through a test route, and check that a JQL search on a
second project returns nothing and a write call is refused.

## Sumo Logic

**The vendor documents this**

- An official hosted server exists and went generally available on 30 July 2026
  ([release notes](https://www.sumologic.com/help/release-notes-developer/2026/08/10/mcp-server-oauth-scopes/), 2026-10-01).
  The URL depends on the deployment, for example `https://mcp.sumologic.com/mcp` for US East
  and `https://mcp.eu.sumologic.com/mcp` for Ireland, optionally with the organisation's
  subdomain in front. All commercial deployments are supported except Zurich and the AWS
  European Sovereign Cloud ([MCP server](https://www.sumologic.com/help/docs/api/mcp-server/), 2026-10-01).
  No self-hostable official server was found.
- Transport: the client "must support remote HTTP/SSE transport and OAuth 2.0". Whether that
  is Streamable HTTP, legacy SSE or both is not stated ([MCP server](https://www.sumologic.com/help/docs/api/mcp-server/), 2026-10-01).
- **Authentication.** OAuth 2.0. The recommended mode (CIMD, client ID metadata documents) is
  interactive. For clients without it, Sumo Logic supports a pre-registered client with
  Authorization Code, or "Client Credentials. Best for service-to-service or automated clients
  with no interactive user", set up "with a service account". Creating the client needs the
  Administrator role ([MCP server](https://www.sumologic.com/help/docs/api/mcp-server/), 2026-10-01).
  The page adds that the server "also works behind gateway aggregators" and that such a
  gateway's OAuth client should use the Client Credentials flow.
- **Read-only by scope.** The page says the tools "are scoped to your Sumo Logic role
  permissions", and the tools offered are filtered by the scopes in the token. An OAuth
  client can be limited to chosen scopes: "leave every checkbox unchecked to grant access to all
  scopes, or select specific scopes". Each tool names the scope it needs, for example
  `runLogSearch` needs Run Log Search and `alertsSearch` needs View Alerts ([MCP server](https://www.sumologic.com/help/docs/api/mcp-server/), 2026-10-01).
- **Tools.** About 20: log search (`runLogSearch`), alerts (`alertsSearch`, `alertsReadById`),
  dashboards (get, list, create, update), Cloud SIEM insights and rules (get, create rules,
  update insight status and assignee), and discovery (`listPartitions`, `listCustomFields`,
  `listExtractionRules`). Filtering is by scope, not by a flag.
- **Query rules and cost.** A search over more than 30 minutes with no `_sourceCategory`,
  `_collector`, `_index` or `_view` filter is rejected. A search call times out after 2
  minutes. The limits are 4 requests a second per user and 10 concurrent requests per access
  key, and "MCP requests count toward these account-wide limits". On Flex pricing, broad queries
  and retries "translate directly into scan costs". The page says the server is "not intended
  for bulk data extraction, model training, or high-volume automated queries"
  ([MCP server](https://www.sumologic.com/help/docs/api/mcp-server/), 2026-10-01).
- **API behind a built-in connector, if needed.** The Search Job API returns up to 100,000
  messages a search, allows 200 active search jobs for the organisation, and shares the 4 a
  second and 10 concurrent limits ([search job API](https://www.sumologic.com/help/docs/api/search-job/), 2026-10-01).
  Access keys can be created on a service account and scoped to fewer capabilities
  ([access keys](https://www.sumologic.com/help/docs/manage/security/access-keys/), 2026-10-01;
  [service accounts](https://www.sumologic.com/help/docs/manage/security/service-accounts/), 2026-10-01).

**Not verified**

- The lifetime of a client-credentials access token.
- Whether the scope choice shown for the authorisation-code client also applies to a
  client-credentials client. The page shows it only for the former.
- Whether a role's search filter, which Sumo Logic documents for roles in general
  ([search filters](https://www.sumologic.com/help/docs/manage/users-roles/roles/construct-search-filter-for-role/), 2026-10-01),
  applies to the MCP log search tool. If it does, a service account could be limited to chosen
  source categories, which is what rule 4 needs, because a log query is free text the gateway
  cannot sensibly parse.
- Whether Otto's use counts as "high-volume automated queries".

**Smallest useful surface.** `runLogSearch`, `alertsSearch`, and the three discovery tools
(`listPartitions`, `listCustomFields`, `listExtractionRules`). No dashboard writes, no SIEM
writes.

**Recommendation: proxy the vendor's hosted server.** It is the clearest case: a documented
service identity, scopes that can exclude every write, and a statement that it works behind
gateways. It is a good first proxied vendor server.
To confirm: create a service account with a role limited to chosen source categories, an OAuth
client with only the search, alert and discovery scopes, fetch a token by client credentials,
and check that the tool list has no write tools, that a search outside the allowed categories
returns nothing, and that 2-minute timeouts and 429 responses reach the caller as clear denials.
Decision 0011 requires this test to show that the role's search filter applies to the MCP log
search.

## New Relic

**The vendor documents this**

- An official hosted server exists, at `https://mcp.newrelic.com/mcp/` (EU
  `https://mcp.eu.newrelic.com/mcp/`, Japan `https://mcp.jp.newrelic.com/mcp/`)
  ([setup](https://docs.newrelic.com/docs/agentic-ai/mcp/setup/), 2026-10-01). It was a public
  preview from 4 November 2025
  ([announcement](https://docs.newrelic.com/whats-new/2025/11/whats-new-11-05-mcp-server/), 2026-10-01)
  and was renamed New Relic Ground Truth "for general availability" in the docs release notes
  for 14 to 18 September 2026
  ([release notes](https://docs.newrelic.com/docs/release-notes/docs-release-notes/docs-9-18-2026/), 2026-10-01).
  A GitHub repository, [newrelic/mcp-server](https://github.com/newrelic/mcp-server), points
  to the docs and holds no source licence in its metadata; it was last pushed in October 2025.
  Whether the server can be self-hosted is not verified.
- Transport is HTTP (the setup commands on the same page use `--transport http`). Legacy SSE: not
  verified.
- **Authentication.** OAuth is recommended, with fixed endpoints and the scope
  `observability:read`. A **User API key** (`NRAK-...`) is also listed, sent in an `api-key`
  header ([overview](https://docs.newrelic.com/docs/agentic-ai/mcp/overview/), 2026-10-01). The
  user must belong to a group with an organisation role that can read the MCP server. An admin
  must switch on an "API Keys" sub-toggle in feature control for key connections
  ([overview](https://docs.newrelic.com/docs/agentic-ai/mcp/overview/), 2026-10-01;
  [troubleshooting](https://docs.newrelic.com/docs/agentic-ai/mcp/troubleshoot/), 2026-10-01).
- "Some tools are only accessible via OAuth": `natural_language_to_nrql_query`,
  `generate_alert_insights_report`, `generate_user_impact_report`, `analyze_deployment_impact`
  and the three preview trace tools ([tool reference](https://docs.newrelic.com/docs/agentic-ai/mcp/tool-reference/), 2026-10-01).
- **Read-only.** There is no read-only flag. The tool reference lists no write tools; every
  tool queries, lists or analyses. The three preview tools are described as "read-only". What
  a call may see "is strictly governed by the permissions granted to the New Relic user".
  A user in a read-only organisation role would be the nearest documented thing to a read-only
  credential; the page does not say so
  ([tool reference](https://docs.newrelic.com/docs/agentic-ai/mcp/tool-reference/), 2026-10-01).
- **Tools.** About 38, in six categories that double as tags: `discovery`, `data-access`,
  `alerting`, `incident-response`, `performance-analytics`, `advanced-analysis`. Sending an
  `include-tags` header filters them. The main ones: `execute_nrql_query`, `get_entity`,
  `list_alert_policies`, `search_incident`, `list_recent_issues`, `get_distributed_trace_details`,
  `get_log_statistics`, `analyze_golden_metrics`.
- **Limits.** The server "allows up to 2,000 tool calls per hour per user. These limits may
  vary." Most tools use
  Core Compute Units; four AI tools use Advanced Compute Capacity Units and need an add-on
  ([tool reference](https://docs.newrelic.com/docs/agentic-ai/mcp/tool-reference/), 2026-10-01).
- **API behind a built-in connector.** NerdGraph, a GraphQL API at `https://api.newrelic.com/graphql`,
  called with a user key in an `API-Key` header, runs NRQL ([NerdGraph](https://docs.newrelic.com/docs/apis/nerdgraph/get-started/introduction-new-relic-nerdgraph/), 2026-10-01).

**The sources disagree.** The September release notes say setup "moved to OAuth only", and the
setup page says to use OAuth and that "any setup with an API key will not work as described".
Yet the same setup page configures one client (Antigravity CLI) with an API key only, and the
overview, tool reference and troubleshooting pages still document keys and the key toggle.

**Not verified**

- That an API-key connection works for a service caller in practice, and that a key can belong
  to a service user rather than a person.
- Whether OAuth client credentials exist. None are documented, so OAuth means a person.
- Query cost and result-size limits for `execute_nrql_query`.
- Data-residency and plan requirements beyond the regional URLs.

**Smallest useful surface.** `execute_nrql_query`, `list_recent_issues`, `search_incident`,
`list_alert_policies`, `get_entity`, `list_recent_logs`. Leave out the OAuth-only AI tools.

**Recommendation: built-in (NerdGraph), unless the API-key test passes.** A built-in connector
needs only a user key and NRQL, and the gateway sees the query, so it can bound results. The
hosted server is attractive for its breadth, but its service-identity story is contradictory.
To confirm: create a user in a read-only role, make a user key, enable the API Keys toggle, send
the key to the hosted server, and check that the tool list is usable and that `execute_nrql_query`
cannot reach an account the user cannot read. If it passes, proxy.

## Slack

**The vendor documents this**

- An official hosted server exists at `https://mcp.slack.com/mcp`. Slack's blog says "The Slack
  MCP server and Real-Time Search API are now generally available"
  ([blog](https://slack.com/blog/news/mcp-real-time-search-api-now-available), 2026-10-01); the
  changelog entry announcing the server is dated 17 February 2026
  ([changelog](https://docs.slack.dev/changelog/2026/02/17/slack-mcp/), 2026-10-01). No
  self-hostable server was found.
- Transport: "JSON-RPC 2.0 over Streamable HTTP". "We do not support SSE-based connections or
  Dynamic Client Registration at this time" ([overview](https://docs.slack.dev/ai/mcp-server/), 2026-10-01).
- **Authentication.** Slack "supports confidential OAuth for MCP clients", using the app's
  client ID and secret. The endpoints are Slack's `oauth/v2_user/authorize` and
  `oauth.v2.user.access`, and the scope table is headed "OAuth scopes needed on user token".
  The client must be backed by a registered Slack app; "only apps published in the Slack
  Marketplace and internal apps can use MCP at this time; unlisted apps are prohibited"
  ([overview](https://docs.slack.dev/ai/mcp-server/), 2026-10-01).
- **Read-only by scope.** There is no read-only mode. A token without `chat:write`,
  `reactions:write`, `canvases:write`, `channels:write` and the other write scopes cannot
  call the write tools. The read scopes: `search:read.public`, `search:read.private`,
  `search:read.mpim`, `search:read.im`, `search:read.files`, `search:read.users`,
  `channels:history`, `groups:history`, `mpim:history`, `im:history`, `files:read`,
  `users:read` (same page).
- **Tools.** Search messages, files, users, channels and emoji; read a channel, a thread, a
  canvas, a file and reactions; send, schedule and draft messages; create conversations; add
  reactions; manage canvases, files and lists ([overview](https://docs.slack.dev/ai/mcp-server/), 2026-10-01).
  Tools were added in May 2026 ([changelog](https://docs.slack.dev/changelog/2026/05/13/new-mcp-tools/), 2026-10-01).
  There is no tool filter other than scopes and the workspace admin's approval of the app.
- **Limits.** Slack's own method limits apply to each tool. Reading a channel or thread is
  Tier 3 (50 or more a minute), searching users and channels Tier 2 (20 or more), sending
  messages has special limits ([overview](https://docs.slack.dev/ai/mcp-server/), 2026-10-01).
  IP allowlists on the app apply.
- **The non-Marketplace rule.** Since 29 May 2025, `conversations.history` and
  `conversations.replies` allow 1 request a minute and 15 objects a request for apps
  distributed commercially outside the Marketplace. It does not apply to Marketplace apps or to
  "internal customer-built applications", for which those methods keep Tier 3 limits and 1,000
  objects ([changelog](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/), 2026-10-01).
  An app Org builds for its own workspace is the internal kind.
- **API behind a built-in connector.** `conversations.history` accepts a bot token with
  `channels:history`, `groups:history`, `im:history` and `mpim:history`
  ([method](https://docs.slack.dev/reference/methods/conversations.history), 2026-10-01).
  `search.messages` lists only "User token: search:read"
  ([method](https://docs.slack.dev/reference/methods/search.messages), 2026-10-01). So a bot
  could read the channels it has been invited to, but could not search.

**Not verified**

- Whether the hosted server accepts a bot token. The page names only user tokens; it mentions
  bot tokens only for an "in-Slack experience".
- Whether an internal app can use the server, or whether Org would need a Marketplace listing.
  The page says "internal apps" may.
- Whether reads of private channels and DMs through a user token are acceptable for a shared
  identity. Design section 9 says they are not unless approved per employee.

**Smallest useful surface.** For employees: search, read a channel, read a thread, with no
send. For a service caller, none yet.

**Recommendation: not yet.** The hosted server authenticates users, not services, so it cannot
serve Otto. It fits employees' agents with per-user grants at milestone 5, where each employee's
own token keeps their own channel access. A built-in bot-token reader is possible later if a
service caller needs channel history.
To confirm: with an internal app and a user token carrying only read scopes, call the hosted
server through a test route and check which tools appear and that a write call is refused. Then
try a bot token against the same URL.

## AWS

The direction is brokered, read-only inventory tools, not credentials issued to callers.

**The vendor documents this**

- **AWS MCP Server (managed, hosted).** It went generally available in May 2026 and is "a
  managed server that gives AI coding agents secure, auditable access to AWS services"
  ([announcement](https://aws.amazon.com/about-aws/whats-new/2026/05/aws-mcp-server/), 2026-10-01).
  Endpoints look like `https://aws-mcp.us-east-1.api.aws/mcp`, and the user guide lists eight
  regions ([user guide](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/getting-started-aws-mcp-server.html), 2026-10-01).
  It exposes a small fixed set of tools: `call_aws`, which "executes any of the 15,000+ AWS API
  operations", `search_documentation`, `read_documentation`, and `run_script` (a sandbox with
  your IAM permissions and no network access) ([blog](https://aws.amazon.com/blogs/aws/the-aws-mcp-server-is-now-generally-available/), 2026-10-01).
- **Authentication.** Two options. OAuth through AWS Sign-in, for a person; access tokens last
  one hour and refresh for up to twelve. Or SigV4 request signing using the open-source MCP
  Proxy for AWS, which takes credentials "from AWS CLI, environment variables, or IAM roles"
  ([user guide](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/getting-started-aws-mcp-server.html), 2026-10-01;
  [proxy](https://github.com/aws/mcp-proxy-for-aws), Apache-2.0, Python, 2026-10-01). Read-only
  mode is listed as a reason to choose SigV4.
- **Read-only is an IAM matter.** The server adds the condition keys `aws:ViaAWSMCPService` and
  `aws:CalledViaAWSMCP` to downstream calls, so a policy or service control policy can allow
  only read actions when the call came through the MCP server, while the same user's own role
  can still write directly ([IAM with the AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/security_iam_service-with-iam.html), 2026-10-01;
  [blog](https://aws.amazon.com/blogs/aws/the-aws-mcp-server-is-now-generally-available/), 2026-10-01).
  The proxy also has a `--read-only` flag, which hides tools that are not annotated as read-only
  ([proxy README](https://github.com/aws/mcp-proxy-for-aws), 2026-10-01). Annotations are hints,
  not enforcement.
- **awslabs/mcp.** Open-source servers, [awslabs/mcp](https://github.com/awslabs/mcp), Apache-2.0,
  mostly Python. "The MCP servers in this repository are designed to support stdio only." The
  README says its Agent Toolkit is the successor, that the Cloud Control API server is
  deprecated, and lists CloudWatch, Billing, IAM and other servers
  ([README](https://github.com/awslabs/mcp/blob/main/README.md), 2026-10-01). None was found
  that does cross-account inventory.
- **Workload federation.** AWS recommends not storing long-term keys outside AWS. OIDC
  federation lets a workload exchange its own identity token for temporary credentials mapped
  to a role ([IAM OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html), 2026-10-01).
  IAM Roles Anywhere does the same with X.509 certificates
  ([Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html), 2026-10-01).
  Either gives a gateway short-lived credentials with no stored key.
- **Inventory paths a built-in tool would use.**
  - **AWS Config aggregator advanced queries.** `SelectAggregateResourceConfig` takes a SQL
    `SELECT` and an aggregator and queries "multiple accounts and regions". Queries are at most
    4,096 characters, pages are at most 100 results, and a query reaches only resource types
    Config records; "advanced query does not support querying resources which have not been
    configured" with a recorder ([API](https://docs.aws.amazon.com/config/latest/APIReference/API_SelectAggregateResourceConfig.html), 2026-10-01;
    [querying](https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html), 2026-10-01).
  - **Resource Explorer.** `Search` returns at most 1,000 results. Multi-account search needs
    AWS Organizations trusted access, a service-linked role and, recommended, a delegated
    administrator ([Search](https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_Search.html), 2026-10-01;
    [multi-account](https://docs.aws.amazon.com/resource-explorer/latest/userguide/manage-service-multi-account.html), 2026-10-01).
  - **Cloud Control API.** `list-resources` returns resources of one type in one account and
    one Region, however they were created
    ([listing](https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations-list.html), 2026-10-01).
    It would need a role assumed per account, so it is the fallback, not the first path.

**Not verified**

- What `call_aws` accepts as arguments, and so whether a gateway could check them. The pages
  read describe it only as executing API operations.
- Which accounts and resource types Org's aggregator covers. Otto's draft decision 0016 speaks
  of 55 accounts; no aggregator was inspected here.
- Rate limits for the AWS MCP Server. No figure was found.
- Whether every resource type Org cares about is recorded by Config.

**Smallest useful surface.** One brokered tool, "query inventory", that takes a Config
advanced-query expression or, better, a few fixed parameters (resource type, account, Region,
tag) and builds the query itself. Results are bounded to a page. A second tool, "describe
resource", reads one resource's configuration. Neither takes a free-form AWS call.

**How a team opts in.** Design section 8 says a read that shows more than its caller could
see is opt-in per team or group
([decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md), section 7). For
AWS a team's limit lists the accounts it may query, and the `aws / organization / o-…`
breadth resource if it may query across all of them. The tool takes fixed parameters only
(resource type, account, Region, tag), never a Config query. Its connector builds the query and adds the account
filter: the named accounts, or none when the organization was named. The filter is tested
with hostile parameter values. A team's list is approved by the data's owner, the cloud
platform team, and a security reviewer. Which accounts are in scope is for the cloud platform
team and is still open.

**Recommendation: built-in, brokered, read-only.** The AWS MCP Server's `call_aws` runs any API
operation, so the gateway could limit it only through the role's IAM policy, not by understanding
its arguments, and a role that reads across accounts is exactly the breadth that needs a per-team
opt-in. Brokered tools let the gateway apply the account filter itself and keep AWS's own logs
pointing at one role.
To confirm: run a Config advanced query through an aggregator from a role obtained by OIDC
federation or Roles Anywhere, restricted by IAM to `config:SelectAggregateResourceConfig`, and
check that a query naming a resource type Config does not record returns nothing, and that the
account filter the gateway adds cannot be bypassed.

## Akamai

**The vendor documents this**

- Akamai has a managed service called the Akamai MCP Gateway, at
  `https://mcp.akamai.com/mcp`. Akamai's "Quick Deploy" page says it "helps you bridge AI
  agents and applications with the Akamai product ecosystem" and that deploying the app needs
  an "Akamai MCP Gateway JWT" token ([Akamai MCP](https://techdocs.akamai.com/quick-deploy-apps/docs/akamai-mcp), 2026-10-01).
  The page that explains that token and the service itself,
  `techdocs.akamai.com/mcp-gateway`, requires an Akamai login and could not be read. A plain
  request to the endpoint without a token returned HTTP 403 "No authentication token provided",
  an observation and not a vendor statement (2026-10-01).
- A separate [TrafficPeak MCP server](https://techdocs.akamai.com/trafficpeak/docs/mcp-server)
  (2026-10-01) is offered remotely over HTTP and SSE at the customer's TrafficPeak hostname,
  authenticated with a "service account token" as a Bearer header, and locally over stdio. It
  queries TrafficPeak databases only. Whether Org uses TrafficPeak is not known.
- No official server for the Akamai configuration and delivery APIs was found in Akamai's
  GitHub organisation. A search of its public repositories for "mcp" returned one result,
  `MCProbe`, which was not examined ([GitHub search](https://github.com/akamai), 2026-10-01).
- **EdgeGrid, for a built-in connector.** "Authentication credentials for the majority of
  Akamai APIs use a hash-based message authentication code or HMAC-SHA-256 created through an
  API client." Each request is signed (`EG1-HMAC-SHA256`) over the method, scheme, host, path,
  a timestamp and a nonce, with the client token, access token and client secret. The clock must
  be within 30 seconds. Only the first 128 KB of a POST body is signed
  ([EdgeGrid](https://techdocs.akamai.com/developer/docs/edgegrid), 2026-10-01). So the
  credential cannot be a plain header, and a proxy that forwards a caller's header cannot
  carry it; the gateway must sign each request.
- **Limiting an API client.** An advanced client can "limit the API available to the client",
  "configure read/write permissions for individual API" and "set group access". There is also a
  "service account API client" ([EdgeGrid](https://techdocs.akamai.com/developer/docs/edgegrid), 2026-10-01).
- **Useful read APIs that exist.** Property Manager, Application Security (configurations),
  Edge DNS, Edge Diagnostics, DataStream 2 and reporting, each with its own documentation
  project ([Akamai TechDocs index](https://techdocs.akamai.com/llms.txt), 2026-10-01).

**Not verified**

- Whether the Akamai MCP Gateway is usable by a service, its authentication beyond "JWT", its
  tools, a read-only mode, its status (beta or generally available), and its limits. All sit
  behind a login.
- How an API client's credentials expire and rotate.
- Which read operations Org wants. This needs input from the teams that run the configuration.
- Rate limits of the individual APIs.

**Smallest useful surface.** Property Manager: list properties, read a property's rule tree and
activation status. Application Security: read a configuration's version and policy. Edge DNS:
read a zone's records. Reporting: read traffic by property for a time window. Activation, cache
purge and any write are out.

**Recommendation: built-in, reads only.** Signing every request is gateway code in any case, and
a single advanced API client limited to read-only on named APIs and groups is a service
identity with a bounded route. The vendor's MCP Gateway is worth a look once an Akamai login
for its documentation is available.
To confirm: create an advanced API client with read-only access to the Property Manager API and
one group, sign a request from the gateway, and check that a call to another group, and any
write call, is refused.

## Salesforce

**The vendor documents this**

- Official hosted servers exist and went generally available in April 2026, for Enterprise
  Edition and above ([announcement](https://developer.salesforce.com/blogs/2026/04/salesforce-hosted-mcp-servers-are-now-generally-available), 2026-10-01).
  A URL looks like `https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads`, with a
  sandbox variant under `/v1/sandbox/` ([SObject Reads](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/sobject-reads.html), 2026-10-01).
  Servers are off until an admin enables them under Setup, API Catalog, MCP Servers
  ([activate](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/activate-mcp-servers.html), 2026-10-01).
  Salesforce commits to support each hosted version for at least three years
  ([end of life](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/end-of-life.html), 2026-10-01).
- **The servers.** SObject All (create, read, update, delete), SObject Reads, SObject
  Mutations, SObject Deletes, Data 360, Tableau Next, and Headless 360 (beta). Standard servers
  have a fixed tool set that cannot be changed ([standard servers](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/servers-reference.html), 2026-10-01).
  Teams can also build custom servers from Apex actions, Flows and named queries.
- **Read-only exists as a server.** SObject Reads "provides read-only access ... agents can
  discover schema, query records, search across objects, and traverse relationships". It has
  six tools: `getObjectSchema`, `soqlQuery`, `find` (SOSL), `getUserInfo`,
  `listRecentSobjectRecords`, `getRelatedRecords` ([SObject Reads](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/sobject-reads.html), 2026-10-01).
- **Authentication is per user, and Salesforce says so.** "The system uses OAuth authorization
  code flow exclusively ... There are no service accounts, no machine-to-machine flows, and no
  autonomous operation outside of user context." It "requires browser-based authentication to
  ensure every transaction traces to a named user. This flow prevents automated or headless
  authentication" ([security best practices](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/security-best-practices.html), 2026-10-01).
  Registration needs an External Client App with the scopes `mcp_api` and `refresh_token` and
  PKCE; Connected Apps are not supported ([create an app](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/create-external-client-app.html), 2026-10-01).
  Field-level security and sharing rules of the signed-in user apply to every call.
- Transport and legacy SSE: not stated on the pages read.
- **DX MCP server.** [salesforcecli/mcp](https://github.com/salesforcecli/mcp), Apache-2.0,
  TypeScript, over 60 tools in toolsets such as `data`, `metadata`, `orgs`, `users`. It runs
  locally over stdio against orgs authorised by the developer's CLI, takes `--toolsets` and
  `--tools`, and is a developer tool, not a data service for a gateway
  ([README](https://github.com/salesforcecli/mcp/blob/main/README.md), 2026-10-01).
- **API behind a built-in connector.** The REST API accepts the OAuth 2.0 client credentials
  flow: the app's consumer key and secret are exchanged for a token "on behalf of the
  integration user you assigned", with no interactive user. It needs an External Client App
  and does not issue refresh tokens ([Salesforce Help](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_client_credentials_flow.htm&type=5), 2026-10-01).
  A read-only integration user would limit it to reads.

**Not verified**

- Rate limits and API-call allowances for hosted server calls. None was found on the pages read.
- Whether the hosted servers could accept a token from the client credentials flow. Salesforce
  says they do not.
- The JWT bearer flow, which Salesforce also offers for server-to-server use. Not read.
- Which Salesforce objects Org wants agents to read, and whether a shared read-only integration
  user could see only approved data.

**Smallest useful surface.** For employees' agents: SObject Reads, six tools. For a service
caller: none until it is clear what Otto would ask Salesforce.

**Recommendation: not yet.** Salesforce says the hosted servers cannot serve a service caller.
For employees, proxying SObject Reads with a gateway-held per-user grant fits milestone 5, and
Salesforce's own permissions then apply per person. If a service caller needs Salesforce, the
way in is a built-in connector on the REST API with client credentials and a read-only
integration user, and an integration user's view must be approved under design section 9 before
any employee can use it.
To confirm: create an External Client App, enable SObject Reads in a sandbox, sign in as a
test user, and check that the gateway can hold and refresh that user's token and that a write
is impossible.

## MongoDB Atlas

**The vendor documents this**

- Two official offerings share one codebase ([overview](https://www.mongodb.com/docs/mcp-server/overview.md), 2026-10-01).
  - The **Atlas Managed MCP Server** is hosted by MongoDB and covers Atlas deployments only. It
    is at `https://mcp.mongodb.com`. It was announced "available today" on 13 August 2026
    ([press release](https://www.mongodb.com/company/newsroom/press-releases/mongodb-brings-live-operational-data-to-the-agentic-coding-stack), 2026-10-01).
    The docs implement MCP specification revision 2025-11-25
    ([security](https://www.mongodb.com/docs/mcp-server/remote-mcp/security.md), 2026-10-01).
  - The **local server**, [mongodb-js/mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server),
    Apache-2.0, TypeScript, you run yourself. It also reaches Community and Enterprise
    Advanced deployments. Its default transport is stdio; `--transport http` serves HTTP on
    `/mcp`, bound to localhost. MongoDB says HTTP "is not recommended for production use
    without implementing authentication", and names "an API gateway or a reverse proxy" as a
    way ([standalone service](https://www.mongodb.com/docs/mcp-server/local-mcp/configuration/standalone-service.md), 2026-10-01).
- **Authentication to the hosted server.** Two access models
  ([access models](https://www.mongodb.com/docs/mcp-server/remote-mcp/access-models.md), 2026-10-01).
  - User-delegated: OAuth 2.1 Authorization Code with PKCE, as an individual Atlas user, for
    clients MongoDB registers in advance.
  - **Programmatic**: an administrator creates an "MCP configuration" for "automated agent[s]
    ... rather than as an individual user". Atlas makes a pair of service accounts for it, one
    to reach the server and one for audit records. Each configuration has its own Atlas roles,
    an optional IP access list and a read-only setting, "preselected at creation"; when it is
    read-only, "write tools are not available to the agent". An Organization Owner can give
    org roles, a Project Owner project roles.
  - The agent fetches a token with the client credentials grant from
    `https://cloud.mongodb.com/api/oauth/token` and calls the server with it as a Bearer
    ([get started](https://www.mongodb.com/docs/mcp-server/get-started.md), 2026-10-01).
  - "You cannot authenticate to the remote MongoDB MCP server using a static API key over
    HTTP" ([README](https://github.com/mongodb-js/mongodb-mcp-server/blob/main/README.md), 2026-10-01).
- **Authentication to the local server.** An Atlas API service account (client ID and secret)
  for Atlas tools, and a connection string, hence a database user, for data tools. MongoDB
  recommends the lowest roles, for example Project Read Only ([README](https://github.com/mongodb-js/mongodb-mcp-server/blob/main/README.md), 2026-10-01).
- **Read-only.** Local: `--readOnly` registers only read, connect and metadata tools; create,
  update and delete tools are not registered. `--disabledTools` takes tool names, operation
  types or categories (`atlas`, `mongodb`). Hosted: the read-only setting above. For the hosted
  server, the data-plane access reaches "up to project-level"; the local server reaches "up to
  collection-level" ([overview](https://www.mongodb.com/docs/mcp-server/overview.md), 2026-10-01).
  Annotations such as `readOnlyHint` "aren't a security boundary" ([security](https://www.mongodb.com/docs/mcp-server/remote-mcp/security.md), 2026-10-01).
- **Tools.** About 50 on the tools page, in categories for Atlas management, Atlas Local,
  database operations (`find`, `aggregate`, `list-databases`, `list-collections`, `count`,
  `collection-schema`), performance advisor, and search. Many Atlas tools write, such as
  `atlas-create-cluster` and `atlas-create-db-user`.
- **Limits.** Hosted: 2,000 requests a minute per IP address and 500 a minute per user, "might
  change without prior notice" ([rate limits](https://www.mongodb.com/docs/mcp-server/remote-mcp/rate-limits.md), 2026-10-01).
  Local defaults: 100 documents and 16 MiB per query (`maxDocumentsPerQuery`, `maxBytesPerQuery`),
  and `--indexCheck` rejects collection scans ([README](https://github.com/mongodb-js/mongodb-mcp-server/blob/main/README.md), 2026-10-01).

**The sources disagree, or are unclear**

- Public material says "no service accounts to create" for the hosted server; that describes
  the user-delegated model. The programmatic model does create service accounts. A separate
  package, `mongodb-atlas-mcp-remote`, says its credentials "are different from the standard
  Atlas API service-account credentials" used by the local server.
- The docs mention "public preview" in a banner about Atlas Infinite clusters, not about the
  server itself. The press release says only "available today". Whether the hosted server is
  generally available or preview is not verified.

**Not verified**

- Lifetime of the client credentials access token.
- Which Atlas organisation and projects Org would put behind an MCP configuration, and whether a
  project-level role limits reads to the permitted clusters.
- Whether database users or collections can be limited on the hosted server below project
  level.

**Smallest useful surface.** `list-databases`, `list-collections`, `collection-schema`, `find`,
`count`, and `aggregate` for reads. No Atlas management tools.

**Recommendation: proxy the vendor's hosted server, programmatic and read-only.** It has a
documented service identity, a read-only setting that removes the write tools, project-level
roles that bound the route, and an IP access list. Because `find` and `aggregate` take database
and collection names, the gateway could add an argument check for collection scope. The local
server is the fallback if collection-level limits are needed; MongoDB itself points to a gateway
in front of it.
To confirm: create a project-level, read-only MCP configuration, fetch a token with client
credentials, call the server through a test route, and check that the tool list has no write or
Atlas management tools, that a second project is unreachable, and that a call from an IP outside
the access list fails.

## Self-built

| System | What agents need it for | Leaning | To verify |
| --- | --- | --- | --- |
| Self-built | Whatever an Org team exposes. | Proxied, by definition. | How a team's server proves the gateway is its caller. Who assigns each tool's classification. |

## Okta

Okta is the identity provider for employees' agents (milestone 5, issue 15). It is not a tool
target and is not researched here.

## What this changes

- **Could be among the first proxied servers.** Two have a vendor-documented service identity,
  a read-only way to limit it, and a gateway-friendly shape: **Sumo Logic** (OAuth client
  credentials on a service account, read scopes) and **MongoDB Atlas** (a programmatic MCP
  configuration set to read-only, project-level roles). **Atlassian** is documented too, with a
  service account API key and read scopes, but needs a test of project limits before it can
  replace Otto's built-in Jira. All three need the test named in their sections before anyone
  claims they work; none has been run. Under decision 0011 all three are read-only, and the
  tested reach is recorded in each approval, often as one connector entry per team.
- **Need built-in connectors.** **GitHub** and **Jira** (Otto parity, milestone 4). **AWS**,
  brokered and read-only, because the hosted AWS server runs any API call and the breadth needs
  a per-team opt-in. **Akamai**, because every request must be signed with EdgeGrid and the
  vendor's gateway is undocumented here. **New Relic**, through NerdGraph, unless its hosted
  server works with an API key for a service user.
- **Blocked on per-user OAuth for service callers.** **Salesforce**'s hosted servers, by the
  vendor's own statement. **Slack**'s hosted server, which names only user tokens. New Relic's
  OAuth-only tools, and the AWS MCP Server's OAuth path. These fit employees' agents with
  gateway-held per-user grants at milestone 5, not Otto.
- **The proxied connector is required, as expected.** At least three of the nine systems are
  best reached as proxied servers, and the self-built ones always are. The proxied
  implementation therefore has to handle client-credentials token fetch and refresh, not only a
  static header.
- **Argument checks are not uniform.** Free-text arguments (JQL, SOQL, NRQL, log queries, SQL
  against Config) cannot be limited by the gateway reading them. Where a proxy is chosen, the
  credential must carry the limit: a service account's projects, a role's search filter, a
  project-level Atlas role. That is what each "to confirm" step tests.
- **Rate limits differ widely.** Sumo Logic allows 4 requests a second, New Relic 2,000 tool
  calls an hour per user, the hosted MongoDB server 500 requests a minute per user, and Slack
  channel history 1 request a minute for distributed apps outside the Marketplace (internal
  apps are exempt). The per-vendor queues and circuit
  breakers Otto defers become necessary as soon as several are live.
- **Minting is still not needed.** AWS federation or Roles Anywhere gives the gateway
  short-lived credentials without issuing any to a caller.

## Next step

Run the tests named in each section, starting with Sumo Logic and MongoDB Atlas, and record
each result here with its date. Open follow-on issues only for what a test has confirmed.
