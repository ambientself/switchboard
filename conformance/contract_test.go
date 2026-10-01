package conformance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestBootRefusals(t *testing.T) {
	h := newHarness(t)
	noIdentity := []string{"-identity-audience=", "-insecure-no-caller-identity"}
	noGrant := append(append([]string{}, noIdentity...), "-insecure-no-turn-grant")
	noAudit := append(append([]string{}, noGrant...), "-audit-disabled")
	badManifest := filepath.Join(h.dir, "bad.json")
	must(t, os.WriteFile(badManifest, []byte(`{"id":"bad","sandbox":{"serviceAccount":"not-an-sa"}}`), 0600))
	cases := []struct {
		name string
		args []string
		env  string
		want string
	}{
		{"identity_missing", []string{"-identity-audience="}, "", "no trusted issuer is configured"},
		{"default_audience_is_partial_configuration", nil, "", "identity checking is half configured"},
		{"identity_partial", []string{"-oidc-issuer", h.issuer}, "", "identity checking is half configured"},
		{"identity_contradiction", append(h.identityArgs(), "-insecure-no-caller-identity"), "", "contradiction"},
		{"bad_manifest", append([]string{"-oidc-issuer", h.issuer, "-identity-audience", "otto-gateway", "-team-manifest", badManifest}, h.grantArgs()...), "", "not system:serviceaccount"},
		{"grant_missing", noIdentity, "", "no -turn-grant-key-file"},
		{"grant_contradiction", append(append([]string{}, noIdentity...), append(h.grantArgs(), "-insecure-no-turn-grant")...), "", "one of them is a mistake"},
		{"audit_missing", noGrant, "", "no audit database is configured"},
		{"audit_contradiction", append(append([]string{}, noAudit...), "-database-url", h.dsn), "", "contradiction"},
		{"audit_as_owner", append(append([]string{}, noGrant...), "-database-url", strings.Replace(h.dsn, "otto_gateway:"+requiredEnv(t, "OTTO_TEST_GATEWAY_ROLE_PASSWORD"), "otto:local-conformance-only", 1)), "", `"otto" can write to session and outbox regardless of any grant`},
		{"connector_partial", append(append([]string{}, noAudit...), "-github-org", "test-org"), "", "the github connector is half configured"},
		{"legacy_app_key_variable", noAudit, "OTTO_GATEWAY_GITHUB_APP_ID=1234", "no longer reads the GitHub App key directly"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, requiredEnv(t, "OTTO_TEST_BINARY"), append([]string{"-addr", "127.0.0.1:0"}, tc.args...)...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			if tc.env != "" {
				cmd.Env = append(cmd.Env, tc.env)
			}
			out, err := cmd.CombinedOutput()
			require(t, ctx.Err() == nil, "boot refusal hung")
			require(t, err != nil, "invalid config unexpectedly started: %s", out)
			require(t, strings.Contains(string(out), tc.want), "want %q, got %s", tc.want, out)
			require(t, !strings.Contains(string(out), "otto-gateway listening"), "bound a socket before rejecting configuration")
		})
	}
}

func TestFixtureAndExplicitOptOuts(t *testing.T) {
	h := newHarness(t)
	h.start(mode{})
	r := h.request("initialize", map[string]any{"protocolVersion": "2099-01-01"}, h.legacyTurn().Headers)
	require(t, r.Error == nil && r.Result["protocolVersion"] == readBaseline(t).Protocol, "unexpected initialize: %s", r.Raw)
	require(t, strings.Contains(r.Result["instructions"].(string), "fixture"), "fixture mode not disclosed")
	require(t, r.Headers.Get("Mcp-Session-Id") == "", "unexpected client session")
	r = h.request("tools/list", nil, h.legacyTurn().Headers)
	var names []string
	for _, raw := range r.Result["tools"].([]any) {
		names = append(names, raw.(map[string]any)["name"].(string))
	}
	sort.Strings(names)
	require(t, reflect.DeepEqual(names, []string{"declare_unverified_claim", "github_search"}), "fixture tools: %v", names)
	c := h.legacyTurn()
	p := toolPayload(t, h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "fixture"}}, c.Headers))
	require(t, p["provenance"].(map[string]any)["fixture"] == true, "fixture result unmarked")
	require(t, len(h.rows(c.ID)) == 0, "audit opt-out wrote a row")
	require(t, len(h.vendor.snapshot()) == 0, "fixture contacted vendor")
	// With grant checking off, the acting context is the old five headers, all required.
	for _, header := range []string{"X-Otto-Session", "X-Otto-Turn", "X-Otto-Team", "X-Otto-Actor", "X-Otto-Fencing-Epoch"} {
		c = h.legacyTurn()
		delete(c.Headers, header)
		r = h.request("ping", nil, c.Headers)
		require(t, r.Error != nil && r.Error.Message == "this gateway requires the acting context on every call; missing: "+header, "missing context: %s", r.Raw)
	}
}

func TestLifecycleAndAuditCoverage(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	for _, method := range []string{"initialize", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			c := h.turn(nil)
			r := h.request(method, map[string]any{"protocolVersion": "2099-01-01"}, c.Headers)
			require(t, r.Status == 200 && r.Error == nil && r.ID == "request-1", "unexpected response: %s", r.Raw)
			require(t, r.Headers.Get("Mcp-Session-Id") == "", "unexpected session id")
			row := h.auditRow(c, "allowed", "ok")
			require(t, row["method"] == method && row["tool"] == nil, "wrong lifecycle audit row: %v", row)
			if method == "initialize" {
				require(t, r.Result["protocolVersion"] == readBaseline(t).Protocol, "protocol changed")
			}
		})
	}
	// Successful notifications have no response body and no audit row in this baseline.
	c := h.turn(nil)
	r := h.raw([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), c.Headers)
	require(t, r.Status == 202 && len(r.Raw) == 0, "notification: %s", r.Raw)
	require(t, len(h.rows(c.ID)) == 0, "accepted notification unexpectedly audited")
	// A malformed authenticated message is rejected before audit context is parsed.
	c = h.turn(nil)
	r = h.raw([]byte(`{`), c.Headers)
	require(t, r.Status == 400 && r.Error.Code == -32600, "malformed request: %s", r.Raw)
	require(t, len(h.rows(c.ID)) == 0, "malformed request unexpectedly audited")
	c = h.turn(nil)
	r = h.request("resources/list", nil, c.Headers)
	require(t, r.Error != nil && r.Error.Code == -32601 && r.Error.Message == `this gateway does not implement "resources/list"`, "method denial: %s", r.Raw)
	h.auditRow(c, "denied", "")
}

// The served tool set, each tool's classification and its required arguments
// are pinned in baseline.json. Jira is enabled so the list is the full one.
func TestToolInventory(t *testing.T) {
	h := newHarness(t)
	m := full
	m.jira = true
	h.start(m)
	r := h.request("tools/list", nil, h.turn(nil).Headers)
	require(t, r.Error == nil, "tools/list: %s", r.Raw)
	pin := readBaseline(t)
	seen := map[string]bool{}
	for _, raw := range r.Result["tools"].([]any) {
		d := raw.(map[string]any)
		name := d["name"].(string)
		expected, ok := pin.Tools[name]
		require(t, ok && !seen[name], "unknown or duplicate tool %s", name)
		seen[name] = true
		require(t, d["_ottoClassification"] == expected.Classification, "classification of %s is %v", name, d["_ottoClassification"])
		require(t, expected.Classification == "read" || expected.Classification == "write", "%s has a classification that must never be served", name)
		require(t, d["description"] != "" && d["inputSchema"].(map[string]any)["type"] == "object", "incomplete descriptor for %s", name)
		got := []string{}
		if raw := d["inputSchema"].(map[string]any)["required"]; raw != nil {
			must(t, json.Unmarshal(jsonBytes(t, raw), &got))
		}
		want := expected.Required
		if want == nil {
			want = []string{}
		}
		require(t, reflect.DeepEqual(got, want), "required arguments of %s are %v", name, got)
	}
	for name := range pin.Tools {
		require(t, seen[name], "pinned tool %s is not served", name)
	}
}

func TestIdentityDenialsAreOpaqueAndAudited(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	now := time.Now().Unix()
	valid := h.token(nil, nil)
	cases := []struct{ name, token string }{
		{"missing", ""}, {"malformed", "not-a-token"},
		{"expired", h.token(map[string]any{"iat": now - 600, "exp": now - 120}, nil)},
		{"not_yet_valid", h.token(map[string]any{"nbf": now + 120}, nil)},
		{"wrong_audience", h.token(map[string]any{"aud": "another-gateway"}, nil)},
		{"wrong_issuer", h.token(map[string]any{"iss": "http://127.0.0.1:1/untrusted"}, nil)},
		{"unknown_subject", h.token(map[string]any{"sub": "system:serviceaccount:conformance:unknown"}, nil)},
		{"lifetime_too_long", h.token(map[string]any{"exp": now + 7200}, nil)},
		{"missing_kid", h.token(nil, map[string]any{"kid": ""})},
		{"wrong_algorithm", h.token(nil, map[string]any{"alg": "HS256"})},
		{"invalid_signature", valid[:strings.LastIndex(valid, ".")+1] + "AAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := h.turn(nil)
			delete(c.Headers, "Authorization")
			if tc.token != "" {
				c.Headers["Authorization"] = "Bearer " + tc.token
			}
			r := h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "test"}}, c.Headers)
			require(t, r.Status == 401 && r.Error != nil && r.Error.Code == -32001 && r.Error.Message == opaqueDenial, "identity response: %s", r.Raw)
			require(t, r.ID == nil && r.Headers.Get("WWW-Authenticate") == `Bearer realm="otto-gateway"`, "unexpected challenge or request id")
			row := h.auditRow(c, "denied", "")
			require(t, row["verification"] == "failed" && row["subject_proved"] == nil && row["team_proved"] == nil, "false identity proof")
			require(t, row["method"] == nil && row["deny_reason"] == opaqueDenial, "auth gate read body or leaked reason")
			// The grant verified even though the pod did not, so the row keeps who the turn was for.
			require(t, row["actor_claimed"] == actor && row["team_claimed"] == team, "verified grant not recorded on a failed identity: %v", row)
		})
	}
	require(t, len(h.vendor.snapshot()) == 0, "identity denial reached vendor")
}

func TestTurnGrantIsRequiredAndVerified(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	// No grant at all is told apart from a bad one, and names the likely cause.
	c := h.turn(nil)
	delete(c.Headers, grantHeader)
	r := h.request("ping", nil, c.Headers)
	require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001 &&
		strings.HasPrefix(r.Error.Message, "this gateway requires a turn grant on every call and X-Otto-Turn-Grant was not sent"), "missing grant: %s", r.Raw)

	other := []byte(strings.Repeat("k", 64))
	good := h.turn(nil).Headers[grantHeader]
	cases := map[string]string{
		"wrong_key":        mintGrant(t, other, h.claims("turn-forged")),
		"tampered_claims":  resign(t, good, h.claims("turn-tampered"), map[string]any{"actor": "someone-else@example.invalid"}),
		"widened_tools":    resign(t, good, h.claims("turn-widened"), map[string]any{"tools": []string{"github_search", "github_merge_pr"}}),
		"expired":          mintGrant(t, h.grantKey, merge(h.claims("turn-expired"), map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})),
		"no_tools":         mintGrant(t, h.grantKey, merge(h.claims("turn-empty"), map[string]any{"tools": []string{}})),
		"no_epoch":         mintGrant(t, h.grantKey, merge(h.claims("turn-epoch"), map[string]any{"epoch": 0})),
		"wrong_version":    "v2" + strings.TrimPrefix(good, "v1"),
		"not_a_grant":      "not-a-grant",
		"legacy_headers":   "",
		"oversized":        "v1." + strings.Repeat("a", 9000),
		"qualified_tool":   mintGrant(t, h.grantKey, merge(h.claims("turn-qualified"), map[string]any{"tools": []string{"mcp__otto-gateway__github_search"}})),
		"missing_actor":    mintGrant(t, h.grantKey, merge(h.claims("turn-anon"), map[string]any{"actor": ""})),
		"missing_team":     mintGrant(t, h.grantKey, merge(h.claims("turn-teamless"), map[string]any{"team": ""})),
		"missing_session":  mintGrant(t, h.grantKey, merge(h.claims("turn-sessionless"), map[string]any{"sid": ""})),
		"missing_exec":     mintGrant(t, h.grantKey, merge(h.claims("turn-execless"), map[string]any{"eid": ""})),
		"missing_turn":     mintGrant(t, h.grantKey, merge(h.claims(""), nil)),
		"empty_tool_entry": mintGrant(t, h.grantKey, merge(h.claims("turn-blank"), map[string]any{"tools": []string{""}})),
	}
	for name, grant := range cases {
		t.Run(name, func(t *testing.T) {
			before := h.auditCount()
			headers := map[string]string{"Authorization": "Bearer " + h.token(nil, nil), grantHeader: grant}
			if name == "legacy_headers" {
				// The old headers are not an alternative once grants are verified.
				headers = h.legacyTurn().Headers
			}
			r := h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "test"}}, headers)
			require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001, "bad grant was accepted: %s", r.Raw)
			if name == "legacy_headers" {
				require(t, strings.HasPrefix(r.Error.Message, "this gateway requires a turn grant on every call"), "legacy headers: %s", r.Raw)
			} else {
				require(t, r.Error.Message == grantDenial, "grant failure told the caller which check failed: %s", r.Raw)
			}
			row := h.newestAuditRow(before)
			require(t, row["decision"] == "denied" && row["verification"] == "proved" && row["subject_proved"] == subject, "grant denial row: %v", row)
			// Nothing from an unverified grant is recorded as who the call was for.
			require(t, row["actor_claimed"] == nil && row["team_claimed"] == nil && row["turn_id"] == nil && row["session_id"] == nil, "unverified grant contents were recorded: %v", row)
		})
	}
	require(t, len(h.vendor.snapshot()) == 0, "grant denial reached vendor")
}

func TestGrantTeamMustMatchProvedTeam(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	c := h.turn(map[string]any{"team": "another-team"})
	r := h.request("ping", nil, c.Headers)
	want := `the verified caller's ServiceAccount resolves to team "test-team", but this turn's grant was minted for team "another-team"; a sandbox's proven identity and its granted team must agree`
	require(t, r.Error != nil && r.Error.Message == want, "mismatch denial: %s", r.Raw)
	row := h.auditRow(c, "denied", "")
	require(t, row["team_proved"] == team && row["team_claimed"] == "another-team" && row["subject_proved"] == subject, "lost proved/claimed separation")
	c = h.turn(map[string]any{"team": "another-team"})
	r = h.raw([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), c.Headers)
	require(t, r.Status == 400 && len(r.Raw) == 0, "denied notification must have no body")
	h.auditRow(c, "denied", "")
	require(t, len(h.vendor.snapshot()) == 0, "mismatch reached vendor")
}

func TestToolOutsideTheGrantIsRefused(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	c := h.turn(map[string]any{"tools": []string{"github_get_file"}})
	r := h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "test"}}, c.Headers)
	want := `this turn was granted only "github_get_file"; "github_search" is served by this gateway but was not granted to this turn`
	require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001 && r.Error.Message == want, "ungranted tool: %s", r.Raw)
	row := h.auditRow(c, "denied", "")
	require(t, row["tool"] == "github_search" && row["classification"] == "read", "ungranted denial row: %v", row)
	// The grant narrows calls; it does not hide the served list.
	r = h.request("tools/list", nil, c.Headers)
	require(t, r.Error == nil && len(r.Result["tools"].([]any)) > 1, "tools/list under a narrow grant: %s", r.Raw)
	require(t, len(h.vendor.snapshot()) == 0, "ungranted tool reached vendor")
}

func TestOriginalToolsAndBrokeredCredentials(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	cases := []struct {
		name string
		args map[string]any
	}{
		{"github_search", map[string]any{"query": "repo:outside/repo evidence"}},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "file.txt", "ref": "main"}},
		{"github_get_pr", map[string]any{"owner": "test-org", "repo": "repo", "number": 42}},
		{"github_create_pr", map[string]any{"owner": "test-org", "repo": "repo", "title": "Proposal", "head": "proposal", "base": "main", "body": "review"}},
		{"github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "review"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := h.turn(nil)
			r := h.request("tools/call", map[string]any{"name": tc.name, "arguments": tc.args, "_meta": map[string]any{"claudecode/toolUseId": "toolu_" + tc.name}}, c.Headers)
			p := toolPayload(t, r)
			class := readBaseline(t).Tools[tc.name].Classification
			provenance := p["provenance"].(map[string]any)
			require(t, provenance["tool"] == tc.name && provenance["classification"] == class && provenance["trust"] == "untrusted-external" && provenance["fixture"] == false, "incorrect provenance")
			scope := p["scope"].(map[string]any)
			require(t, scope["team"] == team && scope["provedTeam"] == team && scope["actor"] == actor, "incorrect scope")
			require(t, !bytes.Contains(r.Raw, []byte(fakeTokenPrefix)), "installation credential leaked in result")
			row := h.auditRow(c, "allowed", "ok")
			require(t, row["verification"] == "proved" && row["tool"] == tc.name && row["classification"] == class && row["actor_claimed"] == actor && row["subject_proved"] == subject, "incorrect audit row: %v", row)
			require(t, row["latency_ms"].(float64) >= 0 && row["deny_reason"] == nil && row["refusal_reason"] == nil, "incorrect completion")
			require(t, row["fencing_epoch"] == "7" && row["session_id"] == "session-test", "grant context not recorded: %v", row)
			require(t, row["harness_tool_use_id"] == "toolu_"+tc.name, "caller's tool-use id not recorded: %v", row["harness_tool_use_id"])
			switch tc.name {
			case "github_search":
				// The outside repository is dropped by the per-row scope filter.
				require(t, len(p["results"].([]any)) == 10 && p["truncated"] == true, "search not bounded: %s", r.Raw)
				require(t, scope["query"] == "(repo:outside/repo evidence) org:test-org", "caller query not parenthesised and scoped: %v", scope["query"])
			case "github_get_file":
				require(t, p["file"].(map[string]any)["text"] == "hello from the fake vendor", "file content mismatch")
			case "github_get_pr":
				require(t, len(p["comments"].([]any)) == 20 && p["commentsTruncated"] == true, "comments not bounded")
			case "github_create_pr":
				require(t, p["pr"].(map[string]any)["number"] == float64(42), "PR confirmation mismatch")
			case "github_pr_comment":
				require(t, p["comment"].(map[string]any)["id"] == float64(73), "comment confirmation mismatch")
			}
		})
	}
	writes := 0
	for _, r := range h.vendor.snapshot() {
		require(t, r.AuditPending, "vendor request preceded audit begin: %s", r.Path)
		if strings.HasPrefix(r.Path, "/app/") {
			if strings.HasSuffix(r.Path, "/access_tokens") {
				// Every token is asked for by name: the team's repositories and a stated permission set.
				require(t, reflect.DeepEqual(r.Body["repositories"], []any{"repo"}), "token not scoped to the team's repositories: %v", r.Body)
				require(t, len(r.Body["permissions"].(map[string]any)) > 0, "token asked for with no stated permissions")
			}
			continue
		}
		require(t, h.vendor.issued(r.Authorization), "caller credential forwarded downstream")
		q, err := url.ParseQuery(r.Query)
		must(t, err)
		if r.Path == "/search/issues" {
			require(t, q.Get("per_page") == "10" && strings.HasSuffix(q.Get("q"), ") org:test-org") && q.Get("advanced_search") == "true", "unbounded/unscoped search: %s", r.Query)
		}
		if r.Method == "GET" && strings.HasSuffix(r.Path, "/comments") {
			require(t, q.Get("per_page") == "21", "comment bound changed")
		}
		if r.Method == "POST" {
			writes++
			require(t, r.Path == "/repos/test-org/repo/pulls" || r.Path == "/repos/test-org/repo/issues/42/comments", "non-proposal write")
			if r.Path == "/repos/test-org/repo/pulls" {
				require(t, r.Body["draft"] == true, "pull request not opened as a draft: %v", r.Body)
			}
		}
	}
	h.vendor.mu.Lock()
	valid := h.vendor.appAuthValid
	h.vendor.mu.Unlock()
	require(t, writes == 2 && valid, "broker/proposal path mismatch: writes=%d appAuthValid=%v", writes, valid)
}

func TestUnknownAndDestructiveNamesNeverReachVendor(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	for _, name := range []string{"unknown", "github_merge_pr", "github_delete_repo"} {
		r, c := h.call(name, map[string]any{})
		require(t, r.Error != nil && r.Error.Code == -32001 && strings.HasPrefix(r.Error.Message, "this gateway exposes ") &&
			strings.HasSuffix(r.Error.Message, fmt.Sprintf(`; %q is not classified and is therefore denied`, name)), "unknown denial changed: %s", r.Raw)
		row := h.auditRow(c, "denied", "")
		require(t, row["tool"] == name && row["classification"] == nil, "invented classification")
	}
	require(t, len(h.vendor.snapshot()) == 0, "unknown tool reached vendor")
}

// What a call names is checked by the connector after the audit row is open.
// A scope refusal is the outcome "refused"; a malformed argument is "error".
func TestScopeRefusalsAndArgumentErrors(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	cases := []struct {
		name    string
		args    any
		outcome string
	}{
		{"github_search", map[string]any{"query": "org:outside evidence"}, "refused"},
		{"github_get_file", map[string]any{"owner": "outside", "repo": "repo", "path": "file.txt"}, "refused"},
		{"github_get_pr", map[string]any{"owner": "outside", "repo": "repo", "number": 42}, "refused"},
		{"github_create_pr", map[string]any{"owner": "outside", "repo": "repo", "title": "x", "head": "x", "base": "main"}, "refused"},
		{"github_pr_comment", map[string]any{"owner": "outside", "repo": "repo", "number": 42, "body": "x"}, "refused"},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "not-the-teams", "path": "file.txt"}, "refused"},
		{"github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "atlantis apply"}, "refused"},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "../escape"}, "error"},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "../escape", "path": "file.txt"}, "error"},
		{"github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": ""}, "error"},
		{"github_get_pr", map[string]any{"owner": "test-org", "repo": "repo", "number": 0}, "error"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r, c := h.call(tc.name, tc.args)
			require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001, "call was allowed: %s", r.Raw)
			row := h.auditRow(c, "allowed", tc.outcome)
			require(t, row["deny_reason"] == nil, "connector outcome misreported as a dispatcher denial")
			if tc.outcome == "refused" {
				require(t, row["refusal_reason"] == r.Error.Message, "refusal reason differs from what the caller read: %v", row["refusal_reason"])
			} else {
				require(t, row["refusal_reason"] == nil, "argument error recorded as a policy refusal")
			}
		})
	}
	require(t, len(h.vendor.snapshot()) == 0, "refused or malformed calls reached vendor, including token minting")
}

func TestLargeFilesAndVendorErrorsAreBounded(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	r, c := h.call("github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "large.txt"})
	p := toolPayload(t, r)
	file := p["file"].(map[string]any)
	require(t, file["truncated"] == true && len(file["text"].(string)) <= 256*1024+3, "file output not bounded")
	h.auditRow(c, "allowed", "ok")
	h.vendor.setMode("error")
	r, c = h.call("github_search", map[string]any{"query": "error"})
	require(t, r.Error != nil && strings.Contains(r.Error.Message, "HTTP 503") && len(r.Error.Message) < 500, "vendor error not bounded: %s", r.Raw)
	require(t, !bytes.Contains(r.Raw, []byte(fakeTokenPrefix)), "credential leaked in error")
	h.auditRow(c, "allowed", "error")
}

func TestAuditBeginFailureBlocksExecutionAndDenial(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	_, err := h.pool.Exec(context.Background(), "ALTER TABLE gateway_audit RENAME TO audit_unavailable")
	must(t, err)
	for _, name := range []string{"github_search", "unknown"} {
		r, _ := h.call(name, map[string]any{"query": "test"})
		require(t, r.Status == 200 && r.Error != nil && r.Error.Message == auditDenial, "audit failure response: %s", r.Raw)
	}
	c := h.turn(nil)
	delete(c.Headers, "Authorization")
	r := h.request("ping", nil, c.Headers)
	require(t, r.Status == 401 && r.Error != nil && r.Error.Message == auditDenial, "unauditable identity denial: %s", r.Raw)
	require(t, len(h.vendor.snapshot()) == 0, "tool executed without an audit begin")
}

func TestAuditFinishFailureDoesNotUndoSuccess(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	_, err := h.pool.Exec(context.Background(), `CREATE FUNCTION reject_finish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected finish failure'; END $$;
CREATE TRIGGER fail_finish BEFORE UPDATE ON gateway_audit FOR EACH ROW EXECUTE FUNCTION reject_finish();`)
	must(t, err)
	r, c := h.call("github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "one write"})
	toolPayload(t, r)
	// Stop waits for the handler to finish, so NULL is not a transient observation.
	h.stop()
	row := h.auditRow(c, "allowed", "")
	require(t, row["latency_ms"] == nil, "finish failure left contradictory outcome")
	writes := 0
	for _, r := range h.vendor.snapshot() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/comments") {
			writes++
		}
	}
	require(t, writes == 1, "write was lost or retried after finish failure")
}

// A tool call's audit row is complete by the time the caller can read the answer.
func TestAnswerFollowsAuditFinish(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	// Slow the finishing write down, so an answer that did not wait for it is
	// caught every time and not only when a race happens to go the wrong way.
	_, err := h.pool.Exec(context.Background(), `CREATE FUNCTION slow_finish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$;
CREATE TRIGGER slow_finish BEFORE UPDATE ON gateway_audit FOR EACH ROW EXECUTE FUNCTION slow_finish();`)
	must(t, err)
	for i := 0; i < 3; i++ {
		r, c := h.call("github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "file.txt"})
		toolPayload(t, r)
		rows := h.rows(c.ID)
		require(t, len(rows) == 1 && rows[0]["outcome"] == "ok", "answer arrived before the audit row was finished: %v", rows)
	}
}

func TestDisconnectStillFinishesAudit(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	h.vendor.setMode("blocked")
	c := h.turn(nil)
	body := jsonBytes(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "github_search", "arguments": map[string]any{"query": "wait"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", h.url+"/mcp", bytes.NewReader(body))
	must(t, err)
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-h.vendor.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("vendor never received blocked request")
	}
	h.auditRow(c, "allowed", "")
	cancel()
	select {
	case err := <-done:
		require(t, err != nil, "request unexpectedly succeeded")
	case <-time.After(3 * time.Second):
		t.Fatal("request did not cancel")
	}
	h.auditRow(c, "allowed", "error")
}

func TestRepeatedCommentIsWrittenTwice(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	c := h.turn(nil)
	c.Headers["Idempotency-Key"] = "same-key"
	params := map[string]any{"name": "github_pr_comment", "arguments": map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "same write"}}
	for i := 0; i < 2; i++ {
		toolPayload(t, h.request("tools/call", params, c.Headers))
	}
	h.stop()
	rows := h.rows(c.ID)
	require(t, len(rows) == 2, "baseline unexpectedly deduplicated requests")
	writes := 0
	for _, r := range h.vendor.snapshot() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/comments") {
			writes++
		}
	}
	require(t, writes == 2, "baseline write behavior changed")
}

func TestDisabledIdentityIsDistinctFromFailed(t *testing.T) {
	h := newHarness(t)
	h.start(mode{grant: true, audit: true})
	c := h.turn(nil)
	toolPayload(t, h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "test"}}, c.Headers))
	row := h.auditRow(c, "allowed", "ok")
	require(t, row["verification"] == "disabled" && row["subject_proved"] == nil && row["team_proved"] == nil, "disabled identity fabricated proof")
}

// With pod identity off there is no proved team, so the real connector has no
// scope to mint a token for and answers nothing.
func TestRealConnectorNeedsAProvedTeam(t *testing.T) {
	h := newHarness(t)
	h.start(mode{grant: true, audit: true, connector: true})
	r, c := h.call("github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "file.txt"})
	require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001, "unproved caller was served: %s", r.Raw)
	row := h.auditRow(c, "allowed", "refused")
	require(t, row["verification"] == "disabled", "row: %v", row)
	for _, o := range h.vendor.snapshot() {
		require(t, !strings.HasSuffix(o.Path, "/access_tokens"), "a token was minted for a caller with no proved team")
	}
}

// resign keeps a genuine grant's key id and signature and swaps in different,
// well-formed claims: what a sandbox would send to put another name on a call.
// Only the signature check can refuse it.
func resign(t *testing.T, genuine string, claims, changes map[string]any) string {
	t.Helper()
	parts := strings.Split(genuine, ".")
	require(t, len(parts) == 4, "unexpected grant shape")
	parts[2] = base64.RawURLEncoding.EncodeToString(jsonBytes(t, merge(claims, changes)))
	return strings.Join(parts, ".")
}

func merge(base, changes map[string]any) map[string]any {
	for k, v := range changes {
		base[k] = v
	}
	return base
}
