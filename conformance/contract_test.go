package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBootRefusals(t *testing.T) {
	h := newHarness(t)
	missing := []string{"-identity-audience="}
	insecure := []string{"-identity-audience=", "-insecure-no-caller-identity"}
	noAudit := append(append([]string{}, insecure...), "-audit-disabled")
	badManifest := filepath.Join(h.dir, "bad.json")
	must(t, os.WriteFile(badManifest, []byte(`{"id":"bad","sandbox":{"serviceAccount":"not-an-sa"}}`), 0600))
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"identity_missing", missing, "no trusted issuer is configured"},
		{"default_audience_is_partial_configuration", nil, "identity checking is half configured"},
		{"identity_partial", []string{"-oidc-issuer", h.issuer}, "identity checking is half configured"},
		{"identity_contradiction", append(h.identityArgs(), "-insecure-no-caller-identity"), "contradiction"},
		{"bad_manifest", []string{"-oidc-issuer", h.issuer, "-identity-audience", "otto-gateway", "-team-manifest", badManifest}, "not system:serviceaccount"},
		{"audit_missing", insecure, "no audit database is configured"},
		{"audit_contradiction", append(append([]string{}, noAudit...), "-database-url", h.dsn), "contradiction"},
		{"connector_partial", append(append([]string{}, noAudit...), "-github-app-id", "1234"), "half configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, requiredEnv(t, "OTTO_TEST_BINARY"), append([]string{"-addr", "127.0.0.1:0"}, tc.args...)...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
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
	h.start(false, false, false)
	r := h.request("initialize", map[string]any{"protocolVersion": "2099-01-01"}, h.headers())
	require(t, r.Error == nil && r.Result["protocolVersion"] == readBaseline(t).Protocol, "unexpected initialize: %s", r.Raw)
	require(t, strings.Contains(r.Result["instructions"].(string), "fixture"), "fixture mode not disclosed")
	require(t, r.Headers.Get("Mcp-Session-Id") == "", "unexpected client session")
	r = h.request("tools/list", nil, h.headers())
	tools := r.Result["tools"].([]any)
	require(t, len(tools) == 1, "fixture tool count: %d", len(tools))
	r, headers := h.call("github_search", map[string]any{"query": "fixture"})
	p := toolPayload(t, r)
	require(t, p["provenance"].(map[string]any)["fixture"] == true, "fixture result unmarked")
	require(t, len(h.rows(headers["X-Otto-Turn"])) == 0, "audit opt-out wrote a row")
	require(t, len(h.vendor.snapshot()) == 0, "fixture contacted vendor")
}

func TestLifecycleAndAuditCoverage(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	for _, method := range []string{"initialize", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			headers := h.headers()
			r := h.request(method, map[string]any{"protocolVersion": "2099-01-01"}, headers)
			require(t, r.Status == 200 && r.Error == nil && r.ID == "request-1", "unexpected response: %s", r.Raw)
			require(t, r.Headers.Get("Mcp-Session-Id") == "", "unexpected session id")
			row := h.auditRow(headers, "allowed", "ok")
			require(t, row["method"] == method && row["tool"] == nil, "wrong lifecycle audit row: %v", row)
			if method == "initialize" {
				require(t, r.Result["protocolVersion"] == readBaseline(t).Protocol, "protocol changed")
			}
			if method == "tools/list" {
				tools := r.Result["tools"].([]any)
				pin := readBaseline(t)
				require(t, len(tools) == len(pin.Tools), "tool count: %d", len(tools))
				seen := map[string]bool{}
				required := map[string][]string{
					"github_search":     {"query"},
					"github_get_file":   {"owner", "repo", "path"},
					"github_get_pr":     {"owner", "repo", "number"},
					"github_create_pr":  {"owner", "repo", "title", "head", "base"},
					"github_pr_comment": {"owner", "repo", "number", "body"},
				}
				for _, raw := range tools {
					d := raw.(map[string]any)
					name := d["name"].(string)
					expected, ok := pin.Tools[name]
					require(t, ok && !seen[name], "unknown/duplicate tool %s", name)
					seen[name] = true
					require(t, d["_ottoClassification"] == expected.Classification, "classification mismatch for %s", name)
					require(t, d["description"] != "" && d["inputSchema"].(map[string]any)["type"] == "object", "incomplete descriptor")
					var got []string
					must(t, json.Unmarshal(jsonBytes(t, d["inputSchema"].(map[string]any)["required"]), &got))
					require(t, reflect.DeepEqual(got, required[name]), "required arguments changed for %s: %v", name, got)
				}
			}
		})
	}
	// Successful notifications have no response body and no audit row in this baseline.
	headers := h.headers()
	r := h.raw([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), headers)
	require(t, r.Status == 202 && len(r.Raw) == 0, "notification: %s", r.Raw)
	require(t, len(h.rows(headers["X-Otto-Turn"])) == 0, "accepted notification unexpectedly audited")
	// A malformed authenticated message is rejected before audit context is parsed.
	headers = h.headers()
	r = h.raw([]byte(`{`), headers)
	require(t, r.Status == 400 && r.Error.Code == -32600, "malformed request: %s", r.Raw)
	require(t, len(h.rows(headers["X-Otto-Turn"])) == 0, "malformed request unexpectedly audited")
	headers = h.headers()
	r = h.request("resources/list", nil, headers)
	require(t, r.Error != nil && r.Error.Code == -32601 && r.Error.Message == `this gateway does not implement "resources/list"`, "method denial: %s", r.Raw)
	h.auditRow(headers, "denied", "")
}

func TestIdentityDenialsAreOpaqueAndAudited(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
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
			headers := h.headers()
			delete(headers, "Authorization")
			if tc.token != "" {
				headers["Authorization"] = "Bearer " + tc.token
			}
			r := h.request("tools/call", map[string]any{"name": "github_search", "arguments": map[string]any{"query": "test"}}, headers)
			require(t, r.Status == 401 && r.Error != nil && r.Error.Code == -32001 && r.Error.Message == opaqueDenial, "identity response: %s", r.Raw)
			require(t, r.ID == nil && r.Headers.Get("WWW-Authenticate") == `Bearer realm="otto-gateway"`, "unexpected challenge or request id")
			row := h.auditRow(headers, "denied", "")
			require(t, row["verification"] == "failed" && row["subject_proved"] == nil && row["team_proved"] == nil, "false identity proof")
			require(t, row["method"] == nil && row["deny_reason"] == opaqueDenial, "auth gate read body or leaked reason")
		})
	}
	require(t, len(h.vendor.snapshot()) == 0, "identity denial reached vendor")
}

func TestActingContextAndTeamMismatch(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	headers := h.headers()
	headers["X-Otto-Team"] = "another-team"
	r := h.request("ping", nil, headers)
	want := `the verified caller's ServiceAccount resolves to team "test-team", but the X-Otto-Team header claims "another-team"; a sandbox's proven identity and its claimed team must agree`
	require(t, r.Error != nil && r.Error.Message == want, "mismatch denial: %s", r.Raw)
	row := h.auditRow(headers, "denied", "")
	require(t, row["team_proved"] == team && row["team_claimed"] == "another-team" && row["subject_proved"] == subject, "lost proved/claimed separation")
	for _, header := range []string{"X-Otto-Session", "X-Otto-Team", "X-Otto-Actor", "X-Otto-Fencing-Epoch"} {
		headers = h.headers()
		delete(headers, header)
		r = h.request("ping", nil, headers)
		require(t, r.Error != nil && r.Error.Message == "this gateway requires the acting context on every call; missing: "+header, "missing context: %s", r.Raw)
		h.auditRow(headers, "denied", "")
	}
	headers = h.headers()
	delete(headers, "X-Otto-Actor")
	r = h.raw([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), headers)
	require(t, r.Status == 400 && len(r.Raw) == 0, "denied notification must have no body")
	h.auditRow(headers, "denied", "")
	require(t, len(h.vendor.snapshot()) == 0, "context denial reached vendor")
}

func TestFiveToolsAndBrokeredCredentials(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
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
			r, headers := h.call(tc.name, tc.args)
			p := toolPayload(t, r)
			class := readBaseline(t).Tools[tc.name].Classification
			provenance := p["provenance"].(map[string]any)
			require(t, provenance["tool"] == tc.name && provenance["classification"] == class && provenance["trust"] == "untrusted-external" && provenance["fixture"] == false, "incorrect provenance")
			scope := p["scope"].(map[string]any)
			require(t, scope["team"] == team && scope["provedTeam"] == team && scope["actor"] == "claimed-person", "incorrect scope")
			require(t, !bytes.Contains(r.Raw, []byte(fakeToken)), "installation credential leaked in result")
			row := h.auditRow(headers, "allowed", "ok")
			require(t, row["verification"] == "proved" && row["tool"] == tc.name && row["classification"] == class && row["actor_claimed"] == "claimed-person" && row["subject_proved"] == subject, "incorrect audit row: %v", row)
			require(t, row["latency_ms"].(float64) >= 0 && row["deny_reason"] == nil, "incorrect completion")
			switch tc.name {
			case "github_search":
				require(t, len(p["results"].([]any)) == 10 && p["truncated"] == true, "search not bounded")
				require(t, scope["query"] == "repo:outside/repo evidence org:test-org", "org qualifier not appended")
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
	requests := h.vendor.snapshot()
	mints := 0
	discoveries := 0
	writes := 0
	for _, r := range requests {
		require(t, r.AuditPending, "vendor request preceded audit begin: %s", r.Path)
		if r.Path == "/app/installations" {
			discoveries++
			continue
		}
		if strings.HasSuffix(r.Path, "/access_tokens") {
			mints++
			continue
		}
		require(t, r.Authorization == "Bearer "+fakeToken, "caller credential forwarded downstream")
		q, err := url.ParseQuery(r.Query)
		must(t, err)
		if r.Path == "/search/issues" {
			require(t, q.Get("per_page") == "10" && strings.HasSuffix(q.Get("q"), " org:test-org"), "unbounded/unscoped search")
		}
		if r.Method == "GET" && strings.HasSuffix(r.Path, "/comments") {
			require(t, q.Get("per_page") == "21", "comment bound changed")
		}
		if r.Method == "POST" {
			writes++
			require(t, r.Path == "/repos/test-org/repo/pulls" || r.Path == "/repos/test-org/repo/issues/42/comments", "non-proposal write")
		}
	}
	h.vendor.mu.Lock()
	valid := h.vendor.appAuthValid
	h.vendor.mu.Unlock()
	require(t, mints == 1 && discoveries == 1 && writes == 2 && valid, "broker/proposal path mismatch: mints=%d discoveries=%d writes=%d", mints, discoveries, writes)
}

func TestUnknownAndDestructiveNamesNeverReachVendor(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	for _, name := range []string{"unknown", "github_merge_pr", "github_delete_repo"} {
		r, headers := h.call(name, map[string]any{})
		want := fmt.Sprintf(`this gateway exposes "github_search", "github_get_file", "github_get_pr", "github_create_pr", "github_pr_comment"; %q is not classified and is therefore denied`, name)
		require(t, r.Error != nil && r.Error.Code == -32001 && r.Error.Message == want, "unknown denial changed: %s", r.Raw)
		row := h.auditRow(headers, "denied", "")
		require(t, row["tool"] == name && row["classification"] == nil, "invented classification")
	}
	require(t, len(h.vendor.snapshot()) == 0, "unknown tool reached vendor")
}

func TestOrganizationAndArgumentBoundaries(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	cases := []struct {
		name string
		args any
	}{
		{"github_search", map[string]any{"query": "org:outside evidence"}},
		{"github_get_file", map[string]any{"owner": "outside", "repo": "repo", "path": "file.txt"}},
		{"github_get_pr", map[string]any{"owner": "outside", "repo": "repo", "number": 42}},
		{"github_create_pr", map[string]any{"owner": "outside", "repo": "repo", "title": "x", "head": "x", "base": "main"}},
		{"github_pr_comment", map[string]any{"owner": "outside", "repo": "repo", "number": 42, "body": "x"}},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "../escape"}},
		{"github_get_file", map[string]any{"owner": "test-org", "repo": "../escape", "path": "file.txt"}},
		{"github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": ""}},
		{"github_get_pr", map[string]any{"owner": "test-org", "repo": "repo", "number": 0}},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r, headers := h.call(tc.name, tc.args)
			require(t, r.Status == 200 && r.Error != nil && r.Error.Code == -32001, "invalid arguments were allowed: %s", r.Raw)
			row := h.auditRow(headers, "allowed", "error")
			require(t, row["deny_reason"] == nil, "connector error misreported as policy denial")
		})
	}
	require(t, len(h.vendor.snapshot()) == 0, "invalid arguments reached vendor, including token minting")
}

func TestLargeFilesAndVendorErrorsAreBounded(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	r, headers := h.call("github_get_file", map[string]any{"owner": "test-org", "repo": "repo", "path": "large.txt"})
	p := toolPayload(t, r)
	file := p["file"].(map[string]any)
	require(t, file["truncated"] == true && len(file["text"].(string)) <= 256*1024+3, "file output not bounded")
	h.auditRow(headers, "allowed", "ok")
	h.vendor.setMode("error")
	r, headers = h.call("github_search", map[string]any{"query": "error"})
	require(t, r.Error != nil && strings.Contains(r.Error.Message, "HTTP 503") && len(r.Error.Message) < 500, "vendor error not bounded: %s", r.Raw)
	require(t, !bytes.Contains(r.Raw, []byte(fakeToken)), "credential leaked in error")
	h.auditRow(headers, "allowed", "error")
}

func TestAuditBeginFailureBlocksExecutionAndDenial(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	_, err := h.pool.Exec(context.Background(), "ALTER TABLE gateway_audit RENAME TO audit_unavailable")
	must(t, err)
	for _, name := range []string{"github_search", "unknown"} {
		r, _ := h.call(name, map[string]any{"query": "test"})
		require(t, r.Status == 200 && r.Error != nil && r.Error.Message == auditDenial, "audit failure response: %s", r.Raw)
	}
	headers := h.headers()
	delete(headers, "Authorization")
	r := h.request("ping", nil, headers)
	require(t, r.Status == 401 && r.Error != nil && r.Error.Message == auditDenial, "unauditable identity denial: %s", r.Raw)
	require(t, len(h.vendor.snapshot()) == 0, "tool executed without an audit begin")
}

func TestAuditFinishFailureDoesNotUndoSuccess(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	_, err := h.pool.Exec(context.Background(), `CREATE FUNCTION reject_finish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected finish failure'; END $$;
CREATE TRIGGER fail_finish BEFORE UPDATE ON gateway_audit FOR EACH ROW EXECUTE FUNCTION reject_finish();`)
	must(t, err)
	r, headers := h.call("github_pr_comment", map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "one write"})
	toolPayload(t, r)
	// Stop waits for the handler to finish, so NULL is not a transient observation.
	h.stop()
	row := h.auditRow(headers, "allowed", "")
	require(t, row["latency_ms"] == nil, "finish failure left contradictory outcome")
	writes := 0
	for _, r := range h.vendor.snapshot() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/comments") {
			writes++
		}
	}
	require(t, writes == 1, "write was lost or retried after finish failure")
}

func TestDisconnectStillFinishesAudit(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	h.vendor.setMode("blocked")
	headers := h.headers()
	body := jsonBytes(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "github_search", "arguments": map[string]any{"query": "wait"}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", h.url+"/mcp", bytes.NewReader(body))
	must(t, err)
	for k, v := range headers {
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
	h.auditRow(headers, "allowed", "")
	cancel()
	select {
	case err := <-done:
		require(t, err != nil, "request unexpectedly succeeded")
	case <-time.After(3 * time.Second):
		t.Fatal("request did not cancel")
	}
	h.auditRow(headers, "allowed", "error")
}

func TestBaselineRecordsEpochAndRepeatsWritesWithoutReceipts(t *testing.T) {
	h := newHarness(t)
	h.start(true, true, true)
	headers := h.headers()
	headers["X-Otto-Fencing-Epoch"] = "not-a-validated-epoch"
	headers["Idempotency-Key"] = "same-key"
	params := map[string]any{"name": "github_pr_comment", "arguments": map[string]any{"owner": "test-org", "repo": "repo", "number": 42, "body": "same write"}}
	for i := 0; i < 2; i++ {
		toolPayload(t, h.request("tools/call", params, headers))
	}
	h.stop()
	rows := h.rows(headers["X-Otto-Turn"])
	require(t, len(rows) == 2, "baseline unexpectedly deduplicated requests")
	for _, row := range rows {
		require(t, row["fencing_epoch"] == "not-a-validated-epoch" && row["outcome"] == "ok", "epoch is no longer only recorded")
	}
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
	h.start(false, true, false)
	r, headers := h.call("github_search", map[string]any{"query": "test"})
	toolPayload(t, r)
	row := h.auditRow(headers, "allowed", "ok")
	require(t, row["verification"] == "disabled" && row["subject_proved"] == nil && row["team_proved"] == nil, "disabled identity fabricated proof")
}
