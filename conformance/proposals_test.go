package conformance

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// github_propose_change and github_amend_change against the fake repository in
// harness_test.go, which keeps refs, commits and pull requests between calls.

// proposal is a github_propose_change call's arguments.
func proposal(key string, changes map[string]any) map[string]any {
	return merge(map[string]any{"owner": "test-org", "repo": "repo", "title": "Bump the widget", "idempotency_key": key, "body": "Why this change",
		"files": []any{map[string]any{"path": "a.txt", "content": "x"}}, "unverifiedClaims": []any{"the latest widget is 1.2"}}, changes)
}

func (h *harness) proposalRows() []map[string]any {
	h.t.Helper()
	r, err := h.pool.Query(context.Background(), "SELECT row_to_json(p) FROM github_pr_proposal p ORDER BY created_at")
	must(h.t, err)
	defer r.Close()
	var out []map[string]any
	for r.Next() {
		var raw []byte
		must(h.t, r.Scan(&raw))
		var row map[string]any
		must(h.t, json.Unmarshal(raw, &row))
		out = append(out, row)
	}
	must(h.t, r.Err())
	return out
}

func (h *harness) ref(name string) (string, bool) {
	h.vendor.mu.Lock()
	defer h.vendor.mu.Unlock()
	sha, ok := h.vendor.repo.refs["heads/"+name]
	return sha, ok
}

func writesIn(obs []observation) []observation {
	out := []observation{}
	for _, o := range obs {
		if o.Method != "GET" {
			out = append(out, o)
		}
	}
	return out
}

func writePaths(obs []observation) []string {
	out := []string{}
	for _, o := range writesIn(obs) {
		out = append(out, o.Method+" "+strings.TrimPrefix(o.Path, repoPath))
	}
	return out
}

func mustCall(h *harness, tool string, args map[string]any) rpcReply {
	r, _ := h.call(tool, args)
	return r
}

func TestProposeChange(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	base, _ := h.ref("main")
	n := len(h.vendor.snapshot())
	r, c := h.call("github_propose_change", proposal("widget-1.2", nil))
	p := toolPayload(t, r)
	requireProvenance(t, p, "github_propose_change", "github")
	require(t, p["state"] == "proposed" && p["branch"] == "otto/widget-1.2" && p["prNumber"] == float64(42) && p["baseSha"] == base, "proposal: %v", p)
	requireOK(t, h, c, "github_propose_change")
	// A fresh branch from the default branch's head, one commit whose message is
	// the title alone, and a draft pull request into the default branch.
	writes := writesIn(h.vendor.since(n))
	require(t, reflect.DeepEqual(writePaths(writes), []string{"POST /git/blobs", "POST /git/trees", "POST /git/commits", "POST /git/refs", "POST /pulls"}), "writes: %v", writePaths(writes))
	for _, o := range writes {
		require(t, o.AuditPending, "%s %s preceded the audit row", o.Method, o.Path)
	}
	for _, o := range writes[:4] {
		require(t, reflect.DeepEqual(h.vendor.scope(o.Authorization), map[string]any{"contents": "write"}), "%s written with a token scoped %v", o.Path, h.vendor.scope(o.Authorization))
	}
	require(t, reflect.DeepEqual(h.vendor.scope(writes[4].Authorization), map[string]any{"contents": "read", "pull_requests": "write"}), "pull request opened with a token scoped %v", h.vendor.scope(writes[4].Authorization))
	require(t, writes[2].Body["message"] == "Bump the widget" && reflect.DeepEqual(writes[2].Body["parents"], []any{base}), "commit: %v", writes[2].Body)
	require(t, writes[3].Body["ref"] == "refs/heads/otto/widget-1.2" && writes[3].Body["sha"] == p["commitSha"], "branch: %v", writes[3].Body)
	pr := writes[4].Body
	require(t, pr["draft"] == true && pr["base"] == "main" && pr["head"] == "otto/widget-1.2" && pr["title"] == "Bump the widget", "pull request: %v", pr)
	// The declared claims sit above the caller's body, quoted.
	prBody := pr["body"].(string)
	require(t, strings.HasPrefix(prBody, "> [!WARNING]") && strings.Contains(prBody, "```\nthe latest widget is 1.2\n```") && strings.HasSuffix(prBody, "\n\nWhy this change"), "pull request body: %q", prBody)
	content, ok := h.vendor.branchFile("otto/widget-1.2", "a.txt")
	require(t, ok && content == "x", "committed file: %q %v", content, ok)
	rows := h.proposalRows()
	require(t, len(rows) == 1, "proposal records: %v", rows)
	row := rows[0]
	require(t, row["state"] == "proposed" && row["branch"] == "otto/widget-1.2" && row["pr_number"] == float64(42) && row["base_sha"] == base &&
		row["head_sha"] == p["commitSha"] && row["idempotency_key"] == "widget-1.2" && row["team"] == team && row["turn_id"] == c.ID && row["origin"] == "direct" &&
		reflect.DeepEqual(row["unverified_claims"], []any{"the latest widget is 1.2"}), "proposal record: %v", row)

	t.Run("repeat_returns_the_existing_proposal", func(t *testing.T) {
		r, c := h.call("github_propose_change", proposal("widget-1.2", nil))
		p := toolPayload(t, r)
		require(t, p["state"] == "already_proposed" && p["prNumber"] == float64(42), "repeat: %v", p)
		requireOK(t, h, c, "github_propose_change")
		require(t, len(h.vendor.pullRequests()) == 1 && len(h.proposalRows()) == 1, "a repeat made a second pull request or record")
	})
	t.Run("same_key_other_files_is_a_conflict", func(t *testing.T) {
		r, c := h.call("github_propose_change", proposal("widget-1.2", map[string]any{"files": []any{map[string]any{"path": "b.txt", "content": "y"}}}))
		p := toolPayload(t, r)
		require(t, p["state"] == "key_conflict" && p["prNumber"] == float64(42), "conflict: %v", p)
		requireOK(t, h, c, "github_propose_change")
		_, ok := h.vendor.branchFile("otto/widget-1.2", "b.txt")
		require(t, !ok && len(h.vendor.pullRequests()) == 1, "a conflicting proposal changed the branch or opened a pull request")
	})
	t.Run("same_key_other_body_while_open_is_a_conflict", func(t *testing.T) {
		p := toolPayload(t, mustCall(h, "github_propose_change", proposal("widget-1.2", map[string]any{"body": "Another reason"})))
		require(t, p["state"] == "key_conflict" && strings.Contains(p["message"].(string), "recorded copy"), "body conflict: %v", p)
	})
	t.Run("no_change_from_the_base_is_refused", func(t *testing.T) {
		r, c := h.call("github_propose_change", proposal("noop", map[string]any{"files": []any{map[string]any{"path": "README.md", "content": seedContent}}}))
		require(t, r.Error != nil && decision(r) == "errored" && strings.Contains(r.Error.Message, "no change"), "empty proposal: %s", r.Raw)
		h.auditRow(c, "allowed", "error")
		_, made := h.ref("otto/noop")
		require(t, !made, "an empty proposal made a branch")
	})
	// A known gap: the description promises "proposal_declined" for a retry after
	// a human closed the proposal. GitHub accepts a new pull request from a branch
	// whose only pull request is closed, and the pinned gateway opens one.
	t.Run("a_closed_proposal_is_proposed_again", func(t *testing.T) {
		toolPayload(t, mustCall(h, "github_propose_change", proposal("declined", nil)))
		h.vendor.setPull(43, map[string]any{"state": "closed"})
		before := len(h.vendor.snapshot())
		r, c := h.call("github_propose_change", proposal("declined", nil))
		p := toolPayload(t, r)
		require(t, p["state"] == "proposed" && p["prNumber"] == float64(44) && p["branch"] == "otto/declined", "retry after a decline: %v", p)
		requireOK(t, h, c, "github_propose_change")
		require(t, reflect.DeepEqual(writePaths(h.vendor.since(before)), []string{"POST /git/blobs", "POST /git/trees", "POST /git/commits", "POST /git/refs", "POST /pulls"}), "retry writes: %v", writePaths(h.vendor.since(before)))
		pulls := h.vendor.pullRequests()
		require(t, len(pulls) == 3 && pulls[1]["head_ref"] == "otto/declined" && pulls[2]["head_ref"] == "otto/declined" && pulls[1]["state"] == "closed", "pull requests: %v", pulls)
	})
	for _, o := range h.vendor.snapshot() {
		if o.Method == "POST" && o.Path == repoPath+"/pulls" {
			require(t, o.Body["draft"] == true, "pull request opened ready for review: %v", o.Body)
		}
		require(t, o.Method != "DELETE" && !(o.Method == "PATCH" && strings.Contains(o.Path, "/git/refs/")), "propose moved or deleted a ref: %s %s", o.Method, o.Path)
	}
}

func TestAmendChange(t *testing.T) {
	h := newHarness(t)
	m := full
	m.botLogin = true
	h.start(m)
	toolPayload(t, mustCall(h, "github_propose_change", proposal("widget-1.2", nil)))
	first, _ := h.ref("otto/widget-1.2")
	n := len(h.vendor.snapshot())
	r, c := h.call("github_amend_change", map[string]any{"owner": "test-org", "repo": "repo", "pr_number": 42,
		"files": []any{map[string]any{"path": "a.txt", "content": "y"}}, "unverifiedClaims": []any{"the widget's API is unchanged"}})
	p := toolPayload(t, r)
	requireProvenance(t, p, "github_amend_change", "github")
	require(t, p["state"] == "amended" && p["branch"] == "otto/widget-1.2" && p["prNumber"] == float64(42), "amend: %v", p)
	requireOK(t, h, c, "github_amend_change")
	content, _ := h.vendor.branchFile("otto/widget-1.2", "a.txt")
	require(t, content == "y", "amended file: %q", content)
	writes := writesIn(h.vendor.since(n))
	require(t, reflect.DeepEqual(writePaths(writes), []string{"POST /git/blobs", "POST /git/trees", "POST /git/commits", "PATCH /git/refs/heads/otto/widget-1.2", "PATCH /pulls/42"}), "writes: %v", writePaths(writes))
	// One commit on top of the branch, a fast-forward of it, and the claims block rewritten.
	require(t, reflect.DeepEqual(writes[2].Body["parents"], []any{first}) && writes[2].Body["message"] == "Amend pull request #42", "commit: %v", writes[2].Body)
	require(t, writes[3].Body["force"] == false && writes[3].Body["sha"] == p["headSha"], "branch update: %v", writes[3].Body)
	body := writes[4].Body["body"].(string)
	require(t, strings.Contains(body, "the widget's API is unchanged") && !strings.Contains(body, "the latest widget is 1.2") && strings.HasSuffix(body, "\n\nWhy this change") &&
		writes[4].Body["title"] == nil, "refreshed body: %q", body)
	require(t, h.vendor.pullRequests()[0]["body"] == body, "the pull request body was not replaced")

	t.Run("repeat_needs_the_expected_head", func(t *testing.T) {
		args := map[string]any{"owner": "test-org", "repo": "repo", "pr_number": 42, "files": []any{map[string]any{"path": "a.txt", "content": "y"}}, "unverifiedClaims": []any{}}
		before := len(h.vendor.snapshot())
		r, c := h.call("github_amend_change", args)
		require(t, r.Error != nil && decision(r) == "errored" && strings.Contains(r.Error.Message, "expected_head is required"), "repeat amend: %s", r.Raw)
		h.auditRow(c, "allowed", "error")
		for _, o := range writesIn(h.vendor.since(before)) {
			require(t, o.Path == repoPath+"/git/blobs" || o.Path == repoPath+"/git/trees", "a repeated amend wrote %s %s", o.Method, o.Path)
		}
		args["expected_head"] = p["headSha"]
		r, _ = h.call("github_amend_change", args)
		require(t, r.Error == nil && toolPayload(t, r)["state"] == "no_change", "repeat with the expected head: %s", r.Raw)
	})
	t.Run("ready_for_review_is_refused", func(t *testing.T) {
		h.vendor.setPull(42, map[string]any{"draft": false})
		defer h.vendor.setPull(42, map[string]any{"draft": true})
		before := len(h.vendor.snapshot())
		r, c := h.call("github_amend_change", map[string]any{"owner": "test-org", "repo": "repo", "pr_number": 42, "files": []any{map[string]any{"path": "a.txt", "content": "z"}}, "unverifiedClaims": []any{}})
		require(t, r.Error != nil && decision(r) == "denied" && strings.Contains(r.Error.Message, "marked ready for review"), "ready pull request: %s", r.Raw)
		require(t, h.auditRow(c, "allowed", "refused")["refusal_reason"] == r.Error.Message, "refusal reason differs")
		require(t, len(writesIn(h.vendor.since(before))) == 0, "a ready pull request was written to")
	})
	// Pull requests opened by github_create_pr: one from an ordinary branch, and
	// one from a branch under the reserved prefix that has no proposal record.
	for _, tc := range []struct{ head, want string }{
		{"feature", `which is not under the reserved "otto/" prefix`},
		{"otto/hand-made", "is not one github_propose_change opened"},
	} {
		t.Run("not_proposed_by_this_tool_"+strings.ReplaceAll(tc.head, "/", "_"), func(t *testing.T) {
			created := toolPayload(t, mustCall(h, "github_create_pr", map[string]any{"owner": "test-org", "repo": "repo", "title": "Hand made", "head": tc.head, "base": "main"}))
			number := created["pr"].(map[string]any)["number"]
			before := len(h.vendor.snapshot())
			r, c := h.call("github_amend_change", map[string]any{"owner": "test-org", "repo": "repo", "pr_number": number, "files": []any{map[string]any{"path": "a.txt", "content": "z"}}, "unverifiedClaims": []any{}})
			require(t, r.Error != nil && decision(r) == "denied" && strings.Contains(r.Error.Message, tc.want), "foreign pull request: %s", r.Raw)
			h.auditRow(c, "allowed", "refused")
			require(t, len(writesIn(h.vendor.since(before))) == 0, "a foreign pull request was written to")
		})
	}
	t.Run("closed_is_an_error", func(t *testing.T) {
		h.vendor.setPull(42, map[string]any{"state": "closed"})
		before := len(h.vendor.snapshot())
		r, c := h.call("github_amend_change", map[string]any{"owner": "test-org", "repo": "repo", "pr_number": 42, "files": []any{map[string]any{"path": "a.txt", "content": "z"}}, "unverifiedClaims": []any{}})
		require(t, r.Error != nil && decision(r) == "errored" && strings.Contains(r.Error.Message, "is closed, not open"), "closed pull request: %s", r.Raw)
		h.auditRow(c, "allowed", "error")
		require(t, len(writesIn(h.vendor.since(before))) == 0, "a closed pull request was written to")
	})
}

// Without the App's own login there is nothing to check authorship against,
// so every amend fails before any request.
func TestAmendNeedsTheBotLogin(t *testing.T) {
	h := newHarness(t)
	h.start(full)
	r, c := h.call("github_amend_change", map[string]any{"owner": "test-org", "repo": "repo", "pr_number": 42, "files": []any{map[string]any{"path": "a.txt", "content": "y"}}, "unverifiedClaims": []any{}})
	require(t, r.Error != nil && decision(r) == "errored" && strings.Contains(r.Error.Message, "no bot login configured"), "amend without a bot login: %s", r.Raw)
	h.auditRow(c, "allowed", "error")
	require(t, len(h.vendor.snapshot()) == 0, "an amend without a bot login reached the vendor")
}
