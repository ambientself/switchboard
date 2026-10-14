package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// The three Jira tools against the fake Jira in harness_test.go, confined to
// the project TEST.

const jiraIssueFields = "summary,status,issuetype,project,assignee,reporter,priority,labels,created,updated,description,comment,security"

func adf(paragraphs ...string) map[string]any {
	content := []any{}
	for _, p := range paragraphs {
		content = append(content, map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": p}}})
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

// jiraRequests is what a call sent to Jira, each with the shared account's
// basic credentials and never the caller's.
func jiraRequests(t *testing.T, h *harness, before int) []observation {
	t.Helper()
	got := h.jira.snapshot()[before:]
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("otto@example.invalid:jira-token-generated-for-local-conformance-only"))
	for _, o := range got {
		require(t, o.Authorization == want, "Jira credential: %q", o.Authorization)
	}
	return got
}

// jiraOnly is the one request a call made.
func jiraOnly(t *testing.T, h *harness, before int) observation {
	t.Helper()
	got := jiraRequests(t, h, before)
	require(t, len(got) == 1, "want one Jira request, got %v", got)
	return got[0]
}

func searchIssue(key, project string) map[string]any {
	return map[string]any{"key": key, "fields": map[string]any{"summary": "Upgrade the widget", "status": map[string]any{"name": "Open"}, "issuetype": map[string]any{"name": "Task"},
		"project": map[string]any{"key": project}, "assignee": map[string]any{"displayName": "A Person", "emailAddress": "a.person@example.invalid", "accountId": "assignee-account"},
		"reporter": map[string]any{"displayName": "R Person"}, "priority": map[string]any{"name": "High"}, "labels": []any{"widget"}, "updated": "2026-01-01T00:00:00.000+0000"}}
}

func TestJiraSearch(t *testing.T) {
	h := newHarness(t)
	m := full
	m.jira = true
	h.start(m)
	h.jira.answer("GET /rest/api/3/search/jql", answer{Body: map[string]any{"issues": []any{searchIssue("TEST-1", "TEST")}, "nextPageToken": "page-2"}})
	h.jira.answer("GET /rest/api/3/user", answer{Body: map[string]any{"accountId": atlassianAccount, "displayName": "A Person"}})
	cases := []struct {
		name          string
		args          map[string]any
		jql, maxPage  string
		nextPageToken string
	}{
		// The caller's JQL is parenthesized after the project restriction, and a
		// trailing ORDER BY is kept outside it. Pages are 10 by default, at most 20.
		{"restricted", map[string]any{"jql": "status = Open ORDER BY updated DESC", "maxResults": 50}, `project in ("TEST") AND (status = Open) ORDER BY updated DESC`, "20", ""},
		{"default_page", map[string]any{"jql": "project = OTHER"}, `project in ("TEST") AND (project = OTHER)`, "10", ""},
		{"next_page", map[string]any{"jql": "status = Open", "maxResults": 5, "nextPageToken": "page-2"}, `project in ("TEST") AND (status = Open)`, "5", "page-2"},
		// {me} is the asker's Atlassian account from the team manifest.
		{"me", map[string]any{"jql": "assignee = {me}"}, `project in ("TEST") AND (assignee = "` + atlassianAccount + `")`, "10", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.jira.snapshot())
			r, c := h.call("jira_search", tc.args)
			p := toolPayload(t, r)
			requireProvenance(t, p, "jira_search", "jira")
			got := jiraRequests(t, h, before)
			if tc.name == "me" {
				// The account id is checked with Jira before it is put in the query.
				require(t, len(got) == 2 && got[0].Method == "GET" && got[0].Path == "/rest/api/3/user" && got[0].Query == "accountId="+atlassianAccount, "account lookup: %v", got)
				got = got[1:]
			}
			require(t, len(got) == 1, "want one search request, got %v", got)
			o := got[0]
			q, err := url.ParseQuery(o.Query)
			must(t, err)
			require(t, o.Method == "GET" && o.Path == "/rest/api/3/search/jql" && q.Get("jql") == tc.jql && q.Get("maxResults") == tc.maxPage &&
				q.Get("nextPageToken") == tc.nextPageToken && q.Get("fields") == "summary,status,issuetype,project,assignee,reporter,priority,labels,updated,created", "search request: %s", o.Query)
			// The caller is shown the query with {me} unresolved.
			shown := strings.ReplaceAll(tc.jql, `"`+atlassianAccount+`"`, "{me}")
			require(t, p["scope"].(map[string]any)["query"] == shown && reflect.DeepEqual(p["scope"].(map[string]any)["projects"], []any{"TEST"}), "scope: %v", p["scope"])
			require(t, p["count"] == float64(1) && p["nextPageToken"] == "page-2" && p["isLast"] == false, "page: %v", p)
			issue := p["results"].([]any)[0].(map[string]any)
			require(t, issue["key"] == "TEST-1" && issue["project"] == "TEST" && issue["assignee"] == "A Person" && issue["reporter"] == "R Person" &&
				issue["url"] == h.jira.server.URL+"/browse/TEST-1", "issue: %v", issue)
			// Display names only: no address or account id reaches the caller.
			require(t, !bytes.Contains(r.Raw, []byte("a.person@example.invalid")) && !bytes.Contains(r.Raw, []byte("assignee-account")), "assignee identity leaked: %s", r.Raw)
			requireOK(t, h, c, "jira_search")
		})
	}
	// A manifest account id Jira does not know is refused, and the search is not sent.
	h.jira.answer("GET /rest/api/3/user", answer{Status: 404, Body: map[string]any{"errorMessages": []any{"not found"}}})
	before := len(h.jira.snapshot())
	r, c := h.call("jira_search", map[string]any{"jql": "assignee = {me}"})
	require(t, r.Error != nil && decision(r) == "denied" && strings.Contains(r.Error.Message, "matches no Atlassian account"), "unknown account: %s", r.Raw)
	h.auditRow(c, "allowed", "refused")
	require(t, jiraOnly(t, h, before).Path == "/rest/api/3/user", "the search was sent for an unknown account")

	// An answer naming an issue outside the allowed projects is withheld whole.
	h.jira.answer("GET /rest/api/3/search/jql", answer{Body: map[string]any{"issues": []any{searchIssue("TEST-2", "TEST"), searchIssue("OTHER-9", "OTHER")}}})
	before = len(h.jira.snapshot())
	r, c = h.call("jira_search", map[string]any{"jql": "status = Open"})
	require(t, r.Error != nil && decision(r) == "denied" && strings.Contains(r.Error.Message, "could not be completed within the projects"), "outside issue: %s", r.Raw)
	require(t, !bytes.Contains(r.Raw, []byte("TEST-2")) && !bytes.Contains(r.Raw, []byte("OTHER-9")), "results of a withheld search reached the caller")
	require(t, h.auditRow(c, "allowed", "refused")["refusal_reason"] == r.Error.Message, "refusal reason differs")
	jiraOnly(t, h, before)
	require(t, len(h.vendor.snapshot()) == 0, "a Jira tool reached GitHub")
}

func TestJiraGetIssue(t *testing.T) {
	h := newHarness(t)
	m := full
	m.jira = true
	h.start(m)
	h.jira.answer("GET /rest/api/3/issue/TEST-1", answer{Body: map[string]any{"id": "10001", "key": "TEST-1", "fields": map[string]any{
		"summary": "Upgrade the widget", "status": map[string]any{"name": "Open"}, "project": map[string]any{"key": "TEST"}, "description": adf("first paragraph", "second paragraph"),
		"comment": map[string]any{"total": 2, "comments": []any{
			map[string]any{"id": "1", "author": map[string]any{"displayName": "A Person"}, "body": adf("visible comment"), "created": "2026-01-01T00:00:00.000+0000"},
			map[string]any{"id": "2", "author": map[string]any{"displayName": "B Person"}, "body": adf("restricted comment"), "visibility": map[string]any{"type": "role", "value": "Administrators"}},
		}}}}})
	before := len(h.jira.snapshot())
	r, c := h.call("jira_get_issue", map[string]any{"key": "TEST-1"})
	p := toolPayload(t, r)
	requireProvenance(t, p, "jira_get_issue", "jira")
	o := jiraOnly(t, h, before)
	q, err := url.ParseQuery(o.Query)
	must(t, err)
	require(t, o.Path == "/rest/api/3/issue/TEST-1" && q.Get("fields") == jiraIssueFields, "issue request: %s %s", o.Path, o.Query)
	issue := p["issue"].(map[string]any)
	require(t, issue["key"] == "TEST-1" && issue["summary"] == "Upgrade the widget" && issue["status"] == "Open" && issue["url"] == h.jira.server.URL+"/browse/TEST-1", "issue: %v", issue)
	require(t, strings.Contains(issue["description"].(string), "first paragraph") && strings.Contains(issue["description"].(string), "second paragraph") && issue["descriptionTruncated"] == false, "description: %q", issue["description"])
	// A comment with a visibility restriction is withheld and counted.
	comments := p["comments"].([]any)
	require(t, len(comments) == 1 && comments[0].(map[string]any)["body"] == "visible comment" && p["commentsWithheldRestricted"] == float64(1) &&
		p["commentsTotal"] == float64(2), "comments: %v", p)
	require(t, !bytes.Contains(r.Raw, []byte("restricted comment")), "a restricted comment was returned")
	requireOK(t, h, c, "jira_get_issue")

	// An issue under a security level is refused after Jira answers.
	h.jira.answer("GET /rest/api/3/issue/TEST-2", answer{Body: map[string]any{"id": "10002", "key": "TEST-2", "fields": map[string]any{
		"summary": "Secret", "project": map[string]any{"key": "TEST"}, "description": adf("secret text"), "security": map[string]any{"name": "Restricted"}}}})
	before = len(h.jira.snapshot())
	r, c = h.call("jira_get_issue", map[string]any{"key": "TEST-2"})
	require(t, r.Error != nil && decision(r) == "denied" && strings.Contains(r.Error.Message, "issue security level") && !bytes.Contains(r.Raw, []byte("secret text")), "secured issue: %s", r.Raw)
	require(t, h.auditRow(c, "allowed", "refused")["refusal_reason"] == r.Error.Message, "refusal reason differs")
	jiraOnly(t, h, before)

	// An issue Jira does not show is an error, not a refusal.
	r, c = h.call("jira_get_issue", map[string]any{"key": "TEST-3"})
	require(t, r.Error != nil && decision(r) == "errored" && strings.Contains(r.Error.Message, "was not found"), "missing issue: %s", r.Raw)
	h.auditRow(c, "allowed", "error")
}

func TestJiraComment(t *testing.T) {
	h := newHarness(t)
	m := full
	m.jira = true
	h.start(m)
	h.jira.answer("GET /rest/api/3/issue/TEST-1", answer{Body: map[string]any{"id": "10001", "key": "TEST-1", "fields": map[string]any{"project": map[string]any{"key": "TEST"}}}})
	h.jira.answer("POST /rest/api/3/issue/10001/comment", answer{Status: 201, Body: map[string]any{"id": "900", "created": "2026-01-01T00:00:00.000+0000"}})
	args := map[string]any{"key": "TEST-1", "body": "First paragraph.\n\nSecond paragraph."}
	for i := 0; i < 2; i++ {
		before := len(h.jira.snapshot())
		r, c := h.call("jira_comment", args)
		p := toolPayload(t, r)
		requireProvenance(t, p, "jira_comment", "jira")
		comment := p["comment"].(map[string]any)
		require(t, p["posted"] == true && comment["id"] == "900" && comment["issue"] == "TEST-1" && comment["url"] == h.jira.server.URL+"/browse/TEST-1?focusedCommentId=900", "comment payload: %v", p)
		requireOK(t, h, c, "jira_comment")
		got := h.jira.snapshot()[before:]
		require(t, len(got) == 2, "comment requests: %v", got)
		// The issue is looked up first, then the comment is posted to its id.
		q, err := url.ParseQuery(got[0].Query)
		must(t, err)
		require(t, got[0].Method == "GET" && got[0].Path == "/rest/api/3/issue/TEST-1" && q.Get("fields") == "project,security", "lookup: %v", got[0])
		require(t, got[1].Method == "POST" && got[1].Path == "/rest/api/3/issue/10001/comment", "post: %v", got[1])
		// Blank lines make paragraphs, and a final line names Otto, the person and the team.
		want := adf("First paragraph.", "Second paragraph.", "— posted by Otto, requested by person (team test-team)")
		want["content"].([]any)[2].(map[string]any)["content"].([]any)[0].(map[string]any)["marks"] = []any{map[string]any{"type": "em"}}
		require(t, reflect.DeepEqual(got[1].Body["body"], any(jsonRoundTrip(t, want))), "comment body: %v", got[1].Body)
	}
	// The same comment twice is two comments: no deduplication, as for GitHub.
	posts := 0
	for _, o := range h.jira.snapshot() {
		if o.Method == "POST" {
			posts++
		}
	}
	require(t, posts == 2, "comment posts: %d", posts)
}

func jsonRoundTrip(t *testing.T, v any) any {
	t.Helper()
	var out any
	must(t, json.Unmarshal(jsonBytes(t, v), &out))
	return out
}
