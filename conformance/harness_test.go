package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const subject = "system:serviceaccount:conformance:agent"
const team = "test-team"
const actor = "person@example.invalid"
const fakeTokenPrefix = "installation-token-generated-for-local-conformance-only-"
const grantHeader = "X-Otto-Turn-Grant"
const grantDenial = "this gateway requires a verifiable turn grant on every call, and this call's did not verify"
const opaqueDenial = "this call did not prove which pod it came from"
const auditDenial = "the gateway could not record this call and refuses to answer unaudited"

type baseline struct {
	Protocol string `json:"protocol_version"`
	Endpoint string `json:"endpoint"`
	Tools    map[string]struct {
		Switchboard    string   `json:"switchboard"`
		Classification string   `json:"classification"`
		Required       []string `json:"required"`
	} `json:"tools"`
}

func readBaseline(t *testing.T) baseline {
	t.Helper()
	b, err := os.ReadFile("baseline.json")
	must(t, err)
	var p baseline
	must(t, json.Unmarshal(b, &p))
	return p
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func require(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is required; run python3 conformance/run.py --otto-source /path/to/otto", key)
	}
	return v
}

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return b
}

type observation struct {
	Method, Path, Query, Authorization string
	Body                               map[string]any
	AuditPending                       bool
}

type fakeVendor struct {
	server       *httptest.Server
	pool         *pgxpool.Pool
	key          *rsa.PrivateKey
	mu           sync.Mutex
	requests     []observation
	tokens       map[string]bool
	mode         string
	entered      chan struct{}
	release      chan struct{}
	appAuthValid bool
}

// issued reports whether the vendor handed out this bearer value. The gateway
// asks for a separately scoped token per permission set, so there are several.
func (v *fakeVendor) issued(authorization string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.tokens[strings.TrimPrefix(authorization, "Bearer ")]
}

func (v *fakeVendor) snapshot() []observation {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]observation(nil), v.requests...)
}

func (v *fakeVendor) setMode(mode string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.mode = mode
}

func (v *fakeVendor) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	var pending int
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	err := v.pool.QueryRow(ctx, "SELECT count(*) FROM gateway_audit WHERE method='tools/call' AND decision='allowed' AND outcome IS NULL").Scan(&pending)
	o := observation{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body, err == nil && pending > 0}
	v.mu.Lock()
	v.requests = append(v.requests, o)
	mode := v.mode
	v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/app/") {
		valid := verifyAppJWT(strings.TrimPrefix(o.Authorization, "Bearer "), &v.key.PublicKey)
		v.mu.Lock()
		v.appAuthValid = v.appAuthValid && valid
		v.mu.Unlock()
		if !valid {
			http.Error(w, "invalid fake app authentication", 401)
			return
		}
		switch r.URL.Path {
		case "/app/installations":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": 123, "account": map[string]any{"login": "test-org"}}})
		case "/app/installations/123/access_tokens":
			// Answer exactly the scope that was asked for, as GitHub does; the
			// custodian refuses a token that is broader or unscoped.
			repos := []any{}
			if names, ok := body["repositories"].([]any); ok {
				for _, name := range names {
					repos = append(repos, map[string]any{"name": name})
				}
			}
			permissions := map[string]any{"metadata": "read"}
			if asked, ok := body["permissions"].(map[string]any); ok {
				for k, level := range asked {
					permissions[k] = level
				}
			}
			v.mu.Lock()
			token := fmt.Sprintf("%s%d", fakeTokenPrefix, len(v.tokens)+1)
			v.tokens[token] = true
			v.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"repository_selection": "selected", "repositories": repos, "permissions": permissions})
		default:
			http.NotFound(w, r)
		}
		return
	}
	if !v.issued(o.Authorization) {
		http.Error(w, "wrong downstream credential", 401)
		return
	}
	if mode == "blocked" {
		select {
		case v.entered <- struct{}{}:
		default:
		}
		select {
		case <-v.release:
		case <-r.Context().Done():
			return
		}
	}
	if mode == "error" {
		http.Error(w, "fake upstream failure "+strings.TrimPrefix(o.Authorization, "Bearer ")+strings.Repeat("x", 400), 503)
		return
	}
	var result any
	switch {
	case r.URL.Path == "/search/issues":
		items := []any{}
		for i := 0; i < 12; i++ {
			items = append(items, map[string]any{"number": i + 1, "title": "Evidence", "state": "open", "html_url": "https://example.invalid/pr/1", "body": strings.TrimPrefix(o.Authorization, "Bearer ") + strings.Repeat("x", 3000), "repository_url": v.server.URL + "/repos/test-org/repo", "user": map[string]any{"login": "bot"}})
		}
		result = map[string]any{"total_count": 12, "items": items}
	case strings.Contains(r.URL.Path, "/contents/"):
		content := "hello from the fake vendor"
		if strings.HasSuffix(r.URL.Path, "/large.txt") {
			content = strings.Repeat("a", 270000)
		}
		result = map[string]any{"name": "file.txt", "path": "file.txt", "sha": "fake-sha", "size": len(content), "type": "file", "content": base64.StdEncoding.EncodeToString([]byte(content))}
	case strings.HasSuffix(r.URL.Path, "/pulls") && r.Method == "POST":
		result = map[string]any{"number": 42, "html_url": "https://example.invalid/pull/42"}
	case strings.HasSuffix(r.URL.Path, "/pulls/42"):
		result = map[string]any{"number": 42, "title": "Proposal", "state": "open", "body": "review this", "user": map[string]any{"login": "bot"}}
	case strings.HasSuffix(r.URL.Path, "/issues/42/comments") && r.Method == "POST":
		result = map[string]any{"id": 73, "html_url": "https://example.invalid/comment/73"}
	case strings.HasSuffix(r.URL.Path, "/issues/42/comments"):
		comments := []any{}
		for i := 0; i < 21; i++ {
			comments = append(comments, map[string]any{"body": "comment", "user": map[string]any{"login": "bot"}})
		}
		result = comments
	default:
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func verifyAppJWT(token string, key *rsa.PublicKey) bool {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return false
	}
	var claims struct {
		Issuer string `json:"iss"`
		Expiry int64  `json:"exp"`
	}
	b, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return false
	}
	return json.Unmarshal(b, &claims) == nil && claims.Issuer == "1234" && claims.Expiry > time.Now().Unix()
}

type harness struct {
	t                                        *testing.T
	pool                                     *pgxpool.Pool
	dsn, dir, url, issuer, manifest, keyPath string
	grantKeyPath, socket, jiraTokenPath      string
	grantKey                                 []byte
	key                                      *rsa.PrivateKey
	vendor                                   *fakeVendor
	jira                                     *httptest.Server
	stop                                     func()
	seq                                      int
	granted                                  []string
}

var databaseSeq atomic.Int64

// withDatabase rewrites a connection URL to name another database and login.
func withDatabase(t *testing.T, raw, user, password, database string) string {
	t.Helper()
	u, err := url.Parse(raw)
	must(t, err)
	if user != "" {
		u.User = url.UserPassword(user, password)
	}
	u.Path = "/" + database
	return u.String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// A short directory: the custodian's Unix socket path has a small length limit.
	dir, err := os.MkdirTemp("/tmp", "sbc-")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	h := &harness{t: t, dir: dir}
	adminURL := requiredEnv(t, "OTTO_TEST_ADMIN_URL")
	admin, err := pgxpool.New(context.Background(), adminURL)
	must(t, err)
	// Each test gets its own copy of the migrated database, grants included.
	database := fmt.Sprintf("conformance_%d_%d", os.Getpid(), databaseSeq.Add(1))
	_, err = admin.Exec(context.Background(), "CREATE DATABASE "+database+" TEMPLATE "+requiredEnv(t, "OTTO_TEST_TEMPLATE_DB"))
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := admin.Exec(ctx, "DROP DATABASE "+database+" WITH (FORCE)")
		if err != nil {
			t.Errorf("cleanup database: %v", err)
		}
		admin.Close()
	})
	// The gateway connects as its own narrow role; the suite inspects as the owner.
	h.dsn = withDatabase(t, adminURL, "otto_gateway", requiredEnv(t, "OTTO_TEST_GATEWAY_ROLE_PASSWORD"), database)
	h.pool, err = pgxpool.New(context.Background(), withDatabase(t, adminURL, "", "", database))
	must(t, err)
	t.Cleanup(h.pool.Close)
	h.key, err = rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	h.keyPath = filepath.Join(h.dir, "test-key.pem")
	must(t, os.WriteFile(h.keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(h.key)}), 0600))
	raw := make([]byte, 32)
	_, err = rand.Read(raw)
	must(t, err)
	h.grantKey = []byte(hex.EncodeToString(raw))
	h.grantKeyPath = filepath.Join(h.dir, "grant.key")
	must(t, os.WriteFile(h.grantKeyPath, h.grantKey, 0600))
	h.jiraTokenPath = filepath.Join(h.dir, "jira.token")
	must(t, os.WriteFile(h.jiraTokenPath, []byte("jira-token-generated-for-local-conformance-only"), 0600))
	h.socket = filepath.Join(h.dir, "custodian.sock")
	h.manifest = filepath.Join(h.dir, "team.json")
	must(t, os.WriteFile(h.manifest, jsonBytes(t, map[string]any{
		"id": team, "displayName": "Test team",
		"sandbox":    map[string]any{"serviceAccount": subject},
		"members":    []any{map[string]any{"email": actor}},
		"actOnRepos": []string{"repo"},
	}), 0600))
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": h.issuer + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "local", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(h.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	h.issuer = issuer.URL
	t.Cleanup(issuer.Close)
	h.vendor = &fakeVendor{pool: h.pool, key: h.key, tokens: map[string]bool{}, entered: make(chan struct{}, 1), release: make(chan struct{}), appAuthValid: true}
	h.vendor.server = httptest.NewServer(http.HandlerFunc(h.vendor.serve))
	t.Cleanup(h.vendor.server.Close)
	// A minimal Jira: enough for the gateway's boot-time credential check.
	h.jira = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/rest/api/3/myself" {
			_ = json.NewEncoder(w).Encode(map[string]any{"accountId": "fake-account", "displayName": "Fake"})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(h.jira.Close)
	for name := range readBaseline(t).Tools {
		h.granted = append(h.granted, name)
	}
	return h
}

// mode says which of the gateway's gates a test turns on.
type mode struct{ identity, grant, audit, connector, jira bool }

var full = mode{identity: true, grant: true, audit: true, connector: true}

func (h *harness) identityArgs() []string {
	return []string{"-oidc-issuer", h.issuer, "-identity-audience", "otto-gateway", "-team-manifest", h.manifest}
}

func (h *harness) grantArgs() []string {
	return []string{"-turn-grant-key-file", h.grantKeyPath}
}

func (h *harness) connectorArgs() []string {
	return []string{"-github-custodian-socket", h.socket, "-github-org", "test-org", "-github-api-url", h.vendor.server.URL}
}

func (h *harness) jiraArgs() []string {
	return []string{"-jira-base-url", h.jira.URL, "-jira-site-url", h.jira.URL, "-jira-email", "otto@example.invalid",
		"-jira-api-token-file", h.jiraTokenPath, "-jira-projects", "TEST"}
}

// startCustodian runs the separate process that holds the App key. Peer checks
// are off: they need Linux, and this suite also runs on macOS.
func (h *harness) startCustodian() {
	h.t.Helper()
	logPath := filepath.Join(h.dir, "custodian.log")
	log, err := os.Create(logPath)
	must(h.t, err)
	cmd := exec.Command(requiredEnv(h.t, "OTTO_TEST_CUSTODIAN_BINARY"), "-socket", h.socket, "-app-id", "1234",
		"-private-key-file", h.keyPath, "-api-url", h.vendor.server.URL)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = log, log
	must(h.t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	h.t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = log.Close()
		if h.t.Failed() {
			b, _ := os.ReadFile(logPath)
			h.t.Logf("custodian log:\n%s", b)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", h.socket); err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	h.t.Fatalf("custodian did not become ready: %s", b)
}

func (h *harness) start(m mode) {
	h.t.Helper()
	args := []string{}
	if m.identity {
		args = append(args, h.identityArgs()...)
	} else {
		args = append(args, "-identity-audience=", "-insecure-no-caller-identity")
	}
	if m.grant {
		args = append(args, h.grantArgs()...)
	} else {
		args = append(args, "-insecure-no-turn-grant")
	}
	if m.audit {
		args = append(args, "-database-url", h.dsn)
	} else {
		args = append(args, "-audit-disabled")
	}
	if m.connector {
		h.startCustodian()
		args = append(args, h.connectorArgs()...)
	}
	if m.jira {
		args = append(args, h.jiraArgs()...)
	}
	h.url, h.stop = startProcess(h.t, args)
}

func startProcess(t *testing.T, args []string) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := l.Addr().String()
	must(t, l.Close())
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	log, err := os.Create(logPath)
	must(t, err)
	cmd := exec.Command(requiredEnv(t, "OTTO_TEST_BINARY"), append([]string{"-addr", addr}, args...)...)
	// All security-relevant configuration is explicit; never inherit OTTO_* flags.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout = log
	cmd.Stderr = log
	must(t, cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			_ = log.Close()
			if t.Failed() {
				b, _ := os.ReadFile(logPath)
				t.Logf("gateway log:\n%s", b)
			}
		})
	}
	t.Cleanup(stop)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return "http://" + addr, stop
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	b, _ := os.ReadFile(logPath)
	t.Fatalf("gateway did not become ready: %s", b)
	return "", nil
}

func (h *harness) token(changes map[string]any, headerChanges map[string]any) string {
	h.t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{"iss": h.issuer, "sub": subject, "aud": []string{"other", "otto-gateway"}, "iat": now - 5, "nbf": now - 5, "exp": now + 300}
	for k, v := range changes {
		claims[k] = v
	}
	header := map[string]any{"alg": "RS256", "kid": "local", "typ": "JWT"}
	for k, v := range headerChanges {
		header[k] = v
	}
	payload := base64.RawURLEncoding.EncodeToString(jsonBytes(h.t, header)) + "." + base64.RawURLEncoding.EncodeToString(jsonBytes(h.t, claims))
	digest := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, digest[:])
	must(h.t, err)
	return payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mintGrant signs a turn grant the way Otto's control plane does. The format is
// reimplemented from Otto's wire description, not imported: version, key id,
// claims and a MAC over all three under a fixed prefix.
func mintGrant(t *testing.T, key []byte, claims map[string]any) string {
	t.Helper()
	kid := sha256.New()
	kid.Write([]byte("otto/gateway-turn-grant/kid/v1\x00"))
	kid.Write(key)
	signed := "v1." + hex.EncodeToString(kid.Sum(nil)[:6]) + "." + base64.RawURLEncoding.EncodeToString(jsonBytes(t, claims))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("otto/gateway-turn-grant/v1\x00"))
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// claims are one turn's grant: who is acting, for which team, and which tools.
func (h *harness) claims(turn string) map[string]any {
	return map[string]any{"sid": "session-test", "tid": turn, "eid": "execution-test", "team": team, "actor": actor,
		"epoch": 7, "exp": time.Now().Add(5 * time.Minute).Unix(), "tools": h.granted}
}

// A turn is one call's acting context: the headers to send and the turn id its
// audit row is found by.
type turn struct {
	ID      string
	Headers map[string]string
}

func (h *harness) nextTurn() string {
	h.seq++
	return fmt.Sprintf("turn-%d", h.seq)
}

// turn builds a verified caller: a ServiceAccount token and a signed grant.
func (h *harness) turn(changes map[string]any) turn {
	id := h.nextTurn()
	claims := h.claims(id)
	for k, v := range changes {
		claims[k] = v
	}
	return turn{id, map[string]string{"Authorization": "Bearer " + h.token(nil, nil), grantHeader: mintGrant(h.t, h.grantKey, claims)}}
}

// legacyTurn sends the acting context as plain headers, which the gateway reads
// only when grant checking is explicitly off.
func (h *harness) legacyTurn() turn {
	id := h.nextTurn()
	return turn{id, map[string]string{"X-Otto-Session": "session-test", "X-Otto-Turn": id, "X-Otto-Team": team,
		"X-Otto-Actor": actor, "X-Otto-Fencing-Epoch": "7", "Authorization": "Bearer " + h.token(nil, nil)}}
}

type rpcReply struct {
	Status  int
	Headers http.Header
	Raw     []byte
	ID      any            `json:"id"`
	Result  map[string]any `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (h *harness) request(method string, params any, headers map[string]string) rpcReply {
	return h.raw(jsonBytes(h.t, map[string]any{"jsonrpc": "2.0", "id": "request-1", "method": method, "params": params}), headers)
}

func (h *harness) call(tool string, args any) (rpcReply, turn) {
	c := h.turn(nil)
	return h.request("tools/call", map[string]any{"name": tool, "arguments": args}, c.Headers), c
}

func (h *harness) raw(body []byte, headers map[string]string) rpcReply {
	h.t.Helper()
	req, err := http.NewRequest("POST", h.url+readBaseline(h.t).Endpoint, bytes.NewReader(body))
	must(h.t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	must(h.t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	must(h.t, err)
	var result rpcReply
	if len(b) > 0 {
		must(h.t, json.Unmarshal(b, &result))
	}
	result.Status = resp.StatusCode
	result.Headers = resp.Header
	result.Raw = b
	return result
}

func toolPayload(t *testing.T, r rpcReply) map[string]any {
	t.Helper()
	require(t, r.Status == 200 && r.Error == nil, "tool call failed: %s", r.Raw)
	require(t, r.Result["isError"] == false, "unexpected tool error: %s", r.Raw)
	content, ok := r.Result["content"].([]any)
	require(t, ok && len(content) == 1, "unexpected tool content: %s", r.Raw)
	item := content[0].(map[string]any)
	require(t, item["type"] == "text", "expected text")
	var value map[string]any
	must(t, json.Unmarshal([]byte(item["text"].(string)), &value))
	return value
}

func (h *harness) rows(turn string) []map[string]any {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, err := h.pool.Query(ctx, "SELECT row_to_json(a) FROM gateway_audit a WHERE turn_id=$1 ORDER BY occurred_at", turn)
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

func (h *harness) auditRow(c turn, decision, outcome string) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows := h.rows(c.ID)
		if len(rows) == 1 {
			r := rows[0]
			if r["decision"] == decision && ((outcome == "" && r["outcome"] == nil) || r["outcome"] == outcome) {
				return r
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("audit: want one %s/%s row, got %v", decision, outcome, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// auditCount and newestAuditRow find a row by arrival order, for calls whose
// turn the gateway deliberately did not record.
func (h *harness) auditCount() int {
	h.t.Helper()
	var n int
	must(h.t, h.pool.QueryRow(context.Background(), "SELECT count(*) FROM gateway_audit").Scan(&n))
	return n
}

func (h *harness) newestAuditRow(before int) map[string]any {
	h.t.Helper()
	require(h.t, h.auditCount() == before+1, "want exactly one new audit row, have %d", h.auditCount()-before)
	var raw []byte
	must(h.t, h.pool.QueryRow(context.Background(), "SELECT row_to_json(a) FROM gateway_audit a ORDER BY occurred_at DESC LIMIT 1").Scan(&raw))
	var row map[string]any
	must(h.t, json.Unmarshal(raw, &row))
	return row
}
