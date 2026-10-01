package conformance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const subject = "system:serviceaccount:conformance:agent"
const team = "test-team"
const fakeToken = "installation-token-generated-for-local-conformance-only"
const opaqueDenial = "this call did not prove which pod it came from"
const auditDenial = "the gateway could not record this call and refuses to answer unaudited"

type baseline struct {
	Protocol string `json:"protocol_version"`
	Endpoint string `json:"endpoint"`
	Tools    map[string]struct {
		Switchboard    string `json:"switchboard"`
		Classification string `json:"classification"`
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
		t.Fatalf("%s is required; run python3 conformance/run.py --otto-source /path/to/agentrunner", key)
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
	mode         string
	entered      chan struct{}
	release      chan struct{}
	appAuthValid bool
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
			_ = json.NewEncoder(w).Encode(map[string]any{"token": fakeToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			http.NotFound(w, r)
		}
		return
	}
	if o.Authorization != "Bearer "+fakeToken {
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
		http.Error(w, "fake upstream failure "+fakeToken+strings.Repeat("x", 400), 503)
		return
	}
	var result any
	switch {
	case r.URL.Path == "/search/issues":
		items := []any{}
		for i := 0; i < 12; i++ {
			items = append(items, map[string]any{"number": i + 1, "title": "Evidence", "state": "open", "html_url": "https://example.invalid/pr/1", "body": fakeToken + strings.Repeat("x", 3000), "repository_url": "https://example.invalid/repos/test-org/repo", "user": map[string]any{"login": "bot"}})
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
	key                                      *rsa.PrivateKey
	vendor                                   *fakeVendor
	stop                                     func()
	seq                                      int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir()}
	admin, err := pgxpool.New(context.Background(), requiredEnv(t, "OTTO_TEST_DATABASE_URL"))
	must(t, err)
	schema := fmt.Sprintf("conformance_%d", time.Now().UnixNano())
	_, err = admin.Exec(context.Background(), "CREATE SCHEMA "+schema)
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		if err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
		admin.Close()
	})
	u, err := url.Parse(requiredEnv(t, "OTTO_TEST_DATABASE_URL"))
	must(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	h.dsn = u.String()
	h.pool, err = pgxpool.New(context.Background(), h.dsn)
	must(t, err)
	t.Cleanup(h.pool.Close)
	sql, err := os.ReadFile(requiredEnv(t, "OTTO_TEST_AUDIT_SQL"))
	must(t, err)
	_, err = h.pool.Exec(context.Background(), string(sql))
	must(t, err)
	h.key, err = rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	h.keyPath = filepath.Join(h.dir, "test-key.pem")
	must(t, os.WriteFile(h.keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(h.key)}), 0600))
	h.manifest = filepath.Join(h.dir, "team.json")
	must(t, os.WriteFile(h.manifest, jsonBytes(t, map[string]any{"id": team, "sandbox": map[string]any{"serviceAccount": subject}}), 0600))
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
	h.vendor = &fakeVendor{pool: h.pool, key: h.key, entered: make(chan struct{}, 1), release: make(chan struct{}), appAuthValid: true}
	h.vendor.server = httptest.NewServer(http.HandlerFunc(h.vendor.serve))
	t.Cleanup(h.vendor.server.Close)
	return h
}

func (h *harness) identityArgs() []string {
	return []string{"-oidc-issuer", h.issuer, "-identity-audience", "otto-gateway", "-team-manifest", h.manifest}
}

func (h *harness) connectorArgs() []string {
	return []string{"-github-app-id", "1234", "-github-private-key-file", h.keyPath, "-github-org", "test-org", "-github-api-url", h.vendor.server.URL}
}

func (h *harness) start(identity, audit, connector bool) {
	h.t.Helper()
	args := []string{}
	if identity {
		args = append(args, h.identityArgs()...)
	} else {
		args = append(args, "-identity-audience=", "-insecure-no-caller-identity")
	}
	if audit {
		args = append(args, "-database-url", h.dsn)
	} else {
		args = append(args, "-audit-disabled")
	}
	if connector {
		args = append(args, h.connectorArgs()...)
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
	deadline := time.Now().Add(5 * time.Second)
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

func (h *harness) headers() map[string]string {
	h.seq++
	return map[string]string{"X-Otto-Session": "session-test", "X-Otto-Turn": fmt.Sprintf("turn-%d", h.seq), "X-Otto-Team": team, "X-Otto-Actor": "claimed-person", "X-Otto-Fencing-Epoch": "7", "Authorization": "Bearer " + h.token(nil, nil)}
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

func (h *harness) call(tool string, args any) (rpcReply, map[string]string) {
	headers := h.headers()
	return h.request("tools/call", map[string]any{"name": tool, "arguments": args}, headers), headers
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

func (h *harness) auditRow(headers map[string]string, decision, outcome string) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows := h.rows(headers["X-Otto-Turn"])
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
