package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

func agentTestServer(t *testing.T) (http.Handler, *store.SQLiteStore, *stepca.Manager) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable enrollment CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certPath := write("root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPath := write("root.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyder}))
	conf := map[string]any{"root": []string{certPath}, "crt": certPath, "key": keyPath, "address": ":443", "dnsNames": []string{"ca.test"}, "db": map[string]any{"type": "badgerv2", "dataSource": filepath.Join(dir, "ca-db")}, "authority": map[string]any{"provisioners": []any{map[string]any{"type": "ACME", "name": "default", "requireEAB": true}, map[string]any{"type": "ACME", "name": "other", "requireEAB": true}}}}
	b, _ := json.Marshal(conf)
	cfgpath := write("ca.json", b)
	mgr, err := stepca.New(context.Background(), "https://ca.test", "", cfgpath, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	st, err := store.NewSQLite(filepath.Join(dir, "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	h, err := New(&config.Config{BaseURL: "https://ca.test", SessionKey: strings.Repeat("s", 32), CookieName: "dance_session"}, st, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return h, st, mgr
}
func TestAgentEnrollmentAPIAndSecretBoundary(t *testing.T) {
	h, st, _ := agentTestServer(t)
	ctx := context.Background()
	grant := enrollment.Principal{Target: "host-a", Provisioners: []string{"acme/default"}, Operations: []string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, ReferencePrefix: "caddy-", ExpiresAt: time.Now().Add(time.Hour)}
	token, err := st.MintMachine(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := st.MintMachine(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	call := func(method, path, token, id, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if id != "" {
			r.Header.Set("Idempotency-Key", id)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const base = "/api/v1/acme/provisioners/default"
	const rid = "request_1234567890"
	const body = `{"reference":"caddy-host-a","target":"host-a"}`
	for _, method := range []string{"GET", "POST"} {
		w := call(method, base+"/eab-keys", "", rid, body)
		if w.Code != 401 {
			t.Fatalf("unauthenticated %s=%d", method, w.Code)
		}
	}
	w := call("GET", "/api/v1/acme/provisioners", token, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `"name":"other"`) || !strings.Contains(w.Body.String(), "require_eab") {
		t.Fatal("provisioner scope or discovery failed")
	}
	w = call("POST", base+"/eab-keys", token, rid, body)
	if w.Code != 201 {
		t.Fatalf("create status %d", w.Code)
	}
	var created enrollment.Created
	if json.Unmarshal(w.Body.Bytes(), &created) != nil || created.HMAC == "" {
		t.Fatal("missing one-time credential")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret response cacheable")
	}
	for _, path := range []string{base + "/eab-keys", base + "/eab-keys/" + created.ID, base + "/enrollment-requests/" + rid} {
		w = call("GET", path, token, "", "")
		if w.Code != 200 || strings.Contains(w.Body.String(), created.HMAC) || strings.Contains(w.Body.String(), `"hmac"`) {
			t.Fatal("metadata leaked or lookup failed")
		}
	}
	w = call("POST", base+"/eab-keys", token, rid, body)
	if w.Code != 200 || strings.Contains(w.Body.String(), created.HMAC) || strings.Contains(w.Body.String(), `"hmac"`) {
		t.Fatal("replay disclosed secret")
	}
	w = call("POST", base+"/eab-keys", token, rid, `{"target":"host-a","reference":"caddy-changed"}`)
	if w.Code != 409 {
		t.Fatal("idempotency conflict missing")
	}
	for _, entry := range []struct {
		path, body string
		status     int
	}{
		{base + "/eab-keys", `{"reference":"caddy-a","target":"host-b"}`, 403},
		{base + "/eab-keys", `{"reference":"wrong-prefix","target":"host-a"}`, 403},
		{base + "/eab-keys", `{"reference":"caddy-a","target":"host-a","dns_names":["x"]}`, 400},
		{base + "/eab-keys", `{"reference":"caddy-a","reference":"caddy-b","target":"host-a"}`, 400},
		{base + "/eab-keys", body + body, 400},
		{base + "/eab-keys", `{"reference":"` + strings.Repeat("x", 5000) + `","target":"host-a"}`, 400},
		{"/api/v1/acme/provisioners/other/eab-keys", body, 403},
	} {
		w = call("POST", entry.path, token, "another_123456789", entry.body)
		if w.Code != entry.status {
			t.Fatalf("validation status=%d want=%d", w.Code, entry.status)
		}
	}
	for _, method := range []string{"GET", "DELETE"} {
		w = call(method, base+"/eab-keys/"+created.ID, otherToken, "", "")
		if w.Code != 404 {
			t.Fatal("cross-principal access")
		}
	}
	// No invalidation privilege is implied by creation.
	grant.Operations = []string{"eab:create", "eab:read-own"}
	readToken, err := st.MintMachine(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	w = call("DELETE", base+"/eab-keys/"+created.ID, readToken, "", "")
	if w.Code != 403 {
		t.Fatal("invalidation privilege missing")
	}
	w = call("DELETE", base+"/eab-keys/"+created.ID, token, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "invalidated") {
		t.Fatal("invalidation failed")
	}
	p, err := st.AuthenticateMachine(ctx, token)
	if err != nil || p == nil {
		t.Fatal("authenticate")
	}
	if err = st.RevokeMachine(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	w = call("GET", base+"/enrollment-requests/"+rid, token, "", "")
	if w.Code != 401 {
		t.Fatal("revocation not immediate")
	}
	audit, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(audit)
	for _, secret := range []string{token, created.HMAC} {
		if strings.Contains(logs.String(), secret) || strings.Contains(string(b), secret) {
			t.Fatal("secret leaked to logs or audit")
		}
	}
}
func TestOpenAPIDiscoveryMatchesAgentRoutes(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/openapi.json", nil))
	if w.Code != 200 {
		t.Fatal("schema unavailable")
	}
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(w.Body.Bytes(), &spec) != nil || spec.OpenAPI != "3.1.0" || len(spec.Paths) != 4 {
		t.Fatal("invalid OpenAPI contract")
	}
	for path, ops := range spec.Paths {
		for method := range ops {
			req := httptest.NewRequest(strings.ToUpper(method), strings.ReplaceAll(strings.ReplaceAll(path, "{name}", "default"), "{id}", "some-id"), nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Fatalf("advertised route not protected: %s %s: %d", method, path, rec.Code)
			}
		}
	}
}
