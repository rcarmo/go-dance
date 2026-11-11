package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/enrollment"
)

// The client has ONLY HTTPS and a bearer token: no Dance client executable,
// machine-id, keychain, target agent, host login or local delivery integration.
func TestHTTPSAdminEnrollmentWithoutTargetAccess(t *testing.T) {
	_, st, mgr := agentTestServer(t)
	token := "admin-api-canary-" + strings.Repeat("x", 64)
	cfg := &config.Config{BaseURL: "https://ca.test", SessionKey: strings.Repeat("s", 32), CookieName: "dance_session", APIAdminToken: token}
	handler, err := New(cfg, st, mgr)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()
	client := srv.Client()
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	call := func(method, path, bearer, rid, body string) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "bearer "+bearer)
		}
		if rid != "" {
			req.Header.Set("Idempotency-Key", rid)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, b, res.Header
	}
	const base = "/api/v1/acme/provisioners/default"
	for _, bad := range []string{"", "bad-token"} {
		status, _, _ := call("GET", "/api/v1/acme/provisioners", bad, "", "")
		if status != 401 {
			t.Fatal("invalid admin authentication accepted")
		}
	}
	status, b, _ := call("GET", "/api/v1/acme/provisioners", token, "", "")
	if status != 200 || !bytes.Contains(b, []byte(`"name":"default"`)) || !bytes.Contains(b, []byte(`"name":"other"`)) {
		t.Fatal("admin discovery did not include configured provisioners")
	}
	// The target need not exist/be reachable. This is an administrative label;
	// provisioning credentials is not a remote install or a claim of delivery.
	body := `{"reference":"caddy-host-a","target":"no-daemon.no-login.invalid"}`
	status, b, headers := call("POST", base+"/eab-keys", token, "admin_request_123456", body)
	if status != 201 {
		t.Fatalf("creation status %d", status)
	}
	var first enrollment.Created
	if json.Unmarshal(b, &first) != nil || first.HMAC == "" || first.Target != "no-daemon.no-login.invalid" {
		t.Fatal("missing one-time credential/target metadata")
	}
	if headers.Get("Cache-Control") != "no-store" {
		t.Fatal("secret response cacheable")
	}
	status, b, _ = call("POST", base+"/eab-keys", token, "admin_request_123456", body)
	if status != 200 || bytes.Contains(b, []byte(first.HMAC)) || bytes.Contains(b, []byte(`"hmac"`)) {
		t.Fatal("replay leaked or reminted secret")
	}
	for _, path := range []string{base + "/eab-keys/" + first.ID, base + "/enrollment-requests/admin_request_123456", base + "/eab-keys"} {
		status, b, _ = call("GET", path, token, "", "")
		if status != 200 || bytes.Contains(b, []byte(first.HMAC)) {
			t.Fatal("admin status/list leaked a secret")
		}
	}
	// Existing human-created keys are manageable through JSON too. Their target
	// is unknown; matching a human reference must not confer machine ownership.
	legacy, err := mgr.CreateExternalAccountKey(context.Background(), "acme/default", "human-created")
	if err != nil {
		t.Fatal(err)
	}
	status, b, _ = call("GET", base+"/eab-keys/"+legacy.ID, token, "", "")
	if status != 200 || bytes.Contains(b, []byte(legacy.HMACKey)) {
		t.Fatal("legacy metadata unavailable or secret-bearing")
	}
	for _, path := range []string{base + "/eab-keys/no-such-key", "/api/v1/acme/provisioners/other/eab-keys/" + legacy.ID, "/api/v1/acme/provisioners/other/eab-keys/" + first.ID} {
		status, _, _ = call("GET", path, token, "", "")
		if status != 404 {
			t.Fatalf("admin missing/mismatched key: status %d", status)
		}
	}
	scoped, err := st.MintMachine(context.Background(), enrollment.Principal{Target: "host-a", Provisioners: []string{"acme/default"}, Operations: []string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ID, legacy.ID} {
		status, _, _ = call("GET", base+"/eab-keys/"+id, scoped, "", "")
		if status != 404 {
			t.Fatal("machine principal adopted admin/human credentials")
		}
	}
	status, b, _ = call("POST", base+"/eab-keys", scoped, "scoped_request_12345", `{"reference":"machine-created","target":"host-a"}`)
	var machineKey enrollment.Created
	if status != 201 || json.Unmarshal(b, &machineKey) != nil {
		t.Fatal("scoped creation failed")
	}
	status, b, _ = call("GET", base+"/eab-keys", token, "", "")
	for _, id := range []string{first.ID, legacy.ID, machineKey.ID} {
		if status != 200 || !bytes.Contains(b, []byte(id)) {
			t.Fatal("admin inventory omitted another principal/legacy key")
		}
	}
	status, _, _ = call("DELETE", base+"/eab-keys/"+machineKey.ID, token, "", "")
	if status != 200 {
		t.Fatal("admin could not manage another principal's key")
	}
	status, b, _ = call("GET", base+"/eab-keys/"+machineKey.ID, scoped, "", "")
	if status != 200 || !bytes.Contains(b, []byte("invalidated")) {
		t.Fatal("admin changed original scoped ownership")
	}
	status, _, _ = call("POST", "/api/v1/acme/provisioners/other/eab-keys", token, "admin_second_request_123", `{"reference":"second","target":"second-label"}`)
	if status != 201 {
		t.Fatal("admin creation on second provisioner failed")
	}
	status, _, _ = call("DELETE", base+"/eab-keys/"+legacy.ID, token, "", "")
	if status != 200 {
		t.Fatal("admin could not invalidate unused human key")
	}
	status, b, _ = call("GET", base+"/eab-keys/"+legacy.ID, token, "", "")
	if status != 200 || !bytes.Contains(b, []byte("invalidated")) {
		t.Fatal("legacy invalidation tombstone missing")
	}
	status, _, _ = call("DELETE", base+"/eab-keys/"+first.ID, token, "", "")
	if status != 200 {
		t.Fatal("admin could not invalidate unused key")
	}
	status, _, _ = call("POST", base+"/eab-keys", token, "admin_new_request_123", body)
	if status != 201 {
		t.Fatal("admin replacement after explicit invalidation failed")
	}
	// An API admin token must not become a browser session/password.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatal("API token bypassed browser login")
	}
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), first.HMAC) || strings.Contains(logs.String(), legacy.HMACKey) {
		t.Fatal("admin API leaked secrets into access logs")
	}
}

func TestAPIAdminTokenRotationWithoutRestart(t *testing.T) {
	_, st, mgr := agentTestServer(t)
	file := filepath.Join(t.TempDir(), "admin-token")
	old := strings.Repeat("a", 64)
	fresh := strings.Repeat("b", 64)
	if err := os.WriteFile(file, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{BaseURL: "https://ca.test", SessionKey: strings.Repeat("s", 32), APIAdminTokenFile: file}
	h, err := New(cfg, st, mgr)
	if err != nil {
		t.Fatal(err)
	}
	call := func(token string) int {
		r := httptest.NewRequest("GET", "/api/v1/acme/provisioners", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call(old) != 200 {
		t.Fatal("initial token denied")
	}
	create := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/acme/provisioners/default/eab-keys", strings.NewReader(`{"reference":"rotation","target":"any-label"}`))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "rotation_request_12345")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	initial := create(old)
	var key enrollment.Created
	if initial.Code != 201 || json.Unmarshal(initial.Body.Bytes(), &key) != nil || key.HMAC == "" {
		t.Fatal("pre-rotation creation failed")
	}
	if err := os.WriteFile(file, []byte(fresh), 0600); err != nil {
		t.Fatal(err)
	}
	if call(old) != 401 || call(fresh) != 200 {
		t.Fatal("rotation did not revoke old token")
	}
	replay := create(fresh)
	if replay.Code != 200 || !strings.Contains(replay.Body.String(), key.ID) || strings.Contains(replay.Body.String(), key.HMAC) {
		t.Fatal("token rotation changed idempotency identity or replayed a secret")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if call(fresh) != 401 {
		t.Fatal("token-file removal did not revoke access")
	}
}
