package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

func newTestHandler(t *testing.T, withRoot bool) (http.Handler, *store.SQLiteStore, *config.Config) {
	t.Helper()
	ctx := context.Background()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "dance.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAdmin(ctx, "admin@example.com", "secret"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Addr:          ":0",
		BaseURL:       "http://example.test",
		DBPath:        filepath.Join(t.TempDir(), "dance.sqlite"),
		SessionKey:    "test-secret",
		AdminEmail:    "admin@example.com",
		AdminPassword: "secret",
		CookieName:    "dance_session",
	}
	if withRoot {
		rootPath := filepath.Join(t.TempDir(), "root.pem")
		pem := "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
		if err := osWriteFile(rootPath, []byte(pem)); err != nil {
			t.Fatal(err)
		}
		cfg.RootCertPath = rootPath
	}
	h, err := New(cfg, st, &stepca.Manager{})
	if err != nil {
		t.Fatal(err)
	}
	return h, st, cfg
}

func TestIndexContainsEnrollmentLinks(t *testing.T) {
	h, st, _ := newTestHandler(t, true)
	defer st.Close()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"/enroll/macos", "/enroll/ios", "/enroll/windows", "/enroll/linux"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected body to contain %q", want)
		}
	}
}

func TestHealthAndReadiness(t *testing.T) {
	h, st, _ := newTestHandler(t, true)
	defer st.Close()
	for _, tc := range []struct{ path, want string }{{"/healthz", "ok\n"}, {"/readyz", ""}} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if tc.path == "/readyz" {
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("readyz status = %d", w.Code)
			}
			continue
		}
		if w.Code != http.StatusOK || w.Body.String() != tc.want {
			t.Fatalf("%s => status %d body %q", tc.path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("missing security header on %s", tc.path)
		}
		if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Fatalf("missing frame header on %s", tc.path)
		}
	}
}

func TestRootCertDownload(t *testing.T) {
	h, st, _ := newTestHandler(t, true)
	defer st.Close()
	req := httptest.NewRequest(http.MethodGet, "/enroll/root.pem", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Fatalf("unexpected content type %q", got)
	}
	if !strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("expected PEM body")
	}
}

func TestAdminRedirectsWithoutSession(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("got status %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Fatalf("got location %q", loc)
	}
}

func TestLoginAndAccessAdmin(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	cookie := loginCookie(t, h)
	adminReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	adminReq.AddCookie(cookie)
	adminW := httptest.NewRecorder()
	h.ServeHTTP(adminW, adminReq)
	if adminW.Code != http.StatusOK {
		t.Fatalf("got admin status %d", adminW.Code)
	}
	body := adminW.Body.String()
	for _, want := range []string{"dance admin", "Audit log", "Admins"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected admin body to contain %q", want)
		}
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	csrf := loginCSRFToken(t, h)
	form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid credentials") {
		t.Fatal("expected invalid credentials message")
	}
}

func TestLoginRequiresCSRF(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	form := url.Values{"email": {"admin@example.com"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got status %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	for range 5 {
		csrf := loginCSRFToken(t, h)
		form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}, "csrf_token": {csrf}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}
	csrf := loginCSRFToken(t, h)
	form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d", w.Code)
	}
}

func TestCertificateDetailNotFoundWithoutEmbeddedCA(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	cookie := loginCookie(t, h)
	req := httptest.NewRequest(http.MethodGet, "/admin/certificates/123", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got status %d", w.Code)
	}
}

func TestCreateEABRedirectsOnUnavailableEmbeddedDB(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	cookie := loginCookie(t, h)
	form := url.Values{"provisioner_id": {"acme/acme"}, "reference": {"gateway"}, "csrf_token": {adminCSRFToken(t, h, cookie)}}
	req := httptest.NewRequest(http.MethodPost, "/admin/eab", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("got status %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Fatalf("expected redirect with error, got %q", loc)
	}
}

func TestRevokeCertificateRedirectsOnUnavailableEmbeddedAuthority(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	cookie := loginCookie(t, h)
	form := url.Values{"reason": {"superseded"}, "reason_code": {"4"}, "csrf_token": {adminCSRFToken(t, h, cookie)}}
	req := httptest.NewRequest(http.MethodPost, "/admin/certificates/123/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("got status %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Fatalf("expected redirect with error, got %q", loc)
	}
}

func TestEnrollmentPagesRender(t *testing.T) {
	h, st, _ := newTestHandler(t, true)
	defer st.Close()
	pages := map[string]string{
		"/enroll/macos":   "Enroll macOS",
		"/enroll/ios":     "Enroll iPhone / iPad",
		"/enroll/windows": "Enroll Windows",
		"/enroll/linux":   "Enroll Linux",
	}
	for path, want := range pages {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("got status %d", w.Code)
			}
			body := w.Body.String()
			if !strings.Contains(body, want) {
				t.Fatalf("expected body to contain %q", want)
			}
			for _, extra := range []string{"Apple profile", "Windows script", "Linux script"} {
				if !strings.Contains(body, extra) {
					t.Fatalf("expected body to contain %q", extra)
				}
			}
		})
	}
}

func TestEnrollmentArtifactRoutes(t *testing.T) {
	h, st, cfg := newTestHandler(t, true)
	defer st.Close()
	tests := []struct {
		path        string
		contentType string
		contains    string
	}{
		{"/enroll/apple.mobileconfig", "application/x-apple-aspen-config", "PayloadType"},
		{"/enroll/windows.ps1", "text/plain; charset=utf-8", strings.TrimRight(cfg.BaseURL, "/") + "/enroll/root.pem"},
		{"/enroll/linux.sh", "text/plain; charset=utf-8", strings.TrimRight(cfg.BaseURL, "/") + "/enroll/root.pem"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("got status %d", w.Code)
			}
			if got := w.Header().Get("Content-Type"); got != tc.contentType {
				t.Fatalf("content type = %q", got)
			}
			if !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("expected body to contain %q", tc.contains)
			}
		})
	}
}

func loginCookie(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	form := url.Values{"email": {"admin@example.com"}, "password": {"secret"}, "csrf_token": {loginCSRFToken(t, h)}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	return cookies[0]
}

func loginCSRFToken(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	prefix := "name=\"csrf_token\" value=\""
	idx := strings.Index(body, prefix)
	if idx == -1 {
		t.Fatal("csrf token not found in login page")
	}
	rest := body[idx+len(prefix):]
	end := strings.Index(rest, "\"")
	if end == -1 {
		t.Fatal("csrf token terminator not found")
	}
	return rest[:end]
}

func adminCSRFToken(t *testing.T, h http.Handler, cookie *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()
	prefix := "name=\"csrf_token\" value=\""
	idx := strings.Index(body, prefix)
	if idx == -1 {
		t.Fatal("csrf token not found in admin page")
	}
	rest := body[idx+len(prefix):]
	end := strings.Index(rest, "\"")
	if end == -1 {
		t.Fatal("csrf token terminator not found")
	}
	return rest[:end]
}

func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
