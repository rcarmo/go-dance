package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentGuideIsPublicAndHonestAboutCapabilities(t *testing.T) {
	for _, withRoot := range []bool{false, true} {
		h, st, _ := newTestHandler(t, withRoot)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/llms.txt", nil))
		st.Close()
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("content type = %q", got)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing nosniff")
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("public guide should not create a session")
		}
		for _, forbidden := range []string{"issue #", "github.com/", "planned", "NOT implemented", "roadmap", "MCP", "keychain", "target daemon", "unchanged", "GO-2026-", "Nix"} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Fatalf("agent guide contains project commentary %q", forbidden)
			}
		}
		for _, want := range []string{
			"externalAccountRequired", "Authorization: Bearer", "Idempotency-Key", "target", "separate approval", "Do not scrape", "/enroll/root.pem",
		} {
			if !strings.Contains(w.Body.String(), want) {
				t.Fatalf("missing guidance %q", want)
			}
		}
	}
}

func TestLandingPageAdvertisesAgentGuideWithoutChangingNavigation(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := w.Header().Get("Link"); got != `</llms.txt>; rel="describedby"; type="text/plain"` {
		t.Fatalf("discovery link = %q", got)
	}
	if strings.Contains(w.Body.String(), "/llms.txt") {
		t.Fatal("agent discovery should not alter the human navigation")
	}
}

func TestAgentGuideHeadAndUnsupportedMethod(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	for _, tc := range []struct {
		method string
		status int
	}{
		{http.MethodHead, http.StatusOK}, {http.MethodPost, http.StatusMethodNotAllowed},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, "/llms.txt", nil))
		if w.Code != tc.status {
			t.Fatalf("%s status = %d", tc.method, w.Code)
		}
		if tc.method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("HEAD must not include the document body")
		}
	}
}
