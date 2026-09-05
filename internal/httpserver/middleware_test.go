package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type basicWriter struct{ header http.Header }

func (w *basicWriter) Header() http.Header       { return w.header }
func (*basicWriter) Write(p []byte) (int, error) { return len(p), nil }
func (*basicWriter) WriteHeader(int)             {}

func TestLoggingPreservesWriterInterfaces(t *testing.T) {
	for _, flush := range []bool{false, true} {
		var writer http.ResponseWriter = &basicWriter{header: make(http.Header)}
		if flush {
			writer = httptest.NewRecorder()
		}
		loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := w.(http.Flusher); ok != flush {
				t.Fatalf("Flusher = %v, want %v", ok, flush)
			}
			if _, ok := w.(http.Hijacker); ok {
				t.Fatal("invented Hijacker support")
			}
			if _, ok := w.(http.Pusher); ok {
				t.Fatal("invented Pusher support")
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(writer, httptest.NewRequest("GET", "/", nil))
	}
}

func TestBrowserProtection(t *testing.T) {
	h := browserProtection(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		w.WriteHeader(204)
	}))
	for _, tc := range []struct {
		path, origin, body string
		want               int
	}{
		{"/login", "https://evil.example", "", 403},
		{"/admin/eab", "https://evil.example", "", 403},
		{"/logout", "https://evil.example", "", 403},
		{"/login", "http://example.com", "", 204},
		{"/acme/acme/new-order", "https://evil.example", "", 204},
		{"/login", "", "password=" + strings.Repeat("x", 65<<10), 400},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
}
