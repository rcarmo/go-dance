package httpserver

import (
	"net/http"
	"net/http/httptest"
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
