package httpserver

import (
	"log"
	"net/http"
	"strings"

	"github.com/felixge/httpsnoop"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		// Preserve the underlying writer's optional interfaces and record the
		// actual final response, including implicit writes and informational headers.
		metrics := httpsnoop.CaptureMetrics(next, w, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, metrics.Code, metrics.Duration)
	})
}

// Browser forms have a small, bounded payload. ACME uses its own signed request
// protocol and must not inherit browser form limits or origin restrictions.
func browserProtection(next http.Handler) http.Handler {
	protection := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/logout" || r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			w.Header().Set("Cache-Control", "no-store")
			if err := protection.Check(r); err != nil {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r)
	})
}
