package httpserver

import (
	"log"
	"net/http"

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
