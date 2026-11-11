package httpserver

import "net/http"

// The guide advertises only interfaces shipped by this binary. Future API and
// MCP discovery documents must be added alongside the corresponding handlers.
func (s *server) handleAgentGuide(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFileFS(w, r, assets, "agent/llms.txt")
}
