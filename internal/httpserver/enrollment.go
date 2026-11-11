package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/rcarmo/dance/internal/store"
)

type machineContext struct{}

func (s *server) agentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFileFS(w, r, assets, "agent/openapi.json")
	})
	mux.Handle("GET /api/v1/acme/provisioners", s.machine(http.HandlerFunc(s.agentProvisioners)))
	base := "/api/v1/acme/provisioners/{name}"
	mux.Handle("POST "+base+"/eab-keys", s.machine(http.HandlerFunc(s.agentCreate)))
	mux.Handle("GET "+base+"/eab-keys", s.machine(http.HandlerFunc(s.agentList)))
	mux.Handle("GET "+base+"/eab-keys/{id}", s.machine(http.HandlerFunc(s.agentStatus)))
	mux.Handle("DELETE "+base+"/eab-keys/{id}", s.machine(http.HandlerFunc(s.agentInvalidate)))
	mux.Handle("GET "+base+"/enrollment-requests/{id}", s.machine(http.HandlerFunc(s.agentReconcile)))
}
func (s *server) machine(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Link", `</api/v1/openapi.json>; rel="service-desc"; type="application/json"`)
		if !s.agentLimiter.Allow("ip:" + clientIP(r)) {
			agentError(w, enrollment.E("rate_limited"))
			return
		}
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 {
			agentError(w, enrollment.E("unauthenticated"))
			return
		}
		parts := strings.SplitN(auth[0], " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			agentError(w, enrollment.E("unauthenticated"))
			return
		}
		p, err := s.authenticateEnrollment(r.Context(), parts[1])
		if err != nil {
			agentError(w, err)
			return
		}
		if p == nil {
			agentError(w, enrollment.E("unauthenticated"))
			return
		}
		if !s.agentLimiter.Allow("principal:" + p.ID) {
			agentError(w, enrollment.E("rate_limited"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), machineContext{}, *p)))
	})
}
func principal(r *http.Request) enrollment.Principal {
	return r.Context().Value(machineContext{}).(enrollment.Principal)
}
func agentJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func agentError(w http.ResponseWriter, err error) {
	code := enrollment.Code(err)
	status := 503
	switch code {
	case "unauthenticated":
		status = 401
		w.Header().Set("WWW-Authenticate", `Bearer realm="dance"`)
	case "scope_denied":
		status = 403
	case "not_found":
		status = 404
	case "invalid_request":
		status = 400
	case "idempotency_conflict", "already_bound", "existing_entry":
		status = 409
	case "rate_limited":
		status = 429
		w.Header().Set("Retry-After", "60")
	}
	agentJSON(w, status, map[string]any{"version": "v1", "error": map[string]string{"code": code, "message": code}})
}
func (s *server) agentProvisioners(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	allowed := p.Admin
	for _, op := range p.Operations {
		if op == "provisioners:read" {
			allowed = true
		}
	}
	if !allowed {
		agentError(w, enrollment.E("scope_denied"))
		return
	}
	items, err := s.stepCA.EnrollmentProvisioners(p)
	if err != nil {
		agentError(w, err)
		return
	}
	agentJSON(w, 200, map[string]any{"provisioners": items})
}
func strictEnrollmentRequest(r *http.Request) (enrollment.Request, error) {
	var req enrollment.Request
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		return req, enrollment.E("invalid_request")
	}
	dec := json.NewDecoder(r.Body)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return req, enrollment.E("invalid_request")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return req, enrollment.E("invalid_request")
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return req, enrollment.E("invalid_request")
		}
		seen[key] = true
		value, err := dec.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			return req, enrollment.E("invalid_request")
		}
		switch key {
		case "reference":
			req.Reference = text
		case "target":
			req.Target = text
		default:
			return req, enrollment.E("invalid_request")
		}
	}
	if _, err := dec.Token(); err != nil {
		return req, enrollment.E("invalid_request")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || !seen["reference"] || !seen["target"] {
		return req, enrollment.E("invalid_request")
	}
	return req, nil
}
func (s *server) agentCreate(w http.ResponseWriter, r *http.Request) {
	req, err := strictEnrollmentRequest(r)
	if err != nil {
		agentError(w, err)
		return
	}
	ids := r.Header.Values("Idempotency-Key")
	if len(ids) != 1 {
		agentError(w, enrollment.E("invalid_request"))
		return
	}
	created, fresh, err := s.stepCA.CreateEnrollment(r.Context(), principal(r), r.PathValue("name"), ids[0], req)
	if err != nil {
		agentError(w, err)
		return
	}
	if err := s.projectAgentAudit(r.Context()); err != nil {
		agentError(w, enrollment.E("delivery_unknown"))
		return
	}
	status := 200
	if fresh {
		status = 201
	}
	agentJSON(w, status, created)
}
func (s *server) agentList(w http.ResponseWriter, r *http.Request) {
	items, err := s.stepCA.ListEnrollments(r.Context(), principal(r), r.PathValue("name"))
	if err != nil {
		agentError(w, err)
		return
	}
	agentJSON(w, 200, map[string]any{"keys": items})
}
func (s *server) agentStatus(w http.ResponseWriter, r *http.Request)    { s.agentGet(w, r, false) }
func (s *server) agentReconcile(w http.ResponseWriter, r *http.Request) { s.agentGet(w, r, true) }
func (s *server) agentGet(w http.ResponseWriter, r *http.Request, request bool) {
	meta, err := s.stepCA.EnrollmentStatus(r.Context(), principal(r), r.PathValue("name"), r.PathValue("id"), request)
	if err != nil {
		agentError(w, err)
		return
	}
	agentJSON(w, 200, meta)
}
func (s *server) agentInvalidate(w http.ResponseWriter, r *http.Request) {
	meta, err := s.stepCA.InvalidateEnrollment(r.Context(), principal(r), r.PathValue("name"), r.PathValue("id"))
	if err != nil {
		agentError(w, err)
		return
	}
	if err := s.projectAgentAudit(r.Context()); err != nil {
		agentError(w, enrollment.E("delivery_unknown"))
		return
	}
	agentJSON(w, 200, meta)
}
func newAgentLimiter() *loginLimiter {
	l := newLoginLimiter()
	l.maxAttempts = 120
	l.window = time.Minute
	l.blockFor = time.Minute
	return l
}

func (s *server) projectAgentAudit(ctx context.Context) error {
	st, ok := s.store.(interface {
		ProjectMachineAudit(context.Context, string, store.AuditEvent) error
	})
	if !ok {
		return enrollment.E("backend_unavailable")
	}
	events, err := s.stepCA.EnrollmentAudit()
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := st.ProjectMachineAudit(ctx, event.ID, store.AuditEvent{Action: event.Action, Actor: event.Actor, CreatedAt: event.At.Format(time.RFC3339)}); err != nil {
			return enrollment.E("backend_unavailable")
		}
	}
	return nil
}

func (s *server) authenticateEnrollment(ctx context.Context, token string) (*enrollment.Principal, error) {
	admin, adminErr := s.cfg.EnrollmentAdminToken()
	if adminErr == nil && admin != "" {
		supplied := sha256.Sum256([]byte(token))
		expected := sha256.Sum256([]byte(admin))
		if subtle.ConstantTimeCompare(supplied[:], expected[:]) == 1 {
			return &enrollment.Principal{ID: "api-admin", Admin: true}, nil
		}
	}
	if st, ok := s.store.(store.MachineStore); ok {
		principal, err := st.AuthenticateMachine(ctx, token)
		if err != nil {
			return nil, err
		}
		if principal != nil {
			return principal, nil
		}
	}
	if adminErr != nil {
		return nil, enrollment.E("backend_unavailable")
	}
	return nil, nil
}
