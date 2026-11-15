package stepca

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	apiLog "github.com/smallstep/certificates/api/log"
	"github.com/smallstep/nosql"
)

const acmeSlowThreshold = 5 * time.Second
const acmeFailureWindow = 30 * time.Second
const readinessTimeout = time.Second

type backendHealth struct {
	mu     sync.Mutex
	active map[string]time.Time
	failed map[string]time.Time
	probe  *storageProbe
}

type storageProbe struct {
	done chan struct{}
	err  error
}

func (m *Manager) healthState() *backendHealth {
	m.healthOnce.Do(func() { m.health = &backendHealth{active: map[string]time.Time{}, failed: map[string]time.Time{}} })
	return m.health
}

// ReadyContext checks a non-mutating storage read and observed operational
// failures. At most one uncancellable storage probe can be outstanding, even
// when callers time out. No nonce, account, order or certificate is created.
func (m *Manager) ReadyContext(ctx context.Context) error {
	if err := m.readyInitialized(); err != nil {
		return err
	}
	if m.mode != "embedded" {
		return nil
	}
	if m.db == nil {
		return fmt.Errorf("ACME storage unavailable")
	}
	h := m.healthState()
	h.mu.Lock()
	now := time.Now()
	for _, start := range h.active {
		if now.Sub(start) >= acmeSlowThreshold {
			h.mu.Unlock()
			return fmt.Errorf("ACME request stalled")
		}
	}
	for stage, at := range h.failed {
		if now.Sub(at) < acmeFailureWindow {
			h.mu.Unlock()
			return fmt.Errorf("ACME operation failed recently")
		}
		delete(h.failed, stage)
	}
	if h.probe == nil {
		h.probe = &storageProbe{done: make(chan struct{})}
		probe := h.probe
		go func() {
			// A reserved lookup key: absence is healthy, other read errors are not.
			_, err := m.db.Get([]byte("nonces"), []byte("dance-readiness-probe"))
			if nosql.IsErrNotFound(err) {
				err = nil
			}
			h.mu.Lock()
			probe.err = err
			close(probe.done)
			h.mu.Unlock()
		}()
	}
	probe := h.probe
	h.mu.Unlock()
	select {
	case <-ctx.Done():
		return fmt.Errorf("ACME storage check timed out")
	case <-probe.done:
		h.mu.Lock()
		err := probe.err
		if h.probe == probe {
			h.probe = nil
		}
		h.mu.Unlock()
		if err != nil {
			return fmt.Errorf("ACME storage unavailable")
		}
		return nil
	}
}

func acmeStage(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		return "unknown"
	}
	idx := 2
	if parts[0] == "2.0" {
		idx = 3
	}
	if len(parts) <= idx {
		return "unknown"
	}
	switch parts[idx] {
	case "new-nonce", "new-account", "new-order", "order", "authz", "challenge", "certificate", "revoke-cert", "key-change", "directory":
		return parts[idx]
	}
	return "unknown"
}

// Do not accept request IDs from clients or log request URLs, bodies, nonce/JWS
// fields, account IDs or raw error messages. The generated ID correlates safe
// storage diagnostics, the slow-request warning and the final response.
func (m *Manager) observeACME(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			http.Error(w, "request identification unavailable", 503)
			return
		}
		id := hex.EncodeToString(idBytes)
		stage := acmeStage(r.URL.Path)
		start := time.Now()
		w.Header().Set("X-Request-ID", id)
		h := m.healthState()
		h.mu.Lock()
		h.active[id] = start
		h.mu.Unlock()
		defer func() { h.mu.Lock(); delete(h.active, id); h.mu.Unlock() }()
		timer := time.AfterFunc(acmeSlowThreshold, func() {
			h.mu.Lock()
			_, active := h.active[id]
			h.mu.Unlock()
			if !active {
				return
			}
			log.Printf("acme_request_stalled request_id=%s stage=%s threshold_ms=%d", id, stage, acmeSlowThreshold.Milliseconds())
		})
		defer timer.Stop()
		// Reuse the initialized schema; constructing the upstream adapter here must
		// not issue CreateTable writes on every nonce/order request.
		db, err := acmeNoSQL.New(&requestDB{DB: m.db, id: id})
		if err != nil {
			http.Error(w, "ACME storage unavailable", 503)
			return
		}
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		ctx = apiLog.WithErrorLogger(ctx, func(_ http.ResponseWriter, _ *http.Request, err error) {
			problem := "backend_error"
			var ae *acme.Error
			if errors.As(err, &ae) {
				for _, code := range []string{"serverInternal", "badNonce", "malformed", "unauthorized", "externalAccountRequired", "rateLimited", "rejectedIdentifier", "connection", "dns"} {
					if ae.Type == "urn:ietf:params:acme:error:"+code {
						problem = code
						break
					}
				}
			}
			log.Printf("acme_error request_id=%s stage=%s problem=%s cause=%s", id, stage, problem, safeErrorCause(err))
		})
		metrics := httpsnoop.CaptureMetrics(next, w, r.WithContext(acme.NewDatabaseContext(ctx, db)))
		if stage != "directory" && stage != "unknown" {
			h.mu.Lock()
			if metrics.Code >= 500 {
				h.failed[stage] = time.Now()
			} else if metrics.Code < 400 {
				delete(h.failed, stage)
			}
			h.mu.Unlock()
		}
		log.Printf("acme_request request_id=%s stage=%s method=%s status=%d duration_ms=%d canceled=%t", id, stage, r.Method, metrics.Code, metrics.Duration.Milliseconds(), errors.Is(r.Context().Err(), context.Canceled))
	})
}

// Canceled new-account callers must not queue indefinitely behind an enrollment
// mutation. This does not abandon or force-unlock an active storage transaction.
func (m *Manager) lockEnrollment(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.enrollmentMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
