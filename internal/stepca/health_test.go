package stepca

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/nosql/database"
)

type probeDB struct {
	fakeNoSQL
	calls   atomic.Int32
	release chan struct{}
	err     error
}

func (d *probeDB) Get([]byte, []byte) ([]byte, error) {
	d.calls.Add(1)
	if d.release != nil {
		<-d.release
	}
	if d.err != nil {
		return nil, d.err
	}
	return nil, database.ErrNotFound
}
func (d *probeDB) CmpAndSwap([]byte, []byte, []byte, []byte) ([]byte, bool, error) {
	return nil, d.err == nil, d.err
}

func healthyManager(db *probeDB) *Manager {
	return &Manager{mode: "embedded", auth: &authority.Authority{}, handler: http.NotFoundHandler(), db: db}
}
func TestReadinessStorageFailureStallAndRecovery(t *testing.T) {
	db := &probeDB{}
	m := healthyManager(db)
	if err := m.Ready(); err != nil {
		t.Fatal(err)
	}
	db.err = fmt.Errorf("secret-canary: %w", syscall.EIO)
	if err := m.Ready(); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("storage failure not reported safely")
	}
	db.err = nil
	h := m.healthState()
	h.mu.Lock()
	h.active["inflight"] = time.Now().Add(-acmeSlowThreshold)
	h.mu.Unlock()
	if err := m.Ready(); err == nil {
		t.Fatal("stalled ACME request reported healthy")
	}
	h.mu.Lock()
	delete(h.active, "inflight")
	h.failed["new-order"] = time.Now()
	h.mu.Unlock()
	if err := m.Ready(); err == nil {
		t.Fatal("recent internal error reported healthy")
	}
	h.mu.Lock()
	h.failed["new-order"] = time.Now().Add(-acmeFailureWindow)
	h.mu.Unlock()
	if err := m.Ready(); err != nil {
		t.Fatal("expired failure did not recover", err)
	}
}
func TestReadinessProbeBoundedWithoutGoroutineAccumulation(t *testing.T) {
	db := &probeDB{release: make(chan struct{})}
	m := healthyManager(db)
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		err := m.ReadyContext(ctx)
		cancel()
		if err == nil {
			t.Fatal("blocked storage ready")
		}
	}
	if db.calls.Load() != 1 {
		t.Fatal("blocked probes accumulated")
	}
	close(db.release)
	if err := m.Ready(); err != nil {
		t.Fatal("probe did not recover", err)
	}
}
func TestACMEErrorDiagnosticsNoSecretsAndRequestCorrelation(t *testing.T) {
	db := &probeDB{err: fmt.Errorf("private-request-canary: %w", syscall.ENOSPC)}
	m := healthyManager(db)
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	h := m.observeACME(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := acme.MustDatabaseFromContext(r.Context()).CreateNonce(r.Context())
		if err != nil {
			render.Error(w, r, acme.WrapErrorISE(err, "nonce creation failed"))
		}
	}))
	// A failed nonce write must have correlated storage/ACME diagnostics, while
	// the public response stays generic.
	request := httptest.NewRequest("POST", "/acme/default/new-order/private-request-canary?nonce=private-query-canary", strings.NewReader("private-body-canary"))
	request.Header.Set("Authorization", "Bearer private-bearer-canary")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "private-request-canary") {
		t.Fatal("failure response leaked backend details")
	}
	if err := m.Ready(); err == nil {
		t.Fatal("failed nonce endpoint remained ready")
	}
	id := rec.Header().Get("X-Request-ID")
	if len(id) != 32 {
		t.Fatal("missing generated request ID")
	}
	(&requestDB{DB: db, id: id}).Get([]byte("nonces"), []byte("secret-key-canary"))
	text := logs.String()
	for _, want := range []string{"request_id=" + id, "stage=new-order", "cause=disk_full", "operation=get", "operation=compare_and_swap", "problem=serverInternal"} {
		if !strings.Contains(text, want) {
			t.Fatal("missing diagnostic", want)
		}
	}
	for _, secret := range []string{"private-request-canary", "private-query-canary", "private-body-canary", "private-bearer-canary", "secret-key-canary"} {
		if strings.Contains(text, secret) {
			t.Fatal("secret logged")
		}
	}
}
func TestCanceledNewAccountDoesNotWaitForEnrollmentGate(t *testing.T) {
	m, _ := enrollmentManager(t, "badgerv2")
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	called := false
	m.atomicAccounts(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, httptest.NewRequest("POST", "/acme/default/new-account", nil).WithContext(ctx))
	if called || rec.Code != 503 {
		t.Fatal("canceled registration reached backend")
	}
}

func TestObservedFailureRecoveryIsStageSpecific(t *testing.T) {
	m := healthyManager(&probeDB{})
	status := 500
	h := m.observeACME(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	call := func(path string) { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, nil)) }
	call("/acme/default/new-order")
	if m.Ready() == nil {
		t.Fatal("internal error remained ready")
	}
	status = 200
	call("/acme/default/new-nonce")
	call("/acme/default/directory")
	if m.Ready() == nil {
		t.Fatal("nonce/directory masked order failure")
	}
	call("/acme/default/new-order")
	if err := m.Ready(); err != nil {
		t.Fatal("successful same-stage recovery not observed", err)
	}
	status = 400
	call("/2.0/acme/default/new-order")
	if err := m.Ready(); err != nil {
		t.Fatal("client error marked backend unavailable", err)
	}
}

func TestObservedStalledRequestReadinessAndRecovery(t *testing.T) {
	m := healthyManager(&probeDB{})
	release := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	h := m.observeACME(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.WriteHeader(204) }))
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("HEAD", "/acme/default/new-nonce", nil))
	}()
	<-started
	// Age the recorded start without making the suite wait five seconds.
	state := m.healthState()
	state.mu.Lock()
	for id := range state.active {
		state.active[id] = time.Now().Add(-acmeSlowThreshold)
	}
	state.mu.Unlock()
	if m.Ready() == nil {
		t.Fatal("active slow request reported ready")
	}
	close(release)
	<-done
	if err := m.Ready(); err != nil {
		t.Fatal("completed request did not recover", err)
	}
}
