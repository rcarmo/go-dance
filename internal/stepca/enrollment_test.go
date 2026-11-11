package stepca

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/smallstep/certificates/acme"
	acmenosql "github.com/smallstep/certificates/acme/db/nosql"
	stepconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	stepdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
	"go.step.sm/crypto/jose"
)

func enrollmentManager(t *testing.T, driver string) (*Manager, enrollment.Principal) {
	raw, db := enrollmentTestDB(t, driver)
	if err := raw.CreateTable([]byte(enrollmentTable)); err != nil {
		t.Fatal(err)
	}
	m := &Manager{db: raw, acmeDB: db, publicBaseURL: "https://ca.test", cfg: &stepconfig.Config{DB: &stepdb.Config{Type: driver}, AuthorityConfig: &stepconfig.AuthConfig{Provisioners: provisioner.List{&provisioner.ACME{ID: "acme/default", Name: "default", RequireEAB: true}}}}}
	p := enrollment.Principal{ID: "principal", Target: "host-a", Provisioners: []string{"acme/default"}, Operations: []string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, ExpiresAt: time.Now().Add(time.Hour)}
	return m, p
}
func TestEnrollmentConcurrentReplayOwnershipAndBinding(t *testing.T) {
	for _, driver := range []string{"badger", "badgerv2"} {
		t.Run(driver, func(t *testing.T) {
			m, p := enrollmentManager(t, driver)
			ctx := context.Background()
			req := enrollment.Request{Target: p.Target, Reference: "caddy"}
			const rid = "request_1234567890"
			var wg sync.WaitGroup
			var mu sync.Mutex
			freshCount := 0
			var first enrollment.Created
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					got, fresh, err := m.CreateEnrollment(ctx, p, "default", rid, req)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					defer mu.Unlock()
					if fresh {
						freshCount++
						first = got
					} else if got.HMAC != "" {
						t.Error("replay disclosed secret")
					}
				}()
			}
			wg.Wait()
			if freshCount != 1 || first.HMAC == "" {
				t.Fatal("creation was not single-delivery")
			}
			keys, err := m.ListExternalAccountKeys(ctx, "acme/default")
			if err != nil || len(keys) != 1 {
				t.Fatal("duplicate upstream key")
			}
			_, _, err = m.CreateEnrollment(ctx, p, "default", rid, enrollment.Request{Target: p.Target, Reference: "changed"})
			if enrollment.Code(err) != "idempotency_conflict" {
				t.Fatal("changed body did not conflict")
			}
			other := p
			other.ID = "other"
			if _, err := m.EnrollmentStatus(ctx, other, "default", first.ID, false); enrollment.Code(err) != "not_found" {
				t.Fatal("cross-principal disclosure")
			}
			other = p
			other.Target = "wrong"
			if _, err := m.EnrollmentStatus(ctx, other, "default", first.ID, false); enrollment.Code(err) != "not_found" {
				t.Fatal("cross-target disclosure")
			}
			if _, _, err := m.CreateEnrollment(ctx, p, "default", "another_123456789", enrollment.Request{Target: "other", Reference: "caddy"}); enrollment.Code(err) != "scope_denied" {
				t.Fatal("wrong target accepted")
			}
			// A freshly constructed manager over persisted state simulates request-ledger
			// recovery; the on-disk reopen case is covered separately.
			recovered := &Manager{db: m.db, acmeDB: m.acmeDB, cfg: m.cfg, publicBaseURL: m.publicBaseURL}
			got, fresh, err := recovered.CreateEnrollment(ctx, p, "default", rid, req)
			if err != nil || fresh || got.HMAC != "" || got.ID != first.ID {
				t.Fatal("recovery reminted or redisclosed")
			}
			key, err := m.acmeDB.GetExternalAccountKey(ctx, "acme/default", first.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := key.BindTo(&acme.Account{ID: "account"}); err != nil {
				t.Fatal(err)
			}
			if err := m.acmeDB.UpdateExternalAccountKey(ctx, "acme/default", key); err != nil {
				t.Fatal(err)
			}
			if _, err := m.InvalidateEnrollment(ctx, p, "default", first.ID); enrollment.Code(err) != "already_bound" {
				t.Fatal("bound key invalidated")
			}
			meta, err := m.EnrollmentStatus(ctx, p, "default", rid, true)
			if err != nil || meta.State != "bound" {
				t.Fatal("binding not reported")
			}
			b, _ := json.Marshal(meta)
			if strings.Contains(string(b), first.HMAC) {
				t.Fatal("metadata leaked HMAC")
			}
			second, _, err := m.CreateEnrollment(ctx, p, "default", "new_request_12345", req)
			if err != nil {
				t.Fatal(err)
			}
			meta, err = m.InvalidateEnrollment(ctx, p, "default", second.ID)
			if err != nil || meta.State != "invalidated" {
				t.Fatal("invalidation failed")
			}
			if _, err = m.InvalidateEnrollment(ctx, p, "default", second.ID); err != nil {
				t.Fatal("invalidation was not idempotent")
			}
		})
	}
}

type failingCommit struct {
	nosql.DB
	commitThenFail bool
}

func (f failingCommit) Update(tx *database.Tx) error {
	if f.commitThenFail {
		if err := f.DB.Update(tx); err != nil {
			return err
		}
	}
	return errors.New("injected commit failure")
}
func TestEnrollmentUncertainCommitReconcilesWithoutReminting(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "lost-ack"}[committed], func(t *testing.T) {
			m, p := enrollmentManager(t, "badgerv2")
			raw := m.db
			m.db = failingCommit{DB: raw, commitThenFail: committed}
			req := enrollment.Request{Target: p.Target, Reference: "label"}
			_, _, err := m.CreateEnrollment(context.Background(), p, "default", "uncertain_12345678", req)
			if enrollment.Code(err) != "delivery_unknown" {
				t.Fatal("uncertainty not reported")
			}
			m.db = raw
			got, fresh, err := m.CreateEnrollment(context.Background(), p, "default", "uncertain_12345678", req)
			if err != nil {
				t.Fatal(err)
			}
			if committed && (fresh || got.HMAC != "") {
				t.Fatal("uncertain committed request minted or disclosed twice")
			}
			keys, err := m.ListExternalAccountKeys(context.Background(), "acme/default")
			if err != nil || len(keys) != 1 {
				t.Fatal("rollback/retry created duplicates")
			}
		})
	}
}
func TestStagedReferenceFailureDoesNotPublishPartialKey(t *testing.T) {
	m, _ := enrollmentManager(t, "badgerv2")
	if _, err := m.CreateExternalAccountKey(context.Background(), "acme/default", "same"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateExternalAccountKey(context.Background(), "acme/default", "same"); err == nil {
		t.Fatal("expected reference conflict")
	}
	keys, err := m.ListExternalAccountKeys(context.Background(), "acme/default")
	if err != nil || len(keys) != 1 {
		t.Fatal("partial creation escaped transaction")
	}
}
func TestAtomicAccountAndBindingFailureRollsBack(t *testing.T) {
	m, p := enrollmentManager(t, "badgerv2")
	created, _, err := m.CreateEnrollment(context.Background(), p, "default", "account_123456789", enrollment.Request{Target: p.Target, Reference: "caddy"})
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := &jose.JSONWebKey{Key: &private.PublicKey}
	thumb, err := acme.KeyToID(jwk)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := acme.MustDatabaseFromContext(r.Context())
		account := &acme.Account{Key: jwk, ProvisionerID: "acme/default", ProvisionerName: "default", Status: acme.StatusValid}
		if err := db.CreateAccount(r.Context(), account); err != nil {
			t.Error(err)
			http.Error(w, "error", 500)
			return
		}
		key, err := db.GetExternalAccountKey(r.Context(), "acme/default", created.ID)
		if err != nil {
			t.Error(err)
			return
		}
		if err := key.BindTo(account); err != nil {
			t.Error(err)
			return
		}
		if err := db.UpdateExternalAccountKey(r.Context(), "acme/default", key); err != nil {
			t.Error(err)
			return
		}
		w.WriteHeader(201)
	})
	raw := m.db
	m.db = failingCommit{DB: raw}
	rec := httptest.NewRecorder()
	m.atomicAccounts(next).ServeHTTP(rec, httptest.NewRequest("POST", "/acme/default/new-account", nil))
	if rec.Code != 500 {
		t.Fatal("commit failure was acknowledged")
	}
	m.db = raw
	if _, err := m.acmeDB.GetAccountByKeyID(context.Background(), thumb); !acme.IsErrNotFound(err) {
		t.Fatal("partial account committed")
	}
	key, err := m.acmeDB.GetExternalAccountKey(context.Background(), "acme/default", created.ID)
	if err != nil || key.AlreadyBound() {
		t.Fatal("partial binding committed")
	}
	rec = httptest.NewRecorder()
	m.atomicAccounts(next).ServeHTTP(rec, httptest.NewRequest("POST", "/2.0/acme/default/new-account", nil))
	if rec.Code != 201 {
		t.Fatal("account retry failed")
	}
	if _, err := m.acmeDB.GetAccountByKeyID(context.Background(), thumb); err != nil {
		t.Fatal(err)
	}
	// Ensure the staged layer can be recreated over the original backend.
	if _, err := acmenosql.New(raw); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentOnDiskRestartKeepsSingleDelivery(t *testing.T) {
	for _, driver := range []string{"badger", "badgerv2"} {
		t.Run(driver, func(t *testing.T) {
			m, p := enrollmentManager(t, driver)
			ctx := context.Background()
			req := enrollment.Request{Target: p.Target, Reference: "restart"}
			created, _, err := m.CreateEnrollment(ctx, p, "default", "restart_123456789", req)
			if err != nil {
				t.Fatal(err)
			}
			// Copy committed on-disk state to a separate fresh DB through the real
			// backend API, close it, and reopen that database as a new process would.
			path := filepath.Join(t.TempDir(), "restart-db")
			raw, err := nosql.New(driver, path)
			if err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{enrollmentTable, "acme_external_account_keys", "acme_external_account_keyID_reference_index", "acme_external_account_keyID_provisionerID_index"} {
				if err := raw.CreateTable([]byte(bucket)); err != nil {
					t.Fatal(err)
				}
				entries, err := m.db.List([]byte(bucket))
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if err := raw.Set([]byte(bucket), e.Key, e.Value); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err = nosql.New(driver, path)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			db, err := acmenosql.New(raw)
			if err != nil {
				t.Fatal(err)
			}
			reopened := &Manager{db: raw, acmeDB: db, cfg: m.cfg, publicBaseURL: m.publicBaseURL}
			got, fresh, err := reopened.CreateEnrollment(ctx, p, "default", "restart_123456789", req)
			if err != nil || fresh || got.ID != created.ID || got.HMAC != "" {
				t.Fatal("reopen did not preserve one-time delivery")
			}
		})
	}
}

func TestRegistrationAndInvalidationAreSerialized(t *testing.T) {
	m, p := enrollmentManager(t, "badgerv2")
	ctx := context.Background()
	created, _, err := m.CreateEnrollment(ctx, p, "default", "race_request_12345", enrollment.Request{Target: p.Target, Reference: "race"})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	registrationDone := make(chan int, 1)
	invalidationDone := make(chan error, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := acme.MustDatabaseFromContext(r.Context())
		key, err := db.GetExternalAccountKey(r.Context(), "acme/default", created.ID)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		close(entered)
		<-release
		if err := key.BindTo(&acme.Account{ID: "registered-account"}); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if err := db.UpdateExternalAccountKey(r.Context(), "acme/default", key); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(201)
	})
	go func() {
		rec := httptest.NewRecorder()
		m.atomicAccounts(next).ServeHTTP(rec, httptest.NewRequest("POST", "/acme/default/new-account", nil))
		registrationDone <- rec.Code
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not enter")
	}
	go func() { _, err := m.InvalidateEnrollment(ctx, p, "default", created.ID); invalidationDone <- err }()
	// Releasing the registration determines the winner; invalidation must see
	// the committed binding rather than delete the previously-read unused key.
	close(release)
	if status := <-registrationDone; status != 201 {
		t.Fatal("registration failed")
	}
	if code := enrollment.Code(<-invalidationDone); code != "already_bound" {
		t.Fatalf("invalidation result %s", code)
	}
	// Conversely, an invalidated key cannot be read by a later registration.
	second, _, err := m.CreateEnrollment(ctx, p, "default", "race_request_67890", enrollment.Request{Target: p.Target, Reference: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InvalidateEnrollment(ctx, p, "default", second.ID); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.atomicAccounts(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := acme.MustDatabaseFromContext(r.Context()).GetExternalAccountKey(r.Context(), "acme/default", second.ID); !acme.IsErrNotFound(err) {
			t.Error("invalidated key accepted")
		}
		w.WriteHeader(400)
	})).ServeHTTP(rec, httptest.NewRequest("POST", "/2.0/acme/default/new-account", nil))
	if rec.Code != 400 {
		t.Fatal("invalidated registration did not fail")
	}
}

func TestStagedAccountFailureStillConsumesNonce(t *testing.T) {
	m, _ := enrollmentManager(t, "badgerv2")
	ctx := context.Background()
	nonce, err := m.acmeDB.CreateNonce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.atomicAccounts(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := acme.MustDatabaseFromContext(r.Context())
		if err := db.DeleteNonce(r.Context(), nonce); err != nil {
			t.Error(err)
		}
		w.WriteHeader(400)
	})).ServeHTTP(rec, httptest.NewRequest("POST", "/acme/default/new-account", nil))
	if err := m.acmeDB.DeleteNonce(ctx, nonce); err == nil {
		t.Fatal("nonce consumption rolled back with rejected request")
	}
}

func TestEnrollmentUnsupportedBackendFailsClosed(t *testing.T) {
	m, p := enrollmentManager(t, "badgerv2")
	m.cfg.DB.Type = "postgresql"
	if _, _, err := m.CreateEnrollment(context.Background(), p, "default", "unsupported_12345", enrollment.Request{Target: p.Target, Reference: "label"}); enrollment.Code(err) != "unsupported_backend" {
		t.Fatal("unsupported backend mutated")
	}
}

func TestNativeCreateRequiresInvalidationBeforeReplacingUnusedCredential(t *testing.T) {
	m, p := enrollmentManager(t, "badgerv2")
	ctx := context.Background()
	req := enrollment.Request{Target: p.Target, Reference: "same-label"}
	first, _, err := m.CreateEnrollment(ctx, p, "default", "first_request_1234", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.CreateEnrollment(ctx, p, "default", "second_request_123", req); enrollment.Code(err) != "existing_entry" {
		t.Fatal("new request ID bypassed uncertain delivery")
	}
	keys, err := m.ListExternalAccountKeys(ctx, "acme/default")
	if err != nil || len(keys) != 1 {
		t.Fatal("extra unused credential minted")
	}
	if _, err := m.InvalidateEnrollment(ctx, p, "default", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := m.CreateEnrollment(ctx, p, "default", "second_request_123", req); err != nil || !fresh {
		t.Fatal("authorised replacement rejected")
	}
}
