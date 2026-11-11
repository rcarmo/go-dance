package stepca

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

// stagedDB runs upstream operations unchanged against a private write set. A
// single Badger transaction publishes the complete set. The manager's gate
// serializes all EAB mutations and new-account requests. Badger exclusively
// locks its database file: shared/multi-process SQL backends are not enabled.
// Unlike upstream transaction CAS, a failed upstream operation discards ALL
// staged writes, including partial reference/index and account/binding writes.
// Nonces deliberately bypass staging, so failed requests still consume them.
type stagedKey struct{ bucket, key string }
type stagedDB struct {
	nosql.DB
	writes map[stagedKey][]byte
}

func stage(db nosql.DB) *stagedDB            { return &stagedDB{DB: db, writes: make(map[stagedKey][]byte)} }
func (s *stagedDB) CreateTable([]byte) error { return nil }
func (s *stagedDB) Get(b, k []byte) ([]byte, error) {
	if v, ok := s.writes[stagedKey{string(b), string(k)}]; ok {
		if v == nil {
			return nil, database.ErrNotFound
		}
		return normalizeEABIndex(b, bytes.Clone(v), nil)
	}
	v, err := s.DB.Get(b, k)
	return normalizeEABIndex(b, v, err)
}

// Upstream expects a missing index when its list is empty, but deleting the
// last key persists []. Present the semantically empty list as missing inside
// the exclusive transaction so an authorised replacement can be created.
func normalizeEABIndex(bucket, value []byte, err error) ([]byte, error) {
	if err == nil && string(bucket) == "acme_external_account_keyID_provisionerID_index" && (bytes.Equal(value, []byte("[]")) || bytes.Equal(value, []byte("null"))) {
		return nil, database.ErrNotFound
	}
	return value, err
}
func (s *stagedDB) Set(b, k, v []byte) error {
	if string(b) == "nonces" {
		return s.DB.Set(b, k, v)
	}
	s.writes[stagedKey{string(b), string(k)}] = bytes.Clone(v)
	return nil
}
func (s *stagedDB) Del(b, k []byte) error {
	if string(b) == "nonces" {
		return s.DB.Del(b, k)
	}
	s.writes[stagedKey{string(b), string(k)}] = nil
	return nil
}
func (s *stagedDB) CmpAndSwap(b, k, old, nu []byte) ([]byte, bool, error) {
	if string(b) == "nonces" {
		return s.DB.CmpAndSwap(b, k, old, nu)
	}
	v, err := s.Get(b, k)
	if err != nil && !nosql.IsErrNotFound(err) {
		return nil, false, err
	}
	if !bytes.Equal(v, old) {
		return v, false, nil
	}
	return nu, true, s.Set(b, k, nu)
}
func (s *stagedDB) commit() error {
	tx := new(database.Tx)
	for k, v := range s.writes {
		if v == nil {
			tx.Del([]byte(k.bucket), []byte(k.key))
		} else {
			tx.Set([]byte(k.bucket), []byte(k.key), v)
		}
	}
	if len(tx.Operations) == 0 {
		return nil
	}
	return s.DB.Update(tx)
}
func (m *Manager) enrollmentSupported() bool {
	if m.cfg == nil || m.cfg.DB == nil || m.db == nil {
		return false
	}
	switch strings.ToLower(m.cfg.DB.Type) {
	case "badger", "badgerv1", "badgerv2":
		return true
	}
	return false
}

// new-account account creation, JWK index and EAB binding commit together. The
// original signed path and request cancellation are preserved.
func (m *Manager) atomicAccounts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enrollmentSupported() || r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/new-account") {
			next.ServeHTTP(w, r)
			return
		}
		m.enrollmentMu.Lock()
		defer m.enrollmentMu.Unlock()
		tx := stage(m.db)
		db, err := acmeNoSQL.New(tx)
		if err != nil {
			http.Error(w, "ACME database unavailable", 503)
			return
		}
		buf := &accountResponse{header: make(http.Header)}
		next.ServeHTTP(buf, r.WithContext(acme.NewDatabaseContext(r.Context(), db)))
		status := buf.status
		if status == 0 {
			status = 200
		}
		if status >= 200 && status < 300 {
			commitErr := m.recordEnrollmentBindings(r.Context(), tx, db)
			if commitErr == nil {
				commitErr = tx.commit()
			}
			if commitErr != nil {
				for k, vs := range buf.header {
					w.Header()[k] = vs
				}
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(500)
				_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:serverInternal","detail":"Account registration could not be committed","status":500}`))
				return
			}
		}
		for k, vs := range buf.header {
			w.Header()[k] = vs
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.body.Bytes())
	})
}

type accountResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *accountResponse) Header() http.Header { return w.header }
func (w *accountResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *accountResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}

// Do not let a future upstream implementation bypass the write set through an
// embedded raw DB method. Unsupported transaction shapes fail closed.
func (s *stagedDB) Update(tx *database.Tx) error {
	// Nonce consumption must commit even if account validation later fails.
	for _, op := range tx.Operations {
		if string(op.Bucket) != "nonces" || (op.Cmd != database.Get && op.Cmd != database.Delete) {
			return database.ErrOpNotSupported
		}
	}
	return s.DB.Update(tx)
}
func (s *stagedDB) DeleteTable([]byte) error               { return database.ErrOpNotSupported }
func (s *stagedDB) List([]byte) ([]*database.Entry, error) { return nil, database.ErrOpNotSupported }
func (s *stagedDB) Open(string, ...database.Option) error  { return database.ErrOpNotSupported }
func (s *stagedDB) Close() error                           { return database.ErrOpNotSupported }
