package stepca

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/smallstep/certificates/acme"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/nosql"
)

const enrollmentTable = "dance_enrollment_requests_v1"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type EnrollmentAuditEvent struct {
	ID     string    `json:"event_id"`
	Action string    `json:"action"`
	Actor  string    `json:"actor"`
	KeyID  string    `json:"key_id"`
	At     time.Time `json:"at"`
}
type enrollmentRow struct {
	Audit         []EnrollmentAuditEvent `json:"audit"`
	Principal     string                 `json:"principal"`
	Digest        string                 `json:"digest"`
	InvalidatedAt time.Time              `json:"invalidated_at,omitempty"`
	enrollment.Metadata
}

func requestKey(principal, provisioner, request string) []byte {
	b, _ := json.Marshal([]string{principal, provisioner, request})
	d := sha256.Sum256(b)
	return []byte(hex.EncodeToString(d[:]))
}
func (m *Manager) enrollmentProvisioner(p enrollment.Principal, name, op string) (ACMEProvisionerInfo, error) {
	if !m.enrollmentSupported() {
		return ACMEProvisionerInfo{}, enrollment.E("unsupported_backend")
	}
	for _, v := range m.ACMEProvisioners() {
		if v.Name == name {
			if !p.Allows(op, v.ID) {
				return v, enrollment.E("scope_denied")
			}
			return v, nil
		}
	}
	return ACMEProvisionerInfo{}, enrollment.E("not_found")
}
func (m *Manager) EnrollmentProvisioners(p enrollment.Principal) ([]enrollment.Provisioner, error) {
	if !m.enrollmentSupported() {
		return nil, enrollment.E("unsupported_backend")
	}
	out := []enrollment.Provisioner{}
	for _, v := range m.ACMEProvisioners() {
		if p.Allows("provisioners:read", v.ID) {
			out = append(out, enrollment.Provisioner{ID: v.ID, Name: v.Name, Directory: m.directory(v.Name), RequireEAB: v.RequireEAB})
		}
	}
	return out, nil
}
func (m *Manager) directory(name string) string {
	return m.publicBaseURL + "/acme/" + url.PathEscape(name) + "/directory"
}
func (m *Manager) CreateEnrollment(ctx context.Context, p enrollment.Principal, name, requestID string, req enrollment.Request) (enrollment.Created, bool, error) {
	var empty enrollment.Created
	prov, err := m.enrollmentProvisioner(p, name, "eab:create")
	if err != nil {
		return empty, false, err
	}
	if !requestIDPattern.MatchString(requestID) {
		return empty, false, enrollment.E("invalid_request")
	}
	if err := req.Validate(p); err != nil {
		return empty, false, err
	}
	canonical, _ := json.Marshal(req)
	hash := sha256.Sum256(canonical)
	digest := hex.EncodeToString(hash[:])
	k := requestKey(p.ID, prov.ID, requestID)
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	if data, err := m.db.Get([]byte(enrollmentTable), k); err == nil {
		var row enrollmentRow
		if json.Unmarshal(data, &row) != nil {
			return empty, false, enrollment.E("backend_unavailable")
		}
		if row.Digest != digest {
			return empty, false, enrollment.E("idempotency_conflict")
		}
		meta, err := m.enrollmentMetadata(ctx, row)
		return enrollment.Created{Metadata: meta}, false, err
	} else if !nosql.IsErrNotFound(err) {
		return empty, false, enrollment.E("backend_unavailable")
	}
	// A new request ID is not permission to replace an unresolved unused
	// credential for the same owned target/reference. Require explicit
	// invalidation first, including clients using the admin credential.
	entries, err := m.db.List([]byte(enrollmentTable))
	if err != nil {
		return empty, false, enrollment.E("backend_unavailable")
	}
	for _, entry := range entries {
		var previous enrollmentRow
		if json.Unmarshal(entry.Value, &previous) != nil {
			return empty, false, enrollment.E("backend_unavailable")
		}
		if (p.Admin || previous.Principal == p.ID) && previous.ProvisionerID == prov.ID && previous.Target == req.Target && previous.Reference == req.Reference {
			meta, err := m.enrollmentMetadata(ctx, previous)
			if err != nil {
				return empty, false, err
			}
			if meta.State == "unused" {
				return empty, false, enrollment.E("existing_entry")
			}
		}
	}
	tx := stage(m.db)
	db, err := acmeNoSQL.New(tx)
	if err != nil {
		return empty, false, err
	}
	// The upstream reference index is global to a provisioner. Preserve the
	// human label in our ledger; use an opaque stable internal index reference.
	key, err := db.CreateExternalAccountKey(ctx, prov.ID, "dance-api-"+string(k))
	if err != nil {
		return empty, false, enrollment.E("backend_unavailable")
	}
	row := enrollmentRow{Principal: p.ID, Digest: digest, Metadata: enrollment.Metadata{ID: key.ID, RequestID: requestID, ProvisionerID: prov.ID, Provisioner: prov.Name, Directory: m.directory(prov.Name), Reference: req.Reference, Target: req.Target, CreatedAt: key.CreatedAt, State: "unused", Delivery: "credential_unavailable"}}
	row.Audit = []EnrollmentAuditEvent{{ID: string(k) + ":create", Action: "agent_eab_created", Actor: p.ID, KeyID: key.ID, At: key.CreatedAt}}
	data, _ := json.Marshal(row)
	if err := tx.Set([]byte(enrollmentTable), k, data); err != nil {
		return empty, false, err
	}
	if err := tx.commit(); err != nil {
		return empty, false, enrollment.E("delivery_unknown")
	}
	row.Delivery = "not_attempted"
	return enrollment.Created{Metadata: row.Metadata, HMAC: base64.RawURLEncoding.EncodeToString(key.HmacKey)}, true, nil
}
func (m *Manager) enrollmentMetadata(ctx context.Context, row enrollmentRow) (enrollment.Metadata, error) {
	meta := row.Metadata
	meta.Delivery = "credential_unavailable"
	if !row.InvalidatedAt.IsZero() {
		meta.State = "invalidated"
		return meta, nil
	}
	if !row.BoundAt.IsZero() {
		meta.State = "bound"
		return meta, nil
	}
	key, err := m.acmeDB.GetExternalAccountKey(ctx, meta.ProvisionerID, meta.ID)
	if acme.IsErrNotFound(err) {
		meta.State = "invalidated"
		return meta, nil
	}
	if err != nil {
		return meta, enrollment.E("backend_unavailable")
	}
	if key.AlreadyBound() {
		meta.State = "bound"
		meta.BoundAt = key.BoundAt
	} else {
		meta.State = "unused"
	}
	return meta, nil
}
func (m *Manager) EnrollmentStatus(ctx context.Context, p enrollment.Principal, name, id string, byRequest bool) (enrollment.Metadata, error) {
	prov, err := m.enrollmentProvisioner(p, name, "eab:read-own")
	if err != nil {
		return enrollment.Metadata{}, err
	}
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	row, _, err := m.ownedEnrollment(ctx, p, prov.ID, id, byRequest)
	if err != nil {
		return enrollment.Metadata{}, err
	}
	return m.enrollmentMetadata(ctx, row)
}
func (m *Manager) ownedEnrollment(ctx context.Context, p enrollment.Principal, prov, id string, byRequest bool) (enrollmentRow, []byte, error) {
	if byRequest {
		key := requestKey(p.ID, prov, id)
		data, err := m.db.Get([]byte(enrollmentTable), key)
		if err != nil {
			if nosql.IsErrNotFound(err) {
				return enrollmentRow{}, nil, enrollment.E("not_found")
			}
			return enrollmentRow{}, nil, enrollment.E("backend_unavailable")
		}
		var row enrollmentRow
		if json.Unmarshal(data, &row) != nil {
			return row, nil, enrollment.E("backend_unavailable")
		}
		if row.ProvisionerID != prov || (!p.Admin && (row.Principal != p.ID || row.Target != p.Target)) {
			return row, nil, enrollment.E("not_found")
		}
		return row, key, nil
	}
	entries, err := m.db.List([]byte(enrollmentTable))
	if err != nil {
		return enrollmentRow{}, nil, enrollment.E("backend_unavailable")
	}
	for _, e := range entries {
		var row enrollmentRow
		if json.Unmarshal(e.Value, &row) != nil {
			return row, nil, enrollment.E("backend_unavailable")
		}
		if (p.Admin || (row.Principal == p.ID && row.Target == p.Target)) && row.ProvisionerID == prov && row.ID == id {
			return row, e.Key, nil
		}
	}
	if p.Admin {
		key, err := m.acmeDB.GetExternalAccountKey(ctx, prov, id)
		if err != nil {
			var problem *acme.Error
			if acme.IsErrNotFound(err) || (errors.As(err, &problem) && problem.Status == http.StatusUnauthorized) {
				return enrollmentRow{}, nil, enrollment.E("not_found")
			}
			return enrollmentRow{}, nil, enrollment.E("backend_unavailable")
		}
		meta := m.unmanagedEnrollment(key)
		return enrollmentRow{Principal: p.ID, Metadata: meta}, requestKey(p.ID, prov, "legacy:"+id), nil
	}
	return enrollmentRow{}, nil, enrollment.E("not_found")
}
func (m *Manager) ListEnrollments(ctx context.Context, p enrollment.Principal, name string) ([]enrollment.Metadata, error) {
	prov, err := m.enrollmentProvisioner(p, name, "eab:read-own")
	if err != nil {
		return nil, err
	}
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	entries, err := m.db.List([]byte(enrollmentTable))
	if err != nil {
		return nil, enrollment.E("backend_unavailable")
	}
	out := []enrollment.Metadata{}
	seen := map[string]bool{}
	for _, e := range entries {
		var row enrollmentRow
		if json.Unmarshal(e.Value, &row) != nil {
			return nil, enrollment.E("backend_unavailable")
		}
		if (p.Admin || (row.Principal == p.ID && row.Target == p.Target)) && row.ProvisionerID == prov.ID {
			meta, err := m.enrollmentMetadata(ctx, row)
			if err != nil {
				return nil, err
			}
			out = append(out, meta)
			seen[meta.ID] = true
		}
	}
	if p.Admin {
		keys, _, err := m.acmeDB.GetExternalAccountKeys(ctx, prov.ID, "", 100)
		if err != nil {
			return nil, enrollment.E("backend_unavailable")
		}
		for _, key := range keys {
			if !seen[key.ID] {
				out = append(out, m.unmanagedEnrollment(key))
			}
		}
	}
	return out, nil
}
func (m *Manager) InvalidateEnrollment(ctx context.Context, p enrollment.Principal, name, id string) (enrollment.Metadata, error) {
	prov, err := m.enrollmentProvisioner(p, name, "eab:invalidate-own")
	if err != nil {
		return enrollment.Metadata{}, err
	}
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	row, k, err := m.ownedEnrollment(ctx, p, prov.ID, id, false)
	if err != nil {
		return enrollment.Metadata{}, err
	}
	meta, err := m.enrollmentMetadata(ctx, row)
	if err != nil {
		return meta, err
	}
	if meta.State == "bound" {
		return meta, enrollment.E("already_bound")
	}
	if meta.State == "invalidated" {
		return meta, nil
	}
	tx := stage(m.db)
	db, err := acmeNoSQL.New(tx)
	if err != nil {
		return meta, err
	}
	if err := db.DeleteExternalAccountKey(ctx, prov.ID, id); err != nil {
		return meta, enrollment.E("backend_unavailable")
	}
	row.InvalidatedAt = time.Now().UTC()
	row.State = "invalidated"
	row.Audit = append(row.Audit, EnrollmentAuditEvent{ID: string(k) + ":invalidate", Action: "agent_eab_invalidated", Actor: p.ID, KeyID: id, At: row.InvalidatedAt})
	data, _ := json.Marshal(row)
	if err := tx.Set([]byte(enrollmentTable), k, data); err != nil {
		return meta, err
	}
	if err := tx.commit(); err != nil {
		return meta, enrollment.E("delivery_unknown")
	}
	row.Delivery = "credential_unavailable"
	return row.Metadata, nil
}

// EnrollmentAudit is a non-secret durable outbox. These events commit in the
// same transaction as their credential and ownership/idempotency records.
func (m *Manager) EnrollmentAudit() ([]EnrollmentAuditEvent, error) {
	if !m.enrollmentSupported() {
		return nil, nil
	}
	m.enrollmentMu.Lock()
	defer m.enrollmentMu.Unlock()
	entries, err := m.db.List([]byte(enrollmentTable))
	if err != nil {
		return nil, enrollment.E("backend_unavailable")
	}
	var events []EnrollmentAuditEvent
	for _, e := range entries {
		var row enrollmentRow
		if json.Unmarshal(e.Value, &row) != nil {
			return nil, enrollment.E("backend_unavailable")
		}
		events = append(events, row.Audit...)
	}
	return events, nil
}

func (m *Manager) recordEnrollmentBindings(ctx context.Context, tx *stagedDB, db acme.DB) error {
	entries, err := m.db.List([]byte(enrollmentTable))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var row enrollmentRow
		if json.Unmarshal(entry.Value, &row) != nil {
			return enrollment.E("backend_unavailable")
		}
		if _, changed := tx.writes[stagedKey{"acme_external_account_keys", row.ID}]; !changed {
			continue
		}
		key, err := db.GetExternalAccountKey(ctx, row.ProvisionerID, row.ID)
		if err != nil {
			return err
		}
		if !key.AlreadyBound() || !row.BoundAt.IsZero() {
			continue
		}
		row.BoundAt = key.BoundAt
		row.State = "bound"
		row.Audit = append(row.Audit, EnrollmentAuditEvent{ID: string(entry.Key) + ":bind", Action: "agent_eab_bound", Actor: "acme:" + key.AccountID, KeyID: key.ID, At: key.BoundAt})
		b, _ := json.Marshal(row)
		if err := tx.Set([]byte(enrollmentTable), entry.Key, b); err != nil {
			return err
		}
	}
	return nil
}

// Existing human-created EAB keys have no API request/target assignment. Admin
// management can inspect/invalidate them without inventing target ownership or
// ever exposing their stored HMAC. Scoped machine principals cannot adopt them.
func (m *Manager) unmanagedEnrollment(key *acme.ExternalAccountKey) enrollment.Metadata {
	name := ""
	for _, prov := range m.ACMEProvisioners() {
		if prov.ID == key.ProvisionerID {
			name = prov.Name
			break
		}
	}
	state := "unused"
	if key.AlreadyBound() {
		state = "bound"
	}
	return enrollment.Metadata{ID: key.ID, ProvisionerID: key.ProvisionerID, Provisioner: name, Directory: m.directory(name), Reference: key.Reference, CreatedAt: key.CreatedAt, BoundAt: key.BoundAt, State: state, Delivery: "credential_unavailable"}
}
