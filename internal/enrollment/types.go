// Package enrollment defines the secret-free contract shared by transports and
// the embedded CA adapter. Secrets have a separate, one-time response type.
package enrollment

import (
	"errors"
	"strings"
	"time"
)

type Principal struct {
	Admin           bool      `json:"-"`
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	Provisioners    []string  `json:"provisioners"`
	Operations      []string  `json:"operations"`
	ReferencePrefix string    `json:"reference_prefix"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (p Principal) Allows(operation, provisioner string) bool {
	if p.Admin {
		return contains([]string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, operation)
	}
	return contains(p.Operations, operation) && contains(p.Provisioners, provisioner)
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func (p Principal) Validate() error {
	if p.Admin || p.ID == "" || p.Target == "" || len(p.Provisioners) == 0 || len(p.Operations) == 0 || p.ExpiresAt.IsZero() {
		return E("invalid_request")
	}
	for _, op := range p.Operations {
		if !contains([]string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, op) {
			return E("invalid_request")
		}
	}
	return nil
}

type Request struct {
	Reference string `json:"reference"`
	Target    string `json:"target"`
}

func (r Request) Validate(p Principal) error {
	if !p.Admin && (r.Target != p.Target || !strings.HasPrefix(r.Reference, p.ReferencePrefix)) {
		return E("scope_denied")
	}
	if len(r.Reference) == 0 || len(r.Reference) > 128 || len(r.Target) == 0 || len(r.Target) > 128 {
		return E("invalid_request")
	}
	for _, c := range r.Reference + r.Target {
		if c < 32 || c == 127 {
			return E("invalid_request")
		}
	}
	return nil
}

type Metadata struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	ProvisionerID string    `json:"provisioner_id"`
	Provisioner   string    `json:"provisioner"`
	Directory     string    `json:"directory"`
	Reference     string    `json:"reference"`
	Target        string    `json:"target"`
	CreatedAt     time.Time `json:"created_at"`
	BoundAt       time.Time `json:"bound_at,omitempty"`
	State         string    `json:"state"`
	Delivery      string    `json:"delivery"`
}
type Created struct {
	Metadata
	HMAC string `json:"hmac,omitempty"`
}
type Provisioner struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Directory  string `json:"directory"`
	RequireEAB bool   `json:"require_eab"`
}
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }
func E(code string) error      { return &Error{Code: code} }
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "backend_unavailable"
}
