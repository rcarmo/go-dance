package store

import "context"

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	IsAdmin      bool
}

type AuditEvent struct {
	Action    string
	Actor     string
	RemoteIP  string
	UserAgent string
}

type Store interface {
	Close() error
	EnsureSchema(context.Context) error
	EnsureAdmin(context.Context, string, string) error
	AuthenticateUser(context.Context, string, string) (*User, error)
	GetUserByID(context.Context, int64) (*User, error)
	ListUsers(context.Context) ([]User, error)
	AppendAudit(context.Context, AuditEvent) error
}
