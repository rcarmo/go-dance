package stepca

import (
	"context"
	"errors"
	"log"
	"syscall"
	"time"

	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

type requestIDKey struct{}
type requestDB struct {
	nosql.DB
	id string
}

func (*requestDB) CreateTable([]byte) error { return nil }
func (d *requestDB) record(op string, start time.Time, err error) {
	duration := time.Since(start)
	if (err == nil || nosql.IsErrNotFound(err)) && duration < acmeSlowThreshold {
		return
	}
	// Raw backend strings can contain keys, signed payloads or HMAC material.
	// Only allowlisted underlying error classes leave the storage boundary.
	cause := safeErrorCause(err)
	log.Printf("acme_storage request_id=%s operation=%s cause=%s duration_ms=%d", d.id, op, cause, duration.Milliseconds())
}

func safeErrorCause(err error) string {
	if err == nil || nosql.IsErrNotFound(err) {
		return "none"
	}
	for depth := 0; depth < 16; depth++ {
		causer, ok := err.(interface{ Cause() error })
		if !ok {
			break
		}
		next := causer.Cause()
		if next == nil {
			break
		}
		err = next
	}
	cause := "backend_error"
	for _, v := range []struct {
		err  error
		code string
	}{{syscall.ENOSPC, "disk_full"}, {syscall.EIO, "io_error"}, {syscall.EACCES, "permission_denied"}, {syscall.EROFS, "read_only"}, {context.DeadlineExceeded, "deadline_exceeded"}, {context.Canceled, "canceled"}, {database.ErrOpNotSupported, "unsupported_operation"}} {
		if errors.Is(err, v.err) {
			cause = v.code
			break
		}
	}
	return cause
}
func (d *requestDB) Get(b, k []byte) (v []byte, err error) {
	start := time.Now()
	defer func() { d.record("get", start, err) }()
	return d.DB.Get(b, k)
}
func (d *requestDB) Set(b, k, v []byte) (err error) {
	start := time.Now()
	defer func() { d.record("set", start, err) }()
	return d.DB.Set(b, k, v)
}
func (d *requestDB) Del(b, k []byte) (err error) {
	start := time.Now()
	defer func() { d.record("delete", start, err) }()
	return d.DB.Del(b, k)
}
func (d *requestDB) CmpAndSwap(b, k, old, nu []byte) (v []byte, swapped bool, err error) {
	start := time.Now()
	defer func() { d.record("compare_and_swap", start, err) }()
	return d.DB.CmpAndSwap(b, k, old, nu)
}
func (d *requestDB) Update(tx *database.Tx) (err error) {
	start := time.Now()
	defer func() { d.record("transaction", start, err) }()
	return d.DB.Update(tx)
}
