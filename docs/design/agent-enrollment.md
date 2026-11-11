# Enrollment API design

The HTTPS enrollment API supports provisioner discovery, EAB credential creation,
metadata inspection and unused-key invalidation.

## Authentication and ownership

`DANCE_API_ADMIN_TOKEN` or `DANCE_API_ADMIN_TOKEN_FILE` supplies an independent
enrollment administrator credential. Comparison uses constant-time SHA-256 digest
comparison. It never substitutes for browser login, a session key or CA passwords.
Production configuration requires an HTTPS public base URL. File-backed credentials
are read per request for rotation/removal. The stable `api-admin` principal keeps
idempotency identity across rotation.

Administrators can inspect/invalidate API-managed keys across targets and existing
human-created EAB keys. Unknown legacy target/request IDs stay empty; labels never
confer ownership. Invalidated legacy keys acquire a metadata tombstone so repeated
status/deletion remains safe. HMACs are excluded from every metadata response.
Request reconciliation uses the creating principal's request namespace; an admin's
request-ID route reconciles admin-created requests, while its key-ID route can
manage keys created by other principals.

Optional machine credentials store only bearer digests in Dance SQLite and are
scoped by provisioner ID, operations, target, reference prefix, expiry and principal.
They cannot adopt another principal's keys. Local `dance admin` is an operator
utility for these optional grants/revocations; consumers still use only HTTPS.
Admin access is assigned only by server configuration, never by a machine grant.

## Transactional CA adapter

Embedded Badger v1/v2 support enrollment mutations. Proxy/shared SQL backends fail
closed with `unsupported_backend`. A manager gate covers API/UI EAB mutation and
both new-account aliases. Upstream EAB create/delete and new-account writes are
staged, then published in a single Badger transaction with ownership/idempotency
metadata and an audit outbox record.

Upstream EAB creation can save a key before reference-index failure. Badger's
`CmpOrRollback` is unsupported and failed CAS does not abort unrelated writes.
Upstream account creation precedes binding. Staging prevents partial visibility
across these operations. ACME nonces deliberately bypass staging and stay consumed
on failure. Empty EAB index arrays are normalised to semantic absence so creating
a key after invalidating the last unused one still works.

`dance_enrollment_requests_v1` stores principal/provisioner/request identity,
canonical request digest, metadata and audit events. It does not duplicate HMACs.
The request key hashes the principal, provisioner ID and client request ID. Only
the first committed creation response includes the HMAC; retries/reconciliation
return metadata. An uncertain commit reports `delivery_unknown`. The caller must
reconcile the original request instead of creating blind replacements.

Admin inventory merges API ledger metadata with human-created keys from the
provisioner index, without returning stored HMAC material. An unused key must be
explicitly invalidated before replacement for the same target/reference. Bound
keys cannot be invalidated. Account deactivation and certificate revocation are
separate operations.

## HTTPS boundary

Handlers use strict 4 KiB JSON, reject unknown fields, enforce the versioned
idempotency-key format and return `Cache-Control: no-store`. Browser sessions do
not authenticate API routes; bearer credentials do not authenticate browser pages.
Rate limits apply before backend work. Error responses contain stable versioned
codes without raw backend messages, bearer credentials or HMACs.

`target` and `reference` are inventory labels. They do not authenticate hosts,
restrict certificate names, prove delivery or authorise proxy changes. The API
makes no connection to the labelled target. The one-time response goes to the
authorised client, which chooses its own secret handling and consumer handoff.

## Discovery and transport

The landing response advertises `/llms.txt` through its `Link` header.
`/api/v1/openapi.json` provides the route, authentication and schema contract.

## Verification

Unit/integration tests cover admin/scoped authentication, independent credentials,
private-file validation, rotation/removal, legacy-key inventory/invalidation,
one-time secrets, log/audit exclusion, strict input, conflict/restart/concurrency,
transaction failure, unused invalidation and atomic account binding. Targeted
race tests exercise the shared manager gate.

The disposable Caddy fixture uses the API admin token over verified HTTPS. It
performs discovery, one-time creation and
metadata-only replay, then proves real challenge/issuance, automatic renewal and
restart without EAB using the same persisted account and single bootstrap key.
Native Linux AMD64/ARM64 CI runs the fixture; matching Windows builds remain
cross-compilation only.
