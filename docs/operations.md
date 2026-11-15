# Operations

## Running `dance`

Typical local run:

```bash
cd projects/dance
DANCE_ADMIN_EMAIL=admin@example.com \
DANCE_ADMIN_PASSWORD=changeme \
DANCE_STEPCA_CONFIG=./ca.json \
DANCE_STEPCA_PASSWORD=changeme \
go run ./cmd/dance
```

## Build

```bash
go build ./cmd/dance
```

## Test

```bash
go test ./...
```

## What to back up

You should back up both application and CA state.

### `dance` state
Back up:
- `.dance/dance.sqlite` or your configured `DANCE_DB_PATH`

Contains:
- admin users
- local audit log

### `step-ca` state
Back up whatever your embedded `step-ca` config points to:
- CA config JSON
- root and intermediate certs/keys
- CA DB backend files or service data

`dance` does not replace CA backup responsibility.

## Secrets to protect

At minimum:
- `DANCE_SESSION_KEY`
- `DANCE_STEPCA_PASSWORD`
- any CA private key files referenced by `step-ca` config

## Health checks

Use:

```text
GET /healthz
GET /readyz
```

`/healthz` confirms that the HTTP server can respond. It does not test ACME.

In embedded mode, `/readyz` checks authority initialization and a non-mutating
CA storage read, bounded to one second. It returns 503 while an ACME request has
been outstanding for five seconds, or for 30 seconds after an ACME server error.
A successful request at the same operation clears that operation's failure.
Directory or nonce success does not clear an order failure. Only one storage
probe can remain outstanding when the underlying database is blocked.

Readiness does not issue a nonce or certificate, test storage writes, validate
DNS/challenge reachability or guarantee renewal. Monitor actual certificate
expiry and ACME client failures separately. In proxy mode, readiness checks only
that an upstream URL is configured; it does not probe the upstream service.

## ACME failure diagnostics

Embedded ACME responses include a generated `X-Request-ID`. Server logs use that
ID to correlate the request's operation, duration and status with storage errors.
Requests taking five seconds produce an `acme_request_stalled` warning before
completion. Storage diagnostics identify the operation and safe error class,
including `disk_full`, `io_error`, `permission_denied` and `read_only`.

When requests stall or return `serverInternal`:

1. Record the UTC timestamp, `X-Request-ID`, operation, latency and HTTP status.
2. Collect the matching `acme_request`, `acme_error` and `acme_storage` log lines.
3. Record the running binary's build identity with `go version -m /path/to/dance`,
   or the deployed container image digest.
4. Check available disk space, storage I/O errors, filesystem permissions and
   service/container resource limits. Compare direct-backend and reverse-proxy
   response timings where operator access permits.
5. Verify renewal using the existing ACME account and trusted root. Do not disable
   EAB or reset accounts, keys or CA state to diagnose an operational failure.

Do not enable request-body dumps or include bearer credentials, EAB HMACs,
account/certificate private keys, JWS payloads or challenge tokens in reports.
Unknown backend errors use a generic class rather than logging raw messages.
A readiness failure is evidence of degradation, not a diagnosis of its cause.

## Embedded mode operational notes

In embedded mode:
- one process owns both UI and ACME endpoints
- failures in embedded authority initialization prevent startup
- inventory reads depend on access to the configured CA DB

## Proxy mode operational notes

In proxy mode:
- UI may be healthy while ACME backend is degraded
- root metadata and certificate inventory are limited or unavailable
- external `step-ca` remains a separate operational unit

## Restarts

If `DANCE_SESSION_KEY` is randomly generated on boot:
- all existing sessions become invalid after restart

Set a stable key in any non-ephemeral environment.

## Deployment model recommendations

### Small local deployment
- single host
- embedded mode
- local filesystem CA config
- local DBs

### Hardened local deployment
- embedded mode
- stable session key
- managed backups
- service manager unit file or container runtime unit
- restricted filesystem permissions on CA material

See also:
- [Deployment](deployment.md)

## Failure modes to watch

### Wrong `DANCE_STEPCA_PASSWORD`
Symptoms:
- startup failure
- authority initialization error

### Missing or invalid `step-ca` config
Symptoms:
- startup failure
- embedded mode unavailable

### CA DB inaccessible
Symptoms:
- embedded inventory unavailable
- ACME handler may fail depending on DB/config state

### Rotating session key accidentally
Symptoms:
- all users are logged out after restart

Mitigation:
- set `DANCE_SESSION_KEY` explicitly in non-development environments
- `dance` now rejects secure/non-development setups that rely on an ephemeral generated session key

## Suggested production checklist

- [ ] stable `DANCE_BASE_URL`
- [ ] stable `DANCE_SESSION_KEY`
- [ ] secure secret injection for `DANCE_STEPCA_PASSWORD`
- [ ] backup CA config and CA DB
- [ ] backup local `dance` SQLite
- [ ] test root download
- [ ] test admin login
- [ ] test Caddy or other ACME client issuance
