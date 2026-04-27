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
```

Current meaning:
- the HTTP server is up

It does **not** yet deeply validate:
- embedded authority health
- CA DB readability
- certificate issuance readiness

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
- service manager unit file
- restricted filesystem permissions on CA material

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

## Suggested production checklist

- [ ] stable `DANCE_BASE_URL`
- [ ] stable `DANCE_SESSION_KEY`
- [ ] secure secret injection for `DANCE_STEPCA_PASSWORD`
- [ ] backup CA config and CA DB
- [ ] backup local `dance` SQLite
- [ ] test root download
- [ ] test admin login
- [ ] test Caddy or other ACME client issuance
