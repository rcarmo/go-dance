# dance

![](docs/icon-256.png)

`dance` is a local-first web wrapper around an embedded private CA backend, initially targeting `step-ca`.

## Overview

`dance` is motivated by a simple idea: a **dead simple, reliable certificate authority for LAN and homelab use** should not require heavyweight enterprise PKI tooling, multiple moving parts, or a fragile operational model.

The project is meant to make private TLS practical for small trusted environments by focusing on a few concrete outcomes:

- **easy server enrollment** for local services, especially through ACME-compatible clients like Caddy
- **simple certificate distribution** through direct CA certificate downloads
- **device-friendly trust onboarding**, including room for enrollment profiles for macOS, iOS, and other platforms
- **single-binary deployment** so the CA UI and ACME surface can run together predictably
- **reliable local administration** with a small, understandable operational footprint

In short, `dance` is intended to sit between raw CA internals and real-world homelab usability: keeping the certificate engine solid while making trust bootstrap and server enrollment much easier.

It provides:

- a browser-friendly landing page for root certificate enrollment
- a password-protected admin UI
- embedded root certificate metadata and recent certificate inventory
- an embedded ACME front-end for compatible clients like Caddy
- SQLite-backed local state for admins and audit events
- single-binary operation with in-process `step-ca` authority embedding

## Status

Initial scaffold. The wrapper is functional for:

- root certificate download
- admin login/bootstrap
- embedded ACME endpoints backed by a configured `step-ca` authority
- root certificate fingerprint/validity display in the admin UI
- recent issued certificate inventory from the embedded CA database
- certificate detail pages
- passive certificate revocation from the admin UI
- EAB / enrollment token creation and deletion for embedded ACME provisioners
- optional fallback proxying to an external `step-ca` URL

Richer enrollment UX and broader policy/admin workflows are still to be implemented.

## Documentation

Full project documentation lives under [`docs/`](docs/README.md):

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Bootstrap guide](docs/bootstrap.md)
- [Platform enrollment](docs/enrollment.md)
- [HTTP routes and UI](docs/http.md)
- [Operations](docs/operations.md)
- [Development](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Example `ca.json`](docs/examples/ca.json)

## Layout

```text
cmd/dance/             Main entrypoint
internal/app/          App wiring
internal/config/       Env configuration
internal/httpserver/   HTTP handlers, sessions, templates, static assets
internal/stepca/       embedded step-ca integration
internal/store/        SQLite storage
```

## Configuration

Environment variables:

- `DANCE_ADDR` HTTP bind address. Default `:8088`
- `DANCE_BASE_URL` public base URL. Default `http://localhost:8088`
- `DANCE_DB_PATH` SQLite path. Default `.dance/dance.sqlite`
- `DANCE_SESSION_KEY` HMAC key for session cookies. Required outside dev.
- `DANCE_ROOT_CERT_PATH` optional PEM root certificate served at `/enroll/root.pem`; if unset, `dance` serves embedded step-ca roots when available
- `DANCE_STEPCA_CONFIG` path to a `step-ca` config file for in-process embedding
- `DANCE_STEPCA_PASSWORD` password used to unlock the embedded step-ca intermediate key
- `DANCE_STEPCA_URL` optional fallback upstream `step-ca` URL for ACME proxying when not embedding
- `DANCE_ADMIN_EMAIL` bootstrap admin email
- `DANCE_ADMIN_PASSWORD` bootstrap admin password

## Running

```bash
make test
DANCE_ADMIN_EMAIL=admin@example.com \
DANCE_ADMIN_PASSWORD=changeme \
DANCE_STEPCA_CONFIG=./ca.json \
DANCE_STEPCA_PASSWORD=changeme \
go run ./cmd/dance
```

Then open:

- `/` landing page
- `/login` admin login
- `/admin` admin dashboard
- `/acme/...` served by the embedded ACME authority when configured
