# dance documentation

`dance` is a local-first certificate authority wrapper and admin UI built in Go. It embeds `step-ca` in-process for single-binary deployments and exposes a small web UI for enrollment, administration, and ACME client integration.

Project artwork in this folder:

- [`icon-256.png`](icon-256.png)
- [`icon.png`](icon.png)

## Documentation map

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Bootstrap guide](bootstrap.md)
- [Platform enrollment](enrollment.md)
- [Deployment](deployment.md)
- [HTTP routes and UI](http.md)
- [Operations](operations.md)
- [Development](development.md)
- [Roadmap](roadmap.md)
- [Example `ca.json`](examples/ca.json)
- [Example systemd unit](examples/dance.service)
- [Example Dockerfile](examples/Dockerfile)

## Project goals

`dance` exists to provide a friendlier local-first experience on top of a private CA backend:

- a landing page for root certificate enrollment
- a password-protected admin back office
- an embedded ACME endpoint for automation clients like Caddy
- a single-binary deployment model
- a place to grow certificate inventory, revocation, and enrollment policy features

## Current status

Implemented today:

- embedded `step-ca` authority initialization from config
- optional fallback proxy mode to an external `step-ca`
- landing page and root certificate download
- admin login with SQLite-backed bootstrap user
- root certificate metadata in the admin UI
- recent issued certificate inventory from the embedded CA DB
- certificate detail pages with PEM/CRT downloads
- passive revocation UI and revocation history
- EAB / enrollment token management for embedded ACME provisioners
- OS-specific guided enrollment pages

Not yet implemented:

- richer policy management
- generated Apple enrollment profiles
- platform-specific automation scripts

## Quick start

```bash
cd projects/dance
make test
DANCE_ADMIN_EMAIL=admin@example.com \
DANCE_ADMIN_PASSWORD=changeme \
DANCE_STEPCA_CONFIG=./ca.json \
DANCE_STEPCA_PASSWORD=changeme \
go run ./cmd/dance
```

Open:

- `http://localhost:8088/`
- `http://localhost:8088/login`
- `http://localhost:8088/admin`

## Design stance

`dance` is intentionally a wrapper and product shell, not a ground-up CA reimplementation. The current design prefers:

- embedding proven `step-ca` components
- isolating that dependency behind `internal/stepca`
- keeping UI/session/admin logic in `dance`
- growing product features incrementally without forking PKI fundamentals
