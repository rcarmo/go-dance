# Deployment

`dance` is intended to be simple to run either as:

- a **systemd-managed service** on a host
- a **single container** in a small deployment stack

The same operational assumptions apply to both:
- mount or inject CA material securely
- set a stable `DANCE_SESSION_KEY`
- set `DANCE_STEPCA_PASSWORD` securely
- back up both the local SQLite DB and the CA backend data

## Systemd deployment

A typical host deployment uses:
- one dedicated service user
- a working directory containing CA config and DB data
- an environment file for runtime configuration

### Example unit

See:
- [`examples/dance.service`](examples/dance.service)

Typical layout:

```text
/opt/dance/
  dance
  ca.json
  .env
  pki/
  data/
```

Suggested environment file entries:

```bash
DANCE_ADDR=:8088
DANCE_BASE_URL=https://ca.example.lan
DANCE_DB_PATH=/opt/dance/data/dance.sqlite
DANCE_SESSION_KEY=replace-me
DANCE_STEPCA_CONFIG=/opt/dance/ca.json
DANCE_STEPCA_PASSWORD=replace-me
DANCE_ADMIN_EMAIL=admin@example.com
DANCE_ADMIN_PASSWORD=replace-me
```

## Container deployment

A container deployment should still keep state outside the image.

That means mounting:
- CA config
- CA key/cert material
- CA DB path
- `dance` SQLite path

### Example container recipe

See:
- [`examples/Dockerfile`](examples/Dockerfile)

Typical pattern:
- build a static-ish Go binary in one stage
- copy only the binary into a small runtime image
- mount `/data` and `/pki` at runtime

### Suggested runtime mounts

```text
/data   -> dance SQLite + CA DB
/pki    -> root/intermediate certs and keys
/app    -> optional config location
```

## Preview / beta recommendation

For a preview or beta deployment:

### Prefer systemd when
- you are running on a homelab VM or mini-PC
- you want easier local debugging
- you want direct filesystem access to PKI material

### Prefer a container when
- you already run a small Docker/Podman stack
- you have a clean volume and secrets story
- you want reproducible packaging and upgrades

## Health endpoints

Use both:

- `/healthz`
- `/readyz`

Recommended checks:
- liveness probe -> `/healthz`
- readiness probe -> `/readyz`

## Backup checklist

Back up at least:
- `dance` SQLite DB
- `step-ca` DB files or backend storage
- CA config JSON
- root/intermediate certs and keys
- environment file or secrets source
