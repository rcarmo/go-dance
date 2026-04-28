# Configuration

## Configuration sources

`dance` is currently configured through environment variables.

## Environment variables

### Core server

#### `DANCE_ADDR`
HTTP bind address.

Default:

```text
:8088
```

#### `DANCE_BASE_URL`
Public base URL used for generated links and UI display.

Default:

```text
http://localhost:8088
```

This also controls whether cookies are marked `Secure`.

### Local app storage

#### `DANCE_DB_PATH`
Path to the SQLite database used by `dance` itself.

Default:

```text
.dance/dance.sqlite
```

This database stores local admin users and audit events.

### Sessions

#### `DANCE_SESSION_KEY`
HMAC signing key for session cookies.

Behavior:
- if unset, a random key is generated at startup
- that is fine for development
- in production, set this explicitly or all sessions will be invalid after restart
- secure/non-development setups should set this explicitly; `dance` validates this during startup

#### `DANCE_COOKIE_NAME`
Optional cookie name override.

Default:

```text
dance_session
```

#### `DANCE_DEVELOPMENT_MODE`
Enables development-mode validation leniency.

Useful for:
- temporary local runs
- allowing an ephemeral session key in a non-default environment during development

### Admin bootstrap

#### `DANCE_ADMIN_EMAIL`
Bootstrap admin email.

If set together with `DANCE_ADMIN_PASSWORD`, `dance` ensures that an admin user exists at startup.

#### `DANCE_ADMIN_PASSWORD`
Bootstrap admin password.

Passwords are stored using bcrypt in the local SQLite DB.

### Root certificate serving

#### `DANCE_ROOT_CERT_PATH`
Optional path to a PEM root certificate file served at `/enroll/root.pem`.

If unset, `dance` serves the embedded root chain from `step-ca` when available.

### Embedded step-ca

#### `DANCE_STEPCA_CONFIG`
Path to a `step-ca` JSON config file.

When set, `dance` starts in **embedded** mode and initializes `step-ca` in-process.

#### `DANCE_STEPCA_PASSWORD`
Password used to unlock the embedded `step-ca` intermediate key.

If your `step-ca` config requires key decryption, this must be correct.

### Fallback proxy mode

#### `DANCE_STEPCA_URL`
Optional external `step-ca` URL.

When `DANCE_STEPCA_CONFIG` is not set, `dance` can fall back to **proxy** mode using this URL for `/acme/...` requests.

## Mode selection

`dance` currently chooses CA mode like this:

1. if `DANCE_STEPCA_CONFIG` is set -> **embedded mode**
2. else if `DANCE_STEPCA_URL` is set -> **proxy mode**
3. else -> **disabled mode**

## Example: embedded development setup

```bash
export DANCE_ADMIN_EMAIL=admin@example.com
export DANCE_ADMIN_PASSWORD=changeme
export DANCE_STEPCA_CONFIG=./ca.json
export DANCE_STEPCA_PASSWORD=changeme
export DANCE_BASE_URL=http://localhost:8088

go run ./cmd/dance
```

## Example: proxy setup

```bash
export DANCE_ADMIN_EMAIL=admin@example.com
export DANCE_ADMIN_PASSWORD=changeme
export DANCE_STEPCA_URL=https://ca.internal
export DANCE_ROOT_CERT_PATH=./root_ca.pem

go run ./cmd/dance
```

## Expected `step-ca` config concerns

Because `dance` embeds `step-ca`, the configured CA JSON still matters for:
- roots and intermediate chain
- database backend
- provisioners
- DNS names
- address metadata used for link generation

`dance` does not replace that configuration; it wraps it.

## Recommendations

### Development
- use `DANCE_BASE_URL=http://localhost:8088`
- allow random `DANCE_SESSION_KEY`
- use a local `step-ca` config and local DB

### Production-like deployments
- set a stable `DANCE_SESSION_KEY`
- use a stable `DANCE_BASE_URL`
- back up both the `dance` SQLite DB and the `step-ca` DB
- store `DANCE_STEPCA_PASSWORD` securely
- avoid checking CA secrets into source control
