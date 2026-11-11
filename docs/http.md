# HTTP routes and UI

## Overview

`dance` exposes a small combined UI and ACME surface.

## Public routes

### `GET /`
Landing page.

Purpose:
- explain what `dance` is
- offer root certificate download
- show ACME bootstrap hints
- link to admin login

### `GET /llms.txt`
Public plain-text agent guide, also available through `HEAD`. The landing response
advertises it with `Link: </llms.txt>; rel="describedby"; type="text/plain"`.

The guide links the enrollment API contract and provides authentication, trust
bootstrap and credential lifecycle instructions.

### `GET /healthz`
Basic health endpoint.

Response:

```text
ok
```

### `GET /enroll/root.pem`
Downloads the root certificate PEM.

Source precedence:
1. `DANCE_ROOT_CERT_PATH`
2. embedded `step-ca` roots

### `GET /static/...`
Static CSS assets for the UI.

## Agent enrollment routes

`GET /api/v1/openapi.json` serves the public OpenAPI 3.1 contract.
These routes require an API admin bearer token or a scoped machine credential.
Responses use `Cache-Control: no-store`. Browser sessions are not accepted.

- `GET /api/v1/acme/provisioners`: granted provisioners, canonical directory URLs, EAB requirements.
- `POST /api/v1/acme/provisioners/{name}/eab-keys`: create one key; requires `Idempotency-Key`; the initial response contains a one-time HMAC for authorised HTTPS clients.
- `GET /api/v1/acme/provisioners/{name}/eab-keys`: metadata (all keys for administrators; owned keys for machine principals).
- `GET /api/v1/acme/provisioners/{name}/eab-keys/{id}`: availability/binding metadata with the same ownership restrictions.
- `DELETE /api/v1/acme/provisioners/{name}/eab-keys/{id}`: separately authorised unused-key invalidation; bound keys are rejected.
- `GET /api/v1/acme/provisioners/{name}/enrollment-requests/{id}`: metadata-only reconciliation after a lost response using the original request ID.

See [Agent enrollment](agent-enrollment.md) for admin token configuration, optional
machine grants, versioned errors, idempotency/reconciliation and Caddy lifecycle.

## Authentication routes

### `GET /login`
Admin login form.

### `POST /login`
Authenticates an admin against the local SQLite user table.

On success:
- issues signed session cookie
- records a login audit event
- redirects to `/admin`

### `POST /logout`
Clears session cookie and redirects to `/`.

## Admin routes

### `GET /admin`
Protected admin dashboard.

Current sections:
- status
- root certificate metadata
- recent issued certificate inventory
- EAB / enrollment token management
- admin user list

### `GET /admin/certificates/{serial}`
Protected certificate detail page.

Shows:
- certificate metadata
- DNS names
- PEM
- current revocation status
- passive revocation form

### `POST /admin/certificates/{serial}/revoke`
Passive certificate revocation action for embedded mode.

### `POST /admin/eab`
Creates a new external account binding key for the selected ACME provisioner.

### `POST /admin/eab/{keyID}/delete`
Deletes an external account binding key.

## ACME routes

### Embedded mode
In embedded mode, `dance` mounts the internal ACME handler under:

- `/acme/...`
- `/2.0/acme/...`

The handler is backed by `step-ca`'s ACME API router and context.

### Proxy mode
In proxy mode, `dance` reverse proxies `/acme/...` to the configured external `step-ca` URL.

## Admin page contents

### Status panel
Shows:
- whether a root certificate is available
- ACME backend endpoint
- ACME backend mode

### Root certificates panel
Displays root certificate metadata:
- subject
- serial
- validity range
- SHA-256 fingerprint

### Recent issued certificates panel
Displays a recent slice of issued certificates:
- subject
- DNS names
- provisioner
- expiry time
- serial number
- link to detail page

This panel is currently backed by direct reads of the embedded CA DB.

### EAB / enrollment tokens panel
Displays:
- ACME provisioner selector
- create form for new EAB keys
- current EAB keys for the selected provisioner
- one-time display of newly created HMAC key material

### Audit log panel
Displays recent local administrative events such as:
- login
- certificate revocation
- EAB creation/deletion

### Admins panel
Displays local `dance` admin users.

## Caddy integration shape

The UI currently shows the intended Caddy pattern:

```caddyfile
{
    acme_ca http://localhost:8088/acme/default/directory
    acme_ca_root /path/to/dance-root-ca.pem
}
```

In real deployments, replace `localhost:8088` with your `DANCE_BASE_URL` host and use the provisioner name configured in `ca.json`. The sample has one provisioner named `default`; enable EAB on that same provisioner if required.

The landing page prefers `default` when configured, otherwise it uses the first configured ACME provisioner. It does not guess a directory URL when provisioner information is unavailable (for example, external proxy mode). Existing provisioner identities and stored account/EAB state are not renamed.
