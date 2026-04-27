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

### Admins panel
Displays local `dance` admin users.

## Caddy integration shape

The UI currently shows the intended Caddy pattern:

```caddyfile
{
    acme_ca http://localhost:8088/acme/acme/directory
    acme_ca_root /path/to/dance-root-ca.pem
}
```

In real deployments, replace `localhost:8088` with your `DANCE_BASE_URL` host.

## Future route candidates

Likely future additions:
- `/admin/revocations`
- `/admin/audit`
- `/enroll/macos`
- `/enroll/windows`
- `/enroll/linux`
- `/enroll/ios`
