# Architecture

## Overview

`dance` is a Go web application with two major responsibilities:

1. **product/UI layer** owned by `dance`
2. **certificate authority / ACME layer** currently provided by embedded `step-ca`

The result is a single-process, single-binary deployment where one HTTP server exposes both the UI and the ACME endpoints.

## High-level model

```text
browser / ACME client
        |
        v
+---------------------------+
|         dance             |
|                           |
|  +---------------------+  |
|  | HTTP/UI layer       |  |
|  | - landing page      |  |
|  | - login             |  |
|  | - admin dashboard   |  |
|  | - root download     |  |
|  +---------------------+  |
|                           |
|  +---------------------+  |
|  | embedded step-ca    |  |
|  | - authority         |  |
|  | - ACME router       |  |
|  | - CA roots          |  |
|  | - issued cert DB    |  |
|  +---------------------+  |
|                           |
|  +---------------------+  |
|  | local SQLite store  |  |
|  | - admin users       |  |
|  | - sessions support  |  |
|  | - audit events      |  |
|  +---------------------+  |
+---------------------------+
```

## Packages

### `cmd/dance`
Process entrypoint.

Responsibilities:
- create process context with signal handling
- build app wiring
- start HTTP server

### `internal/app`
Application assembly.

Responsibilities:
- load configuration
- initialize local SQLite store
- bootstrap admin user
- initialize embedded/proxy step-ca manager
- construct the HTTP server
- coordinate shutdown

### `internal/config`
Configuration parsing.

Responsibilities:
- read environment variables
- apply defaults
- create required local directories
- derive cookie security behavior from base URL

### `internal/httpserver`
Web application and routing.

Responsibilities:
- landing page
- login/logout flows
- admin dashboard
- session verification
- root certificate download
- mount embedded ACME handler or proxy fallback

### `internal/stepca`
Isolation layer around `step-ca`.

Responsibilities:
- initialize embedded authority from `step-ca` config
- build ACME base context and handler
- expose root certificate PEM
- read recent certificate inventory from the underlying CA DB
- present a stable wrapper interface to the rest of `dance`

This package is the dependency boundary that should absorb upstream API churn.

### `internal/store`
`dance`'s own local relational state.

Responsibilities:
- bootstrap and authenticate admin users
- hold local UI/admin data
- append audit entries

This DB is separate from `step-ca`'s own storage.

## Data model split

There are currently two storage domains.

### 1. `dance` SQLite
Owned by `internal/store`.

Contains:
- users
- audit log
- future app-local metadata

### 2. `step-ca` DB
Owned by embedded `step-ca` configuration.

Contains:
- certificate authority state
- ACME state
- issued certificate records
- provisioner-linked certificate metadata

This separation is intentional. `dance` is not yet trying to replace `step-ca` persistence semantics.

## Request flow

### UI request

```text
browser -> net/http server -> internal/httpserver -> templates/store/stepca wrapper
```

Examples:
- `/` renders landing page
- `/login` authenticates via local SQLite store
- `/admin` combines local user data with root and certificate data from `internal/stepca`

### ACME request

```text
ACME client -> /acme/... -> internal/httpserver -> embedded step-ca handler
```

In embedded mode:
- the request is stripped to the embedded handler
- the request context is seeded with:
  - authority
  - ACME DB
  - ACME linker/client

In proxy mode:
- `/acme/...` is forwarded to the configured external `step-ca`

## Trust and certificate serving

Root certificate download uses this precedence:

1. `DANCE_ROOT_CERT_PATH` if explicitly configured
2. embedded root chain from `step-ca` if available
3. otherwise no root certificate is served

This lets `dance` either:
- serve a manually managed root file, or
- derive its trust material directly from the embedded CA

## Session model

Current sessions are simple signed cookies.

Properties:
- user ID + expiry timestamp in payload
- HMAC-SHA256 signature using `DANCE_SESSION_KEY`
- 24-hour session lifetime
- no server-side session table yet

This is sufficient for the current bootstrap phase but may later evolve into rotated or persisted sessions.

## Why embed instead of spawn

Embedding was chosen to preserve:
- single binary deployment
- single process lifecycle
- simpler packaging
- less runtime orchestration

This avoids shipping `dance` plus a separate `step-ca` executable.

## Current constraints

- embedded ACME is implemented, but not the full `step-ca` admin API surface
- inventory reads depend on access to the underlying `step-ca` DB implementation
- root metadata and recent certificate listings are read-only today
- revocation and EAB administration are not yet surfaced in the UI

## Architectural direction

Near-term evolution should keep the current split:

- `internal/stepca`: CA-facing integration boundary
- `internal/store`: app-facing persistence boundary
- `internal/httpserver`: UI and route composition boundary

That allows feature growth without entangling app concerns with PKI internals.
