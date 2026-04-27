# Development

## Repository layout

```text
cmd/dance/             process entrypoint
internal/app/          wiring and lifecycle
internal/config/       env loading and defaults
internal/httpserver/   routes, templates, sessions, static files
internal/stepca/       embedded step-ca adapter
internal/store/        SQLite-backed local state
```

## Development principles

### Keep the `step-ca` boundary narrow
Do not spread `step-ca` internals throughout the codebase.

Prefer to keep upstream coupling concentrated in:
- `internal/stepca`

This makes future upgrades or substitutions easier.

### Keep app data separate from CA data
`dance` should own:
- admin users
- UI/session state
- app-local metadata

`step-ca` should continue to own:
- authority state
- ACME state
- issued certificate storage

### Add features through composition
When possible:
- read from `internal/stepca`
- present via `internal/httpserver`
- persist local-only state in `internal/store`

Avoid modifying certificate authority logic unless there is a clear product need.

## Current tests

- `internal/httpserver/session_test.go`
- `internal/store/sqlite_test.go`

Current test coverage is intentionally light.

## Recommended next tests

- admin login flow handler tests
- root certificate download handler tests
- embedded ACME route mounting tests
- certificate inventory parsing tests
- config mode-selection tests

## Formatting and checks

```bash
gofmt -w $(find . -name '*.go')
go test ./...
go build ./cmd/dance
```

## Local iteration loop

Typical flow:

```bash
cd projects/dance
go test ./...
go run ./cmd/dance
```

## Adding UI features

For UI changes:
- handlers live in `internal/httpserver/server.go`
- templates live in `internal/httpserver/templates/`
- CSS lives in `internal/httpserver/static/style.css`

## Adding local persistence

For local app-owned persistence:
- update `internal/store/store.go`
- implement schema and methods in `internal/store/sqlite.go`
- add tests in `internal/store/sqlite_test.go`

## Adding CA-derived views

For CA-derived read-only views:
- add extraction helpers to `internal/stepca/manager.go`
- keep data returned as simple structs
- pass those structs into templates via `templateData`

## Dependency notes

Major dependencies currently include:
- `github.com/smallstep/certificates`
- `github.com/go-chi/chi/v5`
- `modernc.org/sqlite`

The `step-ca` dependency graph is large. Keep that complexity contained.

## Safe refactoring direction

Good future refactors:
- split `internal/httpserver/server.go` into smaller handler files
- introduce typed view models per page
- add explicit audit log queries and pages
- add richer config validation

Refactors to avoid too early:
- replacing `step-ca` internals wholesale
- merging `dance` SQLite with CA DB responsibilities
- inventing a parallel CA issuance implementation
