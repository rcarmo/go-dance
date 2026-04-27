# Bootstrap guide

This guide shows the simplest path to getting `dance` running with an embedded `step-ca` authority.

## Goals

The bootstrap path is intentionally aimed at:
- LAN or homelab environments
- a single host deployment
- easy ACME client enrollment
- downloadable local trust roots

## Files

A sample config is provided here:

- [`examples/ca.json`](examples/ca.json)

You should review and customize it before using it anywhere beyond local testing.

## Minimal bootstrap flow

### 1. Create a CA working directory

Example:

```bash
mkdir -p ./pki
```

### 2. Generate or prepare CA materials

The sample `ca.json` assumes you already have:
- a root certificate PEM
- an intermediate certificate PEM
- an encrypted intermediate private key
- a local CA DB path

For a real bootstrap, you can generate these with `step` tooling first, then point `dance` at the resulting config.

### 3. Adjust the sample config

Update at least:
- DNS names
- address metadata
- root/intermediate paths
- DB path
- provisioner names and policies

### 4. Set environment variables

```bash
export DANCE_ADMIN_EMAIL=admin@example.com
export DANCE_ADMIN_PASSWORD=changeme
export DANCE_STEPCA_CONFIG=./docs/examples/ca.json
export DANCE_STEPCA_PASSWORD=changeme
export DANCE_BASE_URL=http://localhost:8088
```

### 5. Run `dance`

```bash
go run ./cmd/dance
```

### 6. Verify

Check:
- `/healthz`
- `/`
- `/enroll/root.pem`
- `/login`
- `/admin`

## Caddy example

Once running, a Caddy instance can be pointed at `dance` like this:

```caddyfile
{
    acme_ca http://localhost:8088/acme/acme/directory
    acme_ca_root /path/to/dance-root-ca.pem
}
```

## Notes on the sample config

The sample `ca.json` is intentionally conservative:
- one ACME provisioner named `acme`
- one optional EAB-enabled ACME provisioner named `acme-eab`
- local DB storage
- no SSH or extra integrations enabled

This matches `dance`'s current product direction: simple local HTTPS first.

## Production-ish cautions

Before using the sample more broadly:
- replace all placeholder hostnames
- replace passwords and key material
- make sure private keys are not committed to git
- use a stable `DANCE_SESSION_KEY`
- back up the CA DB and private key material
