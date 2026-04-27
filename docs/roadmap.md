# Roadmap

## Current baseline

`dance` already has:
- embedded `step-ca` support
- admin login
- root certificate download
- root certificate metadata display
- recent issued certificate inventory
- ACME endpoint mounting

## Near-term priorities

### 1. Bootstrap docs and examples
Add:
- sample `ca.json`
- service manager examples
- clearer first-run instructions

### 2. Certificate detail and revocation
Add:
- certificate detail page by serial
- revocation action
- revocation reason capture
- revoked certificate views

### 3. EAB / enrollment token workflows
Add:
- token creation
- listing and revocation
- future ACME account bootstrapping helpers

### 4. Better enrollment UX
Add:
- macOS instructions
- iOS/mobileconfig support
- Windows import guidance
- Linux trust-store guidance
- Firefox/NSS guidance where needed

## Mid-term priorities

### Audit UX
- audit log page
- filter by actor/action/date
- show login and certificate-admin actions

### Policy UX
- provisioner visibility
- domain restrictions
- issuance constraints

### Better health reporting
- authority initialization status
- CA DB connectivity checks
- embedded mode diagnostics

## Longer-term possibilities

### OIDC admin login
Replace or complement local password auth.

### Managed enrollment flows
Per-device or per-user guided issuance.

### MDM-friendly distribution
Apple profiles, Windows scripts, Linux packages.

### Packaging
- container image
- service installer
- release binaries

## Non-goals for now

- rewriting ACME from scratch
- replacing `step-ca` as a CA engine
- merging all CA and app data into one DB
- public internet PKI ambitions
