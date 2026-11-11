# HTTPS enrollment management

Use the HTTPS API to discover ACME provisioners, issue EAB credentials, inspect
enrollment status and invalidate unused keys. Authenticate with an API bearer
credential supplied by the operator.

## Operator setup

Enable the enrollment API admin credential on the **Dance server**, independently
of browser credentials, session signing keys and CA passwords:

```sh
umask 077
openssl rand -hex 32 > /secure/dance-api-admin.token
export DANCE_API_ADMIN_TOKEN_FILE=/secure/dance-api-admin.token
```

Alternatively supply `DANCE_API_ADMIN_TOKEN` from a secret manager/protected
environment. Configure one source, not both. Tokens must contain at least 32
non-whitespace ASCII characters; use random values rather than passwords. The
file must be a private regular file readable by Dance, not a symlink. Outside
explicit development mode, `DANCE_BASE_URL` must use HTTPS. Serve the existing
Dance HTTP listener behind your verified TLS reverse proxy as usual.

The API admin token grants enrollment management across configured ACME
provisioners: discovery, creation, metadata inspection and unused-key
invalidation. It does not authenticate browser pages, sign certificates itself,
change CA policy, revoke certificates or deactivate ACME accounts. Do not give
this broad credential to an untrusted agent. Optional narrower, independently
revocable machine credentials are described below.

File-backed token rotation is read on every request. Replace its contents to
revoke the old token immediately; removing the file disables that admin
credential. Environment-backed token changes require a server restart. In-flight
requests already authenticated may finish. No default admin API token is created.

## Discovery and authentication

Start at `/llms.txt`, also linked by the landing response's HTTP `Link` header.
`GET /api/v1/openapi.json` serves the OpenAPI 3.1 contract.

Every management request uses:

```http
Authorization: Bearer <API_ADMIN_TOKEN>
```

Verify the CA/root fingerprint with the operator through a trusted channel and
use normal HTTPS certificate validation. Root trust and account authorisation
are separate. Do not disable TLS verification to obtain credentials.

## Enrollment flow

1. `GET /api/v1/acme/provisioners` returns names, immutable IDs, canonical ACME
   directory URLs and `require_eab` policy.
2. Create an enrollment credential for the selected provisioner:

```http
POST /api/v1/acme/provisioners/default/eab-keys
Authorization: Bearer <API_ADMIN_TOKEN>
Idempotency-Key: agent-enrollment-request-0001
Content-Type: application/json

{"reference":"caddy-host-a","target":"host-a"}
```

The initial `201` JSON response contains key ID, provisioner identity, directory,
reference, target label, creation/binding metadata and **one-time `hmac`**. The
response is `Cache-Control: no-store`. Preserve that credential in the caller's
approved secret mechanism; do not print it to chat, access logs or configuration
dumps.

`target` and `reference` are administrative inventory labels, not proof that a
host exists or is reachable. Creating a credential makes no network connection
to that host. Labels are not DNS issuance restrictions; actual CA policy must
enforce any DNS restrictions. Unsupported restriction fields are rejected.

3. Use these metadata-only routes to inspect/reconcile:

| Route | Result |
|---|---|
| `GET /api/v1/acme/provisioners/{name}/eab-keys` | Key metadata; admin sees API-managed and existing human-created keys |
| `GET /api/v1/acme/provisioners/{name}/eab-keys/{id}` | Availability/binding metadata |
| `GET /api/v1/acme/provisioners/{name}/enrollment-requests/{requestID}` | Reconcile the original creation request after a lost response |
| `DELETE /api/v1/acme/provisioners/{name}/eab-keys/{id}` | Explicitly invalidate an unused key |

Human-created keys have no API request ID or target assignment; those fields are
empty. Administrators can inspect and invalidate these keys.
Bound keys cannot be invalidated through this API.

4. Deliver the returned key ID/HMAC through the consumer's approved mechanism.
   Obtain separate approval before modifying a proxy, activating a service
   or replacing a working certificate.

## Safe command-line example

A client can keep the bearer in a private curl configuration rather than command
arguments. Populate `/secure/dance-client.curl` through your secret mechanism:

```text
header = "Authorization: Bearer REPLACE_WITH_API_TOKEN"
cacert = "/secure/dance-root.pem"
```

With a private `request.json` containing the creation JSON:

```sh
umask 077
curl --fail-with-body --config /secure/dance-client.curl \
  --header 'Idempotency-Key: agent-enrollment-request-0001' \
  --json @request.json \
  --output /secure/host-a-eab.json \
  https://dance.example.internal/api/v1/acme/provisioners/default/eab-keys
```

Keep the curl configuration and response file private. Do not enable verbose
request dumps or copy the secret-bearing response into chat or logs.

## Idempotency and loss

Request IDs contain 16–128 ASCII letters, digits, underscores or hyphens. Generate
one per operation and persist/reuse it across retries.
A changed body with the same key returns `409 idempotency_conflict`.

Only the initial committing request can receive the HMAC. A replay returns `200`
metadata with `credential_unavailable`, even if the first response was lost.
Reconcile using the original request ID; never infer that a timeout means nothing
happened. A different ID cannot replace an unresolved unused credential for the
same target/reference (`409 existing_entry`). Explicitly invalidate that unused
key before requesting a replacement. No plaintext secret-retrieval endpoint is
provided. Admin request identity stays stable across admin-token rotation.

Creation does not prove delivery to a host. Native `delivery` metadata describes
one-time credential availability, not installation. Unknown writes report
`delivery_unknown`. Errors use a versioned `v1` JSON envelope and distinguish
unauthenticated, denied scope, missing provisioner/key, invalid input, idempotency
conflict, existing entry, bound key, rate limiting and backend unavailability.

## Optional restricted machine credentials

The admin token is the simple management path. Where least privilege is needed,
an operator can create an independently revocable credential using the local
`dance admin` utility against the existing Dance SQLite database:

```sh
dance admin grant -db /var/lib/dance/dance.sqlite \
  -target host-a -provisioners acme/default \
  -operations provisioners:read,eab:create,eab:read-own,eab:invalidate-own \
  -reference-prefix caddy-host-a -ttl 24h -out /secure/host-a.token
```

Run these commands on the Dance server. The resulting bearer is restricted by
provisioner ID, operation, target, reference prefix, expiry and key ownership.

```sh
dance admin revoke -db /var/lib/dance/dance.sqlite -id PUBLIC_CREDENTIAL_ID
```

Revocation denies subsequent API access; it does not invalidate existing EAB
keys, deactivate accounts or revoke certificates. Review those separately when
offboarding a host.

## Caddy and renewal

Use the **discovered** directory for the actual configured provisioner. If EAB is
required, an ACME `newAccount` request without it returns
`externalAccountRequired`.
Trust, account authorisation and domain validation are separate requirements.

[`integrations/caddy/Caddyfile.example`](../integrations/caddy/Caddyfile.example)
uses `eab {env.DANCE_EAB_ID} {env.DANCE_EAB_HMAC}`. Supply these through protected
service configuration or a secret mechanism, not command arguments or logs. The
optional service launcher reads a protected API response file through systemd
credentials.
Validate privately before activation and protect/disable Caddy's admin/config
export API. HTTP-01/TLS-ALPN-01 require CA-to-target DNS/reachability on the
appropriate challenge ports, independently of EAB and trust.

Preserve Caddy's account key/storage. EAB bootstraps an account once; renewal does
not require repeatedly minting tokens. Unused-key invalidation is not account
deactivation or certificate revocation.

## Supported backends

Enrollment mutations currently support embedded Badger v1/v2. Proxy/shared SQL
backends return `unsupported_backend`.
