#!/bin/sh
# Optional consumer handoff. Install only after operator approval.
set -eu
set +x
: "${CREDENTIALS_DIRECTORY:?systemd service credentials required}"
CREDENTIAL="$CREDENTIALS_DIRECTORY/dance-eab"
# Command substitutions stay inside the service; no secret appears in argv/stdout.
DANCE_EAB_ID=$(jq -er '(.id // .metadata.id) | select(type == "string" and length > 0)' "$CREDENTIAL")
DANCE_EAB_HMAC=$(jq -er '.hmac | select(type == "string" and length > 0)' "$CREDENTIAL")
export DANCE_EAB_ID DANCE_EAB_HMAC
exec /usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
