#!/usr/bin/env bash
# Isolated, real Caddy registration/issuance/automatic renewal. No host trust,
# production account storage, proxy configuration or working cert is touched.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
DIR=$(mktemp -d "${TMPDIR:-/tmp}/dance-caddy.XXXXXX")
SUFFIX="$$-$(date +%s)"
NETWORK="dance-enrollment-$SUFFIX"
CA="dance-enrollment-ca-$SUFFIX"
CADDY="dance-enrollment-caddy-$SUFFIX"
cleanup() {
  docker rm -f "$CADDY" "$CA" > "$DIR/cleanup.log" 2>&1 || true
  docker network rm "$NETWORK" >> "$DIR/cleanup.log" 2>&1 || true
  if [[ ${KEEP_DANCE_FIXTURE:-0} == 1 ]]; then
    echo "Private fixture retained at $DIR (contains disposable credentials)."
  else
    sudo -n rm -rf -- "$DIR" || rm -rf -- "$DIR"
  fi
}
trap cleanup EXIT
fail(){ echo "FAIL: $1 (private diagnostics in $DIR while fixture exists)" >&2; exit 1; }
export GOFLAGS=${GOFLAGS:--p=1} GOMAXPROCS=${GOMAXPROCS:-2} GOMEMLIMIT=${GOMEMLIMIT:-768MiB}
CGO_ENABLED=0 go build -o "$DIR/fixture" ./scripts/enrollment-fixture

"$DIR/fixture" -dir "$DIR" -init > "$DIR/init.log" 2>&1
mkdir "$DIR/caddy-data" "$DIR/caddy-config"
docker network create "$NETWORK" > "$DIR/network.log"
docker run -d --name "$CA" --network "$NETWORK" --network-alias dance-ca \
  -p 127.0.0.1::8443 -v "$DIR:/fixture" --entrypoint /fixture/fixture \
  alpine:3.22 -dir /fixture > "$DIR/ca-container.log"
PORT=$(docker port "$CA" 8443/tcp | sed 's/.*://')
for _ in $(seq 1 40); do
  if curl --cacert "$DIR/root.pem" --silent --fail "https://127.0.0.1:$PORT/healthz" > "$DIR/health.txt"; then break; fi
  sleep 1
done
[[ $(cat "$DIR/health.txt") == ok ]] || fail 'fixture did not start'
# Primary workflow: any HTTPS client plus the API admin token. No connector,
# host identity, target daemon, SSH or keychain integration is involved.
DIR="$DIR" PORT="$PORT" bun - <<'HTTP'
const d=process.env.DIR,token=(await Bun.file(d+'/admin-token').text()).trim(),ca=await Bun.file(d+'/root.pem').text();
const origin='https://127.0.0.1:'+process.env.PORT;
const headers={Authorization:'Bearer '+token};
const discovery=await fetch(origin+'/api/v1/acme/provisioners',{headers,tls:{ca}});
const provisioners=await discovery.json();
if(!discovery.ok||!provisioners.provisioners?.some(p=>p.name==='default'&&p.require_eab))throw Error('HTTPS admin discovery failed');
const options={method:'POST',headers:{...headers,'Content-Type':'application/json','Idempotency-Key':'caddy_integration_123456'},body:JSON.stringify({reference:'caddy-integration',target:'fixture-host'}),tls:{ca}};
const response=await fetch(origin+'/api/v1/acme/provisioners/default/eab-keys',options);
if(response.status!==201||response.headers.get('cache-control')!=='no-store')throw Error('HTTPS admin creation failed');
const {hmac,...metadata}=await response.json();
if(!hmac||metadata.target!=='fixture-host')throw Error('Missing one-time enrollment credential');
await Bun.write(d+'/consumer.json',JSON.stringify({metadata,hmac}));
const replay=await fetch(origin+'/api/v1/acme/provisioners/default/eab-keys',options);
const replayed=await replay.json();if(replay.status!==200||replayed.id!==metadata.id||'hmac' in replayed)throw Error('HTTPS idempotency failed');
HTTP
test ! -d "$DIR/vault"
echo 'PASS: HTTPS-only admin discovery/create/replay, without a target connector or keychain.'
DIR="$DIR" bun - <<'JS'
const d=process.env.DIR;const secret=await Bun.file(d+'/consumer.json').json();
const config={admin:{disabled:true},apps:{http:{servers:{test:{listen:[':443'],routes:[{match:[{host:['host.dance.test']}],handle:[{handler:'static_response',body:'Dance enrollment fixture'}]}],tls_connection_policies:[{}]}}},tls:{automation:{renew_interval:'2s',policies:[{subjects:['host.dance.test'],renewal_window_ratio:0.8,issuers:[{module:'acme',ca:'https://dance-ca:8443/acme/default/directory',email:'fixture@example.invalid',trusted_roots_pem_files:['/fixture/root.pem'],external_account:{key_id:secret.metadata.id,mac_key:secret.hmac}}]}]},certificates:{automate:['host.dance.test']}}}};
await Bun.write(d+'/caddy.json',JSON.stringify(config));
JS
CADDY_IMAGE=${CADDY_IMAGE:-caddy:2.11.9-alpine}
docker run --rm --network "$NETWORK" -v "$DIR:/fixture" "$CADDY_IMAGE" \
  caddy validate --config /fixture/caddy.json > "$DIR/caddy-validate.log" 2>&1 || fail 'Caddy validation failed'
# Validate the shipped Caddyfile example as well, using non-secret dummy values.
docker run --rm -v "$PWD/integrations/caddy/Caddyfile.example:/example:ro" \
  -v "$DIR/root.pem:/etc/caddy/dance-root.pem:ro" \
  -e DANCE_EAB_ID=documentation-example \
  -e DANCE_EAB_HMAC=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
  "$CADDY_IMAGE" caddy validate --config /example --adapter caddyfile \
  > "$DIR/caddy-example.log" 2>&1 || fail 'Shipped Caddyfile example did not validate'
start_caddy(){ docker run -d --name "$CADDY" --network "$NETWORK" --network-alias host.dance.test \
  -v "$DIR:/fixture:ro" -v "$DIR/caddy-data:/data" -v "$DIR/caddy-config:/config" \
  "$CADDY_IMAGE" caddy run --config /fixture/caddy.json > "$DIR/caddy-container.log"; }
start_caddy
serial(){ docker exec "$CADDY" sh -c 'cat /data/caddy/certificates/*/host.dance.test/host.dance.test.crt' 2>/dev/null | openssl x509 -noout -serial 2>/dev/null; }
FIRST=''
for _ in $(seq 1 120); do if FIRST=$(serial); then break; fi; sleep 1; done
[[ -n "$FIRST" ]] || fail 'Caddy did not obtain a certificate'
ACCOUNT=$(docker exec "$CADDY" sh -c 'find /data/caddy/acme -type f -name "*.key" -exec sha256sum {} \;')
[[ -n "$ACCOUNT" ]] || fail 'Caddy account not persisted'
echo 'PASS: HTTPS enrollment, Caddy EAB registration, real challenge and issuance.'
SECOND=''
for _ in $(seq 1 120); do SECOND=$(serial || true); if [[ -n "$SECOND" && "$SECOND" != "$FIRST" ]]; then break; fi; sleep 1; done
[[ -n "$SECOND" && "$SECOND" != "$FIRST" ]] || fail 'automatic renewal did not occur'
echo 'PASS: automatic renewal changed the certificate without another enrollment key.'
# Restart without EAB material, retaining exactly the same Caddy account storage.
docker logs "$CADDY" > "$DIR/caddy-first.log" 2>&1
docker rm -f "$CADDY" > "$DIR/caddy-stop.log"
DIR="$DIR" bun - <<'JS'
const path=process.env.DIR+'/caddy.json';const c=await Bun.file(path).json();delete c.apps.tls.automation.policies[0].issuers[0].external_account;await Bun.write(path,JSON.stringify(c));
JS
start_caddy
THIRD=''
for _ in $(seq 1 120); do THIRD=$(serial || true); if [[ -n "$THIRD" && "$THIRD" != "$SECOND" ]]; then break; fi; sleep 1; done
[[ -n "$THIRD" && "$THIRD" != "$SECOND" ]] || fail 'renewal after restart without EAB failed'
[[ "$ACCOUNT" == "$(docker exec "$CADDY" sh -c 'find /data/caddy/acme -type f -name "*.key" -exec sha256sum {} \;')" ]] || fail 'Caddy account key changed'
docker logs "$CADDY" > "$DIR/caddy-restart.log" 2>&1
docker logs "$CA" > "$DIR/dance.log" 2>&1
# Use the authenticated metadata API to prove that only one key was created/bound.
DIR="$DIR" PORT="$PORT" bun - <<'JS'
const d=process.env.DIR,root=await Bun.file(d+'/root.pem').text(),token=(await Bun.file(d+'/admin-token').text()).trim();
const r=await fetch('https://127.0.0.1:'+process.env.PORT+'/api/v1/acme/provisioners/default/eab-keys',{headers:{Authorization:'Bearer '+token},tls:{ca:root}});
const data=await r.json();if(!r.ok||data.keys?.length!==1||data.keys[0].state!=='bound')throw Error('Expected exactly one bound EAB key');
const invalidation=await fetch('https://127.0.0.1:'+process.env.PORT+'/api/v1/acme/provisioners/default/eab-keys/'+data.keys[0].id,{method:'DELETE',headers:{Authorization:'Bearer '+token},tls:{ca:root}});
if(invalidation.status!==409||(await invalidation.json()).error?.code!=='already_bound')throw Error('Admin invalidated a bound EAB key');
const secret=(await Bun.file(d+'/consumer.json').json()).hmac;
for await(const f of new Bun.Glob('*.{log,stdout}').scan(d)){const text=await Bun.file(d+'/'+f).text();if(text.includes(secret)||text.includes(token))throw Error('Secret appeared in diagnostic output');}
JS
echo 'PASS: persisted account renewed after restart without bootstrap EAB; one bound key, no secret in diagnostic output.'
