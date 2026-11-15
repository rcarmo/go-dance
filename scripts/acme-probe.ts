// Disposable-fixture regression only. Never prints keys, JWS, nonce or response
// bodies. The existing account is reused; probes create no enrollment keys.
import { createPrivateKey, sign } from "node:crypto";

const dir = process.env.DIR;
const port = process.env.PORT;
if (!dir || !port) throw new Error("Fixture DIR and PORT required");
const ca = await Bun.file(`${dir}/root.pem`).text();
const key = createPrivateKey(await Bun.file(`${dir}/probe-account.key`).text());
const { location: kid } = await Bun.file(`${dir}/probe-account.json`).json();
if (typeof kid !== "string" || !kid.startsWith("https://dance-ca:8443/acme/default/account/")) {
  throw new Error("Expected the fixture's persisted ACME account");
}
const origin = `https://127.0.0.1:${port}`;
const times: number[] = [];
async function request(url: string, init: RequestInit, stage: string) {
  const path = new URL(url).pathname;
  const start = performance.now();
  try {
    const response = await fetch(origin + path, {
      ...init, tls: { ca }, signal: AbortSignal.timeout(6000),
    });
    // Bound body reception as well as headers; report no response contents.
    const body = await response.text();
    if (!response.ok) throw new Error("Unexpected status");
    if (path.startsWith("/acme/") && !/^[a-f0-9]{32}$/.test(response.headers.get("X-Request-ID") ?? "")) {
      throw new Error("Missing request correlation");
    }
    times.push(performance.now() - start);
    return { response, body };
  } catch {
    throw new Error(`Bounded ACME regression failed at ${stage}`);
  }
}
const directoryURL = "https://dance-ca:8443/acme/default/directory";
const directory = JSON.parse((await request(directoryURL, {}, "directory")).body);
async function post(url: string, payload: string) {
  const nonceReply = await request(directory.newNonce, { method: "HEAD" }, "nonce");
  const nonce = nonceReply.response.headers.get("Replay-Nonce");
  if (!nonce) throw new Error("Missing nonce");
  const protectedValue = Buffer.from(JSON.stringify({ alg: "ES256", kid, nonce, url })).toString("base64url");
  const encodedPayload = Buffer.from(payload).toString("base64url");
  const signature = sign("sha256", Buffer.from(`${protectedValue}.${encodedPayload}`), { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return request(url, {
    method: "POST", headers: { "Content-Type": "application/jose+json" },
    body: JSON.stringify({ protected: protectedValue, payload: encodedPayload, signature }),
  }, "signed-request");
}
for (let i = 0; i < 25; i++) {
  const [created] = await Promise.all([
    post(directory.newOrder, JSON.stringify({ identifiers: [{ type: "dns", value: "host.dance.test" }] })),
    request(origin + "/healthz", {}, "health"),
    request(origin + "/readyz", {}, "readiness"),
    request(directoryURL, {}, "directory"),
  ]);
  if (created.response.status !== 201) throw new Error("Order creation did not return 201");
  const orderURL = created.response.headers.get("Location");
  if (!orderURL) throw new Error("Missing order URL");
  const order = JSON.parse((await post(orderURL, "")).body);
  if (!order.authorizations?.length) throw new Error("Missing authorization");
  for (const url of order.authorizations) await post(url, "");
}
console.log(`PASS: 25 bounded signed order/authorization cycles with the existing account and concurrent health/readiness/directory probes; maximum stage latency ${Math.ceil(Math.max(...times))} ms.`);
