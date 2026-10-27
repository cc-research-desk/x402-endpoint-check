// Offline tests with a mocked fetch: `npm test`.
import assert from "node:assert/strict";
import { checkEndpoint, toChecksum, isPrivateHost } from "./check.js";

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAY = "0x152cCC3a3DFAFF7E03cA5345d07f0BBA6bFB9646";
const abiStr = s => { const b = Buffer.from(s); return "0x" + "20".padStart(64, "0") + b.length.toString(16).padStart(64, "0") + b.toString("hex").padEnd(64, "0"); };
function mock({ status = 402, pr, body = "{}", headers = {}, preflight = {}, name = "USD Coin", version = "2" }) {
  return async (url, init = {}) => {
    if (url === "https://base-rpc.publicnode.com") {
      const { method, params } = JSON.parse(init.body);
      let result = "0x";
      if (method === "eth_getCode") result = params[0].toLowerCase() === USDC.toLowerCase() ? "0x6080" : "0x";
      if (method === "eth_call") result = { "0x06fdde03": abiStr(name), "0x54fd4d50": abiStr(version), "0x313ce567": "0x" + "6".padStart(64, "0") }[params[0].data];
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
    }
    if (init.method === "OPTIONS") return new Response(null, { status: 204, headers: preflight });
    if (!url.endsWith("/paid")) return new Response("nope", { status: 404 });
    const h = { "content-type": "application/json", ...headers };
    if (pr) h["payment-required"] = Buffer.from(JSON.stringify(pr)).toString("base64");
    return new Response(body, { status, headers: h });
  };
}
const good = (over = {}) => ({ x402Version: 2, resource: { url: "https://x.example.com/paid", description: "d", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:8453", amount: "10000", asset: USDC, payTo: PAY, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" }, ...over }],
  extensions: { bazaar: { info: { input: { type: "http", method: "GET" }, output: { example: {} } }, schema: {} } } });
const CORS = { "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const PF = { "access-control-allow-headers": "Content-Type, PAYMENT-SIGNATURE" };
const ids = r => r.findings.filter(f => f.severity === "error" || f.severity === "warn").map(f => f.id).sort();
const run = (m, url = "https://x.example.com/paid") => checkEndpoint({ url }, { fetch: m, discovery: false });

// 1 clean endpoint passes
let r = await run(mock({ pr: good(), headers: CORS, preflight: PF }));
assert.equal(r.verdict, "pass", JSON.stringify(ids(r)));
assert.equal(r.requirements[0].price, "0.01 USDC");
// 2 wrong EIP-712 name in extra is caught on-chain
r = await run(mock({ pr: good({ extra: { name: "USDC", version: "2" } }), headers: CORS, preflight: PF }));
assert.deepEqual(ids(r), ["EXTRA_NAME_ONCHAIN"]);
// 3 bad checksum, payTo == asset, v1 field in v2, missing timeout
const typo = "0x152cCC3a3DFAFF7E03cA5345d07f0BBA6bFB9646".replace("cCC", "ccC");
r = await run(mock({ pr: good({ payTo: typo, amount: undefined, maxAmountRequired: "10000", maxTimeoutSeconds: undefined }), headers: CORS, preflight: PF }));
assert.deepEqual(ids(r), ["AMOUNT_FIELD", "MAX_TIMEOUT", "PAYTO_CHECKSUM"]);
r = await run(mock({ pr: good({ payTo: USDC }), headers: CORS, preflight: PF }));
assert.ok(ids(r).includes("PAYTO_IS_ASSET"));
// 4 no CORS, and CORS without exposed header / preflight
r = await run(mock({ pr: good() }));
assert.deepEqual(ids(r), ["CORS_ALLOW_ORIGIN"]);
r = await run(mock({ pr: good(), headers: { "access-control-allow-origin": "*" } }));
assert.deepEqual(ids(r), ["CORS_EXPOSE_PAYMENT_REQUIRED", "CORS_PREFLIGHT_PAYMENT_HEADER"]);
// 5 not a 402, and a 402 with nothing in it
r = await run(mock({ status: 200 }));
assert.deepEqual(ids(r), ["HTTP_STATUS_402"]);
r = await run(mock({}));
assert.deepEqual(ids(r), ["NO_REQUIREMENTS"]);
// 6 v1 body, v1 network name, testnet warning, non-USDC asset
r = await run(mock({ body: JSON.stringify({ x402Version: 1, accepts: [{ scheme: "exact", network: "base-sepolia", maxAmountRequired: "1000", asset: USDC, payTo: PAY, resource: "https://x.example.com/paid", description: "d", mimeType: "application/json", maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }] }), headers: CORS, preflight: { "access-control-allow-headers": "*" } }));
assert.deepEqual(ids(r), ["ASSET_NOT_USDC", "NETWORK_TESTNET", "V1_OUTPUT_SCHEMA"]);
// 7 input guards
for (const u of ["http://x.example.com/paid", "https://localhost/x", "https://127.0.0.1/x", "https://[::1]/x", "nope"]) await assert.rejects(checkEndpoint({ url: u }, { fetch: mock({}) }), TypeError);
assert.equal(toChecksum(PAY.toLowerCase()), PAY); assert.equal(toChecksum(USDC.toLowerCase()), USDC);
assert.ok(isPrivateHost("foo.internal") && !isPrivateHost("example.com"));
console.log("all tests passed");
