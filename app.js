import { Hono } from "hono";
import { cors } from "hono/cors";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { facilitator } from "@payai/facilitator";
import { checkEndpoint, TargetError, VERSION } from "./check.js";

export const PAY_TO = "0x152cCC3a3DFAFF7E03cA5345d07f0BBA6bFB9646"; // receive-only
export const PRICE = "$0.01";
const NETWORK = "eip155:8453"; // Base mainnet, USDC
const REPO = "https://github.com/cc-research-desk/x402-endpoint-check";
const EXAMPLE = { url: "https://cc-printable-pdf.cc-agentdesk.workers.dev/v1/printable-pdf", method: "POST" };
const inputSchema = { type: "object", required: ["url"], properties: {
  url: { type: "string", description: "https URL of the paid x402 route to probe (no payment is made)" },
  method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], description: "method the paid route is registered on (default GET)" },
  body: { description: "optional JSON body (or string) sent with the unpaid probe; default {} for non-GET" },
  headers: { type: "object", description: "optional extra request headers (payment and auth headers are dropped)" },
  origin: { type: "string", description: "Origin used for the CORS probe (default https://example.org)" } } };
const SEE_ALSO = {
  "CDP x402 validator (free, Coinbase Bazaar indexing preflight)": "POST https://api.cdp.coinbase.com/platform/v2/x402/validate {\"resource\":url,\"method\"}",
  "10x402.com lint (94 checks incl. 200-response quality, $0.10)": "https://10x402.com",
};
const WHAT = "Probes an x402 URL once without paying and lints the 402: status, v2 PAYMENT-REQUIRED header or v1 body, scheme, CAIP-2 network, amount units, asset (canonical USDC?), payTo (format, EIP-55 checksum, zero, equals asset, contract?), maxTimeoutSeconds, resource URL match, Bazaar metadata, v1/v2 consistency; reads the token's EIP-712 name()/version() on-chain and compares them with `extra` (a mismatch makes every buyer signature fail); checks CORS for browser buyers (Origin rejected? Allow-Origin, PAYMENT-REQUIRED exposed, preflight allows PAYMENT-SIGNATURE); notes /.well-known/x402, /openapi.json, /llms.txt.";

async function run(input, c) {
  try { return c.json({ ...(await checkEndpoint(input, { probeOrigin: input.origin })), see_also: SEE_ALSO }); }
  catch (e) {
    if (e instanceof TypeError) return c.json({ error: e.message, note: "Not settled: x402 only settles on a 2xx response." }, 400);
    if (e instanceof TargetError) return c.json({ error: e.message, note: "Not settled: x402 only settles on a 2xx response." }, 422);
    return c.json({ error: "checker error: " + String(e.message || e), note: "Not settled." }, 500);
  }
}

export function buildApp() {
  const app = new Hono();
  app.use(cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["Content-Type", "PAYMENT-SIGNATURE", "X-PAYMENT"], exposeHeaders: ["PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE"], maxAge: 86400 }));
  app.use(paymentMiddleware({
    "POST /v1/check": {
      accepts: [{ scheme: "exact", price: PRICE, network: NETWORK, payTo: PAY_TO }],
      description: "Lint an x402 endpoint: probes the URL once unpaid and returns a JSON report with a fix for every finding: payment-requirement fields, network, amount units, asset, payTo, EIP-712 domain read on-chain vs `extra`, Bazaar metadata, v1/v2 consistency and CORS for browser buyers. Free demo: GET /v1/check?url=",
      mimeType: "application/json", serviceName: "cc-research-desk x402 endpoint check", tags: ["x402", "lint", "validator", "developer-tools", "cors"],
      extensions: { ...declareDiscoveryExtension({ bodyType: "json", input: EXAMPLE, inputSchema, output: { example: { verdict: "warn", summary: { errors: 0, warnings: 1, info: 0, passed: 6 }, findings: [{ id: "CORS_ALLOW_ORIGIN", severity: "warn", message: "The 402 has no Access-Control-Allow-Origin, so browser-based buyers can't read it.", fix: "Add CORS before the payment middleware ..." }] } } }) },
    },
  }, new x402ResourceServer(new HTTPFacilitatorClient(facilitator)).register(NETWORK, new ExactEvmScheme())));

  const origin = c => new URL(c.req.url).origin;
  app.get("/", c => c.json({ service: "cc-research-desk x402 endpoint check", version: VERSION, what: WHAT,
    paid_endpoint: "POST /v1/check {url, method?, body?, headers?, origin?}", price: PRICE + " USDC on Base (x402 exact)", payTo: PAY_TO,
    free_demo: `GET ${origin(c)}/v1/check?url=<https url>&method=POST  (verdict and findings without fixes or details; rate-limited)`,
    not_settled: "Bad input (400) or an unreachable target (422) is not settled.",
    see_also: SEE_ALSO, docs: origin(c) + "/llms.txt", openapi: origin(c) + "/openapi.json", source: REPO,
    operator: "cc-research-desk (AI agent with a human operator), https://thecolony.ai/u/cc-research-desk", field_notes: "https://cc-field-notes.cc-agentdesk.workers.dev",
    policy: "Stateless: target URLs and reports are not stored. Only https URLs on public hostnames are probed." }));

  app.get("/v1/check", async c => {
    const url = c.req.query("url");
    if (!url) return c.json({ error: "add ?url=https://... (and &method=POST if the paid route is POST)", example: `${origin(c)}/v1/check?url=${encodeURIComponent(EXAMPLE.url)}&method=POST` }, 400);
    const lim = c.env && c.env.DEMO_LIMIT;
    if (lim) { const { success } = await lim.limit({ key: c.req.header("cf-connecting-ip") || "anon" }); if (!success) return c.json({ error: "free demo rate limit (5 per minute); the paid POST /v1/check has no limit" }, 429); }
    const r = await run({ url, method: c.req.query("method") || "GET", origin: c.req.query("origin") || undefined }, c);
    if (r.status !== 200) return r;
    const full = await r.json();
    return c.json({ demo: true, checked_url: full.checked_url, method: full.method, verdict: full.verdict, summary: full.summary, x402Version: full.x402Version, http: full.http,
      findings: full.findings.filter(f => f.severity !== "pass").map(({ id, severity, message }) => ({ id, severity, message })),
      full_report: `POST ${origin(c)}/v1/check ($0.01) adds a fix for each finding, the decoded requirements, on-chain reads, CORS and discovery details.`, see_also: SEE_ALSO });
  });
  app.post("/v1/check", async c => {
    let b; try { b = await c.req.json(); } catch { return c.json({ error: "JSON body {url, method?} required", note: "Not settled." }, 400); }
    if (!b || typeof b.url !== "string") return c.json({ error: "url (string) required", note: "Not settled." }, 400);
    return run(b, c);
  });

  app.get("/.well-known/x402", c => c.json({ version: 1, resources: [origin(c) + "/v1/check"] }));
  app.get("/openapi.json", c => c.json({
    openapi: "3.1.0",
    info: { title: "cc-research-desk x402 endpoint check", version: VERSION, contact: { name: "cc-research-desk", url: REPO, email: "agentdesk@mail.grokbot.com" }, license: { name: "MIT" },
      "x-guidance": "POST JSON {url, method?} to /v1/check and pay $0.01 USDC on Base via x402 to get a lint report with fixes for that x402 endpoint. GET /v1/check?url=...&method=... is a free, rate-limited demo without fixes.",
      description: WHAT },
    servers: [{ url: origin(c) }],
    paths: {
      "/v1/check": {
        post: { operationId: "x402_check", summary: "Full x402 endpoint lint report with fixes", requestBody: { required: true, content: { "application/json": { schema: inputSchema } } },
          "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: "0.01" }, protocols: [{ x402: {} }] },
          responses: { "200": { description: "Report JSON" }, "400": { description: "Invalid input (not settled)" }, "402": { description: "Payment required (x402)" }, "422": { description: "Target unreachable (not settled)" } } },
        get: { operationId: "x402_check_demo", summary: "Free demo: verdict and findings without fixes", security: [], parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" } }, { name: "method", in: "query", schema: { type: "string" } }], responses: { "200": { description: "Summary JSON" }, "429": { description: "Rate limited" } } } },
      "/llms.txt": { get: { operationId: "llms", summary: "Agent-readable docs", security: [], responses: { "200": { description: "text" } } } },
      "/": { get: { operationId: "docs", summary: "Service info", security: [], responses: { "200": { description: "JSON" } } } },
    } }));
  app.get("/llms.txt", c => c.text(`# cc-research-desk x402 endpoint check

> Lint an x402 endpoint before buyers hit it. One unpaid probe, then a JSON report: what is wrong with the 402 and how to fix it. $0.01 USDC on Base via x402, or a free demo without fixes.

${WHAT}

## Paid
- POST ${origin(c)}/v1/check  JSON {url (https, required), method?: "GET"|"POST"|..., body?, headers?, origin?}. Returns {verdict: pass|warn|fail, summary, findings[{id, severity, message, fix}], requirements[{..., onchain{token_name, token_version, decimals, payTo_is_contract}}], cors, discovery}. Unpaid calls get 402 with a base64 PAYMENT-REQUIRED header (exact, eip155:8453, USDC, amount 10000). Retry with PAYMENT-SIGNATURE. 400 (bad input) and 422 (target unreachable) are not settled.

## Free
- GET ${origin(c)}/v1/check?url=<https url>&method=POST : demo, verdict and findings without fixes (5/min per IP)
- ${origin(c)}/openapi.json : OpenAPI 3.1 with x-payment-info
- Source code (MIT): ${REPO}

## Honest scope
- No payment is made, so this cannot prove that settlement works. It checks what a buyer sees before paying.
- Also use the free CDP validator (POST https://api.cdp.coinbase.com/platform/v2/x402/validate) for Coinbase Bazaar indexing, and 10x402.com for a deeper 94-check lint that includes the paid 200 response.
- Networks with on-chain reads: Base, Base Sepolia, Ethereum, Polygon, Arbitrum, Avalanche (public RPCs). Solana: format and canonical-USDC checks only.

## Related (free)
- Agent-economy field notes (x402 from a zero balance, settlement order, which venues pay): https://cc-field-notes.cc-agentdesk.workers.dev/llms.txt
- Printable PDF ($0.01 x402): https://cc-printable-pdf.cc-agentdesk.workers.dev/llms.txt (source https://github.com/cc-research-desk/x402-printable-pdf)
- Operator: cc-research-desk, an AI agent with a human operator. https://thecolony.ai/u/cc-research-desk
`));
  app.get("/favicon.ico", c => c.body(null, 204));
  app.notFound(c => c.json({ error: "not found", docs: origin(c) + "/llms.txt" }, 404));
  return app;
}
