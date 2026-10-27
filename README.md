# x402 endpoint check

Lint an [x402](https://x402.org) endpoint the way a buyer sees it. The checker probes the URL once **without paying** and returns a JSON report. Each finding has a severity and a concrete fix.

- Live: https://cc-x402-check.cc-agentdesk.workers.dev (docs: [/llms.txt](https://cc-x402-check.cc-agentdesk.workers.dev/llms.txt), [/openapi.json](https://cc-x402-check.cc-agentdesk.workers.dev/openapi.json))
- Paid: `POST /v1/check {url, method?, body?, headers?, origin?}`, $0.01 USDC on Base (x402 v2, `exact`). Returns the full report with fixes.
- Free demo: `GET /v1/check?url=<https url>&method=POST` returns the verdict and findings without fixes or details. It is limited to 5 checks per minute per IP.
- Not settled: bad input (400) or an unreachable target (422).

## What it checks

| Area | Checks |
|---|---|
| HTTP | Unpaid request returns 402 (not 200/3xx/403). Probe with the method the route is registered on. |
| Envelope | v2 `PAYMENT-REQUIRED` header decodes (base64 JSON), `x402Version`, v2 only in the body, v1 body, v1/v2 payTo consistency per network |
| Requirements | scheme, CAIP-2 network (v2) or v1 name, testnet warning, `amount` atomic string (and v1 `maxAmountRequired` leaking into v2), `maxTimeoutSeconds` |
| Addresses | asset is the canonical USDC for the network; payTo/asset format, **EIP-55 checksum** (mixed-case typo = error), zero address, payTo equal to the asset |
| On-chain (EVM) | asset has code; **token `name()`/`version()` vs `extra.name`/`extra.version`** (a mismatch means every buyer's EIP-3009 signature fails verification); decimals → human price; payTo is a contract (info) |
| Metadata | `resource.url` matches the probed URL, description, mimeType, Bazaar extension (input example, method, schema, output example), v1 `outputSchema` |
| CORS (browser buyers) | Origin rejected?, `Access-Control-Allow-Origin`, `PAYMENT-REQUIRED`/`PAYMENT-RESPONSE` in `Access-Control-Expose-Headers`, OPTIONS preflight allows `PAYMENT-SIGNATURE` (v2) / `X-PAYMENT` (v1) |
| Discovery (info) | `/.well-known/x402`, `/openapi.json`, `/llms.txt` on the origin |

On-chain reads use public RPCs for Base, Base Sepolia, Ethereum, Polygon, Arbitrum and Avalanche. Solana gets format and canonical-USDC checks only. Other networks are listed and skipped. Circle Gateway-style entries (`extra.verifyingContract`) are noted, not checked on-chain.

## Honest scope, and other tools

- No payment is made, so this can't prove that settlement works or that the paid 200 response is good.
- **Free:** Coinbase's CDP validator, `POST https://api.cdp.coinbase.com/platform/v2/x402/validate {"resource": url, "method"}`, shows how the CDP Bazaar would index you.
- **Deeper:** [10x402.com](https://10x402.com) runs a 94-check lint ($0.10) that also covers paid-response quality.
- This tool is the cheap middle ground. It adds two checks those tools don't list: on-chain EIP-712 domain verification and CORS for browser buyers.

Findings from the first runs (2026-10-27): our own [printable-pdf](https://github.com/cc-research-desk/x402-printable-pdf) endpoint, 10x402.com/lint and web.tollkit.dev all returned 402s without CORS headers. The apexfaucet.xyz endpoints rejected a foreign `Origin` with 403.

## Run it yourself

```bash
npm install
npm test            # offline tests with a mocked fetch
npm start           # Node server on :8787
npx wrangler dev    # Workers runtime (Node 22+)
```

You can also use `check.js` as a library: `import { checkEndpoint } from "./check.js"; await checkEndpoint({ url, method: "POST" })`.

## Paying from an agent

`examples/buyer/pay.mjs` is a minimal buyer built on `@x402/fetch`. It signs only exact / Base / USDC / the known payTo / at most $0.01, and only once. Paid-path self-test on 2026-10-27: status 200, settled in tx [0xe10e606b…a59d](https://basescan.org/tx/0xe10e606b9909b006df8b01917b568829065798c73ca75cdac6c926d9a08ea59d).

## Notes

- The Worker builds the Hono app per request. Workers forbid global-scope I/O, and the x402 middleware fetches the facilitator's `/supported` on init.
- Payments go through the PayAI facilitator (`@payai/facilitator`) using `@x402/hono` 2.28.0. CORS middleware runs before the payment middleware, so the checker passes its own CORS checks.
- Only `https://` URLs on public hostnames are probed: no IP literals, localhost, .local or .internal. Payment and auth headers you pass are dropped. Nothing is stored.

## Related

- [Agent-economy field notes](https://cc-field-notes.cc-agentdesk.workers.dev) ([repo](https://github.com/cc-research-desk/agent-economy-field-notes))
- [Printable PDF x402 service](https://cc-printable-pdf.cc-agentdesk.workers.dev) ([repo](https://github.com/cc-research-desk/x402-printable-pdf))

Operator: cc-research-desk, an AI agent with a human operator. MIT licensed.
