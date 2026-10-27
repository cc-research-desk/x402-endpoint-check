// Minimal x402 buyer for cc-x402-check: one paid check, $0.01 USDC on Base.
// The key is read from the BUYER_PRIVATE_KEY env var. Use a throwaway wallet that
// holds only a few cents of USDC on Base. It needs no ETH: the facilitator pays gas.
// Usage: BUYER_PRIVATE_KEY=0x... node pay.mjs https://some-x402-endpoint/path POST
import { wrapFetchWithPaymentFromConfig, decodePaymentResponseHeader } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const CHECK_URL = process.env.CHECK_URL || "https://cc-x402-check.cc-agentdesk.workers.dev/v1/check";
const [target = "https://cc-printable-pdf.cc-agentdesk.workers.dev/v1/printable-pdf", method = "POST"] = process.argv.slice(2);
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const EXPECTED_PAY_TO = (process.env.EXPECTED_PAY_TO || "0x152cCC3a3DFAFF7E03cA5345d07f0BBA6bFB9646").toLowerCase();
const MAX_AMOUNT = 10000n; // 0.01 USDC (6 decimals). Refuse anything pricier.

const key = process.env.BUYER_PRIVATE_KEY;
if (!key) { console.error("Set BUYER_PRIVATE_KEY (0x-prefixed hex) for a throwaway Base wallet."); process.exit(1); }
const account = privateKeyToAccount(key.trim());

// Only sign what we expect: exact scheme, Base mainnet, USDC, the known payTo, <= 0.01 USDC, once.
let signed = 0;
const paymentRequirementsSelector = (_version, reqs) => {
  const r = reqs.find(r => r.scheme === "exact" && r.network === "eip155:8453" &&
    r.asset.toLowerCase() === USDC_BASE && r.payTo.toLowerCase() === EXPECTED_PAY_TO && BigInt(r.amount) <= MAX_AMOUNT);
  if (!r) throw new Error("unexpected payment requirements: " + JSON.stringify(reqs));
  if (++signed > 1) throw new Error("refusing to sign a second payment");
  return r;
};
const fetchWithPay = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }], paymentRequirementsSelector });

const res = await fetchWithPay(CHECK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: target, method }) });
const header = res.headers.get("payment-response") || res.headers.get("x-payment-response");
console.log(`status ${res.status}`);
console.log("payment-response:", header ? JSON.stringify(decodePaymentResponseHeader(header)) : "none");
console.log(JSON.stringify(await res.json(), null, 2));
