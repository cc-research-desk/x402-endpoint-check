// x402 endpoint checker: probe a URL once without payment and lint the 402 it returns.
// Pure logic, no keys, no storage. Runs on Cloudflare Workers and Node >= 20.
import { keccak_256 } from "@noble/hashes/sha3.js";

export const VERSION = "1.0.0";
const enc = new TextEncoder();
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");

// Networks we know. rpc: public endpoint used for read-only eth_call / eth_getCode.
export const NETWORKS = {
  "eip155:8453": { name: "Base", v1: "base", rpc: ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://1rpc.io/base", "https://base.drpc.org"], usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", domain: { name: "USD Coin", version: "2" } },
  "eip155:84532": { name: "Base Sepolia (testnet)", v1: "base-sepolia", testnet: true, rpc: ["https://base-sepolia-rpc.publicnode.com", "https://sepolia.base.org"], usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", domain: { name: "USDC", version: "2" } },
  "eip155:1": { name: "Ethereum", v1: "ethereum", rpc: "https://ethereum-rpc.publicnode.com", usdc: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", domain: { name: "USD Coin", version: "2" } },
  "eip155:137": { name: "Polygon", v1: "polygon", rpc: "https://polygon-bor-rpc.publicnode.com", usdc: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", domain: { name: "USD Coin", version: "2" } },
  "eip155:42161": { name: "Arbitrum One", v1: "arbitrum", rpc: "https://arbitrum-one-rpc.publicnode.com", usdc: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", domain: { name: "USD Coin", version: "2" } },
  "eip155:43114": { name: "Avalanche C-Chain", v1: "avalanche", rpc: "https://avalanche-c-chain-rpc.publicnode.com", usdc: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", domain: { name: "USD Coin", version: "2" } },
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": { name: "Solana", v1: "solana", usdc: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" },
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": { name: "Solana Devnet (testnet)", v1: "solana-devnet", testnet: true, usdc: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" },
};
const V1_TO_CAIP = Object.fromEntries(Object.entries(NETWORKS).map(([k, v]) => [v.v1, k]));
const KNOWN_SCHEMES = ["exact", "upto"];

export function toChecksum(addr) {
  const a = addr.toLowerCase().replace(/^0x/, "");
  const h = hex(keccak_256(enc.encode(a)));
  return "0x" + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}
const isEvmAddr = s => typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
const isSolAddr = s => typeof s === "string" && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(s);
function b64json(s) {
  const t = s.trim().replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "===".slice((t.length + 3) % 4));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))));
}
function decodeAbiString(h) {
  const d = (h || "").replace(/^0x/, "");
  if (d.length < 128) { // bytes32-style or empty
    const b = d.match(/../g) || []; return b.map(x => String.fromCharCode(parseInt(x, 16))).join("").replace(/\0+$/, "");
  }
  const len = parseInt(d.slice(64, 128), 16); const bytes = (d.slice(128, 128 + len * 2).match(/../g) || []).map(x => parseInt(x, 16));
  return new TextDecoder().decode(Uint8Array.from(bytes));
}

export class TargetError extends Error {}

/** Probe `url` once without payment and return a lint report. */
export async function checkEndpoint(input, opts = {}) {
  const fetchImpl = opts.fetch || fetch;
  const probeOrigin = (input && input.origin) || opts.probeOrigin || "https://example.org";
  const timeoutMs = opts.timeoutMs || 8000;
  const { url, method: m0 = "GET", body, headers: extraHeaders } = input || {};
  let target; try { target = new URL(url); } catch { throw new TypeError("url must be an absolute https:// URL"); }
  if (target.protocol !== "https:") throw new TypeError("only https:// URLs are checked");
  if (isPrivateHost(target.hostname)) throw new TypeError("private, local and IP-literal hosts are not checked");
  const method = String(m0).toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new TypeError("method must be GET, POST, PUT, PATCH or DELETE");

  let requirements = [], cors = null, discovery = null;
  const findings = []; const add = (severity, id, message, fix, extra) => findings.push({ id, severity, message, ...(fix ? { fix } : {}), ...(extra ? { detail: extra } : {}) });
  const t0 = Date.now(); let res, text = "";
  const hdrs = { accept: "application/json", "user-agent": `cc-x402-check/${VERSION} (+https://cc-x402-check.cc-agentdesk.workers.dev)` };
  for (const [k, v] of Object.entries(extraHeaders || {})) if (!/^(payment-signature|x-payment|authorization|cookie)$/i.test(k)) hdrs[k.toLowerCase()] = String(v);
  let reqBody;
  if (!["GET", "DELETE"].includes(method)) { reqBody = body === undefined ? "{}" : (typeof body === "string" ? body : JSON.stringify(body)); hdrs["content-type"] ||= "application/json"; }
  try {
    res = await fetchImpl(target.href, { method, headers: hdrs, body: reqBody, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    text = (await res.text()).slice(0, 65536);
  } catch (e) { throw new TargetError(`could not reach ${target.origin}: ${e.name === "TimeoutError" ? `no response within ${timeoutMs / 1000}s` : String(e.message || e)}`); }
  const ms = Date.now() - t0;
  const h = name => res.headers.get(name);
  const http = { status: res.status, ms, content_type: h("content-type") };

  if (res.status >= 300 && res.status < 400) add("error", "HTTP_REDIRECT", `Got ${res.status} redirect to ${h("location")} instead of 402.`, "Publish the final URL. Many x402 clients do not follow redirects when retrying with a payment, and the signed resource URL must match.");
  else if (res.status !== 402) add("error", "HTTP_STATUS_402", `Expected 402 Payment Required for an unpaid ${method}, got ${res.status}.`, res.status === 200 ? "The paywall is not active for this method/path. Check the route key in your middleware config (e.g. \"POST /v1/x\") and the method you probed." : res.status === 404 || res.status === 405 ? "Probe with the method and path the paid route is registered on (pass \"method\")." : "Make the payment middleware run before body validation, auth and rate limits, so an unpaid request gets 402.");
  else add("pass", "HTTP_STATUS_402", "Unpaid request returns 402.");

  // --- parse requirements
  let v2 = null, v1 = null;
  const prHeader = h("payment-required");
  if (prHeader) {
    try { v2 = b64json(prHeader); add("pass", "V2_HEADER_DECODES", "PAYMENT-REQUIRED header is base64 JSON."); }
    catch { add("error", "V2_HEADER_DECODES", "PAYMENT-REQUIRED header is present but is not base64-encoded JSON.", "Send base64(JSON.stringify(paymentRequired)) in the header (the @x402 middlewares do this for you)."); }
  }
  let bodyJson = null; try { bodyJson = JSON.parse(text); } catch {}
  if (bodyJson && Array.isArray(bodyJson.accepts)) v1 = bodyJson;
  if (!v2 && v1 && v1.x402Version === 2) { v2 = v1; v1 = null; add("warn", "V2_IN_BODY_ONLY", "x402Version 2 requirements are in the body but there is no PAYMENT-REQUIRED header.", "v2 clients read the PAYMENT-REQUIRED header. Send it (body copy is optional)."); }
  if (!v2 && !v1) {
    if (res.status === 402) add("error", "NO_REQUIREMENTS", "402 response carries no payment requirements (no PAYMENT-REQUIRED header, no JSON body with accepts[]).", "Use an x402 middleware (e.g. @x402/hono, @x402/express) or return v2 requirements in the PAYMENT-REQUIRED header.");
    return finish();
  }
  const pr = v2 || v1; const version = pr.x402Version;
  if (v2 && v2.x402Version !== 2) add("error", "VERSION_FIELD", `PAYMENT-REQUIRED header has x402Version ${JSON.stringify(v2.x402Version)}, expected 2.`, "Set x402Version: 2 in the header payload.");
  if (!v2 && v1 && v1.x402Version !== 1) add("error", "VERSION_FIELD", `Body has x402Version ${JSON.stringify(v1.x402Version)}.`, "Set x402Version: 1 for a body-based (v1) response, or move to v2 with the PAYMENT-REQUIRED header.");
  if (!v2 && v1) add("info", "V1_ONLY", "Endpoint speaks x402 v1 only (requirements in the body).", "v1 still works with most facilitators; new clients default to v2 (PAYMENT-REQUIRED header, CAIP-2 networks, `amount`).");
  if (!Array.isArray(pr.accepts) || pr.accepts.length === 0) { add("error", "ACCEPTS_EMPTY", "accepts[] is missing or empty, so there is nothing a buyer can pay.", "Return at least one payment option."); return finish(); }

  for (const [i, a] of pr.accepts.entries()) requirements.push(await checkAccept(a, i, version === 2, add, fetchImpl, opts.rpc !== false));

  // resource + discovery metadata
  const resource = v2 ? pr.resource : { url: pr.accepts[0].resource, description: pr.accepts[0].description, mimeType: pr.accepts[0].mimeType };
  if (!resource || !resource.url) add(v2 ? "error" : "warn", "RESOURCE_URL", "No resource URL in the requirements.", v2 ? "Include resource: {url, description, mimeType}." : "Include `resource` in each accepts[] entry (v1).");
  else {
    let ru; try { ru = new URL(resource.url); } catch {}
    if (!ru) add("error", "RESOURCE_URL", `resource.url is not a valid URL: ${resource.url}`, "Use the absolute URL of the paid route.");
    else if (ru.origin !== target.origin || ru.pathname.replace(/\/$/, "") !== target.pathname.replace(/\/$/, "")) add("warn", "RESOURCE_URL_MATCH", `resource.url (${ru.origin}${ru.pathname}) differs from the probed URL (${target.origin}${target.pathname}).`, "Behind a proxy the middleware may see an internal host. Set the public URL explicitly. Careful buyers refuse a challenge that names another host.");
    else add("pass", "RESOURCE_URL_MATCH", "resource.url matches the probed URL.");
  }
  if (resource && !resource.description) add("warn", "RESOURCE_DESCRIPTION", "No description: directories and agents can't tell what this does.", "Add a one- or two-sentence description that says what the call returns.");
  if (resource && !resource.mimeType) add("warn", "RESOURCE_MIMETYPE", "No mimeType for the paid response.", "Set mimeType (e.g. application/json).");

  // Bazaar discovery metadata
  if (v2) {
    const bz = pr.extensions && pr.extensions.bazaar;
    if (!bz) add("warn", "BAZAAR_EXTENSION", "No extensions.bazaar: the CDP/PayAI Bazaars will index the resource without an input schema or example, so agents can't call it from the listing.", "Declare it, e.g. with declareDiscoveryExtension({ bodyType, input, inputSchema, output }) from @x402/extensions/bazaar.");
    else {
      const inp = bz.info && bz.info.input;
      if (!inp) add("warn", "BAZAAR_INPUT", "extensions.bazaar has no info.input example.", "Add info.input with type \"http\", the method and an example body or query.");
      else {
        if (inp.method && inp.method.toUpperCase() !== method) add("warn", "BAZAAR_METHOD", `Bazaar input says method ${inp.method}, but you probed ${method}.`, "Probe with the declared method, or fix the declared method.");
        if (!bz.schema) add("warn", "BAZAAR_SCHEMA", "extensions.bazaar has no JSON schema.", "Include schema (declareDiscoveryExtension adds it).");
        else add("pass", "BAZAAR_EXTENSION", "Bazaar discovery extension present with input example and schema.");
      }
      if (!(bz.info && bz.info.output)) add("info", "BAZAAR_OUTPUT", "No output example in the Bazaar extension.", "An output example helps agents decide before paying.");
    }
  } else {
    const os = pr.accepts[0].outputSchema;
    if (!os || !os.input) add("warn", "V1_OUTPUT_SCHEMA", "No outputSchema.input: v1 Bazaar listing will lack an input description.", "Add outputSchema: { input: { type: 'http', method, bodyType?, bodyFields? }, output }.");
    else add("pass", "V1_OUTPUT_SCHEMA", "v1 outputSchema.input present.");
  }
  if (v2 && v1 && v1 !== v2 && Array.isArray(v1.accepts) && v1.x402Version === 1) {
    // compare payTo per network between the v1 body and the v2 header
    const byNet = (list, v1style) => { const m = {}; for (const a of list) { const n = v1style ? (a.networkCaip2 || V1_TO_CAIP[a.network] || a.network) : a.network; (m[n] ||= new Set()).add(String(a.payTo || "").toLowerCase()); } return m; };
    const m1 = byNet(v1.accepts, true), m2 = byNet(v2.accepts, false);
    const bad = Object.keys(m1).filter(n => m2[n] && ![...m1[n]].some(x => m2[n].has(x)));
    if (bad.length) add("error", "DUAL_PAYTO", `v1 body and v2 header name different payTo addresses on ${bad.join(", ")}.`, "Serve the same payTo in both, or drop the v1 body.");
    else add("pass", "DUAL_CONSISTENT", "v1 body and v2 header agree on payTo for shared networks.");
  }

  // --- CORS (matters for browser-based buyers and web wallets; server-side agents ignore it)
  // Second unpaid request with an Origin header, as a browser would send it.
  let ch = h, corsStatus = res.status;
  try { const cr = await fetchImpl(target.href, { method, headers: { ...hdrs, origin: probeOrigin }, body: reqBody, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) }); await cr.body?.cancel?.(); ch = n => cr.headers.get(n); corsStatus = cr.status; } catch {}
  cors = { probe_origin: probeOrigin, status: corsStatus, allow_origin: ch("access-control-allow-origin"), expose_headers: ch("access-control-expose-headers") };
  if (corsStatus !== res.status) add("warn", "CORS_ORIGIN_REJECTED", `With an Origin header (${probeOrigin}) the endpoint answers ${corsStatus} instead of ${res.status}, so browser-based buyers from other sites are refused.`, "If you want browser agents and web wallets to pay, don't reject unknown origins on paid routes (payment is the gate). If the allowlist is deliberate, ignore this.");
  if (corsStatus !== res.status) { /* already reported */ }
  else if (!cors.allow_origin) add("warn", "CORS_ALLOW_ORIGIN", "The 402 has no Access-Control-Allow-Origin, so browser-based buyers can't read it.", "Add CORS before the payment middleware (Hono: app.use(cors({ origin: '*', exposeHeaders: ['PAYMENT-REQUIRED','PAYMENT-RESPONSE'], allowHeaders: ['Content-Type','PAYMENT-SIGNATURE','X-PAYMENT'] }))). Server-side agents are unaffected.");
  else {
    add("pass", "CORS_ALLOW_ORIGIN", `Access-Control-Allow-Origin: ${cors.allow_origin}`);
    if (v2) {
      const ex = (cors.expose_headers || "").toLowerCase();
      if (!(ex.includes("payment-required") || ex.trim() === "*")) add("warn", "CORS_EXPOSE_PAYMENT_REQUIRED", "CORS is on, but PAYMENT-REQUIRED is not in Access-Control-Expose-Headers, so browser JS sees the 402 without its requirements.", "Add Access-Control-Expose-Headers: PAYMENT-REQUIRED, PAYMENT-RESPONSE.");
      else add("pass", "CORS_EXPOSE_PAYMENT_REQUIRED", "PAYMENT-REQUIRED is exposed to browsers.");
      if (!(ex.includes("payment-response") || ex.trim() === "*")) add("info", "CORS_EXPOSE_PAYMENT_RESPONSE", "PAYMENT-RESPONSE (the settlement receipt) is not exposed to browsers.", "Add it to Access-Control-Expose-Headers so browser buyers can read their tx hash.");
    }
    // preflight for the paid retry
    const payHeader = v2 ? "payment-signature" : "x-payment";
    try {
      const pf = await fetchImpl(target.href, { method: "OPTIONS", headers: { origin: probeOrigin, "access-control-request-method": method, "access-control-request-headers": `content-type,${payHeader}` }, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      const ah = (pf.headers.get("access-control-allow-headers") || "").toLowerCase();
      cors.preflight = { status: pf.status, allow_headers: pf.headers.get("access-control-allow-headers"), allow_methods: pf.headers.get("access-control-allow-methods") };
      if (pf.status >= 400 || !(ah.includes(payHeader) || ah.trim() === "*")) add("warn", "CORS_PREFLIGHT_PAYMENT_HEADER", `Preflight (OPTIONS) does not allow the ${payHeader.toUpperCase()} request header (status ${pf.status}), so a browser can't send the paid retry.`, `Answer OPTIONS with 204 and Access-Control-Allow-Headers including ${payHeader.toUpperCase()} and Content-Type.`);
      else add("pass", "CORS_PREFLIGHT_PAYMENT_HEADER", `Preflight allows ${payHeader.toUpperCase()}.`);
    } catch (e) { cors.preflight = { error: String(e.message || e) }; }
  }

  // --- optional discovery documents on the origin (informational)
  discovery = {};
  if (opts.discovery !== false) await Promise.all(["/.well-known/x402", "/openapi.json", "/llms.txt"].map(async p => {
    try { const r = await fetchImpl(target.origin + p, { headers: { "user-agent": hdrs["user-agent"] }, redirect: "manual", signal: AbortSignal.timeout(5000) }); discovery[p] = r.status; await r.body?.cancel?.(); }
    catch { discovery[p] = null; }
  }));
  if (opts.discovery !== false && !Object.values(discovery).some(s => s === 200)) add("info", "DISCOVERY_DOCS", "No /.well-known/x402, /openapi.json or /llms.txt on this origin.", "Optional, but x402scan reads /.well-known/x402 and /openapi.json (with x-payment-info), and agents read /llms.txt.");

  return finish();

  function finish() {
    const order = { error: 0, warn: 1, info: 2, pass: 3 }; findings.sort((a, b) => order[a.severity] - order[b.severity]);
    const n = s => findings.filter(f => f.severity === s).length;
    const summary = { errors: n("error"), warnings: n("warn"), info: n("info"), passed: n("pass") };
    return {
      checked_url: target.href, method, checked_at: new Date().toISOString(), checker: `cc-x402-check ${VERSION}`,
      verdict: summary.errors ? "fail" : summary.warnings ? "warn" : "pass", summary, x402Version: (v2 || v1) ? (v2 || v1).x402Version : null, http,
      findings, requirements, cors, discovery,
      limits: "One unpaid probe, a second unpaid probe with an Origin header, an OPTIONS preflight and three GETs for discovery docs. No payment is made, so this cannot prove settlement works. On-chain reads use public RPCs.",
    };
  }
}

async function checkAccept(a, i, isV2, add, fetchImpl, doRpc) {
  const p = `accepts[${i}]`; const out = { index: i, scheme: a.scheme, network: a.network, asset: a.asset, payTo: a.payTo };
  if (!KNOWN_SCHEMES.includes(a.scheme)) add("warn", "SCHEME", `${p}.scheme is ${JSON.stringify(a.scheme)}; most clients and facilitators only handle "exact".`, "Use scheme \"exact\" unless you know your buyers support another.");
  // network
  let caip = a.network;
  if (isV2) { if (!/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(a.network || "")) add("error", "NETWORK_CAIP2", `${p}.network ${JSON.stringify(a.network)} is not a CAIP-2 id (v2 needs e.g. "eip155:8453").`, `Use "eip155:8453" for Base mainnet.`); }
  else { caip = V1_TO_CAIP[a.network]; if (!caip) add("warn", "NETWORK_V1", `${p}.network ${JSON.stringify(a.network)} is not a v1 name we know.`, "Use e.g. \"base\"."); }
  const net = NETWORKS[caip]; out.network_name = net ? net.name : null;
  if (caip && !net) add("info", "NETWORK_UNKNOWN", `${p}.network ${a.network} is not one this checker knows; asset and on-chain checks are skipped.`);
  if (net && net.testnet) add("warn", "NETWORK_TESTNET", `${p} is on ${net.name}. Real buyers won't pay testnet USDC.`, "Switch to the mainnet network before listing.");
  const evm = (caip || "").startsWith("eip155:"), sol = (caip || "").startsWith("solana:");
  // amount
  const amtKey = isV2 ? "amount" : "maxAmountRequired"; const amt = a[amtKey];
  if (isV2 && a.amount === undefined && a.maxAmountRequired !== undefined) add("error", "AMOUNT_FIELD", `${p} uses v1 field maxAmountRequired in a v2 response.`, "Rename to `amount` for v2.");
  else if (typeof amt !== "string" || !/^\d+$/.test(amt) || BigInt(amt) === 0n) add("error", "AMOUNT", `${p}.${amtKey} must be a positive integer string in atomic units, got ${JSON.stringify(amt)}.`, "For 0.01 USDC (6 decimals) use \"10000\".");
  // addresses
  for (const k of ["asset", "payTo"]) {
    const v = a[k];
    if (evm) {
      if (!isEvmAddr(v)) { add("error", k.toUpperCase() + "_FORMAT", `${p}.${k} is not a 0x-prefixed 20-byte address: ${JSON.stringify(v)}.`, `Use the checksummed address.`); continue; }
      const cs = toChecksum(v);
      if (v !== v.toLowerCase() && v !== cs) add("error", k.toUpperCase() + "_CHECKSUM", `${p}.${k} has mixed case but a wrong EIP-55 checksum (a typo?).`, `Correct form: ${cs}.`);
      else if (v !== cs) add("info", k.toUpperCase() + "_CHECKSUM", `${p}.${k} is all lowercase. Valid, but strict clients compare checksummed strings.`, `Use ${cs}.`);
      if (/^0x0{40}$/.test(v)) add("error", k.toUpperCase() + "_ZERO", `${p}.${k} is the zero address.`, "Set a real address.");
    } else if (sol && !isSolAddr(v)) add("error", k.toUpperCase() + "_FORMAT", `${p}.${k} is not a base58 Solana address: ${JSON.stringify(v)}.`, "Use the base58 address.");
  }
  if (evm && isEvmAddr(a.asset) && isEvmAddr(a.payTo) && a.asset.toLowerCase() === a.payTo.toLowerCase()) add("error", "PAYTO_IS_ASSET", `${p}.payTo equals the asset contract; payments would go to the token contract.`, "Set payTo to your wallet.");
  if (net && a.asset) {
    if (String(a.asset).toLowerCase() === net.usdc.toLowerCase()) { out.asset_name = "USDC"; add("pass", "ASSET_KNOWN", `${p}.asset is the canonical USDC on ${net.name}.`); }
    else add("warn", "ASSET_NOT_USDC", `${p}.asset is not the canonical USDC on ${net.name} (${net.usdc}). Buyers that pin USDC will refuse, and the facilitator may not support it.`, "Use USDC unless you deliberately accept another EIP-3009 token.");
  }
  // timeout
  const customDomain = a.extra && isEvmAddr(a.extra.verifyingContract);
  if (customDomain) add("info", "EXTRA_VERIFYING_CONTRACT", `${p} signs against verifyingContract ${a.extra.verifyingContract} (e.g. Circle Gateway batched payments), not the token. Its domain is not checked on-chain here, and buyers need a client that supports it.`);
  const to = a.maxTimeoutSeconds;
  if (to === undefined) add(isV2 ? "error" : "warn", "MAX_TIMEOUT", `${p}.maxTimeoutSeconds is missing.`, "Set it (60-300 is typical).");
  else if (typeof to !== "number" || to <= 0) add("error", "MAX_TIMEOUT", `${p}.maxTimeoutSeconds must be a positive number, got ${JSON.stringify(to)}.`, "Use e.g. 300.");
  else if (to < 15 || to > 3600) add(customDomain && to > 3600 ? "info" : "warn", "MAX_TIMEOUT", `${p}.maxTimeoutSeconds is ${to}s, outside 15-3600s.`, to < 15 ? "Very short windows can expire before settlement." : "Long windows leave a valid authorization usable for longer than needed.");
  // EIP-712 domain (exact scheme on EVM needs token name/version to build the signature)
  if (evm && a.scheme === "exact") {
    const ex = a.extra || {};
    if (!ex.name || !ex.version) add("error", "EXTRA_EIP712", `${p}.extra.name/extra.version missing; buyers need the token's EIP-712 domain to sign.`, net ? `For USDC on ${net.name}: extra: { name: "${net.domain.name}", version: "${net.domain.version}" }.` : "Add the token's EIP-712 name and version.");
    out.extra = ex;
  }
  // on-chain reads
  if (evm && net && net.rpc && doRpc && isEvmAddr(a.asset)) {
    const rpcs = [].concat(net.rpc); let used = rpcs[0];
    const rpc = async (method, params) => { // try each public RPC until one answers with a hex string
      let last;
      for (const u of rpcs) {
        try { const r = await fetchImpl(u, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(6000) });
          const j = await r.json(); if (j.error) { last = new Error(j.error.message); if (/revert/i.test(last.message)) throw last; continue; }
          if (typeof j.result === "string") { used = u; return j.result; } last = new Error(`empty RPC result from ${new URL(u).host} (HTTP ${r.status})`); }
        catch (e) { if (/revert/i.test(String(e && e.message))) throw e; last = e; }
      }
      throw last || new Error("no RPC answered");
    };
    const call = data => rpc("eth_call", [{ to: a.asset, data }, "latest"]);
    try {
      const [code, nameH, verH, decH, payCode] = await Promise.all([rpc("eth_getCode", [a.asset, "latest"]), call("0x06fdde03").catch(() => null), call("0x54fd4d50").catch(() => null), call("0x313ce567").catch(() => null), isEvmAddr(a.payTo) ? rpc("eth_getCode", [a.payTo, "latest"]) : null]);
      const oc = out.onchain = { rpc: used, asset_has_code: !!code && code !== "0x", token_name: nameH ? decodeAbiString(nameH) : null, token_version: verH ? decodeAbiString(verH) : null, decimals: decH ? parseInt(decH, 16) : null, payTo_is_contract: !!payCode && payCode !== "0x" };
      if (!oc.asset_has_code && !oc.token_name) add("error", "ASSET_NO_CODE", `${p}.asset has no contract code on ${net.name}.`, "Wrong network or wrong address.");
      const ex = a.extra || {};
      if (customDomain) { /* domain belongs to verifyingContract */ }
      else if (oc.token_name && ex.name && ex.name !== oc.token_name) add("error", "EXTRA_NAME_ONCHAIN", `${p}.extra.name is "${ex.name}" but the token's on-chain name() is "${oc.token_name}". Signatures built from this domain will fail verification.`, `Set extra.name to "${oc.token_name}".`);
      if (!customDomain && oc.token_version && ex.version && ex.version !== oc.token_version) add("error", "EXTRA_VERSION_ONCHAIN", `${p}.extra.version is "${ex.version}" but on-chain version() is "${oc.token_version}".`, `Set extra.version to "${oc.token_version}".`);
      if (!customDomain && oc.token_name && ex.name === oc.token_name && (!oc.token_version || ex.version === oc.token_version)) add("pass", "EXTRA_EIP712_ONCHAIN", `${p}.extra matches the token's on-chain EIP-712 name/version.`);
      if (oc.payTo_is_contract) add("info", "PAYTO_CONTRACT", `${p}.payTo is a contract (e.g. a smart wallet or splitter). USDC can be sent to it; make sure you can move funds out of it.`);
      if (oc.decimals != null && typeof amt === "string" && /^\d+$/.test(amt)) out.amount_human = Number(amt) / 10 ** oc.decimals;
    } catch (e) { out.onchain = { error: `RPC read failed: ${String(e.message || e)}` }; add("info", "ONCHAIN_SKIPPED", `${p}: on-chain checks skipped (public RPC error: ${String(e.message || e).slice(0, 120)}). Re-run to retry.`); }
  }
  if (out.amount_human === undefined && net && String(a.asset || "").toLowerCase() === net.usdc.toLowerCase() && /^\d+$/.test(String(amt))) out.amount_human = Number(amt) / 1e6;
  if (out.amount_human !== undefined) out.price = `${out.amount_human} ${out.asset_name || "tokens"}`;
  out.amount = amt;
  return out;
}

export function isPrivateHost(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(":")) return true; // IP literals (v4/v6) not accepted
  return false;
}
