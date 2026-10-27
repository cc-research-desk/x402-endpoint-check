// Cloudflare Workers entry. Workers forbid I/O at global scope and forbid sharing an
// in-flight I/O promise across requests; the x402 middleware fetches the facilitator's
// /supported list on init, so build the app per request (cheap; one small fetch).
import { buildApp } from "./app.js";
export default { fetch(req, env, ctx) { return buildApp().fetch(req, env, ctx); } };
