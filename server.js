// Local Node server: `npm start` (PORT=8787 by default).
import { serve } from "@hono/node-server";
import { buildApp } from "./app.js";
const port = Number(process.env.PORT || 8787);
serve({ fetch: buildApp().fetch, port }, () => console.log(`x402 endpoint check on http://localhost:${port}`));
