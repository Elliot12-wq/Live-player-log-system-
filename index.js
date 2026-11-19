// Live Player Log - Worker entry.
//
// Two ways to run it (see docs/DEPLOY.md):
//   A) mounted into the existing banner Worker:   import { handleLiveLog, LiveLogHub } from "./live/index.js"
//      call `const r = await handleLiveLog(request, env); if (r) return r;` at the top of its fetch(), and `export { LiveLogHub }`
//   B) standalone:                                `wrangler deploy` this repo as its own Worker (default export below)
//
// Everything under /live/* is handled here. Cheap rejections (unknown route, no bearer token, oversized body) happen BEFORE the
// Durable Object is touched, so junk traffic never costs more than one Worker invocation.

import { LiveLogHub } from "./hub.js";
export { LiveLogHub };

const HUB_NAME = "main";
const MAX_BODY = 2048;

// route -> does it need a session token?
const ROUTES = {
  "POST /live/auth/challenge": false,
  "POST /live/auth/verify": false,
  "POST /live/auth/logout": true,
  "POST /live/presence": true,
  "POST /live/presence/leave": true,
  "GET /live/list": true,
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store" },
  });
}

/** Returns a Response for /live/* requests, or null when the path is not ours (so a host Worker can carry on). */
export async function handleLiveLog(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/live/") && url.pathname !== "/live") return null;

  // public, data-free liveness probe (no Durable Object, no player data)
  if (request.method === "GET" && url.pathname === "/live/health") {
    return json({ ok: true, service: "live-player-log" });
  }

  const key = `${request.method} ${url.pathname}`;
  if (!(key in ROUTES)) return json({ ok: false, err: "not_found" }, 404);
  if (!env.LIVE_LOG_HUB) return json({ ok: false, err: "not_configured" }, 503);

  if (ROUTES[key]) {
    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ") || auth.length < 40 || auth.length > 160) {
      return json({ ok: false, err: "unauthorized" }, 401); // no token: fail closed without waking the Durable Object
    }
  }
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > MAX_BODY) return json({ ok: false, err: "too_large" }, 413);

  const stub = env.LIVE_LOG_HUB.get(env.LIVE_LOG_HUB.idFromName(HUB_NAME));
  return stub.fetch(request);
}

export default {
  async fetch(request, env) {
    const res = await handleLiveLog(request, env);
    if (res) return res;
    return json({ ok: false, err: "not_found" }, 404);
  },
};
