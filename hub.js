// LiveLogHub - the single Durable Object behind the Live Player Log.
//
//  * Identity: NO ownership proof is required. The client claims a Roblox user id; the Worker looks up the real username on
//    users.roblox.com and issues a random session token (only its SHA-256 is stored). Anyone can therefore claim any user id.
//    The user id / username used afterwards come from that session, never from the request body.
//  * Publishing presence needs a session. Viewing the list needs a session AND a viewer role (roles.js), re-checked on every request.
//  * The list is a change log: clients send a cursor ("epoch.seq") and get only what changed (or an empty "no change" answer).
//  * Presence lives in memory and is persisted only when its content changes; heartbeats never write to storage.

import { loadRoleTable, roleFor } from "./roles.js";

const PRESENCE_TTL_MS = 240_000;     // abandoned presence disappears after ~2 missed heartbeats (client beats about every 100s)
const MAX_PRESENCE = 500;
const MAX_TOMBS = 300;               // removal log kept for delta answers; older cursors simply get a full snapshot
const SESSION_TTL_MS = 14 * 86_400_000;
const SESSION_TOUCH_MS = 86_400_000; // sliding expiry is written at most once a day
const MAX_SESSIONS_PER_USER = 5;
const CHALLENGE_TTL_MS = 600_000;
const MIN_PRESENCE_GAP_MS = 15_000;
const MAX_BODY = 2048;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const CID_RE = /^[0-9a-f]{32}$/;

const enc = new TextEncoder();

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", Vary: "Authorization", ...headers },
  });
}
const fail = (status, err, extra = {}) => json({ ok: false, err, ...extra }, status);

function randomHex(bytes) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
}
function randomCode(len) {
  const a = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(a, (b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
}
function randomToken() {
  const a = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...a)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
function cleanText(v, max) {
  return String(v ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "").trim().slice(0, max);
}
function bearer(request) {
  const h = request.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}
async function readJson(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) return null;
  try {
    const v = JSON.parse(text || "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

export class LiveLogHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.ready = state.blockConcurrencyWhile(() => this.load());
  }

  async load() {
    this.epoch = randomHex(4);       // new epoch on every cold start => clients holding an old cursor receive a full snapshot
    this.seq = 1;
    this.tombFloor = 0;              // newest removal that fell out of the log
    this.tombs = [];                 // [{u, rev}] removals, oldest first
    this.pres = new Map();           // userId -> {u, n, pid, g, j, seen, rev, crev, last}
    this.sess = new Map();           // sha256(token) -> session record (read-through cache of storage)
    this.rate = new Map();           // best-effort in-memory rate limits
    this.lastPurge = 0;
    this.lastSweep = 0;
    const now = Date.now();
    const stored = await this.state.storage.list({ prefix: "p:" });
    for (const [, v] of stored) {
      if (!v || typeof v.u !== "number") continue;
      // cold start: give persisted entries one full TTL of grace; real users refresh it with their next heartbeat, ghosts expire
      this.pres.set(v.u, { ...v, seen: now, rev: this.seq, crev: this.seq, last: 0 });
    }
  }

  async fetch(request) {
    await this.ready;
    const url = new URL(request.url);
    try {
      switch (`${request.method} ${url.pathname}`) {
        case "POST /live/auth/challenge": return await this.authChallenge(request);
        case "POST /live/auth/verify": return await this.authVerify(request);
        case "POST /live/auth/logout": return await this.authLogout(request);
        case "POST /live/presence": return await this.presence(request);
        case "POST /live/presence/leave": return await this.leave(request);
        case "GET /live/list": return await this.list(request, url);
        default: return fail(404, "not_found");
      }
    } catch (err) {
      console.error("live-log error", err && err.stack || err);
      return fail(500, "internal");
    }
  }

  // ---------- helpers ----------
  hit(key, max, windowMs) {
    const now = Date.now();
    let r = this.rate.get(key);
    if (!r || now - r.t > windowMs) r = { t: now, n: 0 };
    r.n++;
    this.rate.set(key, r);
    if (this.rate.size > 5000) for (const [k, v] of this.rate) if (now - v.t > windowMs) this.rate.delete(k);
    return r.n <= max;
  }

  async session(request) {
    const token = bearer(request);
    if (token.length < 32 || token.length > 128) return null;
    const h = await sha256hex(token);
    let s = this.sess.get(h);
    if (!s) {
      s = await this.state.storage.get("s:" + h);
      if (s) this.sess.set(h, s);
    }
    if (!s) return null;
    const now = Date.now();
    if (s.x < now) { await this.dropSession(h, s); return null; }
    if (now - s.t > SESSION_TOUCH_MS) {
      s.t = now; s.x = now + SESSION_TTL_MS;
      await this.state.storage.put("s:" + h, s);
    }
    return { h, u: s.u, n: s.n };
  }

  async dropSession(h, s) {
    this.sess.delete(h);
    await this.state.storage.delete("s:" + h);
    const key = "ui:" + s.u;
    const idx = ((await this.state.storage.get(key)) || []).filter((x) => x !== h);
    if (idx.length) await this.state.storage.put(key, idx); else await this.state.storage.delete(key);
  }

  removePresence(uid) {
    if (!this.pres.delete(uid)) return false;
    this.tombs.push({ u: uid, rev: ++this.seq });
    while (this.tombs.length > MAX_TOMBS) this.tombFloor = this.tombs.shift().rev;
    return true;
  }

  async purge(now) {
    if (now - this.lastPurge >= 10_000) {
      this.lastPurge = now;
      const gone = [];
      for (const p of this.pres.values()) if (now - p.seen > PRESENCE_TTL_MS) gone.push(p.u);
      for (const uid of gone) this.removePresence(uid);
      for (let i = 0; i < gone.length; i += 100) await this.state.storage.delete(gone.slice(i, i + 100).map((u) => "p:" + u));
    }
    if (now - this.lastSweep >= 600_000) { // expired verification challenges
      this.lastSweep = now;
      const all = await this.state.storage.list({ prefix: "c:" });
      const dead = [];
      for (const [k, c] of all) if (!c || c.exp < now) { dead.push(k); if (c) dead.push("cu:" + c.u); }
      for (let i = 0; i < dead.length; i += 100) await this.state.storage.delete(dead.slice(i, i + 100));
    }
  }

  // ---------- sign-in (no ownership proof; the profile code is issued but no longer checked) ----------
  async authChallenge(request) {
    const b = await readJson(request);
    const uid = b && Number.isSafeInteger(b.userId) ? b.userId : 0;
    if (uid < 1 || uid > 1e12) return fail(400, "bad_request");
    if (!this.hit("ch:" + uid, 8, 3_600_000)) return fail(429, "slow");
    const now = Date.now();
    const existingCid = await this.state.storage.get("cu:" + uid);
    if (existingCid && b.renew !== true) {
      const c = await this.state.storage.get("c:" + existingCid);
      if (c && c.u === uid && c.exp - now > 120_000) {
        return json({ ok: true, cid: existingCid, code: c.code, ttl: Math.floor((c.exp - now) / 1000) });
      }
    }
    if (existingCid) await this.state.storage.delete("c:" + existingCid);
    const cid = randomHex(16);
    const code = "UHLOG-" + randomCode(10);
    await this.state.storage.put({ ["c:" + cid]: { u: uid, code, exp: now + CHALLENGE_TTL_MS }, ["cu:" + uid]: cid });
    return json({ ok: true, cid, code, ttl: Math.floor(CHALLENGE_TTL_MS / 1000) });
  }

  async authVerify(request) {
    const b = await readJson(request);
    const cid = b && typeof b.cid === "string" ? b.cid : "";
    if (!CID_RE.test(cid)) return fail(400, "bad_request");
    if (!this.hit("vf:" + cid, 20, 600_000) || !this.hit("vfg", 120, 60_000)) return fail(429, "slow");
    const c = await this.state.storage.get("c:" + cid);
    const now = Date.now();
    if (!c || c.exp < now) return fail(410, "expired");

    let res;
    try {
      res = await fetch(`https://users.roblox.com/v1/users/${c.u}`, {
        headers: { Accept: "application/json" },
        cf: { cacheTtl: 0, cacheEverything: false },
      });
    } catch {
      return fail(503, "roblox_unavailable");
    }
    if (!res.ok) return fail(503, "roblox_unavailable");
    let u;
    try { u = await res.json(); } catch { return fail(503, "roblox_unavailable"); }
    if (!u || u.id !== c.u || typeof u.name !== "string" || !NAME_RE.test(u.name)) return fail(422, "account_invalid");

    // no profile-code check: the claimed account is accepted as-is. Issue a session (the token is shown once; only its hash is stored).
    const token = randomToken();
    const h = await sha256hex(token);
    const rec = { u: c.u, n: u.name, c: now, t: now, x: now + SESSION_TTL_MS };
    const idxKey = "ui:" + c.u;
    const idx = (await this.state.storage.get(idxKey)) || [];
    idx.push(h);
    while (idx.length > MAX_SESSIONS_PER_USER) {
      const old = idx.shift();
      this.sess.delete(old);
      await this.state.storage.delete("s:" + old);
    }
    await this.state.storage.put({ ["s:" + h]: rec, [idxKey]: idx });
    await this.state.storage.delete(["c:" + cid, "cu:" + c.u]);
    this.sess.set(h, rec);
    return json({ ok: true, token, uid: c.u, name: u.name });
  }

  async authLogout(request) {
    const s = await this.session(request);
    if (!s) return fail(401, "unauthorized");
    if (this.removePresence(s.u)) await this.state.storage.delete("p:" + s.u);
    await this.dropSession(s.h, { u: s.u });
    return json({ ok: true });
  }

  // ---------- presence (publisher) ----------
  async presence(request) {
    const s = await this.session(request);
    if (!s) return fail(401, "unauthorized");
    const b = await readJson(request);
    if (!b) return fail(400, "bad_request");
    const now = Date.now();
    const rec = this.pres.get(s.u);
    if (rec && now - rec.last < MIN_PRESENCE_GAP_MS) return fail(429, "slow", { retry: Math.ceil((MIN_PRESENCE_GAP_MS - (now - rec.last)) / 1000) });

    if (b.t === "hb") { // heartbeat: only refreshes an existing entry (a missing one asks the client to send its full state)
      if (!rec) return fail(409, "resync");
      rec.seen = now; rec.last = now; rec.rev = ++this.seq;
      return json({ ok: true });
    }

    const pid = Number.isSafeInteger(b.pid) && b.pid > 0 && b.pid < 1e14 ? b.pid : 0;
    if (!pid) return fail(400, "bad_request");
    const g = cleanText(b.g, 64);
    const shareJob = b.pub === true && typeof b.j === "string" && GUID_RE.test(b.j);
    const j = shareJob ? b.j.toLowerCase() : "";
    if (!rec && this.pres.size >= MAX_PRESENCE) return fail(503, "full");

    const changed = !rec || rec.pid !== pid || rec.g !== g || rec.j !== j;
    const rev = ++this.seq;
    this.pres.set(s.u, { u: s.u, n: s.n, pid, g, j, seen: now, rev, crev: changed ? rev : rec.crev, last: now });
    if (changed) await this.state.storage.put("p:" + s.u, { u: s.u, n: s.n, pid, g, j });
    return json({ ok: true });
  }

  async leave(request) {
    const s = await this.session(request);
    if (!s) return fail(401, "unauthorized");
    if (this.removePresence(s.u)) await this.state.storage.delete("p:" + s.u);
    return json({ ok: true });
  }

  // ---------- list (viewer) ----------
  async list(request, url) {
    const s = await this.session(request);
    if (!s) return fail(401, "unauthorized");

    // authorization is decided here, on every request, from the session identity (the user id is client-claimed, see authVerify)
    const table = await loadRoleTable(this.env);
    if (!table) return fail(503, "roles_unavailable"); // cannot establish who is allowed => return nothing
    if (!roleFor(table, s.u, s.n)) return fail(403, "forbidden");

    const now = Date.now();
    await this.purge(now);

    const [e, q] = String(url.searchParams.get("c") || "").split(".");
    const since = e === this.epoch && /^\d{1,12}$/.test(q || "") ? Number(q) : -1;
    const etag = `"${this.epoch}.${this.seq}"`;
    const headers = { ETag: etag };
    if (request.headers.get("If-None-Match") === etag) return new Response(null, { status: 304, headers: { ...headers, "Cache-Control": "private, no-store" } });
    if (since === this.seq) return json({ ok: true, nc: 1, e: this.epoch, s: this.seq }, 200, headers);

    const full = since < 0 || since < this.tombFloor || since > this.seq;
    const age = (p) => Math.max(0, Math.floor((now - p.seen) / 1000));
    const up = [], tc = [], rm = [];
    for (const p of this.pres.values()) {
      if (full || p.crev > since) up.push({ u: p.u, n: p.n, p: p.pid, g: p.g, j: p.j || undefined, a: age(p) });
      else if (p.rev > since) tc.push([p.u, age(p)]);
    }
    if (!full) for (const t of this.tombs) if (t.rev > since && !this.pres.has(t.u)) rm.push(t.u);

    const body = { ok: true, e: this.epoch, s: this.seq };
    if (full) body.full = true;
    if (up.length) body.up = up;
    if (tc.length) body.tc = tc;
    if (rm.length) body.rm = rm;
    return json(body, 200, headers);
  }
}
