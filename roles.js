// Who may VIEW the Live Player Log? The same official sources the script already uses:
//   roles.json      -> entries with role "owner" | "co-owner" | "verified"
//   whitelist.json  -> plain verified players
// (both in the uh-mod-visual-system GitHub repo). Optional extra user ids can be set with the EXTRA_VIEWER_IDS variable.
//
// The identity that is checked against this table is the one the Worker verified itself (Roblox profile-code verification).
// A user id / name / role sent by the client is never used as proof of anything.

const DEFAULT_BASE = "https://raw.githubusercontent.com/Elliot12-wq/uh-mod-visual-system/main/";
const FRESH_MS = 30_000;      // a loaded table is reused for 30s (a role change reaches the log within ~30s + one request)
const MAX_STALE_MS = 120_000; // if GitHub is unreachable the last good table is trusted for at most 2 more minutes, then every viewer is denied
const VIEW_ROLES = new Set(["owner", "co-owner", "verified"]);
const NAME_RE = /^[A-Za-z0-9_]{3,20}$/;

let cache = { at: 0, table: null };
let inflight = null;

async function getJson(url) {
  const res = await fetch(url, { cf: { cacheTtl: 30, cacheEverything: true } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function build(rolesJson, whitelistJson, env) {
  const ids = new Map();
  const names = new Map();
  const add = (e, role) => {
    if (!e || typeof e !== "object") return;
    const id = Math.floor(Number(e.userId));
    if (Number.isSafeInteger(id) && id > 0 && !ids.has(id)) ids.set(id, role);
    if (typeof e.username === "string" && NAME_RE.test(e.username)) {
      const n = e.username.toLowerCase();
      if (!names.has(n)) names.set(n, role);
    }
  };
  for (const e of Array.isArray(rolesJson?.entries) ? rolesJson.entries : []) {
    const role = String(e?.role ?? "").toLowerCase();
    if (VIEW_ROLES.has(role)) add(e, role);
  }
  for (const e of Array.isArray(whitelistJson?.entries) ? whitelistJson.entries : []) add(e, "verified");
  for (const raw of String(env.EXTRA_VIEWER_IDS || "").split(",")) {
    const id = Math.floor(Number(raw.trim()));
    if (Number.isSafeInteger(id) && id > 0 && !ids.has(id)) ids.set(id, "verified");
  }
  return { ids, names };
}

async function refresh(env) {
  const base = String(env.ROLES_BASE || DEFAULT_BASE).replace(/\/+$/, "") + "/";
  const [roles, whitelist] = await Promise.all([
    getJson(base + "roles.json"),
    getJson(base + "whitelist.json").catch(() => null), // an absent whitelist just means "no extra verified players"
  ]);
  cache = { at: Date.now(), table: build(roles, whitelist, env) };
  return cache.table;
}

/** Returns the role table, or null when it cannot be trusted (callers must then deny everyone). */
export async function loadRoleTable(env) {
  const now = Date.now();
  if (cache.table && now - cache.at < FRESH_MS) return cache.table;
  try {
    inflight ??= refresh(env).finally(() => { inflight = null; });
    return await inflight;
  } catch {
    if (cache.table && now - cache.at < FRESH_MS + MAX_STALE_MS) return cache.table;
    return null;
  }
}

/** "owner" | "co-owner" | "verified" | null */
export function roleFor(table, userId, name) {
  if (!table) return null;
  return table.ids.get(userId) ?? table.names.get(String(name || "").toLowerCase()) ?? null;
}
