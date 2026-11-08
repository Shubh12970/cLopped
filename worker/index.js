// URL shortener API + redirect worker.
//
// Routes:
//   POST /api/links                 { url, custom_code?, expires_at? } -> 201 { code, short_url, long_url }
//   GET  /api/links/:code/stats     -> { code, long_url, created_at, expires_at, total_clicks, by_day, recent }
//   GET  /:code                     -> 302 Location: long_url (the hot path: cache, lookup, log click, redirect)
//                                     410 if the link has expired, 404 if it never existed
//
// Everything else falls through to the static frontend (env.ASSETS).

const BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CODE_RE = /^[0-9A-Za-z_-]{1,32}$/;

// Sequential database id -> short base62 string. Auto codes never collide
// with each other (the database hands out each id once); a custom code can
// take a string a future auto code would want, which the UNIQUE constraint
// catches - the insert is retried with the next id. Sequential codes are
// enumerable (guessable), documented in the security section.
export function toBase62(n) {
  if (n === 0) return "0";
  let s = "";
  while (n > 0) {
    s = BASE62[n % 62] + s;
    n = Math.floor(n / 62);
  }
  return s;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// Custom codes cannot squat on route-like words (a code "api" would
// shadow the API path) or common reserved pages.
const BLOCKED_CODES = new Set([
  "api", "admin", "login", "signin", "signup", "auth", "www", "app",
  "dashboard", "settings", "support", "abuse", "help", "stats",
]);

// Shorteners get abused to hide malicious links, so validate before storing:
// http/https only, sane length, never point at ourselves (redirect loop),
// never at private/local network addresses.
export function validateLongUrl(raw, ownHost) {
  if (raw.length > 2048) return { error: "That URL is too long (2048 characters max)." };
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { error: "That doesn't look like a valid URL. Include http:// or https://." };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { error: "Only http:// and https:// links can be shortened." };
  }
  const h = u.hostname.toLowerCase();
  if (h === ownHost) {
    return { error: "That link points back to this shortener - it would create a redirect loop." };
  }
  if (
    h === "localhost" || h === "0.0.0.0" || h === "::1" || h === "[::1]" ||
    /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) ||
    /^169\.254\./.test(h) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(h)
  ) {
    return { error: "Private or local network addresses can't be shortened." };
  }
  return { url: u.toString() };
}

export function validateCustomCode(custom) {
  if (!/^[0-9A-Za-z_-]{3,32}$/.test(custom)) {
    return { error: "Custom codes must be 3-32 characters: letters, numbers, - or _." };
  }
  if (BLOCKED_CODES.has(custom.toLowerCase())) {
    return { error: "That code is reserved. Pick another one." };
  }
  return null;
}

export function validateExpiry(raw) {
  if (raw === undefined || raw === null || raw === "") return { expires_at: null };
  const t = Date.parse(raw);
  if (Number.isNaN(t)) return { error: "The expiry date didn't parse. Use YYYY-MM-DD." };
  if (t <= Date.now()) return { error: "The expiry date is already in the past." };
  return { expires_at: new Date(t).toISOString() };
}

// ---- Auth (stage 2): Clerk session verification ----
//
// Owner accounts use Clerk (same provider as the StudyFlow dashboard).
// The client sends the Clerk session token as `Authorization: Bearer <jwt>`.
// The Worker verifies the RS256 signature against the instance JWKS (cached
// for an hour), checks expiry and the issuer, and trusts `sub` as the owner
// id. Anything unverifiable is simply treated as anonymous - the public
// endpoints keep working.
//
// Privacy model:
//   - Redirects are PUBLIC for every link, owned or not (a short link is
//     meant to be shared).
//   - Stats are PUBLIC for anonymous links, PRIVATE for owned links
//     (owner session required).
//   - Delete exists only for owned links, enforced server-side by owner id.
const jwksCache = new Map(); // jwksUrl -> { keys, fetchedAt }

async function getJwks(jwksUrl) {
  const hit = jwksCache.get(jwksUrl);
  if (hit && Date.now() - hit.fetchedAt < 3600_000) return hit.keys;
  const res = await fetch(jwksUrl);
  if (!res.ok) throw new Error("JWKS fetch failed");
  const data = await res.json();
  jwksCache.set(jwksUrl, { keys: data.keys, fetchedAt: Date.now() });
  return data.keys;
}

function b64urlDecode(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

// Returns the Clerk user id (sub) for a valid session token, else null.
export async function verifySessionUser(request, env) {
  if (!env.CLERK_JWKS_URL || !env.CLERK_ISSUER) return null;
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  try {
    const [h, p, sig] = token.split(".");
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    if (payload.iss !== env.CLERK_ISSUER) return null;
    const headerObj = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
    const keys = await getJwks(env.CLERK_JWKS_URL);
    const jwk = keys.find((k) => k.kid === headerObj.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey(
      "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", key, b64urlDecode(sig), new TextEncoder().encode(`${h}.${p}`)
    );
    if (!ok) return null;
    return payload.sub || null;
  } catch {
    return null;
  }
}

// Fixed-window per-IP rate limit on creation (30/hour): shorteners get
// abused to hide malicious links, and an open create endpoint needs a brake.
// A fixed window can burst 2x at a boundary; the interview upgrade is a
// sliding window or token bucket (the sibling project).
const CREATE_LIMIT_PER_HOUR = 30;

export function hourWindowStart(now = Date.now()) {
  return new Date(Math.floor(now / 3600000) * 3600000).toISOString();
}

async function checkRateLimit(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const windowStart = hourWindowStart();
  const row = await env.DB.prepare("SELECT count FROM rate_limits WHERE ip = ? AND window_start = ?")
    .bind(ip, windowStart).first();
  if (row && row.count >= CREATE_LIMIT_PER_HOUR) return false;
  await env.DB.prepare(
    `INSERT INTO rate_limits (ip, window_start, count) VALUES (?, ?, 1)
     ON CONFLICT(ip, window_start) DO UPDATE SET count = count + 1`
  ).bind(ip, windowStart).run();
  return true;
}

async function createLink(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Expected a JSON body like { \"url\": \"https://...\" }." }, 400);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Rate limit: too many links created from your network. Try again in a bit." }, 429);
  }
  const ownerId = await verifySessionUser(request, env);
  const ownHost = new URL(request.url).hostname;
  const check = validateLongUrl(String(body.url || "").trim(), ownHost);
  if (check.error) return json({ error: check.error }, 400);
  const expiry = validateExpiry(body.expires_at);
  if (expiry.error) return json({ error: expiry.error }, 400);

  const insert = "INSERT INTO links (code, long_url, created_at, expires_at, owner_id) VALUES (?, ?, ?, ?, ?)";
  const custom = typeof body.custom_code === "string" ? body.custom_code.trim() : "";
  if (custom) {
    const codeErr = validateCustomCode(custom);
    if (codeErr) return json({ error: codeErr.error }, 400);
    const clash = await env.DB.prepare("SELECT 1 FROM links WHERE code = ?").bind(custom).first();
    if (clash) return json({ error: `The code "${custom}" is already taken.` }, 409);
    // The UNIQUE constraint is the real guard; the SELECT above is just a
    // friendlier error. A concurrent insert can still win the race, so
    // catch the constraint violation and answer 409 the same way.
    try {
      await env.DB.prepare(insert)
        .bind(custom, check.url, new Date().toISOString(), expiry.expires_at, ownerId).run();
    } catch {
      return json({ error: `The code "${custom}" is already taken.` }, 409);
    }
    return json({ code: custom, long_url: check.url, short_url: `https://${ownHost}/${custom}`, expires_at: expiry.expires_at, owned: Boolean(ownerId) }, 201);
  }

  // Auto code: insert with a unique placeholder, then set code = base62(id).
  // If that string is already taken by a custom code, retry; the next id
  // gives a different code.
  for (let attempt = 0; attempt < 3; attempt++) {
    const placeholder = "~" + crypto.randomUUID();
    await env.DB.prepare(insert)
      .bind(placeholder, check.url, new Date().toISOString(), expiry.expires_at, ownerId).run();
    const row = await env.DB.prepare("SELECT id FROM links WHERE code = ?").bind(placeholder).first();
    const code = toBase62(row.id);
    try {
      await env.DB.prepare("UPDATE links SET code = ? WHERE id = ?").bind(code, row.id).run();
      return json({ code, long_url: check.url, short_url: `https://${ownHost}/${code}`, expires_at: expiry.expires_at, owned: Boolean(ownerId) }, 201);
    } catch {
      await env.DB.prepare("DELETE FROM links WHERE id = ?").bind(row.id).run();
    }
  }
  return json({ error: "Could not allocate a code, please try again." }, 500);
}

// Stats are public for anonymous links and private for owned links: the
// redirect itself is public either way (a short link is meant to be shared),
// but click analytics belong to the owner.
async function getStats(request, env, code) {
  const link = await env.DB.prepare("SELECT code, long_url, created_at, expires_at, owner_id FROM links WHERE code = ?").bind(code).first();
  if (!link) return json({ error: "No link with that code." }, 404);
  if (link.owner_id) {
    const userId = await verifySessionUser(request, env);
    if (userId !== link.owner_id) {
      return json({ error: "Stats for this link are private to its owner." }, 403);
    }
  }
  const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM clicks WHERE link_code = ?").bind(code).first();
  const byDay = await env.DB.prepare(
    `SELECT substr(clicked_at, 1, 10) AS day, COUNT(*) AS clicks
     FROM clicks WHERE link_code = ?
     GROUP BY day ORDER BY day DESC LIMIT 30`
  ).bind(code).all();
  const recent = await env.DB.prepare(
    `SELECT clicked_at, referrer, country FROM clicks
     WHERE link_code = ? ORDER BY id DESC LIMIT 20`
  ).bind(code).all();
  const { owner_id, ...rest } = link;
  return json({ ...rest, owned: Boolean(owner_id), total_clicks: total.n, by_day: byDay.results, recent: recent.results });
}

// The signed-in user's own links, newest first (stage 2).
async function listMine(request, env) {
  const userId = await verifySessionUser(request, env);
  if (!userId) return json({ error: "Sign in to see your links." }, 401);
  const rows = await env.DB.prepare(
    `SELECT code, long_url, created_at, expires_at,
            (SELECT COUNT(*) FROM clicks WHERE link_code = links.code) AS total_clicks
     FROM links WHERE owner_id = ? ORDER BY id DESC LIMIT 200`
  ).bind(userId).all();
  return json({ links: rows.results });
}

// Only the owner can delete a link. Anonymous links (owner_id NULL, which
// includes every link that predates accounts) can never be deleted through
// the API and are never reassigned. Deleting also drops the edge-cached
// redirect so a deleted code stops working within seconds, not at cache TTL.
async function deleteLink(request, env, code) {
  const userId = await verifySessionUser(request, env);
  if (!userId) return json({ error: "Sign in to delete a link." }, 401);
  const link = await env.DB.prepare("SELECT owner_id FROM links WHERE code = ?").bind(code).first();
  if (!link) return json({ error: "No link with that code." }, 404);
  if (!link.owner_id || link.owner_id !== userId) {
    return json({ error: "Only the owner can delete this link." }, 403);
  }
  await env.DB.prepare("DELETE FROM clicks WHERE link_code = ?").bind(code).run();
  await env.DB.prepare("DELETE FROM links WHERE code = ?").bind(code).run();
  try {
    const host = new URL(request.url).host;
    await caches.default.delete(new Request(`https://${host}/${code}`, { method: "GET" }));
  } catch { /* cache delete is best-effort; the TTL also bounds staleness */ }
  return json({ deleted: code });
}

function redirectPage(message, status) {
  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><title>${status}</title>
     <style>body{font-family:system-ui;background:#12121a;color:#e8e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
     main{text-align:center}a{color:#8f85ff}</style></head>
     <body><main><h1>${status}</h1><p>${message}</p><p><a href="/">Make your own short link</a></p></main></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

// The hot path. The destination is cached at the edge for 60s so a viral
// link does not hammer the database; clicks are still logged on every
// request because the worker runs even on a cache hit.
async function redirect(request, env, ctx, code) {
  const cacheKey = new Request(request.url, { method: "GET" });
  const cached = await caches.default.match(cacheKey);
  let longUrl = cached ? cached.headers.get("Location") : null;
  let cacheable = Boolean(cached);

  if (!longUrl) {
    const row = await env.DB.prepare("SELECT long_url, expires_at FROM links WHERE code = ?").bind(code).first();
    if (!row) return redirectPage("No short link with that code.", 404);
    if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
      return redirectPage("This short link has expired.", 410);
    }
    longUrl = row.long_url;
    // Links with an expiry are not edge-cached: a cached 302 could outlive
    // the link's own expiry by up to the cache TTL.
    cacheable = !row.expires_at;
  }

  ctx.waitUntil(
    env.DB.prepare("INSERT INTO clicks (link_code, clicked_at, referrer, country) VALUES (?, ?, ?, ?)")
      .bind(code, new Date().toISOString(), request.headers.get("referer") || "", request.cf?.country || "").run()
  );
  // 302, not 301: the browser asks us again next time, so clicks stay countable.
  const res = new Response(null, {
    status: 302,
    headers: { Location: longUrl, "Cache-Control": "public, max-age=60" },
  });
  if (!cached && cacheable) ctx.waitUntil(caches.default.put(cacheKey, res.clone()));
  return res;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "POST" && path === "/api/links") return createLink(request, env);
    if (request.method === "GET" && path === "/api/links/mine") return listMine(request, env);
    const statsMatch = path.match(/^\/api\/links\/([0-9A-Za-z_-]{1,32})\/stats$/);
    if (request.method === "GET" && statsMatch) return getStats(request, env, statsMatch[1]);
    const deleteMatch = path.match(/^\/api\/links\/([0-9A-Za-z_-]{1,32})$/);
    if (request.method === "DELETE" && deleteMatch) return deleteLink(request, env, deleteMatch[1]);

    if (request.method === "GET" && path.length > 1 && !path.startsWith("/api/")) {
      const code = decodeURIComponent(path.slice(1));
      if (CODE_RE.test(code)) return redirect(request, env, ctx, code);
    }
    return env.ASSETS.fetch(request);
  },
};
