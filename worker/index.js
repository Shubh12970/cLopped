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

// Unguessable codes: 8 random base62 characters drawn from crypto
// randomness, for links the owner does not want discoverable by walking
// sequential codes. 62^8 is about 218 trillion codes, so collisions are
// astronomically rare - but possible in principle, so the insert still
// retries on the UNIQUE constraint. Bytes >= 248 are discarded (248 is the
// largest multiple of 62 that fits in a byte), so every character is
// equally likely - naive `byte % 62` would slightly favour early digits.
const RANDOM_CODE_LENGTH = 8;
export function randomCode(length = RANDOM_CODE_LENGTH) {
  let s = "";
  while (s.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const b of bytes) {
      if (b >= 248) continue;
      s += BASE62[b % 62];
      if (s.length === length) break;
    }
  }
  return s;
}

// Referrers are stored as full URLs; the stats breakdown groups them by
// host so "https://x.com/post/1" and "https://x.com/post/2" count as one
// source, x.com. Empty means the visitor came directly.
export function refererHost(referrer) {
  if (!referrer) return "direct";
  try { return new URL(referrer).hostname; } catch { return "other"; }
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

// Sliding-window per-IP rate limit on creation (30 per trailing 60 min):
// shorteners get abused to hide malicious links, and an open create endpoint
// needs a brake. This is an exact rolling log: every create attempt writes a
// row to create_events, and the check counts that IP's rows in the trailing
// 60 minutes. Unlike a fixed clock-hour window it cannot burst 2x at an
// hour boundary - the window always looks back 60 real minutes.
// Two honest trade-offs: a rejected attempt still counts toward the window
// (standard limiter behavior; it keeps an abuser limited), and two creates
// that land in the same instant can both be rejected at the limit's edge
// (rare, and failing safe). A cheaper alternative is the weighted two-window
// estimate the sibling rate-limiter project teaches; we chose exactness.
const CREATE_LIMIT_PER_HOUR = 30;
const WINDOW_MS = 60 * 60 * 1000;

async function checkRateLimit(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const now = new Date();
  await env.DB.prepare("INSERT INTO create_events (ip, created_at) VALUES (?, ?)")
    .bind(ip, now.toISOString()).run();
  const since = new Date(now.getTime() - WINDOW_MS).toISOString();
  // ISO-8601 UTC strings sort lexicographically, so >= works on text.
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM create_events WHERE ip = ? AND created_at >= ?"
  ).bind(ip, since).first();
  // Keep the log bounded: rows older than a day can never matter again.
  const dayAgo = new Date(now.getTime() - 24 * WINDOW_MS).toISOString();
  await env.DB.prepare("DELETE FROM create_events WHERE created_at < ?").bind(dayAgo).run();
  return (row?.n || 0) <= CREATE_LIMIT_PER_HOUR;
}

async function createLink(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Expected a JSON body like { \"url\": \"https://...\" }." }, 400);
  }
  if (!(await checkRateLimit(request, env))) {
    return json({ error: "Rate limit: at most 30 links per rolling 60 minutes from your network. Try again soon." }, 429);
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

  // Unguessable code (opt-in): random string, retry on the rare collision.
  if (body.code_style === "random") {
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = randomCode();
      try {
        await env.DB.prepare(insert)
          .bind(code, check.url, new Date().toISOString(), expiry.expires_at, ownerId).run();
        return json({ code, long_url: check.url, short_url: `https://${ownHost}/${code}`, expires_at: expiry.expires_at, owned: Boolean(ownerId) }, 201);
      } catch { /* UNIQUE collision: draw again */ }
    }
    return json({ error: "Could not allocate a code, please try again." }, 500);
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
  const byHour = await env.DB.prepare(
    `SELECT substr(clicked_at, 12, 2) AS hour, COUNT(*) AS clicks
     FROM clicks WHERE link_code = ? GROUP BY hour`
  ).bind(code).all();
  const by_hour = Array.from({ length: 24 }, (_, h) => ({ hour: h, clicks: 0 }));
  for (const r of byHour.results) by_hour[parseInt(r.hour, 10)].clicks = r.clicks;
  const recent = await env.DB.prepare(
    `SELECT clicked_at, referrer, country FROM clicks
     WHERE link_code = ? ORDER BY id DESC LIMIT 20`
  ).bind(code).all();
  const refRaw = await env.DB.prepare(
    `SELECT referrer, COUNT(*) AS clicks FROM clicks WHERE link_code = ? GROUP BY referrer ORDER BY clicks DESC LIMIT 100`
  ).bind(code).all();
  const refMap = new Map();
  for (const r of refRaw.results) {
    const label = refererHost(r.referrer);
    refMap.set(label, (refMap.get(label) || 0) + r.clicks);
  }
  const by_referrer = [...refMap.entries()].map(([label, clicks]) => ({ label, clicks }))
    .sort((a, b) => b.clicks - a.clicks || a.label.localeCompare(b.label)).slice(0, 10);
  const countryRaw = await env.DB.prepare(
    `SELECT country, COUNT(*) AS clicks FROM clicks WHERE link_code = ? GROUP BY country ORDER BY clicks DESC LIMIT 30`
  ).bind(code).all();
  const by_country = countryRaw.results.map((r) => ({ label: r.country || "unknown", clicks: r.clicks }));
  const { owner_id, ...rest } = link;
  return json({ ...rest, owned: Boolean(owner_id), total_clicks: total.n, by_day: byDay.results, by_hour, by_referrer, by_country, recent: recent.results });
}

// Raw clicks as a CSV download. Same privacy rule as stats: public for
// anonymous links, owner-only for owned links. Capped at 5000 rows.
async function getClicksCsv(request, env, code) {
  const link = await env.DB.prepare("SELECT owner_id FROM links WHERE code = ?").bind(code).first();
  if (!link) return json({ error: "No short link with that code." }, 404);
  if (link.owner_id) {
    const userId = await verifySessionUser(request, env);
    if (userId !== link.owner_id) return json({ error: "Stats for this link are private to its owner." }, 403);
  }
  const rows = await env.DB.prepare(
    "SELECT clicked_at, referrer, country FROM clicks WHERE link_code = ? ORDER BY id DESC LIMIT 5000"
  ).bind(code).all();
  const esc = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;
  const csv = ["clicked_at,referrer,country",
    ...rows.results.map((r) => `${esc(r.clicked_at)},${esc(r.referrer)},${esc(r.country)}`)].join("\n") + "\n";
  return new Response(csv, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="clicks-${code}.csv"`,
    },
  });
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
    const csvMatch = path.match(/^\/api\/links\/([0-9A-Za-z_-]{1,32})\/clicks\.csv$/);
    if (request.method === "GET" && csvMatch) return getClicksCsv(request, env, csvMatch[1]);
    const deleteMatch = path.match(/^\/api\/links\/([0-9A-Za-z_-]{1,32})$/);
    if (request.method === "DELETE" && deleteMatch) return deleteLink(request, env, deleteMatch[1]);

    if (request.method === "GET" && path.length > 1 && !path.startsWith("/api/")) {
      const code = decodeURIComponent(path.slice(1));
      if (CODE_RE.test(code)) return redirect(request, env, ctx, code);
    }
    return env.ASSETS.fetch(request);
  },
};
