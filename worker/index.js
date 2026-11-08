// URL shortener API + redirect worker.
//
// Routes:
//   POST /api/links                 { url, custom_code? } -> 201 { code, short_url, long_url }
//   GET  /api/links/:code/stats     -> { code, long_url, created_at, total_clicks, by_day, recent }
//   GET  /:code                     -> 302 Location: long_url (the hot path: lookup, log click, redirect)
//
// Everything else falls through to the static frontend (env.ASSETS).

const BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CODE_RE = /^[0-9A-Za-z_-]{1,32}$/;

// Sequential database id -> short base62 string. Collision-free by
// construction (unlike random strings, which need a uniqueness check).
// Interview tradeoff, documented: sequential codes are enumerable.
function toBase62(n) {
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

// Shorteners get abused to hide malicious links, so validate before storing:
// http/https only, never point at ourselves (redirect loop), never at
// private/local network addresses.
function validateLongUrl(raw, ownHost) {
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

// Fixed-window per-IP rate limit on creation (30/hour): shorteners get
// abused to hide malicious links, and an open create endpoint needs a brake.
// True per-user limits arrive with accounts in stage 2.
const CREATE_LIMIT_PER_HOUR = 30;
async function checkRateLimit(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const windowStart = new Date(Math.floor(Date.now() / 3600000) * 3600000).toISOString();
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
  const ownHost = new URL(request.url).hostname;
  const check = validateLongUrl(String(body.url || "").trim(), ownHost);
  if (check.error) return json({ error: check.error }, 400);

  const custom = typeof body.custom_code === "string" ? body.custom_code.trim() : "";
  if (custom) {
    if (!/^[0-9A-Za-z_-]{3,32}$/.test(custom)) {
      return json({ error: "Custom codes must be 3-32 characters: letters, numbers, - or _." }, 400);
    }
    const clash = await env.DB.prepare("SELECT 1 FROM links WHERE code = ?").bind(custom).first();
    if (clash) return json({ error: `The code "${custom}" is already taken.` }, 409);
    await env.DB.prepare("INSERT INTO links (code, long_url, created_at) VALUES (?, ?, ?)")
      .bind(custom, check.url, new Date().toISOString()).run();
    return json({ code: custom, long_url: check.url, short_url: `https://${ownHost}/${custom}` }, 201);
  }

  // Auto code: insert with a unique placeholder, then set code = base62(id).
  // If that string is already taken by a custom code, retry; the next id
  // gives a different code.
  for (let attempt = 0; attempt < 3; attempt++) {
    const placeholder = "~" + crypto.randomUUID();
    await env.DB.prepare("INSERT INTO links (code, long_url, created_at) VALUES (?, ?, ?)")
      .bind(placeholder, check.url, new Date().toISOString()).run();
    const row = await env.DB.prepare("SELECT id FROM links WHERE code = ?").bind(placeholder).first();
    const code = toBase62(row.id);
    try {
      await env.DB.prepare("UPDATE links SET code = ? WHERE id = ?").bind(code, row.id).run();
      return json({ code, long_url: check.url, short_url: `https://${ownHost}/${code}` }, 201);
    } catch {
      await env.DB.prepare("DELETE FROM links WHERE id = ?").bind(row.id).run();
    }
  }
  return json({ error: "Could not allocate a code, please try again." }, 500);
}

async function getStats(env, code) {
  const link = await env.DB.prepare("SELECT code, long_url, created_at FROM links WHERE code = ?").bind(code).first();
  if (!link) return json({ error: "No link with that code." }, 404);
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
  return json({ ...link, total_clicks: total.n, by_day: byDay.results, recent: recent.results });
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

function redirect(request, env, ctx, code) {
  return env.DB.prepare("SELECT long_url FROM links WHERE code = ?").bind(code).first().then((row) => {
    if (!row) return redirectPage("No short link with that code.", 404);
    // Log the click without delaying the redirect (fire and forget).
    ctx.waitUntil(
      env.DB.prepare("INSERT INTO clicks (link_code, clicked_at, referrer, country) VALUES (?, ?, ?, ?)")
        .bind(code, new Date().toISOString(), request.headers.get("referer") || "", (request.cf && request.cf.country) || "")
        .run()
    );
    // 302, not 301: the browser asks us again next time, so clicks stay countable.
    return Response.redirect(row.long_url, 302);
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "POST" && path === "/api/links") return createLink(request, env);
    const statsMatch = path.match(/^\/api\/links\/([0-9A-Za-z_-]{1,32})\/stats$/);
    if (request.method === "GET" && statsMatch) return getStats(env, statsMatch[1]);

    if (request.method === "GET" && path.length > 1 && !path.startsWith("/api/")) {
      const code = decodeURIComponent(path.slice(1));
      if (CODE_RE.test(code)) return redirect(request, env, ctx, code);
    }
    return env.ASSETS.fetch(request);
  },
};
