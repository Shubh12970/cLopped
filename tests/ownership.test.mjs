// Ownership (stage 2) tests: real RS256 JWTs against a stubbed JWKS
// endpoint, plus an in-memory D1 stub. Covers server-side ownership
// enforcement: private stats for owned links, owner-only delete, cache
// invalidation on delete, and anonymous/legacy links never reassigned.
import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import worker from "../worker/index.js";

const ISSUER = "https://test-issuer.clerk.accounts.dev";
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;

function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let privateKey, publicJwk;

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]
  );
  privateKey = pair.privateKey;
  publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  publicJwk.kid = "test-key-1";
});

async function makeToken(sub, { iss = ISSUER, kid = "test-key-1", key = privateKey, exp } = {}) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT", kid })));
  const payload = b64url(new TextEncoder().encode(JSON.stringify({
    sub, iss, exp: exp ?? Math.floor(Date.now() / 1000) + 600,
  })));
  const data = new TextEncoder().encode(`${header}.${payload}`);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  return `${header}.${payload}.${b64url(sig)}`;
}

// Minimal in-memory D1 stand-in covering only the queries the worker runs.
function fakeDb() {
  const links = [];
  const clicks = [];
  const rate = new Map();
  let nextId = 1;
  const route = (sql, args) => {
    sql = sql.replace(/\s+/g, " ").trim();
    let m;
    if ((m = sql.match(/^SELECT count FROM rate_limits WHERE ip = \? AND window_start = \?$/))) {
      const n = rate.get(`${args[0]}|${args[1]}`) || 0;
      return { first: n ? { count: n } : null };
    }
    if (sql.startsWith("INSERT INTO rate_limits")) {
      const k = `${args[0]}|${args[1]}`;
      rate.set(k, (rate.get(k) || 0) + 1);
      return { run: true };
    }
    if (sql.startsWith("INSERT INTO links")) {
      const [code, long_url, created_at, expires_at, owner_id] = args;
      if (links.some((l) => l.code === code)) throw new Error("UNIQUE constraint failed");
      links.push({ id: nextId++, code, long_url, created_at, expires_at: expires_at ?? null, owner_id: owner_id ?? null });
      return { run: true };
    }
    if (sql.startsWith("SELECT 1 FROM links WHERE code")) {
      const l = links.find((x) => x.code === args[0]);
      return { first: l ? { "1": 1 } : null };
    }
    if ((m = sql.match(/^SELECT id FROM links WHERE code = \?$/))) {
      const l = links.find((x) => x.code === args[0]);
      return { first: l ? { id: l.id } : null };
    }
    if (sql.startsWith("UPDATE links SET code")) {
      const l = links.find((x) => x.id === args[1]);
      if (links.some((x) => x.code === args[0] && x.id !== args[1])) throw new Error("UNIQUE constraint failed");
      l.code = args[0];
      return { run: true };
    }
    if (sql.startsWith("DELETE FROM links WHERE id")) {
      const i = links.findIndex((x) => x.id === args[0]);
      if (i >= 0) links.splice(i, 1);
      return { run: true };
    }
    if (sql.startsWith("DELETE FROM links WHERE code")) {
      const i = links.findIndex((x) => x.code === args[0]);
      if (i >= 0) links.splice(i, 1);
      return { run: true };
    }
    if (sql.startsWith("DELETE FROM clicks WHERE link_code")) {
      for (let i = clicks.length - 1; i >= 0; i--) if (clicks[i].link_code === args[0]) clicks.splice(i, 1);
      return { run: true };
    }
    if (sql.startsWith("SELECT code, long_url, created_at, expires_at, owner_id FROM links WHERE code")) {
      const l = links.find((x) => x.code === args[0]);
      return { first: l ? { code: l.code, long_url: l.long_url, created_at: l.created_at, expires_at: l.expires_at, owner_id: l.owner_id } : null };
    }
    if (sql.startsWith("SELECT owner_id FROM links WHERE code")) {
      const l = links.find((x) => x.code === args[0]);
      return { first: l ? { owner_id: l.owner_id } : null };
    }
    if (sql.startsWith("SELECT long_url, expires_at FROM links WHERE code")) {
      const l = links.find((x) => x.code === args[0]);
      return { first: l ? { long_url: l.long_url, expires_at: l.expires_at } : null };
    }
    if (sql.startsWith("SELECT COUNT(*) AS n FROM clicks")) {
      return { first: { n: clicks.filter((c) => c.link_code === args[0]).length } };
    }
    if (sql.startsWith("SELECT substr(clicked_at, 12, 2)")) {
      const byHour = {};
      for (const c of clicks.filter((x) => x.link_code === args[0])) {
        const h = c.clicked_at.slice(11, 13);
        byHour[h] = (byHour[h] || 0) + 1;
      }
      return { all: { results: Object.entries(byHour).map(([hour, n]) => ({ hour, clicks: n })) } };
    }
    if (sql.startsWith("SELECT substr(clicked_at")) {
      const byDay = {};
      for (const c of clicks.filter((x) => x.link_code === args[0])) {
        const d = c.clicked_at.slice(0, 10);
        byDay[d] = (byDay[d] || 0) + 1;
      }
      return { all: { results: Object.entries(byDay).map(([day, n]) => ({ day, clicks: n })) } };
    }
    if (sql.startsWith("SELECT referrer, COUNT(*) AS clicks FROM clicks")) {
      const m = {};
      for (const c of clicks.filter((x) => x.link_code === args[0])) m[c.referrer] = (m[c.referrer] || 0) + 1;
      return { all: { results: Object.entries(m).map(([referrer, n]) => ({ referrer, clicks: n })) } };
    }
    if (sql.startsWith("SELECT country, COUNT(*) AS clicks FROM clicks")) {
      const m = {};
      for (const c of clicks.filter((x) => x.link_code === args[0])) m[c.country] = (m[c.country] || 0) + 1;
      return { all: { results: Object.entries(m).map(([country, n]) => ({ country, clicks: n })) } };
    }
    if (sql.startsWith("SELECT clicked_at, referrer, country")) {
      return { all: { results: clicks.filter((c) => c.link_code === args[0]).slice(-20).reverse() } };
    }
    if (sql.startsWith("SELECT code, long_url, created_at, expires_at,")) {
      return { all: { results: links.filter((l) => l.owner_id === args[0])
        .map((l) => ({ code: l.code, long_url: l.long_url, created_at: l.created_at, expires_at: l.expires_at,
          total_clicks: clicks.filter((c) => c.link_code === l.code).length }))
        .reverse() } };
    }
    if (sql.startsWith("INSERT INTO clicks")) {
      clicks.push({ id: clicks.length + 1, link_code: args[0], clicked_at: args[1], referrer: args[2], country: args[3] });
      return { run: true };
    }
    throw new Error("unhandled SQL: " + sql);
  };
  return {
    prepare(sql) {
      return {
        bind(...args) {
          const r = () => route(sql, args);
          return {
            first: async () => r().first ?? null,
            all: async () => r().all ?? { results: [] },
            run: async () => r().run,
          };
        },
      };
    },
    _links: links,
  };
}

let cacheDeletes;
beforeEach(() => {
  cacheDeletes = [];
  globalThis.caches = { default: {
    match: async () => undefined,
    put: async () => {},
    delete: async (req) => { cacheDeletes.push(req.url); return true; },
  } };
  const jwks = JSON.stringify({ keys: [publicJwk] });
  globalThis.fetch = vi.fn(async (url) =>
    url === JWKS_URL ? new Response(jwks, { status: 200 }) : new Response("nf", { status: 404 }));
});

const env = () => ({ DB: fakeDb(), CLERK_JWKS_URL: JWKS_URL, CLERK_ISSUER: ISSUER });
const ctx = { waitUntil: (p) => p };
const authed = (token) => ({ headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } });

async function createLink(env, token, body) {
  const res = await worker.fetch(new Request("https://short.dev/api/links", {
    method: "POST", ...(token ? authed(token) : { headers: { "content-type": "application/json" } }),
    body: JSON.stringify(body),
  }), env, ctx);
  return { status: res.status, data: await res.json() };
}

describe("ownership", () => {
  it("links created while signed in belong to the owner", async () => {
    const e = env();
    const token = await makeToken("user_a");
    const r = await createLink(e, token, { url: "https://example.com" });
    expect(r.status).toBe(201);
    expect(r.data.owned).toBe(true);
    expect(e.DB._links[0].owner_id).toBe("user_a");
  });

  it("anonymous creation still works and stays anonymous", async () => {
    const e = env();
    const r = await createLink(e, null, { url: "https://example.com" });
    expect(r.status).toBe(201);
    expect(r.data.owned).toBe(false);
    expect(e.DB._links[0].owner_id).toBeNull();
  });

  it("stats for an owned link are private: owner sees them, others and anonymous get 403", async () => {
    const e = env();
    const owner = await makeToken("user_a");
    const stranger = await makeToken("user_b");
    const r = await createLink(e, owner, { url: "https://example.com", custom_code: "mine-1" });
    const stats = (t) => worker.fetch(new Request(`https://short.dev/api/links/${r.data.code}/stats`,
      t ? authed(t) : {}), e, ctx);
    expect((await stats(owner)).status).toBe(200);
    expect((await stats(stranger)).status).toBe(403);
    expect((await stats(null)).status).toBe(403);
  });

  it("stats for an anonymous link stay public", async () => {
    const e = env();
    const r = await createLink(e, null, { url: "https://example.com" });
    const res = await worker.fetch(new Request(`https://short.dev/api/links/${r.data.code}/stats`), e, ctx);
    expect(res.status).toBe(200);
  });

  it("delete is owner-only, removes the link, and invalidates the cached redirect", async () => {
    const e = env();
    const owner = await makeToken("user_a");
    const stranger = await makeToken("user_b");
    const r = await createLink(e, owner, { url: "https://example.com", custom_code: "del-me" });
    const del = (t) => worker.fetch(new Request(`https://short.dev/api/links/${r.data.code}`,
      { method: "DELETE", ...(t ? authed(t) : {}) }), e, ctx);
    expect((await del(stranger)).status).toBe(403);
    expect((await del(null)).status).toBe(401);
    expect((await del(owner)).status).toBe(200);
    expect(cacheDeletes).toEqual(["https://short.dev/del-me"]);
    const redir = await worker.fetch(new Request("https://short.dev/del-me"), e, ctx);
    expect(redir.status).toBe(404);
  });

  it("anonymous (legacy) links can never be deleted, even by a signed-in user", async () => {
    const e = env();
    await createLink(e, null, { url: "https://example.com", custom_code: "legacy-1" });
    const someone = await makeToken("user_a");
    const res = await worker.fetch(new Request("https://short.dev/api/links/legacy-1",
      { method: "DELETE", ...authed(someone) }), e, ctx);
    expect(res.status).toBe(403);
    expect(e.DB._links).toHaveLength(1); // not reassigned, not deleted
  });

  it("/api/links/mine lists only the caller's links", async () => {
    const e = env();
    const a = await makeToken("user_a");
    const b = await makeToken("user_b");
    await createLink(e, a, { url: "https://a.example", custom_code: "a-link" });
    await createLink(e, b, { url: "https://b.example", custom_code: "b-link" });
    await createLink(e, null, { url: "https://anon.example", custom_code: "anon-link" });
    const res = await worker.fetch(new Request("https://short.dev/api/links/mine", authed(a)), e, ctx);
    const data = await res.json();
    expect(data.links.map((l) => l.code)).toEqual(["a-link"]);
    const anon = await worker.fetch(new Request("https://short.dev/api/links/mine"), e, ctx);
    expect(anon.status).toBe(401);
  });

  it("a tampered or wrong-issuer token is treated as anonymous", async () => {
    const e = env();
    const badIss = await makeToken("user_a", { iss: "https://evil.example" });
    const r1 = await createLink(e, badIss, { url: "https://example.com" });
    expect(r1.data.owned).toBe(false);
    const otherKey = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"])).privateKey;
    const forged = await makeToken("user_a", { key: otherKey });
    const r2 = await createLink(e, forged, { url: "https://example.com" });
    expect(r2.data.owned).toBe(false);
    const expired = await makeToken("user_a", { exp: Math.floor(Date.now() / 1000) - 10 });
    const r3 = await createLink(e, expired, { url: "https://example.com" });
    expect(r3.data.owned).toBe(false);
  });
});

describe("analytics breakdowns and CSV export (milestone: option 1)", () => {
  it("stats include host-level referrer and country breakdowns", async () => {
    const e = env();
    const r = await createLink(e, null, { url: "https://example.com" });
    const code = r.data.code;
    const click = (ref) => worker.fetch(new Request(`https://short.dev/${code}`,
      { headers: ref ? { referer: ref } : {} }), e, ctx);
    await click("https://x.com/post/1");
    await click("https://x.com/post/2");
    await click("https://instagram.com/p/abc");
    await click(null); // direct
    const res = await worker.fetch(new Request(`https://short.dev/api/links/${code}/stats`), e, ctx);
    const s = await res.json();
    expect(res.status).toBe(200);
    expect(s.by_referrer).toEqual([
      { label: "x.com", clicks: 2 },
      { label: "direct", clicks: 1 },
      { label: "instagram.com", clicks: 1 },
    ]);
    expect(s.by_country).toEqual([{ label: "unknown", clicks: 4 }]); // no cf country in tests
  });

  it("CSV download serves raw clicks for an anonymous link", async () => {
    const e = env();
    const r = await createLink(e, null, { url: "https://example.com" });
    const code = r.data.code;
    await worker.fetch(new Request(`https://short.dev/${code}`,
      { headers: { referer: "https://x.com/a" } }), e, ctx);
    const res = await worker.fetch(new Request(`https://short.dev/api/links/${code}/clicks.csv`), e, ctx);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/csv/);
    const body = await res.text();
    expect(body.split("\n")[0]).toBe("clicked_at,referrer,country");
    expect(body).toContain("https://x.com/a");
  });

  it("CSV for an owned link is private to the owner", async () => {
    const e = env();
    const owner = await makeToken("user_a");
    const r = await createLink(e, owner, { url: "https://example.com" });
    const csv = (t) => worker.fetch(new Request(`https://short.dev/api/links/${r.data.code}/clicks.csv`,
      t ? authed(t) : {}), e, ctx);
    expect((await csv(null)).status).toBe(403);
    expect((await csv(await makeToken("user_b"))).status).toBe(403);
    expect((await csv(owner)).status).toBe(200);
  });
});
