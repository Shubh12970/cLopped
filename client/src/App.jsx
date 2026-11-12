import React, { useEffect, useState, useCallback } from "react";
import QRCode from "qrcode";
import { SignedIn, SignedOut, SignInButton, UserButton, useAuth } from "@clerk/clerk-react";

const shortHref = (code) => `${window.location.origin}/${code}`;

// Sends the Clerk session token when signed in, so owned links get
// attributed, owned stats unlock, and delete is authorized. Signed-out
// requests stay anonymous and everything public keeps working.
function useAuthedFetch() {
  const { getToken } = useAuth();
  return useCallback(
    async (path, options = {}) => {
      const token = await getToken().catch(() => null);
      const headers = { ...(options.headers || {}) };
      if (token) headers.authorization = `Bearer ${token}`;
      return fetch(path, { ...options, headers });
    },
    [getToken]
  );
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="btn ghost"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// Stage 2 ownership: signed-in users get a server-side list and delete.
// Signed-out visitors keep the browser-local list: codes they create are
// remembered in localStorage and hydrated from the public per-code stats
// endpoint. There is deliberately no global list endpoint - a public feed
// of everyone's destinations would be an abuse magnet. Anonymous links
// (including everything created before accounts existed) stay anonymous:
// they are never reassigned and cannot be deleted through the API.
const LS_KEY = "snip-links";
const loadCodes = () => {
  try { return JSON.parse(localStorage.getItem(LS_KEY)) || []; } catch { return []; }
};

function ShortenForm({ onCreated }) {
  const authedFetch = useAuthedFetch();
  const [url, setUrl] = useState("");
  const [customCode, setCustomCode] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [maxClicks, setMaxClicks] = useState("");
  const [busy, setBusy] = useState(false);
  const [unguessable, setUnguessable] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setCreated(null);
    try {
      const res = await authedFetch("/api/links", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url,
          custom_code: customCode || undefined,
          expires_at: expiresAt || undefined,
          max_clicks: maxClicks ? Number(maxClicks) : undefined,
          code_style: unguessable && !customCode ? "random" : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Something went wrong.");
      } else {
        setCreated(data);
        setUrl("");
        setCustomCode("");
        onCreated(data.code);
      }
    } catch {
      setError("Network error - is the API up?");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Shorten a link</h2>
      <form onSubmit={submit}>
        <input
          type="url"
          required
          placeholder="Paste a long URL (https://...)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <div className="row">
          <input
            type="text"
            placeholder="Custom code (optional)"
            value={customCode}
            onChange={(e) => setCustomCode(e.target.value)}
            pattern="[0-9A-Za-z_\-]{3,32}"
            title="3-32 characters: letters, numbers, - or _"
          />
          <input
            type="date"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
            title="Optional expiry date - the link stops working at 00:00 UTC on this date"
            min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)}
          />
          <input
            type="number"
            min="1"
            max="1000000"
            step="1"
            placeholder="Max clicks (optional)"
            value={maxClicks}
            onChange={(e) => setMaxClicks(e.target.value)}
            title="Optional click limit - the link ends (stops redirecting) after this many clicks"
            style={{ width: "10rem" }}
          />
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "Shortening..." : "Shorten"}
          </button>
        </div>
      </form>
      <label className="check">
        <input
          type="checkbox"
          checked={unguessable}
          onChange={(e) => setUnguessable(e.target.checked)}
          disabled={Boolean(customCode)}
        />
        Unguessable code - a random 8-character code that cannot be found by
        walking sequential numbers (ignored when a custom code is set)
      </label>
      {error && <p className="error">{error}</p>}
      <p className="muted">Expiry dates are UTC: a link expires at 00:00 UTC on the chosen date. With a click limit, the link ends after exactly that many redirects.</p>
      {created && (
        <div className="created">
          <a href={created.short_url} target="_blank" rel="noreferrer">
            {created.short_url}
          </a>
          <CopyButton text={created.short_url} />
        </div>
      )}
    </section>
  );
}

function QrButton({ code }) {
  const [src, setSrc] = useState(null);
  return (
    <>
      <button
        className="btn ghost"
        onClick={async () => {
          if (src) { setSrc(null); return; }
          setSrc(await QRCode.toDataURL(shortHref(code), { margin: 1, width: 220 }));
        }}
      >
        {src ? "Hide QR" : "QR"}
      </button>
      {src && (
        <div className="qr">
          <img src={src} alt={`QR code for ${shortHref(code)}`} />
        </div>
      )}
    </>
  );
}

// One ranked breakdown list (referrers or countries) with plain-CSS bars.
function Breakdown({ title, rows }) {
  if (!rows || rows.length === 0) return null;
  const max = Math.max(1, ...rows.map((r) => r.clicks));
  return (
    <div className="breakdown">
      <p className="muted">{title}</p>
      {rows.map((r) => (
        <div className="break-row" key={r.label}>
          <span className="break-label" title={r.label}>{r.label}</span>
          <div className="break-track">
            <div className="break-bar" style={{ width: `${(r.clicks / max) * 100}%` }} />
          </div>
          <span className="break-count">{r.clicks}</span>
        </div>
      ))}
    </div>
  );
}

function Stats({ code, onClose }) {
  const authedFetch = useAuthedFetch();
  const [stats, setStats] = useState(null);
  useEffect(() => {
    authedFetch(`/api/links/${encodeURIComponent(code)}/stats`)
      .then((r) => r.json())
      .then(setStats);
  }, [code, authedFetch]);

  // CSV is fetched (not linked) so owned links send the session token too.
  const downloadCsv = async () => {
    const r = await authedFetch(`/api/links/${encodeURIComponent(code)}/clicks.csv`);
    if (!r.ok) return;
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `clicks-${code}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  if (!stats) return <section className="card"><p>Loading stats...</p></section>;
  if (stats.error) return <section className="card"><p className="error">{stats.error}</p></section>;

  const max = Math.max(1, ...stats.by_day.map((d) => d.clicks));
  const days = [...stats.by_day].reverse();
  return (
    <section className="card">
      <div className="row spread">
        <h2>Stats for /{stats.code}</h2>
        <button className="btn ghost" onClick={onClose}>Close</button>
      </div>
      <p className="muted long-url">{stats.long_url}</p>
      {stats.expires_at && (
        <p className="muted">Expires {new Date(stats.expires_at).toUTCString()}</p>
      )}
      {stats.max_clicks != null && (
        <p className="muted">Ends after {stats.max_clicks} clicks{stats.total_clicks >= stats.max_clicks ? " (ended)" : ""}</p>
      )}
      <p><strong>{stats.total_clicks}</strong> total clicks</p>
      {days.length > 0 ? (
        <div className="chart" title="Clicks per day">
          {days.map((d) => (
            <div key={d.day} className="bar-col">
              <div className="bar" style={{ height: `${(d.clicks / max) * 100}%` }} title={`${d.day}: ${d.clicks}`} />
              <span className="bar-label">{d.day.slice(5)}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="muted">No clicks yet - share the link to see the chart grow.</p>
      )}
      {stats.by_hour && stats.total_clicks > 0 && (
        <div className="heat-wrap">
          <p className="muted">Clicks by hour (UTC - India is UTC+5:30, so add 5:30 to read it locally)</p>
          <div className="heat" title="Clicks by hour of day (UTC)">
            {stats.by_hour.map((h) => {
              const maxH = Math.max(1, ...stats.by_hour.map((x) => x.clicks));
              return (
                <div
                  key={h.hour}
                  className="heat-cell"
                  style={{ opacity: h.clicks === 0 ? 0.15 : 0.25 + (0.75 * h.clicks) / maxH }}
                  title={`${String(h.hour).padStart(2, "0")}:00 UTC - ${h.clicks} clicks`}
                >
                  <span>{h.hour}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
      {stats.total_clicks > 0 && (
        <>
          <Breakdown title="Top referrers (where clicks came from)" rows={stats.by_referrer} />
          <Breakdown title="Countries (coarse, from Cloudflare)" rows={stats.by_country} />
          <p>
            <button className="btn ghost" onClick={downloadCsv}>Download clicks as CSV (up to 5000)</button>
          </p>
        </>
      )}
      {stats.recent.length > 0 && (
        <table>
          <thead>
            <tr><th>When</th><th>Referrer</th><th>Country</th></tr>
          </thead>
          <tbody>
            {stats.recent.map((c, i) => (
              <tr key={i}>
                <td>{new Date(c.clicked_at).toLocaleString()}</td>
                <td className="muted">{c.referrer || "direct"}</td>
                <td className="muted">{c.country || "?"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}


function ApiTokens() {
  const authedFetch = useAuthedFetch();
  const [tokens, setTokens] = useState([]);
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState(null);
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    authedFetch("/api/tokens")
      .then((r) => (r.ok ? r.json() : { tokens: [] }))
      .then((d) => setTokens(d.tokens))
      .catch(() => setTokens([]));
  }, [authedFetch]);
  useEffect(() => { load(); }, [load]);

  async function generate(e) {
    e.preventDefault();
    setErr("");
    const res = await authedFetch("/api/tokens", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setErr(data.error || "Could not create a token."); return; }
    setFresh(data.token);
    setName("");
    load();
  }

  async function revoke(id) {
    setErr("");
    const res = await authedFetch(`/api/tokens/${id}`, { method: "DELETE" });
    if (!res.ok) setErr("Could not revoke that token.");
    load();
  }

  return (
    <section className="card">
      <h2>API tokens</h2>
      <p className="muted">
        For scripts: call the API with <code>Authorization: Bearer &lt;token&gt;</code>.
        Links created with a token belong to your account. A token is shown once,
        when it is created - save it somewhere safe.
      </p>
      <form className="row" onSubmit={generate}>
        <input
          type="text"
          placeholder="Token name (e.g. my-script)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={60}
        />
        <button className="btn primary" type="submit">Generate</button>
      </form>
      {err && <p className="error">{err}</p>}
      {fresh && (
        <div className="created">
          <p><strong>New token (shown once):</strong></p>
          <div className="row">
            <code className="code">{fresh}</code>
            <CopyButton text={fresh} />
          </div>
        </div>
      )}
      {tokens.length > 0 && tokens.map((t) => (
        <div className="link-row" key={t.id}>
          <div>
            <span>{t.name}</span>
            <span className="muted">
              {" "}made {new Date(t.created_at).toUTCString()}
              {t.last_used_at ? ` - last used ${new Date(t.last_used_at).toUTCString()}` : " - never used"}
            </span>
          </div>
          <div className="row">
            <button className="btn ghost" onClick={() => revoke(t.id)}>Revoke</button>
          </div>
        </div>
      ))}
    </section>
  );
}

export default function App() {
  const authedFetch = useAuthedFetch();
  const { isSignedIn } = useAuth();
  const [links, setLinks] = useState([]);
  const [theme, setTheme] = useState(() => localStorage.getItem("snip-theme") || "dark");
  const [statsFor, setStatsFor] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("snip-theme", theme);
  }, [theme]);

  const refresh = useCallback(
    (newCode) => {
      if (isSignedIn) {
        authedFetch("/api/links/mine")
          .then((r) => (r.ok ? r.json() : { links: [] }))
          .then((data) =>
            setLinks(data.links.map((l) => ({ ...l, clicks: l.total_clicks })))
          )
          .catch(() => setLinks([]));
        return;
      }
      const codes = loadCodes();
      if (newCode && !codes.includes(newCode)) {
        codes.unshift(newCode);
        localStorage.setItem(LS_KEY, JSON.stringify(codes));
      }
      Promise.all(
        codes.map((c) =>
          fetch(`/api/links/${encodeURIComponent(c)}/stats`)
            .then((r) => (r.ok ? r.json() : null))
            .catch(() => null)
        )
      ).then((rows) =>
        setLinks(rows.filter(Boolean).map((s) => ({ ...s, clicks: s.total_clicks })))
      );
    },
    [authedFetch, isSignedIn]
  );
  useEffect(() => { refresh(); }, [refresh]);

  async function remove(code) {
    setError("");
    const res = await authedFetch(`/api/links/${encodeURIComponent(code)}`, { method: "DELETE" });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.error || "Could not delete that link.");
      return;
    }
    refresh();
  }

  return (
    <main>
      <header className="row spread">
        <h1>cLopped <span className="muted">tiny links</span></h1>
        <div className="row">
          <button className="btn ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
          <SignedOut>
            <SignInButton mode="modal">
              <button className="btn primary">Sign in</button>
            </SignInButton>
          </SignedOut>
          <SignedIn>
            <UserButton afterSignOutUrl="/" />
          </SignedIn>
        </div>
      </header>

      <ShortenForm onCreated={refresh} />

      {statsFor && <Stats code={statsFor} onClose={() => setStatsFor(null)} />}

      <section className="card">
        <h2>Your links</h2>
        <SignedOut>
          <p className="muted">
            Saved in this browser only. Sign in to keep links on your account,
            get private stats, and delete them.
          </p>
        </SignedOut>
        {error && <p className="error">{error}</p>}
        {links.length === 0 && <p className="muted">No links yet. Shorten your first one above.</p>}
        {links.map((l) => (
          <div className="link-row" key={l.code}>
            <div>
              <a href={shortHref(l.code)} target="_blank" rel="noreferrer" className="code">
                /{l.code}
              </a>
              <span className="muted long-url">{l.long_url}</span>
              {l.expires_at && (
                <span className="muted"> - expires {new Date(l.expires_at).toUTCString()}</span>
              )}
              {l.max_clicks != null && (
                <span className="muted"> - ends after {l.max_clicks} clicks</span>
              )}
            </div>
            <div className="row">
              <span className="badge">{l.clicks} clicks</span>
              <button className="btn ghost" onClick={() => setStatsFor(l.code)}>Stats</button>
              <QrButton code={l.code} />
              <CopyButton text={shortHref(l.code)} />
              <SignedIn>
                <button className="btn ghost" onClick={() => remove(l.code)}>Delete</button>
              </SignedIn>
            </div>
          </div>
        ))}
      </section>

      <SignedIn>
        <ApiTokens />
      </SignedIn>

      <footer className="muted">
        302 redirects keep clicks countable - counts are approximate (bots and prefetching click too).
        Redirects are public; stats for signed-in links are private to the owner.
      </footer>
    </main>
  );
}
