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
      <p className="muted">Expiry dates are UTC: a link expires at 00:00 UTC on the chosen date.</p>
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

function Stats({ code, onClose }) {
  const authedFetch = useAuthedFetch();
  const [stats, setStats] = useState(null);
  useEffect(() => {
    authedFetch(`/api/links/${encodeURIComponent(code)}/stats`)
      .then((r) => r.json())
      .then(setStats);
  }, [code, authedFetch]);

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
        <h1>snip <span className="muted">tiny links</span></h1>
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

      <footer className="muted">
        302 redirects keep clicks countable - counts are approximate (bots and prefetching click too).
        Redirects are public; stats for signed-in links are private to the owner.
      </footer>
    </main>
  );
}
