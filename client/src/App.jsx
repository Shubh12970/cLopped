import React, { useEffect, useState, useCallback } from "react";
import QRCode from "qrcode";

const shortHref = (code) => `${window.location.origin}/${code}`;

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

// Stage-1 demo has no accounts yet, so "Your links" is browser-local:
// codes you create are remembered in localStorage and hydrated from the
// per-code stats endpoint. There is deliberately no global list endpoint -
// a public feed of everyone's destinations would be an abuse magnet.
// (Real ownership + delete arrives with accounts in stage 2.)
const LS_KEY = "snip-links";
const loadCodes = () => {
  try { return JSON.parse(localStorage.getItem(LS_KEY)) || []; } catch { return []; }
};

function ShortenForm({ onCreated }) {
  const [url, setUrl] = useState("");
  const [customCode, setCustomCode] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setCreated(null);
    try {
      const res = await fetch("/api/links", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url,
          custom_code: customCode || undefined,
          expires_at: expiresAt || undefined,
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
            title="Optional expiry date"
            min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)}
          />
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "Shortening..." : "Shorten"}
          </button>
        </div>
      </form>
      {error && <p className="error">{error}</p>}
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
  const [stats, setStats] = useState(null);
  useEffect(() => {
    fetch(`/api/links/${encodeURIComponent(code)}/stats`)
      .then((r) => r.json())
      .then(setStats);
  }, [code]);

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
        <p className="muted">Expires {new Date(stats.expires_at).toLocaleString()}</p>
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
  const [links, setLinks] = useState([]);
  const [theme, setTheme] = useState(() => localStorage.getItem("snip-theme") || "dark");
  const [statsFor, setStatsFor] = useState(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("snip-theme", theme);
  }, [theme]);

  const refresh = useCallback((newCode) => {
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
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  return (
    <main>
      <header className="row spread">
        <h1>snip <span className="muted">tiny links</span></h1>
        <button className="btn ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "Light mode" : "Dark mode"}
        </button>
      </header>

      <ShortenForm onCreated={refresh} />

      {statsFor && <Stats code={statsFor} onClose={() => setStatsFor(null)} />}

      <section className="card">
        <h2>Your links</h2>
        {links.length === 0 && <p className="muted">No links yet. Shorten your first one above.</p>}
        {links.map((l) => (
          <div className="link-row" key={l.code}>
            <div>
              <a href={shortHref(l.code)} target="_blank" rel="noreferrer" className="code">
                /{l.code}
              </a>
              <span className="muted long-url">{l.long_url}</span>
            </div>
            <div className="row">
              <span className="badge">{l.clicks} clicks</span>
              <button className="btn ghost" onClick={() => setStatsFor(l.code)}>Stats</button>
              <QrButton code={l.code} />
              <CopyButton text={shortHref(l.code)} />
            </div>
          </div>
        ))}
      </section>

      <footer className="muted">
        302 redirects keep clicks countable - counts are approximate (bots and prefetching click too).
      </footer>
    </main>
  );
}
