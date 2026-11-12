-- URL shortener schema (Cloudflare D1 / SQLite)
--
-- links: one row per short link.
--   id         - database-generated sequential id; the short code is base62(id).
--   code       - the short code, unique. Auto codes are base62 of the row id;
--                custom codes are checked for conflicts before insert.
--   long_url   - the original URL (validated http/https, no private addresses).
--   created_at - ISO timestamp (UTC).
--   expires_at - optional ISO timestamp; expired links answer 410 Gone.
--
-- clicks: one row per redirect, so analytics can count per day and keep
--         recent click details (referrer, coarse country from Cloudflare).
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  long_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT
  -- Later migrations add: owner_id TEXT (0003), max_clicks INTEGER (0005),
  -- plus the create_events table (0004, see below). Fresh setups should run
  -- the migrations after this file.
);

CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_code TEXT NOT NULL,
  clicked_at TEXT NOT NULL,
  referrer TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_clicks_link ON clicks(link_code, clicked_at);

-- Abuse control: fixed 1-hour window per client IP for link creation.
-- (A fixed window can burst 2x at a boundary; a sliding window or token
-- bucket is the interview upgrade.)
-- Superseded by create_events (migration 0004); kept so fresh setups match
-- the migrated live database shape.
CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, window_start)
);

-- Start auto ids at 3844 so the first generated code is "100" (three chars).
-- Codes stay >= 3 chars and grow as rows are added; custom codes are checked
-- against existing rows.
INSERT OR IGNORE INTO sqlite_sequence (name, seq) VALUES ('links', 3843);

-- Rolling 60-minute create-rate log (migration 0004). Rows older than a day
-- are pruned by the worker on each create.
CREATE TABLE IF NOT EXISTS create_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_create_events_ip_time ON create_events (ip, created_at);
