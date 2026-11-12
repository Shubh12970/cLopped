-- Migration 0004: sliding-window create rate limit (exact rolling log).
-- Replaces the fixed-window rate_limits counter (table left in place, no
-- longer written): each create attempt is logged and the trailing
-- 60 minutes are counted.
CREATE TABLE IF NOT EXISTS create_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_create_events_ip_time ON create_events (ip, created_at);
