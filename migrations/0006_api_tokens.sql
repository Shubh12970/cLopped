-- Migration 0006: personal API tokens (stage 2, signed-in users only).
-- Only the SHA-256 hash is stored, so a database leak does not leak tokens.
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT NOT NULL,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens(owner_id);
