-- Migration 0002: optional link expiry.
ALTER TABLE links ADD COLUMN expires_at TEXT;
