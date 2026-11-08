-- Migration 0003: link ownership (stage 2, owner accounts via Clerk).
-- owner_id is the Clerk user id for links created while signed in.
-- NULL means an anonymous link (including every link that predates
-- accounts): those stay anonymous - there is no backfill and no silent
-- "claiming", so an unknown link is never reassigned to anyone.
ALTER TABLE links ADD COLUMN owner_id TEXT;
CREATE INDEX IF NOT EXISTS idx_links_owner ON links(owner_id);
