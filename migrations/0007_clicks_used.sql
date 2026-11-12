-- Migration 0007: atomic gate counter for the click limit.
-- clicks_used is incremented in the SAME single statement that checks the
-- limit, so two simultaneous redirects cannot both slip past max_clicks
-- (the previous read-count-then-decide could overshoot under a burst).
-- The clicks table stays the analytics source; the counter is only the gate.
ALTER TABLE links ADD COLUMN clicks_used INTEGER NOT NULL DEFAULT 0;
UPDATE links SET clicks_used = (SELECT COUNT(*) FROM clicks WHERE link_code = links.code) WHERE max_clicks IS NOT NULL;
