-- Migration 0005: optional click-count limit (a link "ends" after N clicks).
ALTER TABLE links ADD COLUMN max_clicks INTEGER;
