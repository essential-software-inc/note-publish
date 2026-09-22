-- Adds unique-viewer tracking for the Publish as Ad tab. Reporting only:
-- this table is never read by anything that gates spend or the existing
-- views_used/views_total counters on `ads` (see handleAdView in the
-- worker) — it exists purely so GET /ads/mine can also return how many
-- distinct devices an ad's edit-time views came from.
--
-- (slug, viewer_id) as the primary key is what makes a repeat view from
-- the same device a no-op: INSERT OR IGNORE against it either adds a new
-- row (first time this device is seen for this slug) or does nothing
-- (device already recorded), so COUNT(*) grouped by slug is always the
-- distinct-device count, no separate dedup logic needed anywhere else.
CREATE TABLE ad_viewers (
  slug TEXT NOT NULL,
  viewer_id TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  PRIMARY KEY (slug, viewer_id)
);

-- Every GET /ads/mine call does one of these subqueries per ad row the
-- account owns, so this index keeps that from becoming a full table scan
-- as ad_viewers grows.
CREATE INDEX idx_ad_viewers_slug ON ad_viewers (slug);
