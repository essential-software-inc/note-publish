-- Publish-as-Ad schema. Everything else (page HTML, slugs, owner tokens,
-- accounts) stays in KV/R2 exactly as it already is — this only covers the
-- two things KV can't do safely: an atomic round-robin cursor and an
-- atomic view-credit ledger under concurrent requests.

-- One row per ad. slug is the same slug the page is published under via
-- the existing /publish flow (handlePublish) — an ad IS a published page,
-- just also listed here. rotation_order is assigned once at ad-publish
-- time and never reused, so "next after cursor" is a stable, gapless-enough
-- ordering even as ads are added/exhausted/unpublished over time.
CREATE TABLE ads (
  slug TEXT PRIMARY KEY,
  owner_sub TEXT NOT NULL,
  views_total INTEGER NOT NULL,
  views_used INTEGER NOT NULL DEFAULT 0,
  rotation_order INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active | unpublished | exhausted
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_ads_rotation ON ads (status, rotation_order);
CREATE INDEX idx_ads_owner ON ads (owner_sub);

-- Monotonic counter ads.rotation_order is assigned from — a single-row
-- table so "next value" is one atomic UPDATE...RETURNING instead of a
-- MAX(rotation_order)+1 race between two simultaneous ad-publish calls.
CREATE TABLE ad_rotation_seq (id INTEGER PRIMARY KEY CHECK (id = 1), next_value INTEGER NOT NULL DEFAULT 1);
INSERT INTO ad_rotation_seq (id, next_value) VALUES (1, 1);

-- Where GET /ads/next remembers its position. Single row, updated in the
-- same transaction as the read that picks the next ad, so two Create taps
-- arriving at once can't both be handed the same ad while the cursor only
-- advances once.
CREATE TABLE ad_rotation_cursor (id INTEGER PRIMARY KEY CHECK (id = 1), position INTEGER NOT NULL DEFAULT 0);
INSERT INTO ad_rotation_cursor (id, position) VALUES (1, 0);

-- View-credit ledger. Balance for a user = SUM(delta) WHERE owner_sub = ?.
-- Positive rows come from verified RevenueCat purchases (reason='purchase',
-- rc_event_id set); negative rows are credits spent allocating views to a
-- specific ad at publish time (reason='allocate', slug set). rc_event_id is
-- UNIQUE so a redelivered webhook (RevenueCat retries on non-2xx, and can
-- occasionally redeliver even after a 200) can't double-credit — the
-- INSERT is done with OR IGNORE keyed on it.
CREATE TABLE view_credits_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_sub TEXT NOT NULL,
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL, -- purchase | allocate | refund
  rc_event_id TEXT UNIQUE,
  slug TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_ledger_owner ON view_credits_ledger (owner_sub);
