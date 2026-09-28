-- Latest-tap-wins for likes and subscriptions. A like/subscribe that was
-- tapped offline is replayed later with the time it was tapped; without a
-- per-item record of the newest action applied, that old replay would beat a
-- newer tap made on another device in the meantime (an unlike leaves no row
-- behind to compare against, so the clock has to live here).
--
-- One row per (account, kind, item): kind is 'like' (item = slug) or 'sub'
-- (item = author sub). t is the action time in ms, clamped to server time.
-- Rows are removed with the account (see purgeAccountData).
--
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0007_action_clocks.sql

CREATE TABLE IF NOT EXISTS action_clocks (
  sub   TEXT NOT NULL,
  kind  TEXT NOT NULL,
  item  TEXT NOT NULL,
  t     INTEGER NOT NULL,
  PRIMARY KEY (sub, kind, item)
);
