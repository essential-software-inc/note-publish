-- Stories feature: "Show in stories" toggle on publish, subscriptions
-- between accounts, and per-viewer seen-state for the story ring.
--
-- Lives in the same D1 database as 0001_ads.sql/0002_ad_viewers.sql
-- (binding ADS_DB) for the identical reason that DB exists at all: these
-- three tables need real relational queries (feed = join subscriptions
-- against stories; ring state = left-join story_seen) that KV's
-- get/put/list-by-prefix can't do. Page HTML, slugs, and owner tokens
-- stay in SLUGS/NOTES_BUCKET as before — a story IS a published page,
-- just also indexed here for the feed/strip queries.
--
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0003_stories.sql

CREATE TABLE IF NOT EXISTS stories (
  slug        TEXT PRIMARY KEY,
  author_sub  TEXT NOT NULL,
  title       TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stories_author_time ON stories(author_sub, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stories_time ON stories(created_at DESC);

CREATE TABLE IF NOT EXISTS subscriptions (
  subscriber_sub TEXT NOT NULL,
  author_sub     TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (subscriber_sub, author_sub)
);
CREATE INDEX IF NOT EXISTS idx_subs_author ON subscriptions(author_sub);

CREATE TABLE IF NOT EXISTS story_seen (
  subscriber_sub TEXT NOT NULL,
  slug           TEXT NOT NULL,
  seen_at        INTEGER NOT NULL,
  PRIMARY KEY (subscriber_sub, slug)
);
