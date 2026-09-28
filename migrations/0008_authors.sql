-- Opaque public author IDs. Story/feed/subscription responses used to carry
-- the author's Google `sub` (authorSub) to every viewer's device. They now
-- carry author_id instead: a random, unguessable ID that means nothing outside
-- this app. D1 tables keep using `sub` internally; this table is the only
-- place the two meet, translated at the API edge (see authorIdFor /
-- resolveAuthorParam in index.js).
--
-- sub is the primary key so "give me this account's ID" is atomic and
-- race-free (INSERT OR IGNORE, then SELECT); author_id is UNIQUE for the
-- reverse lookup. IDs never change for the life of the account and are
-- removed with it (see purgeAccountData).
--
-- Backfill: every account already appearing as a story author or on either
-- side of a subscription gets an ID here; anyone else gets one lazily.
--
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0008_authors.sql

CREATE TABLE IF NOT EXISTS authors (
  sub        TEXT PRIMARY KEY,
  author_id  TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO authors (sub, author_id, created_at)
SELECT s, 'a_' || lower(hex(randomblob(16))), CAST(strftime('%s','now') AS INTEGER) * 1000
FROM (
  SELECT author_sub AS s FROM stories
  UNION SELECT author_sub FROM subscriptions
  UNION SELECT subscriber_sub FROM subscriptions
);
