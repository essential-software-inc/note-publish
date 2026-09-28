-- Likes: a signed-in account can like a published note (by slug). Separate
-- from the app's on-device Favorites, which are private bookmarks and never
-- reach this table.
--
-- One row per (liker, note). author_sub is copied from the note's owner at
-- like time so an author's total ("X likes" on the Account sheet) is a
-- single indexed COUNT instead of a join through KV; it is '' for a note
-- published without an account (those likes are recorded but never counted
-- toward anyone). Rows are removed when the note is unpublished (so a
-- reclaimed slug never inherits old likes) and when either account is
-- deleted — see handleUnpublish and purgeAccountData.
--
-- Same D1 database as the other tables (binding ADS_DB).
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0006_likes.sql

CREATE TABLE IF NOT EXISTS likes (
  liker_sub   TEXT NOT NULL,
  slug        TEXT NOT NULL,
  author_sub  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (liker_sub, slug)
);
CREATE INDEX IF NOT EXISTS idx_likes_author ON likes(author_sub);
CREATE INDEX IF NOT EXISTS idx_likes_slug ON likes(slug);
