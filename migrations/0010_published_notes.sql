-- Index of currently-live published notes per owner, for GET /account/published-notes
-- (the "Published" tab). The SLUGS KV "owner:<sub>:<slug>" keys remain the source of
-- truth for GET /my/pages and the publish-cap check (ownerAtPageCap); this table exists
-- only so the Published tab can page with real SQL keyset pagination (created_at, slug)
-- instead of listing every owned KV key and calling getMeta on each one per request.
-- Kept in sync at the same three points that touch the KV owner index: handlePublish
-- (insert), handleUnpublish (delete), handlePurge's stale-KV sweep and purgeAccountData
-- (delete) — see index.js.
CREATE TABLE IF NOT EXISTS published_notes (
  slug TEXT PRIMARY KEY,
  author_sub TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_published_notes_author_created
  ON published_notes (author_sub, created_at DESC, slug DESC);
