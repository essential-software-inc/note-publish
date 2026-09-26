-- Adds image_url to stories: the note's first image, extracted and stored
-- server-side at publish/update time (see storeStoryImage in index.js,
-- which itself calls extractFirstImageSrc to pull the raw src), for the
-- story-ring avatar preview. Holds either the sentinel STORY_IMAGE_R2_MARKER
-- (image bytes live in R2, served via GET /stories/image/:slug) or a plain
-- remote URL. NULL means no image (or one too large to be worth storing) —
-- the client falls back to a title-text avatar.
--
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0004_stories_image.sql

ALTER TABLE stories ADD COLUMN image_url TEXT;
