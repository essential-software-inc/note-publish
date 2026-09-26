-- Adds image_urls to stories: up to 3 of the note's images, extracted and
-- stored server-side at publish/update time (see storeStoryCardImages in
-- index.js), for the Subscribed-feed note-card thumbnail row — distinct
-- from image_url (0004_stories_image.sql), which holds just the first
-- image for the story-ring avatar in the discovery strip.
--
-- Column holds a JSON array (e.g. '["r2","r2",null]' isn't valid — entries
-- are only ever the sentinel STORY_IMAGE_R2_MARKER string or a plain
-- remote URL string, never null; a missing slot is just absent from the
-- array) of up to 3 entries. Each STORY_IMAGE_R2_MARKER entry's bytes live
-- in R2 at story-card-images/<slug>/<index>, served via
-- GET /stories/card-image/:slug/:index. NULL/empty column (or a row from
-- before this migration) means no card images — the client falls back to
-- no thumbnail row, same as a note with no images.
--
-- Apply with: wrangler d1 execute note-publish-ads --remote --file=migrations/0005_stories_card_images.sql

ALTER TABLE stories ADD COLUMN image_urls TEXT;
