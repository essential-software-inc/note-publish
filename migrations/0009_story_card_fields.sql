-- Story card fields shown on Subscribed-feed cards (same info a note card shows in the
-- author's own list): short description, tags (JSON array of strings), and when the
-- note itself was created. All nullable; rows created before this migration simply
-- have no description/tags, and their card time falls back to created_at.
ALTER TABLE stories ADD COLUMN description TEXT;
ALTER TABLE stories ADD COLUMN tags TEXT;
ALTER TABLE stories ADD COLUMN note_created_at INTEGER;
