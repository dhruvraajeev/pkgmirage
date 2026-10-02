-- When the nightly job last asked the registry about a watched name; NULL = never, so it goes first.
ALTER TABLE watch ADD COLUMN checked_at INTEGER;
