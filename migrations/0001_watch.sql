-- Names seen not to exist. A sighting counts once per caller per UTC day; first_caller is a keyed hash of the first
-- caller (with the name) and is erased once a different caller sees the name, which sets confirmed_at.
CREATE TABLE watch (
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  sightings INTEGER NOT NULL,
  source TEXT NOT NULL,
  first_caller TEXT,
  confirmed_at INTEGER,
  registered_at INTEGER,
  status TEXT NOT NULL DEFAULT 'unregistered', -- unregistered | registered | cleared
  PRIMARY KEY (ecosystem, name)
);

-- Per UTC day, each name counts once across every front door, with its first verdict that day.
CREATE TABLE stats (
  day TEXT PRIMARY KEY,
  checks INTEGER NOT NULL DEFAULT 0,
  blocks INTEGER NOT NULL DEFAULT 0,
  cautions INTEGER NOT NULL DEFAULT 0,
  invented INTEGER NOT NULL DEFAULT 0
);

-- Today's dedupe keys: names already counted in stats, and keyed hashes of caller sightings. Earlier days are
-- deleted on the next write.
CREATE TABLE daily (
  day TEXT NOT NULL,
  key TEXT NOT NULL,
  PRIMARY KEY (day, key)
) WITHOUT ROWID;
