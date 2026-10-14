-- The team's product watchlist. Loaded from a reviewed draft (scripts/watchlist-load.mjs)
-- or edited on /watchlist. Never committed to the repo: it describes the team's stack.
CREATE TABLE watchlist (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  label           TEXT NOT NULL,
  vendors         TEXT NOT NULL DEFAULT '[]',   -- JSON array of vendor names/aliases
  products        TEXT NOT NULL DEFAULT '[]',   -- JSON array of product phrases; empty = whole vendor
  tier            INTEGER NOT NULL DEFAULT 3,   -- 1 = business critical … 3 = low
  match_headlines INTEGER NOT NULL DEFAULT 1,   -- 0 for generic names: KEV matching only
  apps            TEXT NOT NULL DEFAULT '[]',   -- JSON array: inventory app names behind the entry
  source          TEXT NOT NULL DEFAULT 'manual', -- 'import' (replaced on each load) or 'manual'
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
