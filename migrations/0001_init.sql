-- Normalised items from every source.
CREATE TABLE items (
  id            TEXT PRIMARY KEY,             -- "<source>:<source-specific id>", e.g. "kev:CVE-2024-1234"
  source        TEXT NOT NULL,
  type          TEXT NOT NULL,                -- vuln | advisory | ioc | incident | news
  title         TEXT NOT NULL,
  summary       TEXT,
  url           TEXT,
  published_at  TEXT NOT NULL,                -- ISO 8601 date or datetime, as given by the source
  first_seen_at TEXT NOT NULL,                -- when we first ingested it
  updated_at    TEXT NOT NULL,                -- when its content last changed
  severity      TEXT,                         -- critical | high | medium | low, or NULL if unknown
  cves          TEXT NOT NULL DEFAULT '[]',   -- JSON arrays
  vendors       TEXT NOT NULL DEFAULT '[]',
  products      TEXT NOT NULL DEFAULT '[]',
  tags          TEXT NOT NULL DEFAULT '[]',
  details       TEXT NOT NULL DEFAULT '{}'    -- source-specific JSON
);

CREATE INDEX items_source_published ON items (source, published_at DESC);

-- Per-source fetch bookkeeping: conditional-request validators and health.
CREATE TABLE source_state (
  source          TEXT PRIMARY KEY,
  etag            TEXT,
  last_modified   TEXT,
  version         TEXT,                       -- source's own version label, if any
  last_attempt_at TEXT,
  last_success_at TEXT,
  last_changed_at TEXT,                       -- last fetch that returned new content
  last_error      TEXT
);
