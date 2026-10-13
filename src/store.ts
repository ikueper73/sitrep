import type { FetchState, NormalisedItem } from "./sources/types";

// Insert new items; on conflict, only write when content actually changed, so
// unchanged rows don't count against D1's daily write quota.
const UPSERT_SQL = `
INSERT INTO items (id, source, type, title, summary, url, published_at, first_seen_at, updated_at,
                   severity, cves, vendors, products, tags, details)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
ON CONFLICT (id) DO UPDATE SET
  type = excluded.type, title = excluded.title, summary = excluded.summary, url = excluded.url,
  published_at = excluded.published_at, updated_at = excluded.updated_at,
  severity = excluded.severity, cves = excluded.cves, vendors = excluded.vendors,
  products = excluded.products, tags = excluded.tags, details = excluded.details
WHERE items.type IS NOT excluded.type OR items.title IS NOT excluded.title
   OR items.summary IS NOT excluded.summary OR items.url IS NOT excluded.url
   OR items.published_at IS NOT excluded.published_at OR items.severity IS NOT excluded.severity
   OR items.cves IS NOT excluded.cves OR items.vendors IS NOT excluded.vendors
   OR items.products IS NOT excluded.products OR items.tags IS NOT excluded.tags
   OR items.details IS NOT excluded.details`;

const BATCH_SIZE = 100;

/** Upserts items; returns how many rows were inserted or changed. */
export async function upsertItems(db: D1Database, items: NormalisedItem[], now: string): Promise<number> {
  const stmt = db.prepare(UPSERT_SQL);
  let written = 0;
  for (let i = 0; i < items.length; i += BATCH_SIZE) {
    const batch = items.slice(i, i + BATCH_SIZE).map((it) =>
      stmt.bind(
        it.id, it.source, it.type, it.title, it.summary, it.url, it.publishedAt, now,
        it.severity, JSON.stringify(it.cves), JSON.stringify(it.vendors),
        JSON.stringify(it.products), JSON.stringify(it.tags), JSON.stringify(it.details),
      ),
    );
    const results = await db.batch(batch);
    for (const r of results) written += r.meta.changes ?? 0;
  }
  return written;
}

export interface SourceStateRow {
  source: string;
  etag: string | null;
  last_modified: string | null;
  version: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_changed_at: string | null;
  last_error: string | null;
}

export async function getSourceState(db: D1Database, source: string): Promise<FetchState> {
  const row = await db
    .prepare("SELECT etag, last_modified FROM source_state WHERE source = ?")
    .bind(source)
    .first<{ etag: string | null; last_modified: string | null }>();
  return { etag: row?.etag ?? null, lastModified: row?.last_modified ?? null };
}

export async function listSourceStates(db: D1Database): Promise<SourceStateRow[]> {
  const { results } = await db.prepare("SELECT * FROM source_state ORDER BY source").all<SourceStateRow>();
  return results;
}

export async function recordFetchSuccess(
  db: D1Database,
  source: string,
  now: string,
  changed: { validators: FetchState; version: string | null } | null,
): Promise<void> {
  if (changed) {
    await db
      .prepare(
        `INSERT INTO source_state (source, etag, last_modified, version, last_attempt_at, last_success_at, last_changed_at, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, NULL)
         ON CONFLICT (source) DO UPDATE SET etag = ?2, last_modified = ?3, version = ?4,
           last_attempt_at = ?5, last_success_at = ?5, last_changed_at = ?5, last_error = NULL`,
      )
      .bind(source, changed.validators.etag, changed.validators.lastModified, changed.version, now)
      .run();
  } else {
    await db
      .prepare(
        `INSERT INTO source_state (source, last_attempt_at, last_success_at) VALUES (?1, ?2, ?2)
         ON CONFLICT (source) DO UPDATE SET last_attempt_at = ?2, last_success_at = ?2, last_error = NULL`,
      )
      .bind(source, now)
      .run();
  }
}

export async function recordFetchError(db: D1Database, source: string, now: string, error: string): Promise<void> {
  await db
    .prepare(
      `INSERT INTO source_state (source, last_attempt_at, last_error) VALUES (?1, ?2, ?3)
       ON CONFLICT (source) DO UPDATE SET last_attempt_at = ?2, last_error = ?3`,
    )
    .bind(source, now, error.slice(0, 500))
    .run();
}
