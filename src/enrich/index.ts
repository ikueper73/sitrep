import type { Fetcher } from "../sources/types";
import { recordFetchError, recordFetchSuccess } from "../store";
import { EPSS_BATCH, fetchEpss } from "./epss";
import { fetchNvd, NvdRateLimitError, type NvdInfo } from "./nvd";

/** Enrichment sources, listed in the briefing's source footer. */
export const enrichers = [
  { id: "epss", name: "FIRST EPSS" },
  { id: "nvd", name: "NVD" },
] as const;

/** CVEs from items published within this many days get enriched. Matches the briefing's max window. */
export const ENRICH_WINDOW_DAYS = 30;

const HOUR = 3600_000;
// EPSS publishes once a day; recheck a bit sooner so we don't drift a day behind.
const EPSS_MAX_AGE = 20 * HOUR;
// NVD scores change rarely once set; CVEs still awaiting a score are rechecked daily.
const NVD_MAX_AGE = 7 * 24 * HOUR;
const NVD_UNSCORED_MAX_AGE = 24 * HOUR;
// NVD allows 5 requests / 30 s without a key, 50 with one.
export const NVD_PER_RUN_WITHOUT_KEY = 5;
export const NVD_PER_RUN_WITH_KEY = 30;

interface CveRow {
  cve: string;
  newest: string;
  in_kev: number;
  epss_checked_at: string | null;
  nvd_checked_at: string | null;
  cvss_score: number | null;
}

const olderThan = (iso: string | null, maxAgeMs: number, now: number) =>
  iso === null || now - Date.parse(iso) > maxAgeMs;

export interface EnrichOptions {
  now?: Date;
  nvdApiKey?: string;
}

export type EnrichOutcome = { source: string; checked: number; error?: string };

/**
 * Refreshes EPSS and NVD data for CVEs mentioned by recent items. Only CVEs
 * whose data is stale are fetched; NVD lookups are capped per run to respect
 * its rate limit, so a backlog drains over several hourly runs.
 */
export async function runEnrichment(
  db: D1Database,
  fetcher: Fetcher = fetch,
  { now = new Date(), nvdApiKey }: EnrichOptions = {},
): Promise<EnrichOutcome[]> {
  const nowMs = now.getTime();
  const nowIso = now.toISOString();
  const since = new Date(nowMs - ENRICH_WINDOW_DAYS * 24 * HOUR).toISOString().slice(0, 10);

  const { results: rows } = await db
    .prepare(
      `SELECT c.cve, c.newest, c.in_kev, e.epss_checked_at, e.nvd_checked_at, e.cvss_score
       FROM (SELECT j.value AS cve, MAX(i.published_at) AS newest, MAX(i.source = 'kev') AS in_kev
             FROM items i, json_each(i.cves) j
             WHERE i.published_at >= ?
             GROUP BY j.value) c
       LEFT JOIN cve_enrichment e ON e.cve = c.cve
       ORDER BY c.in_kev DESC, c.newest DESC, c.cve`,
    )
    .bind(since)
    .all<CveRow>();

  const epssDue = rows.filter((r) => olderThan(r.epss_checked_at, EPSS_MAX_AGE, nowMs)).map((r) => r.cve);
  const nvdLimit = nvdApiKey ? NVD_PER_RUN_WITH_KEY : NVD_PER_RUN_WITHOUT_KEY;
  const nvdDue = rows
    .filter((r) =>
      r.nvd_checked_at === null ||
      olderThan(r.nvd_checked_at, r.cvss_score === null ? NVD_UNSCORED_MAX_AGE : NVD_MAX_AGE, nowMs),
    )
    // Never-checked CVEs first; within that, KEV CVEs, then most recently reported
    // (the query's order; Array.prototype.sort is stable).
    .sort((a, b) => Number(a.nvd_checked_at !== null) - Number(b.nvd_checked_at !== null))
    .slice(0, nvdLimit)
    .map((r) => r.cve);

  const [epss, nvd] = await Promise.all([
    enrichEpss(db, fetcher, epssDue, nowIso),
    enrichNvd(db, fetcher, nvdDue, nowIso, nvdApiKey),
  ]);
  return [epss, nvd];
}

async function enrichEpss(db: D1Database, fetcher: Fetcher, cves: string[], now: string): Promise<EnrichOutcome> {
  let checked = 0;
  try {
    for (let i = 0; i < cves.length; i += EPSS_BATCH) {
      const batch = cves.slice(i, i + EPSS_BATCH);
      const scores = await fetchEpss(fetcher, batch);
      const stmt = db.prepare(
        `INSERT INTO cve_enrichment (cve, epss, epss_percentile, epss_date, epss_checked_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (cve) DO UPDATE SET epss = ?2, epss_percentile = ?3, epss_date = ?4, epss_checked_at = ?5`,
      );
      // CVEs EPSS doesn't score yet are still marked as checked, with NULL scores.
      await db.batch(
        batch.map((cve) => {
          const s = scores.get(cve);
          return stmt.bind(cve, s?.epss ?? null, s?.percentile ?? null, s?.date ?? null, now);
        }),
      );
      checked += batch.length;
    }
    await recordFetchSuccess(db, "epss", now, null);
    return { source: "epss", checked };
  } catch (err) {
    return recordEnrichError(db, "epss", now, err, checked);
  }
}

async function enrichNvd(
  db: D1Database,
  fetcher: Fetcher,
  cves: string[],
  now: string,
  apiKey: string | undefined,
): Promise<EnrichOutcome> {
  const stmt = db.prepare(
    `INSERT INTO cve_enrichment (cve, cvss_score, cvss_severity, cvss_version, cvss_vector, cvss_source,
                                 ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, nvd_status, nvd_checked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
     ON CONFLICT (cve) DO UPDATE SET cvss_score = ?2, cvss_severity = ?3, cvss_version = ?4, cvss_vector = ?5,
       cvss_source = ?6, ssvc_exploitation = ?7, ssvc_automatable = ?8, ssvc_technical_impact = ?9,
       nvd_status = ?10, nvd_checked_at = ?11`,
  );
  let checked = 0;
  try {
    // Sequential, to stay within NVD's rate limit.
    for (const cve of cves) {
      const info: NvdInfo | null = await fetchNvd(fetcher, cve, apiKey);
      await stmt
        .bind(
          cve,
          info?.cvss?.score ?? null,
          info?.cvss?.severity ?? null,
          info?.cvss?.version ?? null,
          info?.cvss?.vector ?? null,
          info?.cvss?.source ?? null,
          info?.ssvc?.exploitation ?? null,
          info?.ssvc?.automatable ?? null,
          info?.ssvc?.technicalImpact ?? null,
          info?.status ?? null,
          now,
        )
        .run();
      checked++;
    }
    await recordFetchSuccess(db, "nvd", now, null);
    return { source: "nvd", checked };
  } catch (err) {
    // On a rate limit, keep what we got; the rest is retried next run.
    return recordEnrichError(db, "nvd", now, err, checked);
  }
}

async function recordEnrichError(
  db: D1Database,
  source: string,
  now: string,
  err: unknown,
  checked: number,
): Promise<EnrichOutcome> {
  const error = err instanceof Error ? err.message : String(err);
  const level = err instanceof NvdRateLimitError ? "warn" : "error";
  console[level](`enrich ${source}: ${error} (after ${checked})`);
  try {
    await recordFetchError(db, source, now, error);
  } catch (e) {
    console.error(`enrich ${source}: could not record error: ${e}`);
  }
  return { source, checked, error };
}
