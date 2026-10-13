import { addDays, previousBusinessDay, teamDate, teamMidnightUtc } from "./dates";
import { type CisaKind, cisaKind, feeds } from "./sources/feeds";
import { listSourceStates, type SourceStateRow } from "./store";
import { adapters } from "./ingest";
import { enrichers } from "./enrich";

export interface ExploitedVuln {
  cve: string;
  vendor: string;
  product: string;
  name: string;
  description: string | null;
  url: string | null;
  dateAdded: string;
  dueDate: string | null;
  requiredAction: string;
  ransomware: boolean;
  isNew: boolean;
  cvss: { score: number; severity: string; version: string; source: string } | null;
  epss: { score: number; percentile: number } | null;
  automatable: boolean;
}

export interface Advisory {
  kind: CisaKind;
  title: string;
  url: string | null;
  summary: string | null;
  publishedAt: string;
  cves: string[];
  /** The subset of `cves` that is in the KEV catalog. */
  kevCves: string[];
  isNew: boolean;
}

export interface Headline {
  source: string;
  sourceName: string;
  title: string;
  url: string | null;
  summary: string | null;
  publishedAt: string;
  cves: string[];
  kevCves: string[];
  isNew: boolean;
}

export interface SourceStatus {
  id: string;
  name: string;
  lastSuccessAt: string | null;
  lastChangedAt: string | null;
  version: string | null;
  error: string | null;
}

export interface Briefing {
  generatedAt: string;
  today: string;
  /** Items on or after this date are "new since the last standup". */
  newSince: string;
  windowStart: string;
  /** Headlines default to "since the last standup"; an explicit window widens them. */
  headlinesSince: string;
  exploited: ExploitedVuln[];
  advisories: Advisory[];
  headlines: Headline[];
  sources: SourceStatus[];
}

export const DEFAULT_WINDOW_DAYS = 7;

interface KevRow {
  cves: string;
  vendors: string;
  products: string;
  title: string;
  summary: string | null;
  url: string | null;
  published_at: string;
  tags: string;
  details: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_version: string | null;
  cvss_source: string | null;
  epss: number | null;
  epss_percentile: number | null;
  ssvc_automatable: string | null;
}

/**
 * New items first; within each group, most likely to be exploited (EPSS),
 * then most severe (CVSS), then most recently added.
 */
export function rankExploited(a: ExploitedVuln, b: ExploitedVuln): number {
  return (
    Number(b.isNew) - Number(a.isNew) ||
    (b.epss?.score ?? -1) - (a.epss?.score ?? -1) ||
    (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) ||
    b.dateAdded.localeCompare(a.dateAdded) ||
    a.cve.localeCompare(b.cve)
  );
}

interface FeedRow {
  source: string;
  title: string;
  summary: string | null;
  url: string | null;
  published_at: string;
  cves: string;
  kev_cves: string;
}

// For each item, the CVEs it mentions that are also in the KEV catalog.
const FEED_ITEMS_SQL = (where: string) => `
  SELECT i.source, i.title, i.summary, i.url, i.published_at, i.cves,
         (SELECT json_group_array(j.value) FROM json_each(i.cves) j
           WHERE EXISTS (SELECT 1 FROM items k WHERE k.id = 'kev:' || j.value)) AS kev_cves
  FROM items i
  WHERE ${where} AND i.published_at >= ?
  ORDER BY i.published_at DESC
  LIMIT 200`;

const FEED_NAMES = new Map(feeds.map((f) => [f.id, f.name]));
const NEWS_SOURCES = feeds.filter((f) => f.type === "news").map((f) => f.id);

export async function buildBriefing(db: D1Database, now: Date, windowDays?: number): Promise<Briefing> {
  const today = teamDate(now);
  const newSince = previousBusinessDay(today);
  const newSinceInstant = teamMidnightUtc(newSince);
  // Always reach back at least to the last business day (e.g. Monday → Friday).
  const windowStart = [addDays(today, -(windowDays ?? DEFAULT_WINDOW_DAYS)), newSince].sort()[0]!;
  const windowStartInstant = teamMidnightUtc(windowStart);
  const headlinesSince = windowDays === undefined ? newSinceInstant : windowStartInstant;

  const newsPlaceholders = NEWS_SOURCES.map(() => "?").join(", ");
  const [{ results }, { results: advisoryRows }, { results: headlineRows }, states] = await Promise.all([
    db
      .prepare(
        `SELECT i.cves, i.vendors, i.products, i.title, i.summary, i.url, i.published_at, i.tags, i.details,
                e.cvss_score, e.cvss_severity, e.cvss_version, e.cvss_source,
                e.epss, e.epss_percentile, e.ssvc_automatable
         FROM items i
         LEFT JOIN cve_enrichment e ON e.cve = json_extract(i.cves, '$[0]')
         WHERE i.source = 'kev' AND i.published_at >= ?`,
      )
      .bind(windowStart)
      .all<KevRow>(),
    db.prepare(FEED_ITEMS_SQL("i.source = 'cisa'")).bind(windowStartInstant).all<FeedRow>(),
    db
      .prepare(FEED_ITEMS_SQL(`i.source IN (${newsPlaceholders})`))
      .bind(...NEWS_SOURCES, headlinesSince)
      .all<FeedRow>(),
    listSourceStates(db),
  ]);

  const advisories = advisoryRows.map(
    (r): Advisory => ({
      kind: cisaKind(r.url),
      title: r.title,
      url: r.url,
      summary: r.summary,
      publishedAt: r.published_at,
      cves: JSON.parse(r.cves) as string[],
      kevCves: JSON.parse(r.kev_cves) as string[],
      isNew: r.published_at >= newSinceInstant,
    }),
  );

  const headlines = headlineRows.map(
    (r): Headline => ({
      source: r.source,
      sourceName: FEED_NAMES.get(r.source) ?? r.source,
      title: r.title,
      url: r.url,
      summary: r.summary,
      publishedAt: r.published_at,
      cves: JSON.parse(r.cves) as string[],
      kevCves: JSON.parse(r.kev_cves) as string[],
      isNew: r.published_at >= newSinceInstant,
    }),
  );

  const exploited = results.map((r): ExploitedVuln => {
    const details = JSON.parse(r.details) as { dueDate?: string | null; requiredAction?: string };
    return {
      cve: (JSON.parse(r.cves) as string[])[0] ?? "",
      vendor: (JSON.parse(r.vendors) as string[])[0] ?? "",
      product: (JSON.parse(r.products) as string[])[0] ?? "",
      name: r.title,
      description: r.summary,
      url: r.url,
      dateAdded: r.published_at,
      dueDate: details.dueDate ?? null,
      requiredAction: details.requiredAction ?? "",
      ransomware: (JSON.parse(r.tags) as string[]).includes("ransomware"),
      isNew: r.published_at >= newSince,
      cvss:
        r.cvss_score !== null
          ? {
              score: r.cvss_score,
              severity: r.cvss_severity ?? "",
              version: r.cvss_version ?? "",
              source: r.cvss_source ?? "",
            }
          : null,
      epss: r.epss !== null ? { score: r.epss, percentile: r.epss_percentile ?? 0 } : null,
      automatable: r.ssvc_automatable === "yes",
    };
  });
  exploited.sort(rankExploited);

  const byId = new Map<string, SourceStateRow>(states.map((s) => [s.source, s]));
  const sources = [...adapters, ...enrichers].map((a): SourceStatus => {
    const s = byId.get(a.id);
    return {
      id: a.id,
      name: a.name,
      lastSuccessAt: s?.last_success_at ?? null,
      lastChangedAt: s?.last_changed_at ?? null,
      version: s?.version ?? null,
      error: s?.last_error ?? null,
    };
  });

  return {
    generatedAt: now.toISOString(),
    today,
    newSince,
    windowStart,
    headlinesSince,
    exploited,
    advisories,
    headlines,
    sources,
  };
}
