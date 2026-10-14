import { addDays, previousBusinessDay, teamDate, teamMidnightUtc } from "./dates";
import { type CisaKind, cisaKind, feeds } from "./sources/feeds";
import { listSourceStates, type SourceStateRow } from "./store";
import { adapters } from "./ingest";
import { enrichers } from "./enrich";
import { loadWatchlist } from "./watchlist/store";
import { matchText, matchVendorProduct, type WatchEntry } from "./watchlist/match";

/** A watchlist entry an item matched. */
export interface StackMatch {
  label: string;
  tier: number;
}

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
  stack: StackMatch[];
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
  stack: StackMatch[];
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
  stack: StackMatch[];
}

export interface RansomwareVictim {
  victim: string;
  group: string;
  country: string | null;
  sector: string | null;
  website: string | null;
  discoveredAt: string;
  url: string | null;
  press: string | null;
  isNew: boolean;
}

export interface RansomwareSummary {
  total: number;
  inTeamCountry: number;
  topGroups: { group: string; count: number }[];
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
  ransomware: { summary: RansomwareSummary; victims: RansomwareVictim[] };
  /** Number of watchlist entries; 0 means no watchlist is loaded. */
  watchlistSize: number;
  sources: SourceStatus[];
}

/** The team is US-based: its country's victims are listed first. */
export const TEAM_COUNTRY = "US";

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
 * Free-text matching for advisories and headlines. Vendor-wide entries (no
 * product terms) match the title only: a vendor named in passing in a summary
 * is noise. Entries with product terms are specific enough for the summary too.
 */
function matchItem(watchlist: WatchEntry[], title: string, summary: string | null): WatchEntry[] {
  const specific = watchlist.filter((e) => e.products.length > 0);
  const vendorWide = watchlist.filter((e) => e.products.length === 0);
  return [...matchText(specific, `${title} ${summary ?? ""}`), ...matchText(vendorWide, title)];
}

function toStack(matches: WatchEntry[]): StackMatch[] {
  return matches
    .map((m) => ({ label: m.label, tier: m.tier }))
    .sort((a, b) => a.tier - b.tier || a.label.localeCompare(b.label));
}

/** Items matching the team's stack first, most critical tier first. */
function byStack(a: { stack: StackMatch[] }, b: { stack: StackMatch[] }): number {
  const tier = (x: { stack: StackMatch[] }) => x.stack[0]?.tier ?? 99;
  return tier(a) - tier(b);
}

/**
 * Items in the team's stack first, then new items; within each group, most
 * likely to be exploited (EPSS), then most severe (CVSS), then most recent.
 */
export function rankExploited(a: ExploitedVuln, b: ExploitedVuln): number {
  return (
    byStack(a, b) ||
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
  const [{ results }, { results: advisoryRows }, { results: headlineRows }, { results: victimRows }, states, watchlist] = await Promise.all([
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
    db
      .prepare(
        `SELECT title, url, published_at, details FROM items
         WHERE source = 'ransomware-live' AND published_at >= ?
         ORDER BY published_at DESC LIMIT 500`,
      )
      .bind(headlinesSince)
      .all<{ title: string; url: string | null; published_at: string; details: string }>(),
    listSourceStates(db),
    loadWatchlist(db),
  ]);

  const victims = victimRows.map((r): RansomwareVictim => {
    const d = JSON.parse(r.details) as Record<string, string | null>;
    return {
      victim: r.title,
      group: d.group ?? "",
      country: d.country ?? null,
      sector: d.sector ?? null,
      website: d.website ?? null,
      discoveredAt: r.published_at,
      url: r.url,
      press: d.press ?? null,
      isNew: r.published_at >= newSinceInstant,
    };
  });
  // Team-country victims first; otherwise newest first (the query's order; sort is stable).
  victims.sort((a, b) => Number(b.country === TEAM_COUNTRY) - Number(a.country === TEAM_COUNTRY));
  const groupCounts = new Map<string, number>();
  for (const v of victims) groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);
  const ransomware = {
    summary: {
      total: victims.length,
      inTeamCountry: victims.filter((v) => v.country === TEAM_COUNTRY).length,
      topGroups: [...groupCounts]
        .map(([group, count]) => ({ group, count }))
        .sort((a, b) => b.count - a.count || a.group.localeCompare(b.group))
        .slice(0, 5),
    },
    victims,
  };

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
      stack: toStack(matchItem(watchlist, r.title, r.summary)),
    }),
  );
  advisories.sort((a, b) => byStack(a, b) || b.publishedAt.localeCompare(a.publishedAt));

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
      stack: toStack(matchItem(watchlist, r.title, r.summary)),
    }),
  );
  headlines.sort((a, b) => byStack(a, b) || b.publishedAt.localeCompare(a.publishedAt));

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
      stack: toStack(
        matchVendorProduct(watchlist, (JSON.parse(r.vendors) as string[])[0] ?? "", (JSON.parse(r.products) as string[])[0] ?? ""),
      ),
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
    ransomware,
    watchlistSize: watchlist.length,
    sources,
  };
}
