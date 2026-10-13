import { addDays, previousBusinessDay, teamDate } from "./dates";
import { listSourceStates, type SourceStateRow } from "./store";
import { adapters } from "./ingest";

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
  exploited: ExploitedVuln[];
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
}

export async function buildBriefing(db: D1Database, now: Date, windowDays = DEFAULT_WINDOW_DAYS): Promise<Briefing> {
  const today = teamDate(now);
  const newSince = previousBusinessDay(today);
  // Always reach back at least to the last business day (e.g. Monday → Friday).
  const windowStart = [addDays(today, -windowDays), newSince].sort()[0]!;

  const [{ results }, states] = await Promise.all([
    db
      .prepare(
        `SELECT cves, vendors, products, title, summary, url, published_at, tags, details
         FROM items WHERE source = 'kev' AND published_at >= ?
         ORDER BY published_at DESC, id`,
      )
      .bind(windowStart)
      .all<KevRow>(),
    listSourceStates(db),
  ]);

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
    };
  });

  const byId = new Map<string, SourceStateRow>(states.map((s) => [s.source, s]));
  const sources = adapters.map((a): SourceStatus => {
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

  return { generatedAt: now.toISOString(), today, newSince, windowStart, exploited, sources };
}
