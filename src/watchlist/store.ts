import type { WatchEntry } from "./match";

export interface WatchlistRow {
  id: number;
  label: string;
  vendors: string;
  products: string;
  tier: number;
  match_headlines: number;
  apps: string;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface WatchItem extends WatchEntry {
  id: number;
  apps: string[];
  source: string;
}

export function toWatchItem(r: WatchlistRow): WatchItem {
  return {
    id: r.id,
    label: r.label,
    vendors: JSON.parse(r.vendors) as string[],
    products: JSON.parse(r.products) as string[],
    tier: r.tier,
    matchText: r.match_headlines === 1,
    apps: JSON.parse(r.apps) as string[],
    source: r.source,
  };
}

export async function loadWatchlist(db: D1Database): Promise<WatchItem[]> {
  const { results } = await db.prepare("SELECT * FROM watchlist ORDER BY tier, label").all<WatchlistRow>();
  return results.map(toWatchItem);
}

export interface NewWatchEntry {
  label: string;
  vendors: string[];
  products: string[];
  tier: number;
  matchText: boolean;
}

export async function addWatchEntry(db: D1Database, e: NewWatchEntry, now: string): Promise<void> {
  await db
    .prepare(
      `INSERT INTO watchlist (label, vendors, products, tier, match_headlines, apps, source, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, '[]', 'manual', ?6, ?6)`,
    )
    .bind(e.label, JSON.stringify(e.vendors), JSON.stringify(e.products), e.tier, e.matchText ? 1 : 0, now)
    .run();
}

export async function deleteWatchEntry(db: D1Database, id: number): Promise<boolean> {
  // Imported entries are managed through the reviewed CSV; only hand-added ones are removable here.
  const res = await db.prepare("DELETE FROM watchlist WHERE id = ? AND source = 'manual'").bind(id).run();
  return (res.meta.changes ?? 0) > 0;
}
