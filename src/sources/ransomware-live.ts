import { conditionalGet } from "./http";
import { safeUrl } from "./rss";
import type { NormalisedItem, SourceAdapter } from "./types";

export const RANSOMWARE_LIVE_URL = "https://api-pro.ransomware.live/victims/recent";

/**
 * ransomware.live PRO API (free key from my.ransomware.live).
 * T&C: poll no more often than every 30 min (we poll hourly), attribute
 * "Source: Ransomware.live" with a link wherever the data is shown, and
 * don't re-serve the data to third parties. Use is non-commercial (see CLAUDE.md).
 */

type Obj = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");

/**
 * ransomware.live dates look like "2026-10-13 08:12:45.123456" (UTC) or
 * plain dates. Returns ISO UTC, or null.
 */
export function parseRlDate(raw: string): string | null {
  const m = raw.match(/^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?)(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/);
  if (!m) return null;
  const time = m[2] ? (m[2].length === 5 ? `${m[2]}:00` : m[2]) : "00:00:00";
  const zone = m[3] ? (m[3] === "Z" ? "Z" : m[3].replace(/^([+-]\d{2})(\d{2})$/, "$1:$2")) : "Z";
  const t = Date.parse(`${m[1]}T${time}${zone}`);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

export function normaliseVictim(v: unknown): NormalisedItem | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Obj;
  const victim = str(o.victim);
  const group = str(o.group).toLowerCase();
  const discovered = parseRlDate(str(o.discovered));
  if (!victim || !group || !discovered) return null;
  const country = str(o.country).toUpperCase();
  const sector = str(o.activity);
  return {
    id: `ransomware-live:${str(o.id) || `${victim}@${group}`}`,
    source: "ransomware-live",
    type: "incident",
    title: victim,
    summary: str(o.description) || null,
    url: safeUrl(str(o.permalink)),
    publishedAt: discovered,
    severity: null,
    cves: [],
    vendors: [],
    products: [],
    tags: [group],
    details: {
      group,
      country: /^[A-Z]{2}$/.test(country) ? country : null,
      sector: sector && sector.toLowerCase() !== "not found" ? sector : null,
      website: str(o.website) || null,
      attackDate: parseRlDate(str(o.attackdate)),
      press: safeUrl(str(o.press)),
    },
  };
}

export function parseRecentVictims(json: unknown): { items: NormalisedItem[]; skipped: number } {
  // The endpoint returns a bare array; accept {victims: [...]} too in case it gets wrapped.
  const list = Array.isArray(json) ? json : (json as Obj | null)?.victims;
  if (!Array.isArray(list)) throw new Error("ransomware.live response is not a list of victims");
  const items: NormalisedItem[] = [];
  let skipped = 0;
  for (const v of list) {
    const item = normaliseVictim(v);
    if (item) items.push(item);
    else skipped++;
  }
  return { items, skipped };
}

export function ransomwareLive(apiKey: string | undefined): SourceAdapter {
  return {
    id: "ransomware-live",
    name: "Ransomware.live",
    async fetch(fetcher, state) {
      if (!apiKey) throw new Error("API key not set (RANSOMWARE_LIVE_API_KEY)");
      const keyed: typeof fetcher = (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set("X-API-KEY", apiKey);
        return fetcher(input, { ...init, headers });
      };
      const res = await conditionalGet(keyed, RANSOMWARE_LIVE_URL, state);
      if (!res) return { status: "not-modified" };
      const { items, skipped } = parseRecentVictims(await res.response.json());
      if (skipped > 0) console.warn(`ransomware-live: skipped ${skipped} malformed victims`);
      return { status: "ok", items, validators: res.validators, version: null };
    },
  };
}
