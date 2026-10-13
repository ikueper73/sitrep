import { conditionalGet } from "./http";
import type { ItemType, NormalisedItem, SourceAdapter } from "./types";

/**
 * A deliberately small RSS 2.0 reader. Workers has no XML parser, and the
 * feeds we read are plain RSS, so a few regular expressions over the raw text
 * are cheaper (in CPU and bundle size) than an XML library. Each feed has a
 * real-data fixture in test/fixtures/rss/ to keep this honest.
 */

export interface RssItem {
  title: string;
  link: string;
  guid: string;
  pubDate: string;
  /**
   * The start of the description (first DESCRIPTION_HEAD raw characters) with
   * XML escaping/CDATA removed; usually still HTML. Enough for a summary.
   */
  description: string;
  /** The full description exactly as in the XML (still escaped). Search it, don't display it. */
  descriptionRaw: string;
  categories: string[];
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ",
  ndash: "–", mdash: "—", lsquo: "‘", rsquo: "’", ldquo: "“", rdquo: "”",
  hellip: "…", copy: "©", reg: "®", trade: "™", bull: "•", middot: "·",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, ref: string) => {
    if (ref[0] === "#") {
      const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return NAMED_ENTITIES[ref.toLowerCase()] ?? whole;
  });
}

/** Text content of an XML element body: CDATA sections taken verbatim, everything else entity-decoded. */
function elementText(body: string): string {
  let out = "";
  let last = 0;
  for (const m of body.matchAll(/<!\[CDATA\[([\s\S]*?)\]\]>/g)) {
    out += decodeEntities(body.slice(last, m.index)) + m[1];
    last = m.index! + m[0].length;
  }
  return (out + decodeEntities(body.slice(last))).trim();
}

function rawField(block: string, name: string): string {
  const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`));
  return m ? m[1]! : "";
}

/** Splits the (possibly huge) description out, so other fields are searched in the small remainder. */
function splitDescription(block: string): { description: string; rest: string } {
  const open = block.search(/<description(?:\s[^>]*)?>/);
  if (open === -1) return { description: "", rest: block };
  const bodyStart = block.indexOf(">", open) + 1;
  const close = block.indexOf("</description>", bodyStart);
  if (close === -1) return { description: "", rest: block };
  return {
    description: block.slice(bodyStart, close),
    rest: block.slice(0, open) + block.slice(close + "</description>".length),
  };
}

function field(block: string, name: string): string {
  return elementText(rawField(block, name));
}

// CISA puts entire advisories (up to ~100 KB each) in <description>. Decoding
// and stripping all of that costs ~25 ms CPU per run, over the Workers Free
// plan's 10 ms limit, so only the start is decoded for the summary.
const DESCRIPTION_HEAD = 2500;

function head(body: string): string {
  if (body.length <= DESCRIPTION_HEAD) return elementText(body);
  // A cut inside a CDATA section leaves an unterminated opener; drop it.
  return elementText(body.slice(0, DESCRIPTION_HEAD)).replace("<![CDATA[", "");
}

export function parseRss(xml: string, maxItems = 50): RssItem[] {
  const items: RssItem[] = [];
  for (const m of xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/g)) {
    const { description, rest: block } = splitDescription(m[1]!);
    items.push({
      title: field(block, "title"),
      link: field(block, "link"),
      guid: field(block, "guid"),
      pubDate: field(block, "pubDate"),
      description: head(description),
      descriptionRaw: description,
      categories: [...block.matchAll(/<category(?:\s[^>]*)?>([\s\S]*?)<\/category>/g)].map((c) => elementText(c[1]!)),
    });
    if (items.length >= maxItems) break;
  }
  return items;
}

/** Plain text from an HTML fragment. */
export function htmlToText(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/\s+/g, " ")
    .trim();
}

export function truncate(text: string, max = 300): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const space = cut.lastIndexOf(" ");
  return `${(space > max / 2 ? cut.slice(0, space) : cut).replace(/[\s,.;:]+$/, "")}…`;
}

export function extractCves(text: string, max = 25): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(/\bCVE-(\d{4})-(\d{4,7})\b/gi)) {
    found.add(`CVE-${m[1]}-${m[2]}`);
    if (found.size >= max) break;
  }
  return [...found];
}

/** Only http(s) URLs make it into the page, so a feed can't inject javascript: links. */
export function safeUrl(raw: string): string | null {
  try {
    const u = new URL(raw.trim());
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

const MONTHS: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};
const ZONES: Record<string, number> = {
  GMT: 0, UT: 0, UTC: 0, Z: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
};

/**
 * RFC 822 dates as used in RSS, including two-digit years (CISA writes
 * "Thu, 08 Oct 26 12:00:00 +0000"). Falls back to ISO 8601. Returns ISO UTC or null.
 */
export function parseRssDate(raw: string): string | null {
  const m = raw.match(/(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,4})?/);
  if (m) {
    const month = MONTHS[m[2]!.toLowerCase()];
    if (month === undefined) return null;
    let year = Number(m[3]);
    if (m[3]!.length === 2) year += 2000;
    let offsetMin = 0;
    const zone = m[7];
    if (zone && /^[+-]\d{4}$/.test(zone)) {
      const sign = zone[0] === "-" ? -1 : 1;
      offsetMin = sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5)));
    } else if (zone) {
      offsetMin = ZONES[zone.toUpperCase()] ?? 0;
    }
    const utc = Date.UTC(year, month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)) - offsetMin * 60_000;
    return Number.isFinite(utc) ? new Date(utc).toISOString() : null;
  }
  if (/^\d{4}-\d{2}-\d{2}/.test(raw.trim())) {
    const t = Date.parse(raw.trim());
    return Number.isFinite(t) ? new Date(t).toISOString() : null;
  }
  return null;
}

export interface FeedConfig {
  id: string;
  name: string;
  url: string;
  type: ItemType;
  maxItems?: number;
  /** Adjust or drop (return null) a normalised item; receives the raw item for context. */
  transform?: (item: NormalisedItem, raw: RssItem) => NormalisedItem | null;
}

export function normaliseRssItem(feed: FeedConfig, raw: RssItem): NormalisedItem | null {
  const title = htmlToText(raw.title);
  const publishedAt = parseRssDate(raw.pubDate);
  const key = raw.guid || raw.link;
  if (!title || !publishedAt || !key) return null;
  const text = htmlToText(raw.description);
  // CVE IDs survive XML/HTML escaping, so search the raw description in full.
  return {
    id: `${feed.id}:${key}`,
    source: feed.id,
    type: feed.type,
    title,
    summary: text ? truncate(text) : null,
    url: safeUrl(raw.link) ?? safeUrl(raw.guid),
    publishedAt,
    severity: null,
    cves: extractCves(`${title} ${raw.descriptionRaw}`),
    vendors: [],
    products: [],
    tags: [],
    details: raw.categories.length ? { categories: raw.categories } : {},
  };
}

export function parseFeed(feed: FeedConfig, xml: string): { items: NormalisedItem[]; skipped: number } {
  const items: NormalisedItem[] = [];
  let skipped = 0;
  for (const raw of parseRss(xml, feed.maxItems)) {
    const base = normaliseRssItem(feed, raw);
    if (!base) {
      skipped++;
      continue;
    }
    const item = feed.transform ? feed.transform(base, raw) : base;
    if (item) items.push(item);
  }
  return { items, skipped };
}

export function rssAdapter(feed: FeedConfig): SourceAdapter {
  return {
    id: feed.id,
    name: feed.name,
    async fetch(fetcher, state) {
      const res = await conditionalGet(fetcher, feed.url, state, "application/rss+xml, application/xml, text/xml");
      if (!res) return { status: "not-modified" };
      const xml = await res.response.text();
      if (!/<rss\b|<channel\b/.test(xml.slice(0, 2000))) throw new Error(`${feed.id}: response is not an RSS feed`);
      const { items, skipped } = parseFeed(feed, xml);
      if (skipped > 0) console.warn(`${feed.id}: skipped ${skipped} items without title, date or id`);
      return { status: "ok", items, validators: res.validators, version: null };
    },
  };
}
