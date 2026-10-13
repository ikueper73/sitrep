import { type FeedConfig, htmlToText, rssAdapter, truncate } from "./rss";

export type CisaKind = "advisory" | "alert" | "ics" | "other";

export function cisaKind(url: string | null): CisaKind {
  if (!url) return "other";
  if (url.includes("/ics-advisories/") || url.includes("/ics-medical-advisories/")) return "ics";
  if (url.includes("/cybersecurity-advisories/")) return "advisory";
  if (url.includes("/alerts/")) return "alert";
  return "other";
}

/**
 * Joint advisories open with an "Advisory at a Glance" box that repeats the
 * title, so start from the executive summary when there is one. ICS advisory
 * descriptions start with a "View CSAF" link label.
 */
export function cisaSummary(text: string): string | null {
  const exec = text.match(/\bExecutive Summary\s+([\s\S]+)/i);
  const body = (exec ? exec[1]! : text).replace(/^View CSAF\s+(Summary\s+)?/i, "").trim();
  return body ? truncate(body) : null;
}

export const feeds: FeedConfig[] = [
  {
    id: "cisa",
    name: "CISA advisories",
    // All CISA advisory types in one feed: cybersecurity advisories, alerts, ICS advisories.
    url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    type: "advisory",
    transform(item, raw) {
      // "CISA Adds N Known Exploited Vulnerabilities to Catalog" duplicates the KEV section.
      if (/\bAdds?\b.*\bKnown Exploited Vulnerabilit/i.test(item.title)) return null;
      const kind = cisaKind(item.url);
      return { ...item, summary: cisaSummary(htmlToText(raw.description)) ?? item.summary, tags: [kind] };
    },
  },
  {
    id: "bleepingcomputer",
    name: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    type: "news",
  },
  {
    id: "therecord",
    name: "The Record",
    url: "https://therecord.media/feed",
    type: "news",
  },
  {
    id: "sans-isc",
    name: "SANS ISC",
    url: "https://isc.sans.edu/rssfeed.xml",
    type: "news",
    transform(item) {
      // Daily podcast announcements carry no information in the title.
      if (/^ISC Stormcast\b/i.test(item.title)) return null;
      // Diary titles end with ", (Sat, Oct 10th)".
      return { ...item, title: item.title.replace(/,?\s*\((Mon|Tue|Wed|Thu|Fri|Sat|Sun)[^)]*\)\s*$/, "") };
    },
  },
];

export const feedAdapters = feeds.map(rssAdapter);
