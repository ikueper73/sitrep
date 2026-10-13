import { describe, expect, it } from "vitest";
import { feeds } from "../src/sources/feeds";
import {
  decodeEntities,
  extractCves,
  htmlToText,
  parseFeed,
  parseRss,
  parseRssDate,
  rssAdapter,
  safeUrl,
  truncate,
} from "../src/sources/rss";
import bleepingXml from "./fixtures/rss/bleepingcomputer.xml?raw";
import cisaXml from "./fixtures/rss/cisa.xml?raw";
import sansXml from "./fixtures/rss/sans-isc.xml?raw";
import therecordXml from "./fixtures/rss/therecord.xml?raw";

const feed = (id: string) => feeds.find((f) => f.id === id)!;

describe("parseRssDate", () => {
  it("handles CISA's two-digit years", () => {
    expect(parseRssDate("Thu, 08 Oct 26 12:00:00 +0000")).toBe("2026-10-08T12:00:00.000Z");
  });
  it("applies numeric offsets", () => {
    expect(parseRssDate("Mon, 12 Oct 2026 16:13:52 -0400")).toBe("2026-10-12T20:13:52.000Z");
  });
  it("handles named zones", () => {
    expect(parseRssDate("Tue, 13 Oct 2026 12:00:00 GMT")).toBe("2026-10-13T12:00:00.000Z");
    expect(parseRssDate("Tue, 13 Oct 2026 08:00:00 EDT")).toBe("2026-10-13T12:00:00.000Z");
  });
  it("falls back to ISO 8601 and rejects garbage", () => {
    expect(parseRssDate("2026-10-13T12:00:00Z")).toBe("2026-10-13T12:00:00.000Z");
    expect(parseRssDate("yesterday")).toBeNull();
  });
});

describe("text helpers", () => {
  it("decodes named and numeric entities", () => {
    expect(decodeEntities("A &amp; B &#8217;s &#x2014; &nbsp;&bogus;")).toBe("A & B ’s —  &bogus;".replace(" ", " "));
  });
  it("strips HTML, including scripts", () => {
    expect(htmlToText("<p>Hello <b>world</b><script>alert(1)</script></p>")).toBe("Hello world");
  });
  it("truncates at a word boundary", () => {
    expect(truncate("one two three four", 12)).toBe("one two…");
  });
  it("extracts unique, normalised CVE IDs", () => {
    expect(extractCves("cve-2026-1234 and CVE-2026-1234, CVE-2025-123456")).toEqual(["CVE-2026-1234", "CVE-2025-123456"]);
  });
  it("only allows http(s) links", () => {
    expect(safeUrl("https://example.com/a")).toBe("https://example.com/a");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("/node/1")).toBeNull();
  });
});

describe("parseRss", () => {
  it("reads CDATA and escaped content", () => {
    const xml = `<rss><channel>
      <item><title><![CDATA[Fish & Chips <b>]]></title><link>https://a.example/1</link>
        <pubDate>Tue, 13 Oct 2026 12:00:00 GMT</pubDate>
        <description>&lt;p&gt;Escaped &amp;amp; HTML&lt;/p&gt;</description>
        <category>One</category><category><![CDATA[Two]]></category></item>
    </channel></rss>`;
    const [item] = parseRss(xml);
    expect(item).toMatchObject({ title: "Fish & Chips <b>", description: "<p>Escaped &amp; HTML</p>", categories: ["One", "Two"] });
    expect(htmlToText(item!.description)).toBe("Escaped & HTML");
  });

  it("drops javascript: links from feed items", () => {
    const xml = `<rss><channel><item><title>x</title><link>javascript:alert(1)</link><guid>g1</guid>
      <pubDate>Tue, 13 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>`;
    const { items } = parseFeed(feed("therecord"), xml);
    expect(items[0]!.url).toBeNull();
  });
});

describe("feeds (real-data fixtures)", () => {
  it("CISA: classifies advisories and drops KEV-addition alerts", () => {
    const { items, skipped } = parseFeed(feed("cisa"), cisaXml);
    expect(skipped).toBe(0);
    expect(items.map((i) => i.tags[0])).toEqual(["ics", "ics", "advisory", "alert"]);
    expect(items.some((i) => /Known Exploited Vulnerabilit/.test(i.title))).toBe(false);
    const advisory = items.find((i) => i.tags[0] === "advisory")!;
    expect(advisory).toMatchObject({ type: "advisory", publishedAt: "2026-10-08T12:00:00.000Z" });
    expect(advisory.cves).toContain("CVE-2015-5477");
    expect(items[0]!.summary).not.toMatch(/^View CSAF/);
    // Joint advisories: summary starts at the executive summary, not the "at a glance" box.
    expect(advisory.summary).toMatch(/^Chinese government-linked cyber/i);
  });

  it("BleepingComputer: parses all items with offsets", () => {
    const { items } = parseFeed(feed("bleepingcomputer"), bleepingXml);
    expect(items).toHaveLength(6);
    expect(items[0]).toMatchObject({
      type: "news",
      title: "Norway fines Microsoft ad firm $9.6 million over Grindr data sharing",
      publishedAt: "2026-10-12T20:13:52.000Z",
    });
    expect(items[0]!.url).toMatch(/^https:\/\/www\.bleepingcomputer\.com\//);
  });

  it("The Record: parses all items", () => {
    const { items } = parseFeed(feed("therecord"), therecordXml);
    expect(items).toHaveLength(5);
    expect(items.every((i) => i.summary && i.url)).toBe(true);
  });

  it("SANS ISC: drops Stormcast podcasts and the date suffix", () => {
    const { items } = parseFeed(feed("sans-isc"), sansXml);
    expect(items.map((i) => i.title)).toEqual([
      "Why TLP should not replace your internal information classification",
      "Reconstructing AI Agent Activity: Two New Scripts for Forensic Review",
    ]);
  });

  it("rejects a non-RSS response", async () => {
    const adapter = rssAdapter(feed("therecord"));
    const html = async () => new Response("<html><body>Maintenance</body></html>", { headers: { ETag: '"x"' } });
    await expect(adapter.fetch(html, { etag: null, lastModified: null })).rejects.toThrow(/not an RSS feed/);
  });
});
