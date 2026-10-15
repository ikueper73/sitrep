import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { Advisory, ExploitedVuln, Headline, SourceStatus } from "../src/briefing";
import { buildBriefing } from "../src/briefing";
import { buildFocus, FOCUS_LIMIT } from "../src/focus";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
import { addWatchEntry } from "../src/watchlist/store";
import { fakeFeed, kevFixture } from "./helpers";

const vuln = (o: Partial<ExploitedVuln>): ExploitedVuln => ({
  cve: "CVE-2026-0001", vendor: "Acme", product: "Gateway", name: "", description: null, url: null,
  dateAdded: "2026-10-08", dueDate: null, requiredAction: "", ransomware: false, isNew: true,
  cvss: null, epss: null, automatable: false, stack: [], anchor: "kev-CVE-2026-0001", ...o,
});
const advisory = (o: Partial<Advisory>): Advisory => ({
  kind: "advisory", title: "Advisory", url: null, summary: null, publishedAt: "2026-10-08T12:00:00Z",
  cves: [], kevCves: [], isNew: true, stack: [], anchor: "adv-x", ...o,
});
const headline = (o: Partial<Headline>): Headline => ({
  source: "therecord", sourceName: "The Record", title: "Story", url: null, summary: null,
  publishedAt: "2026-10-08T12:00:00Z", cves: [], kevCves: [], isNew: true, stack: [], anchor: "news-x", ...o,
});
const source = (o: Partial<SourceStatus>): SourceStatus => ({
  id: "x", name: "X", lastSuccessAt: null, lastChangedAt: null, version: null, error: null, ...o,
});
const stack = (tier: number) => [{ label: `Entry T${tier}`, tier }];
const empty = { exploited: [], advisories: [], headlines: [], sources: [] };

describe("buildFocus", () => {
  it("is empty on a quiet day", () => {
    expect(buildFocus(empty)).toEqual({ items: [], more: 0 });
  });

  it("flags newly exploited vulnerabilities in the stack as Act, linking to the card", () => {
    const { items } = buildFocus({ ...empty, exploited: [vuln({ stack: stack(1) })] });
    expect(items).toEqual([
      {
        kind: "act",
        text: "Newly exploited in your stack: CVE-2026-0001 · Acme Gateway",
        detail: "Your stack: Entry T1 (tier 1)",
        href: "#kev-CVE-2026-0001",
      },
    ]);
  });

  it("ignores items that are not new since the last standup", () => {
    const f = buildFocus({
      ...empty,
      exploited: [vuln({ isNew: false, stack: stack(1) }), vuln({ isNew: false, ransomware: true })],
      advisories: [advisory({ isNew: false, stack: stack(1) })],
      headlines: [headline({ isNew: false, stack: stack(1) })],
    });
    expect(f.items).toHaveLength(0);
  });

  it("flags new ransomware-linked KEV entries outside the stack as Watch", () => {
    const { items } = buildFocus({ ...empty, exploited: [vuln({ ransomware: true }), vuln({ cve: "CVE-2026-0002" })] });
    expect(items.map((i) => i.kind)).toEqual(["watch"]);
  });

  it("orders Act, News, Watch, Check; then by tier and exploit likelihood", () => {
    const { items } = buildFocus({
      exploited: [
        vuln({ cve: "CVE-W", ransomware: true }),
        vuln({ cve: "CVE-T2", stack: stack(2), epss: { score: 0.9, percentile: 0.99 } }),
        vuln({ cve: "CVE-T1-low", stack: stack(1), epss: { score: 0.1, percentile: 0.5 } }),
        vuln({ cve: "CVE-T1-high", stack: stack(1), epss: { score: 0.8, percentile: 0.9 } }),
      ],
      advisories: [],
      headlines: [headline({ stack: stack(3) })],
      sources: [source({ name: "The Record", error: "GET failed: 503" })],
    });
    expect(items.map((i) => i.kind)).toEqual(["act", "act", "act", "news", "watch"]);
    expect(items.slice(0, 3).map((i) => i.text.split(": ")[1]!.split(" ")[0])).toEqual(["CVE-T1-high", "CVE-T1-low", "CVE-T2"]);
  });

  it(`caps the list at ${FOCUS_LIMIT} and counts the rest`, () => {
    const exploited = Array.from({ length: 8 }, (_, i) => vuln({ cve: `CVE-2026-000${i}`, stack: stack(1) }));
    const f = buildFocus({ ...empty, exploited });
    expect(f.items).toHaveLength(FOCUS_LIMIT);
    expect(f.more).toBe(3);
  });

  it("reports failing sources as Check, without a link", () => {
    const { items } = buildFocus({ ...empty, sources: [source({ name: "NVD", error: "NVD rate limit (403)" })] });
    expect(items).toEqual([
      { kind: "check", text: "NVD is failing — its section may be out of date", detail: "NVD rate limit (403)", href: null },
    ]);
  });
});

describe("Today's focus on the page", () => {
  // Friday Oct 9 2026, 9am Eastern: the KEV fixture's Oct 8 entries are new.
  const friday = new Date("2026-10-09T13:00:00Z");

  it("is built into the briefing from the stack", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    await addWatchEntry(env.DB, { label: "Apache Struts", vendors: ["Apache"], products: ["struts"], tier: 1, matchText: true }, "x");
    const b = await buildBriefing(env.DB, friday);
    expect(b.focus.items[0]).toMatchObject({ kind: "act", href: "#kev-CVE-2016-3081" });
  });

  it("renders above the sections, with anchors that exist on the page", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    await addWatchEntry(env.DB, { label: "Apache Struts", vendors: ["Apache"], products: ["struts"], tier: 1, matchText: true }, "x");
    const html = await (await exports.default.fetch("http://localhost:8787/?days=30")).text();
    expect(html.indexOf("Today&#39;s focus")).toBeGreaterThan(-1);
    expect(html.indexOf("Today&#39;s focus")).toBeLessThan(html.indexOf('id="exploited"'));
    expect(html).toContain('id="kev-CVE-2016-3081"');
  });

  it("says so when nothing needs attention", async () => {
    const html = await (await exports.default.fetch("http://localhost:8787/")).text();
    expect(html).toContain("Load a watchlist to see what concerns your stack.");
  });
});
