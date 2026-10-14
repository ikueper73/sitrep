import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { buildBriefing, type ExploitedVuln, rankExploited } from "../src/briefing";
import { runEnrichment, NVD_PER_RUN_WITHOUT_KEY } from "../src/enrich";
import { parseEpss } from "../src/enrich/epss";
import { parseNvd } from "../src/enrich/nvd";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
import { epssFixture, fakeEnrichmentApis, fakeFeed, kevFixture, nvdBind, nvdVcenter } from "./helpers";

// Friday Oct 9 2026, 9am Eastern.
const now = new Date("2026-10-09T13:00:00Z");
const HOUR = 3600_000;

// The fixture with the vCenter entry (added Aug 18) moved to Oct 1: inside the
// 30-day enrichment window but not "new". The 2021 entry stays outside it.
const feed = structuredClone(kevFixture);
feed.vulnerabilities.find((v) => v.cveID === "CVE-2026-59310")!.dateAdded = "2026-10-01";

const enrichment = async (cve: string) =>
  env.DB.prepare("SELECT * FROM cve_enrichment WHERE cve = ?").bind(cve).first<Record<string, unknown>>();

describe("parseEpss", () => {
  it("parses string scores into numbers", () => {
    const scores = parseEpss(epssFixture);
    expect(scores.get("CVE-2016-3081")).toEqual({ epss: 0.96052, percentile: 0.99877, date: "2026-10-12" });
  });

  it("omits CVEs EPSS doesn't know", () => {
    expect(parseEpss(epssFixture).has("CVE-1999-99999")).toBe(false);
  });
});

describe("parseNvd", () => {
  it("prefers CVSS 3.1 over NVD's own v2 score", () => {
    // CVE-2015-5477 has a CNA v3.1 score (7.5) and an NVD v2 score (7.8).
    expect(parseNvd(nvdBind)!.cvss).toMatchObject({ score: 7.5, severity: "high", version: "3.1", source: "CISA-ADP" });
  });

  it("uses a CNA score when NVD hasn't scored it, and reads SSVC", () => {
    const info = parseNvd(nvdVcenter)!;
    expect(info.cvss).toMatchObject({ score: 9.8, severity: "critical", source: "security@vmware.com" });
    expect(info.ssvc).toEqual({ exploitation: "active", automatable: "yes", technicalImpact: "total" });
  });

  it("returns null when NVD has no record", () => {
    expect(parseNvd({ totalResults: 0, vulnerabilities: [] })).toBeNull();
  });
});

describe("runEnrichment", () => {
  it("enriches CVEs from recent items with EPSS and NVD data", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    const outcomes = await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    // 5 of the 6 entries are within 30 days.
    expect(outcomes).toEqual([
      { source: "epss", checked: 5 },
      { source: "nvd", checked: 5 },
    ]);
    expect(await enrichment("CVE-2026-59310")).toMatchObject({
      epss: 0.02565,
      cvss_score: 9.8,
      cvss_severity: "critical",
      ssvc_automatable: "yes",
      nvd_status: "Analyzed",
    });
    expect(await enrichment("CVE-2021-43890")).toBeNull(); // outside the window
  });

  it("marks CVEs NVD doesn't know as checked, without a score", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    expect(await enrichment("CVE-2016-3081")).toMatchObject({ cvss_score: null, nvd_status: null });
  });

  it("does not refetch fresh data", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    const apis = fakeEnrichmentApis();
    await runEnrichment(env.DB, apis, { now: new Date(now.getTime() + HOUR) });
    expect(apis.calls).toHaveLength(0);
  });

  it("refreshes EPSS daily and rechecks unscored CVEs in NVD daily", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    const apis = fakeEnrichmentApis();
    await runEnrichment(env.DB, apis, { now: new Date(now.getTime() + 25 * HOUR) });
    const nvdCves = apis.calls
      .filter((r) => r.url.includes("nvd.nist.gov"))
      .map((r) => new URL(r.url).searchParams.get("cveId"))
      .sort();
    expect(apis.calls.some((r) => r.url.includes("api.first.org"))).toBe(true);
    // The two scored CVEs aren't due for a week; the three without a score are rechecked.
    expect(nvdCves).toEqual(["CVE-2016-3081", "CVE-2021-3199", "CVE-2023-22894"]);
  });

  it("caps NVD lookups per run without an API key", async () => {
    const many = structuredClone(feed);
    for (let i = 0; i < 8; i++) {
      many.vulnerabilities.push({ ...kevFixture.vulnerabilities[0]!, cveID: `CVE-2026-9000${i}` });
    }
    await runIngestion(env.DB, fakeFeed(many), [kev]);
    const [, nvd] = await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    expect(nvd!.checked).toBe(NVD_PER_RUN_WITHOUT_KEY);
  });

  it("records an NVD rate limit without failing EPSS", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    const [epss, nvd] = await runEnrichment(env.DB, fakeEnrichmentApis({ nvdStatus: 403 }), { now });
    expect(epss).toEqual({ source: "epss", checked: 5 });
    expect(nvd).toMatchObject({ source: "nvd", checked: 0, error: expect.stringMatching(/rate limit/) });
    const b = await buildBriefing(env.DB, now);
    expect(b.sources.find((s) => s.id === "nvd")!.error).toMatch(/rate limit/);
  });
});

describe("briefing with enrichment", () => {
  it("attaches scores and ranks by exploit likelihood", async () => {
    await runIngestion(env.DB, fakeFeed(feed), [kev]);
    await runEnrichment(env.DB, fakeEnrichmentApis(), { now });
    const b = await buildBriefing(env.DB, now, 30);
    // New (Oct 8) entries first, by EPSS; then the older vCenter entry.
    expect(b.exploited.map((v) => v.cve)).toEqual([
      "CVE-2015-5477", // EPSS 0.994
      "CVE-2016-3081", // 0.961
      "CVE-2021-3199", // 0.194
      "CVE-2023-22894", // 0.036
      "CVE-2026-59310", // 0.026, and not new
    ]);
    expect(b.exploited.at(-1)).toMatchObject({
      cvss: { score: 9.8, severity: "critical" },
      epss: { score: 0.02565 },
      automatable: true,
    });
  });

  it("puts unscored entries after scored ones", () => {
    const base: ExploitedVuln = {
      cve: "CVE-A", vendor: "", product: "", name: "", description: null, url: null, dateAdded: "2026-10-08",
      dueDate: null, requiredAction: "", ransomware: false, isNew: true, cvss: null, epss: null, automatable: false, stack: [],
    };
    const scored = { ...base, cve: "CVE-B", epss: { score: 0.01, percentile: 0.5 } };
    expect([base, scored].sort(rankExploited).map((v) => v.cve)).toEqual(["CVE-B", "CVE-A"]);
  });
});
