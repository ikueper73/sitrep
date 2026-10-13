import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { buildBriefing } from "../src/briefing";
import { previousBusinessDay, teamDate } from "../src/dates";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
import { feedAdapters } from "../src/sources/feeds";
import bleepingXml from "./fixtures/rss/bleepingcomputer.xml?raw";
import cisaXml from "./fixtures/rss/cisa.xml?raw";
import sansXml from "./fixtures/rss/sans-isc.xml?raw";
import therecordXml from "./fixtures/rss/therecord.xml?raw";
import { fakeFeed, kevFixture } from "./helpers";

describe("dates", () => {
  it("uses US Eastern time for the team's date", () => {
    // 03:00 UTC on Oct 9 is still Oct 8 in New York.
    expect(teamDate(new Date("2026-10-09T03:00:00Z"))).toBe("2026-10-08");
  });

  it("skips weekends for the previous business day", () => {
    expect(previousBusinessDay("2026-10-12")).toBe("2026-10-09"); // Mon → Fri
    expect(previousBusinessDay("2026-10-13")).toBe("2026-10-12"); // Tue → Mon
  });
});

describe("buildBriefing", () => {
  // Friday Oct 9 2026, 9am Eastern.
  const standup = new Date("2026-10-09T13:00:00Z");

  it("lists KEV entries in the window, newest first, flagging new ones", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    const b = await buildBriefing(env.DB, standup);
    expect(b.today).toBe("2026-10-09");
    expect(b.newSince).toBe("2026-10-08");
    // The four entries added Oct 8; the August and 2021 entries are outside the 7-day window.
    expect(b.exploited.map((v) => v.cve).sort()).toEqual(
      ["CVE-2015-5477", "CVE-2016-3081", "CVE-2021-3199", "CVE-2023-22894"],
    );
    expect(b.exploited.every((v) => v.isNew)).toBe(true);
  });

  it("widens the window on request", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    const b = await buildBriefing(env.DB, standup, 60);
    const vcenter = b.exploited.find((v) => v.cve === "CVE-2026-59310")!;
    expect(vcenter).toMatchObject({ isNew: false, ransomware: true });
  });

  it("reports source status", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    const b = await buildBriefing(env.DB, standup);
    expect(b.sources.map((s) => s.id)).toEqual([
      "kev", "cisa", "bleepingcomputer", "therecord", "sans-isc", "ransomware-live", "epss", "nvd",
    ]);
    expect(b.sources[0]).toMatchObject({ name: "CISA KEV", version: "2026.10.08", error: null });
  });
});

describe("advisories and headlines", () => {
  // Tuesday Oct 13 2026, 9am Eastern: "new" means since Monday Oct 12, 00:00 Eastern (04:00 UTC).
  const tuesday = new Date("2026-10-13T13:00:00Z");

  async function seed() {
    const bodies: Record<string, string> = {
      "www.cisa.gov": cisaXml,
      "www.bleepingcomputer.com": bleepingXml,
      "therecord.media": therecordXml,
      "isc.sans.edu": sansXml,
    };
    const fetcher = async (input: RequestInfo | URL) => new Response(bodies[new URL(String(input)).hostname]!);
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    await runIngestion(env.DB, fetcher, feedAdapters);
  }

  it("shows headlines since the last standup by default", async () => {
    await seed();
    const b = await buildBriefing(env.DB, tuesday);
    expect(b.headlinesSince).toBe("2026-10-12T04:00:00.000Z");
    // Bleeping: 6 on Mon Oct 12 (US time); The Record: Oct 13 + Oct 12; SANS: nothing since Sat.
    expect(b.headlines).toHaveLength(8);
    expect(b.headlines.every((h) => h.isNew)).toBe(true);
    expect(b.headlines[0]).toMatchObject({ sourceName: "The Record", title: expect.stringContaining("grocery") });
  });

  it("widens headlines with an explicit window", async () => {
    await seed();
    const b = await buildBriefing(env.DB, tuesday, 7);
    expect(b.headlines.length).toBeGreaterThan(8);
    expect(b.headlines.some((h) => h.sourceName === "SANS ISC" && !h.isNew)).toBe(true);
  });

  it("lists CISA advisories with KEV cross-references", async () => {
    await seed();
    const b = await buildBriefing(env.DB, tuesday);
    // Since Oct 6: the joint advisory and two ICS advisories (Oct 8); the Citrix alert (Sep 27) is older.
    expect(b.advisories.map((a) => a.kind).sort()).toEqual(["advisory", "ics", "ics"]);
    const advisory = b.advisories.find((a) => a.kind === "advisory")!;
    // CVE-2015-5477 and CVE-2016-3081 are in the KEV fixture.
    expect(advisory.kevCves).toEqual(expect.arrayContaining(["CVE-2015-5477", "CVE-2016-3081"]));
    expect(advisory.isNew).toBe(false);
  });
});
