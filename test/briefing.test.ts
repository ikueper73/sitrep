import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { buildBriefing } from "../src/briefing";
import { previousBusinessDay, teamDate } from "../src/dates";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
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
    expect(b.sources).toEqual([
      expect.objectContaining({ id: "kev", name: "CISA KEV", version: "2026.10.08", error: null }),
    ]);
  });
});
