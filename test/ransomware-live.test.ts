import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { buildBriefing } from "../src/briefing";
import { runIngestion } from "../src/ingest";
import { parseRecentVictims, parseRlDate, ransomwareLive, RANSOMWARE_LIVE_URL } from "../src/sources/ransomware-live";
import victimsFixture from "./fixtures/ransomware-live-recent.json";
import { fakeFeed } from "./helpers";

describe("parseRlDate", () => {
  it("reads ransomware.live timestamps as UTC", () => {
    expect(parseRlDate("2026-10-12 14:05:11.482913")).toBe("2026-10-12T14:05:11.000Z");
    expect(parseRlDate("2026-10-12 18:40")).toBe("2026-10-12T18:40:00.000Z");
    expect(parseRlDate("2026-10-11")).toBe("2026-10-11T00:00:00.000Z");
    expect(parseRlDate("2026-10-12T14:05:11+02:00")).toBe("2026-10-12T12:05:11.000Z");
    expect(parseRlDate("not a date")).toBeNull();
  });
});

describe("parseRecentVictims", () => {
  it("normalises victims and skips malformed ones", () => {
    const { items, skipped } = parseRecentVictims(victimsFixture);
    expect(items).toHaveLength(4);
    expect(skipped).toBe(1);
    expect(items[0]).toMatchObject({
      id: "ransomware-live:RXhhbXBsZSBMb2dpc3RpY3MgSW5jLkBxaWxpbg==",
      type: "incident",
      title: "Example Logistics Inc.",
      publishedAt: "2026-10-12T14:05:11.000Z",
      tags: ["qilin"],
      details: { group: "qilin", country: "US", sector: "Transportation/Logistics" },
    });
  });

  it("normalises group and country case, drops 'Not Found' sectors and unsafe links", () => {
    const { items } = parseRecentVictims(victimsFixture);
    expect(items[1]!.details).toMatchObject({ group: "akira", press: "https://news.example/akira-maschinenbau" });
    expect(items[2]).toMatchObject({ url: null, details: { country: "US" } });
    expect(items[3]!.details).toMatchObject({ sector: null });
  });

  it("rejects a non-list response", () => {
    expect(() => parseRecentVictims({ error: "Invalid API key" })).toThrow(/not a list/);
  });
});

describe("ransomwareLive adapter", () => {
  it("fails clearly without an API key", async () => {
    await expect(ransomwareLive(undefined).fetch(fakeFeed([]), { etag: null, lastModified: null })).rejects.toThrow(
      /API key not set/,
    );
  });

  it("sends the key in X-API-KEY", async () => {
    const feed = fakeFeed(victimsFixture);
    const result = await ransomwareLive("secret-key").fetch(feed, { etag: null, lastModified: null });
    expect(feed.calls[0]!.url).toBe(RANSOMWARE_LIVE_URL);
    expect(feed.calls[0]!.headers.get("X-API-KEY")).toBe("secret-key");
    expect(result).toMatchObject({ status: "ok", items: expect.any(Array) });
  });

  it("records a missing key as a source error without breaking ingestion", async () => {
    const [outcome] = await runIngestion(env.DB, fakeFeed([]), [ransomwareLive(undefined)]);
    expect(outcome).toMatchObject({ status: "error", error: expect.stringMatching(/API key not set/) });
  });
});

describe("ransomware section", () => {
  // Tuesday Oct 13 2026, 9am Eastern: since Monday Oct 12, 04:00 UTC.
  const tuesday = new Date("2026-10-13T13:00:00Z");

  it("lists victims since the last standup, US first, with a summary", async () => {
    await runIngestion(env.DB, fakeFeed(victimsFixture), [ransomwareLive("k")]);
    const { ransomware } = await buildBriefing(env.DB, tuesday);
    // "Old Victim SA" (Oct 9) is before the window.
    expect(ransomware.victims.map((v) => v.victim)).toEqual([
      "Example Health Partners", // US, newest
      "Example Logistics Inc.", // US
      "Beispiel Maschinenbau GmbH",
    ]);
    expect(ransomware.summary).toEqual({
      total: 3,
      inTeamCountry: 2,
      topGroups: [
        { group: "qilin", count: 2 },
        { group: "akira", count: 1 },
      ],
    });
  });

  it("shows the required attribution on the page", async () => {
    await runIngestion(env.DB, fakeFeed(victimsFixture), [ransomwareLive("k")]);
    const { exports } = await import("cloudflare:workers");
    const html = await (await exports.default.fetch("http://localhost:8787/?days=30")).text();
    expect(html).toContain("Ransomware activity");
    expect(html).toMatch(/Source:\s*<a href="https:\/\/www\.ransomware\.live"/);
  });
});
