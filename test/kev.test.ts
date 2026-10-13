import { describe, expect, it } from "vitest";
import { kev, parseKevCatalog } from "../src/sources/kev";
import { USER_AGENT } from "../src/sources/http";
import { fakeFeed, kevFixture } from "./helpers";

describe("parseKevCatalog", () => {
  it("normalises every entry of the real-data fixture", () => {
    const { version, items, skipped } = parseKevCatalog(kevFixture);
    expect(version).toBe("2026.10.08");
    expect(skipped).toBe(0);
    expect(items).toHaveLength(kevFixture.vulnerabilities.length);
  });

  it("maps fields and trims stray whitespace", () => {
    const { items } = parseKevCatalog(kevFixture);
    const bind = items.find((i) => i.id === "kev:CVE-2015-5477")!;
    expect(bind).toMatchObject({
      source: "kev",
      type: "vuln",
      title: "ISC BIND Data Processing Errors Vulnerability", // leading space in the feed
      publishedAt: "2026-10-08",
      cves: ["CVE-2015-5477"],
      vendors: ["ISC"],
      products: ["BIND"],
      url: "https://nvd.nist.gov/vuln/detail/CVE-2015-5477",
      severity: null,
    });
    expect(bind.details).toMatchObject({ dueDate: "2026-10-11", cwes: ["CWE-19"] });
  });

  it("tags known ransomware use", () => {
    const { items } = parseKevCatalog(kevFixture);
    expect(items.find((i) => i.id === "kev:CVE-2026-59310")!.tags).toContain("ransomware");
    expect(items.find((i) => i.id === "kev:CVE-2015-5477")!.tags).not.toContain("ransomware");
  });

  it("skips malformed entries instead of failing the whole feed", () => {
    const { items, skipped } = parseKevCatalog({
      catalogVersion: "x",
      vulnerabilities: [kevFixture.vulnerabilities[0], { cveID: "not-a-cve" }, null],
    });
    expect(items).toHaveLength(1);
    expect(skipped).toBe(2);
  });

  it("rejects a catalog without a vulnerabilities array", () => {
    expect(() => parseKevCatalog({ error: "nope" })).toThrow(/vulnerabilities/);
  });
});

describe("kev adapter", () => {
  it("sends a User-Agent and returns validators", async () => {
    const feed = fakeFeed(kevFixture);
    const result = await kev.fetch(feed, { etag: null, lastModified: null });
    expect(feed.calls[0]!.headers.get("User-Agent")).toBe(USER_AGENT);
    expect(result).toMatchObject({ status: "ok", version: "2026.10.08", validators: { etag: '"v1"' } });
  });

  it("returns not-modified when the ETag matches", async () => {
    const result = await kev.fetch(fakeFeed(kevFixture), { etag: '"v1"', lastModified: null });
    expect(result).toEqual({ status: "not-modified" });
  });
});
