import { describe, expect, it } from "vitest";
import { env, exports } from "cloudflare:workers";
import { buildBriefing } from "../src/briefing";
import { runIngestion } from "../src/ingest";
import { feedAdapters } from "../src/sources/feeds";
import { kev } from "../src/sources/kev";
import { matchText, matchVendorProduct, normalize, productMatches, vendorMatches, type WatchEntry } from "../src/watchlist/match";
import { addWatchEntry, loadWatchlist } from "../src/watchlist/store";
import cisaXml from "./fixtures/rss/cisa.xml?raw";
import therecordXml from "./fixtures/rss/therecord.xml?raw";
import { fakeFeed, kevFixture } from "./helpers";

const entry = (vendors: string[], products: string[]): WatchEntry => ({ label: "x", vendors, products, tier: 1 });

describe("normalize", () => {
  it("lowercases, strips accents and punctuation", () => {
    expect(normalize("Dassault Systèmes, Inc.")).toBe("dassault systemes inc");
    expect(normalize("Notepad++")).toBe("notepadpp");
  });
});

describe("vendorMatches", () => {
  it("matches aliases and longer KEV vendor names", () => {
    expect(vendorMatches(entry(["VMware", "Broadcom"], []), "Broadcom")).toBe(true);
    expect(vendorMatches(entry(["Hitachi"], []), "Hitachi Vantara")).toBe(true);
    expect(vendorMatches(entry(["Cisco"], []), "Microsoft")).toBe(false);
  });

  it("does not match partial words", () => {
    expect(vendorMatches(entry(["SAP"], []), "Sapphire")).toBe(false);
  });
});

describe("productMatches", () => {
  it("matches whole-word phrases only", () => {
    const e = entry(["Microsoft"], ["sharepoint"]);
    expect(productMatches(e, "SharePoint Server")).toBe(true);
    expect(productMatches(entry(["Cisco"], ["ios"]), "IOS XE Software")).toBe(true);
    expect(productMatches(entry(["Cisco"], ["ios"]), "Adaptive Security Appliance")).toBe(false);
    expect(productMatches(entry(["Microsoft"], ["edge"]), "Exchange Server")).toBe(false);
  });

  it("treats an empty product list as vendor-wide", () => {
    expect(productMatches(entry(["Acme"], []), "Anything")).toBe(true);
  });
});

describe("matchVendorProduct", () => {
  it("requires vendor and product to match", () => {
    const entries = [entry(["Microsoft"], ["sharepoint"]), entry(["Citrix"], ["netscaler", "adc"])];
    expect(matchVendorProduct(entries, "Microsoft", "SharePoint")).toHaveLength(1);
    expect(matchVendorProduct(entries, "Microsoft", "Windows")).toHaveLength(0);
    expect(matchVendorProduct(entries, "Citrix", "NetScaler ADC and NetScaler Gateway")).toHaveLength(1);
  });
});

describe("matchText", () => {
  it("needs the vendor, plus a product term when there are any", () => {
    const entries = [entry(["Microsoft"], ["sharepoint"]), entry(["Yandex"], [])];
    expect(matchText(entries, "Microsoft patches SharePoint zero-day")).toHaveLength(1);
    expect(matchText(entries, "Microsoft patches Windows zero-day")).toHaveLength(0);
    expect(matchText(entries, "Ukraine strikes third Yandex data center")).toHaveLength(1);
  });

  it("skips entries flagged as KEV-only", () => {
    const generic = { ...entry(["Microsoft"], ["access"]), matchText: false };
    expect(matchText([generic], "Microsoft revokes Access for old apps")).toHaveLength(0);
    expect(matchVendorProduct([generic], "Microsoft", "Access")).toHaveLength(1);
  });
});

describe("watchlist in the briefing", () => {
  // Tuesday Oct 13 2026, 9am Eastern.
  const tuesday = new Date("2026-10-13T13:00:00Z");
  const now = "2026-10-13T12:00:00.000Z";

  async function seed() {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    const record = feedAdapters.find((a) => a.id === "therecord")!;
    await runIngestion(env.DB, async () => new Response(therecordXml), [record]);
    await addWatchEntry(env.DB, { label: "Apache Struts", vendors: ["Apache"], products: ["struts"], tier: 1, matchText: true }, now);
    await addWatchEntry(env.DB, { label: "Yandex (test)", vendors: ["Yandex"], products: [], tier: 3, matchText: true }, now);
  }

  it("flags matching KEV entries and ranks them first", async () => {
    await seed();
    const b = await buildBriefing(env.DB, tuesday, 30);
    expect(b.watchlistSize).toBe(2);
    expect(b.exploited[0]).toMatchObject({ cve: "CVE-2016-3081", stack: [{ label: "Apache Struts", tier: 1 }] });
    expect(b.exploited.slice(1).every((v) => v.stack.length === 0)).toBe(true);
  });

  it("flags matching headlines and ranks them first", async () => {
    await seed();
    const b = await buildBriefing(env.DB, tuesday);
    expect(b.headlines[0]).toMatchObject({ title: expect.stringContaining("Yandex"), stack: [{ label: "Yandex (test)" }] });
  });

  it("matches vendor-wide entries on headline titles only", async () => {
    await seed();
    // "Ahold Delhaize" appears in a Record summary, not in its title ("Cyber incident hits grocery stores…").
    await addWatchEntry(env.DB, { label: "Delhaize (vendor-wide)", vendors: ["Ahold Delhaize"], products: [], tier: 2, matchText: true }, now);
    await addWatchEntry(env.DB, { label: "Delhaize grocery", vendors: ["Ahold Delhaize"], products: ["grocery"], tier: 2, matchText: true }, now);
    const b = await buildBriefing(env.DB, tuesday, 7);
    const labels = b.headlines.flatMap((h) => h.stack.map((m) => m.label));
    expect(labels).not.toContain("Delhaize (vendor-wide)");
    expect(labels).toContain("Delhaize grocery");
  });

  it("shows the badge on the page", async () => {
    await seed();
    const html = await (await exports.default.fetch("http://localhost:8787/?days=30")).text();
    expect(html).toContain("Your stack");
    expect(html).toMatch(/1 in your stack/);
  });
});

describe("/watchlist", () => {
  const post = (path: string, body: Record<string, string>, headers: Record<string, string> = { "Sec-Fetch-Site": "same-origin" }) =>
    exports.default.fetch(`http://localhost:8787${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(body).toString(),
      redirect: "manual",
    });

  it("adds and removes entries", async () => {
    const res = await post("/watchlist", { label: "Acme Gateway", vendors: "Acme; Acme Corp", products: "gateway", tier: "1", match_headlines: "yes" });
    expect(res.status).toBe(303);
    const [added] = await loadWatchlist(env.DB);
    expect(added).toMatchObject({ label: "Acme Gateway", vendors: ["Acme", "Acme Corp"], products: ["gateway"], tier: 1, matchText: true, source: "manual" });

    const page = await (await exports.default.fetch("http://localhost:8787/watchlist")).text();
    expect(page).toContain("Acme Gateway");

    expect((await post(`/watchlist/${added!.id}/delete`, {})).status).toBe(303);
    expect(await loadWatchlist(env.DB)).toHaveLength(0);
  });

  it("rejects cross-site form posts", async () => {
    const res = await post("/watchlist", { label: "x", vendors: "y" }, { Origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(await loadWatchlist(env.DB)).toHaveLength(0);
  });

  it("does not delete imported entries from the page", async () => {
    await env.DB.prepare(
      `INSERT INTO watchlist (label, vendors, products, tier, match_headlines, apps, source, created_at, updated_at)
       VALUES ('Imported', '["Acme"]', '[]', 1, 1, '[]', 'import', 'x', 'x')`,
    ).run();
    const [imported] = await loadWatchlist(env.DB);
    await post(`/watchlist/${imported!.id}/delete`, {});
    expect(await loadWatchlist(env.DB)).toHaveLength(1);
  });

  it("is behind the access check", async () => {
    expect((await exports.default.fetch("https://sitrep.example.com/watchlist")).status).toBe(403);
  });
});

describe("Add to your stack", () => {
  const page = async (path: string) => (await exports.default.fetch(`http://localhost:8787${path}`)).text();
  const unescape = (s: string) => s.replace(/&amp;/g, "&");

  it("links KEV items not in the stack to a pre-filled form", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    await addWatchEntry(env.DB, { label: "Apache Struts", vendors: ["Apache"], products: ["struts"], tier: 1, matchText: true }, "x");
    const html = unescape(await page("/?days=30"));
    // ISC BIND is not in the stack: it gets a link with its exact KEV vendor and product.
    expect(html).toContain('href="/watchlist?label=ISC+BIND&vendors=ISC&products=BIND&from=CVE-2015-5477#add"');
    // Apache Struts already is: no link.
    expect(html).not.toContain("from=CVE-2016-3081");
  });

  it("links ICS advisories with a guessed vendor", async () => {
    const cisa = feedAdapters.find((a) => a.id === "cisa")!;
    await runIngestion(env.DB, async () => new Response(cisaXml), [cisa]);
    const html = unescape(await page("/?days=30"));
    expect(html).toContain("/watchlist?label=Satel+Netco+Design&vendors=Satel&products=Netco+Design");
    expect(html).toContain("guessed=1");
  });

  it("pre-fills the form and says where the values came from", async () => {
    const html = await page("/watchlist?label=ISC+BIND&vendors=ISC&products=BIND&from=CVE-2015-5477");
    expect(html).toContain('value="ISC BIND"');
    expect(html).toContain('value="BIND"');
    expect(html).toContain("Pre-filled from <strong>CVE-2015-5477</strong>");
    expect(html).not.toContain("guessed from the advisory title");
  });

  it("warns when the values were guessed", async () => {
    const html = await page("/watchlist?label=Satel+Netco+Design&vendors=Satel&products=Netco+Design&from=x&guessed=1");
    expect(html).toContain("guessed from the advisory title");
  });

  it("escapes pre-filled values", async () => {
    const html = await page(`/watchlist?label=${encodeURIComponent('"><script>alert(1)</script>')}&vendors=x&from=x`);
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("does not save anything until the form is submitted", async () => {
    await page("/watchlist?label=ISC+BIND&vendors=ISC&products=BIND&from=CVE-2015-5477");
    expect(await loadWatchlist(env.DB)).toHaveLength(0);
  });
});
