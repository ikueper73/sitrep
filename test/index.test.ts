import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
import { fakeFeed, kevFixture } from "./helpers";

describe("access control", () => {
  // DEV_BYPASS_ACCESS is on in vitest.config.ts, so these also prove the
  // bypass never applies to non-localhost hosts.
  it("rejects requests without an Access JWT", async () => {
    const res = await exports.default.fetch("https://sitrep.example.com/");
    expect(res.status).toBe(403);
  });

  it("rejects requests with an invalid Access JWT", async () => {
    const res = await exports.default.fetch("https://sitrep.example.com/api/briefing", {
      headers: { "Cf-Access-Jwt-Assertion": "not-a-jwt" },
    });
    expect(res.status).toBe(403);
  });

  it("protects static assets too", async () => {
    const res = await exports.default.fetch("https://sitrep.example.com/style.css");
    expect(res.status).toBe(403);
  });

  it("honours the dev bypass on localhost", async () => {
    const res = await exports.default.fetch("http://localhost:8787/");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("sitrep");
  });
});

describe("routes", () => {
  it("serves static assets after the access check", async () => {
    const res = await exports.default.fetch("http://localhost:8787/style.css");
    expect(res.status).toBe(200);
  });

  it("returns the briefing as JSON", async () => {
    const res = await exports.default.fetch("http://localhost:8787/api/briefing");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ exploited: [], sources: [{ id: "kev" }] });
  });

  it("renders the briefing page with source status", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    const res = await exports.default.fetch("http://localhost:8787/");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain("Actively exploited");
    // Date-independent: the fixture's entries may fall outside today's window.
    expect(html).toContain("CISA KEV (catalog 2026.10.08)");
  });
});
