import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { runIngestion } from "../src/ingest";
import { kev } from "../src/sources/kev";
import { listSourceStates } from "../src/store";
import { failingFeed, fakeFeed, kevFixture } from "./helpers";

const count = async () =>
  (await env.DB.prepare("SELECT COUNT(*) AS n FROM items").first<{ n: number }>())!.n;

describe("runIngestion", () => {
  it("stores KEV items and records source state", async () => {
    const [outcome] = await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    expect(outcome).toMatchObject({ status: "ok", fetched: 6, written: 6 });
    expect(await count()).toBe(6);
    const [state] = await listSourceStates(env.DB);
    expect(state).toMatchObject({ source: "kev", etag: '"v1"', version: "2026.10.08", last_error: null });
  });

  it("uses the stored ETag and skips unchanged feeds", async () => {
    const feed = fakeFeed(kevFixture);
    await runIngestion(env.DB, feed, [kev]);
    const [second] = await runIngestion(env.DB, feed, [kev]);
    expect(second).toEqual({ source: "kev", status: "not-modified" });
    expect(feed.calls[1]!.headers.get("If-None-Match")).toBe('"v1"');
  });

  it("only rewrites rows whose content changed", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture, '"v1"'), [kev]);
    const changed = structuredClone(kevFixture);
    changed.vulnerabilities[0]!.knownRansomwareCampaignUse = "Known";
    const [outcome] = await runIngestion(env.DB, fakeFeed(changed, '"v2"'), [kev]);
    expect(outcome).toMatchObject({ status: "ok", fetched: 6, written: 1 });
  });

  it("records a failing source without throwing", async () => {
    const [outcome] = await runIngestion(env.DB, failingFeed, [kev]);
    expect(outcome).toMatchObject({ status: "error" });
    const [state] = await listSourceStates(env.DB);
    expect(state!.last_error).toMatch(/503/);
  });

  it("keeps existing items when a later fetch fails", async () => {
    await runIngestion(env.DB, fakeFeed(kevFixture), [kev]);
    await runIngestion(env.DB, failingFeed, [kev]);
    expect(await count()).toBe(6);
  });
});
