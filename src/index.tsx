import { Hono } from "hono";
import { requireAccess } from "./access";
import { buildBriefing } from "./briefing";
import type { AppEnv, Bindings } from "./env";
import { runEnrichment } from "./enrich";
import { createAdapters, runIngestion } from "./ingest";
import { BriefingPage } from "./views/Briefing";
import { WatchlistPage } from "./views/Watchlist";
import { addWatchEntry, deleteWatchEntry, loadWatchlist } from "./watchlist/store";
import type { MiddlewareHandler } from "hono";

const app = new Hono<AppEnv>();

app.use("*", requireAccess);

/** `?days=1..30`; anything else means "use each section's default window". */
function windowDays(param: string | undefined): number | undefined {
  const n = Number(param);
  return param !== undefined && Number.isInteger(n) && n >= 1 && n <= 30 ? n : undefined;
}

app.get("/", async (c) => {
  const briefing = await buildBriefing(c.env.DB, new Date(), windowDays(c.req.query("days")));
  return c.html(<BriefingPage b={briefing} />);
});

app.get("/api/briefing", async (c) => {
  return c.json(await buildBriefing(c.env.DB, new Date(), windowDays(c.req.query("days"))));
});

/**
 * State-changing requests must come from this site's own pages. Access's
 * session cookie would otherwise let another site submit forms as the user.
 */
const sameOrigin: MiddlewareHandler<AppEnv> = async (c, next) => {
  const site = c.req.header("Sec-Fetch-Site");
  const origin = c.req.header("Origin");
  const ok = site === "same-origin" || (!!origin && new URL(origin).hostname === new URL(c.req.url).hostname);
  if (!ok) return c.text("Forbidden", 403);
  return next();
};

const list = (v: unknown) =>
  typeof v === "string"
    ? v.split(/[;,]/).map((x) => x.trim()).filter(Boolean).slice(0, 20)
    : [];

app.get("/watchlist", async (c) => {
  return c.html(<WatchlistPage items={await loadWatchlist(c.env.DB)} notice={c.req.query("notice")} />);
});

app.post("/watchlist", sameOrigin, async (c) => {
  const form = await c.req.parseBody();
  const label = typeof form.label === "string" ? form.label.trim().slice(0, 120) : "";
  const vendors = list(form.vendors);
  if (!label || vendors.length === 0) return c.redirect("/watchlist?notice=Name and vendor are required.", 303);
  const tier = [1, 2, 3].includes(Number(form.tier)) ? Number(form.tier) : 3;
  await addWatchEntry(
    c.env.DB,
    { label, vendors, products: list(form.products), tier, matchText: form.match_headlines === "yes" },
    new Date().toISOString(),
  );
  return c.redirect(`/watchlist?notice=${encodeURIComponent(`Added “${label}”.`)}`, 303);
});

app.post("/watchlist/:id/delete", sameOrigin, async (c) => {
  const id = Number(c.req.param("id"));
  const removed = Number.isInteger(id) && (await deleteWatchEntry(c.env.DB, id));
  return c.redirect(`/watchlist?notice=${removed ? "Entry removed." : "Entry not found."}`, 303);
});

// Anything not matched above is a static file from ./public.
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(
      (async () => {
        // Ingest first so newly added CVEs are enriched in the same run.
        const ingested = await runIngestion(env.DB, fetch, createAdapters(env));
        const enriched = await runEnrichment(env.DB, fetch, { nvdApiKey: env.NVD_API_KEY });
        console.log(`cron ${controller.cron}: ${JSON.stringify({ ingested, enriched })}`);
      })(),
    );
  },
} satisfies ExportedHandler<Bindings>;
