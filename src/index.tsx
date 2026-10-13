import { Hono } from "hono";
import { requireAccess } from "./access";
import { buildBriefing } from "./briefing";
import type { AppEnv, Bindings } from "./env";
import { runEnrichment } from "./enrich";
import { runIngestion } from "./ingest";
import { BriefingPage } from "./views/Briefing";

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

// Anything not matched above is a static file from ./public.
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(
      (async () => {
        // Ingest first so newly added CVEs are enriched in the same run.
        const ingested = await runIngestion(env.DB);
        const enriched = await runEnrichment(env.DB, fetch, { nvdApiKey: env.NVD_API_KEY });
        console.log(`cron ${controller.cron}: ${JSON.stringify({ ingested, enriched })}`);
      })(),
    );
  },
} satisfies ExportedHandler<Bindings>;
