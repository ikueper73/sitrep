import { Hono } from "hono";
import { requireAccess } from "./access";
import { buildBriefing, DEFAULT_WINDOW_DAYS } from "./briefing";
import type { AppEnv, Bindings } from "./env";
import { runIngestion } from "./ingest";
import { BriefingPage } from "./views/Briefing";

const app = new Hono<AppEnv>();

app.use("*", requireAccess);

function windowDays(param: string | undefined): number {
  const n = Number(param);
  return Number.isInteger(n) && n >= 1 && n <= 30 ? n : DEFAULT_WINDOW_DAYS;
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
      runIngestion(env.DB).then((outcomes) =>
        console.log(`cron ${controller.cron}: ${JSON.stringify(outcomes)}`),
      ),
    );
  },
} satisfies ExportedHandler<Bindings>;
