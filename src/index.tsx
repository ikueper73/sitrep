import { Hono } from "hono";
import { requireAccess } from "./access";
import type { AppEnv, Bindings } from "./env";
import { Layout } from "./views/Layout";

const app = new Hono<AppEnv>();

app.use("*", requireAccess);

app.get("/", (c) =>
  c.html(
    <Layout title="sitrep">
      <header>
        <h1>sitrep</h1>
        <p class="muted">Daily SecOps briefing</p>
      </header>
      <p>No sources connected yet.</p>
    </Layout>,
  ),
);

app.get("/api/briefing", (c) => c.json({ generatedAt: new Date().toISOString(), items: [] }));

// Anything not matched above is a static file from ./public.
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,

  async scheduled(controller, env, ctx) {
    // Source ingestion runs here; adapters are added one at a time (see SESSION.md).
    console.log(`cron ${controller.cron} fired at ${new Date(controller.scheduledTime).toISOString()}`);
  },
} satisfies ExportedHandler<Bindings>;
