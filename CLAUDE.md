# sitrep

A web app, hosted on Cloudflare, that collects information-security intel from public sources and presents it as a short, scannable briefing for a daily SecOps standup.

## Session continuity

- **At the start of every session, read [SESSION.md](SESSION.md).** It records current state, decisions made, and the next steps.
- **Before ending a session (or after any meaningful milestone), update SESSION.md**: what changed, what's in progress, what's next, open questions. Keep it short and current; move finished items to the log at the bottom rather than letting the top grow.
- Record durable decisions in the "Decisions" section here once they are settled, not only in SESSION.md.

## Goals

- **Standup-ready**: one page that a team can walk through in ~5–10 minutes. Prioritised, deduplicated, with "what changed since yesterday" front and centre.
- **Public sources only**: no paid feeds. Sources that need a free API key are acceptable if the key is stored as a Worker secret.
- **Cheap and low-maintenance**: fits the Cloudflare free tier where possible; no servers to run.

## Planned architecture (runtime decided; the rest is a proposal — confirm before building)

- **Runtime**: Cloudflare Workers with static assets (decided — not Pages; Pages Functions lack Cron Triggers). One Worker handles cron ingestion, API routes, and serving the frontend.
- **Ingestion**: a Cron Trigger fetches each source on a schedule, normalises items into a common shape, and stores them.
- **Storage**: D1 (SQLite) for normalised items and dedup; KV for cached rendered briefings if needed.
- **API**: Hono routes serving JSON (e.g. `/api/briefing?since=…`).
- **Web framework**: Hono (decided) for API routes and server-rendered pages (Hono JSX); static assets (CSS, small client scripts) served from Worker assets. No SPA build step unless a real need appears.
- **Access control**: the site sits behind Cloudflare Access (decided). The Worker must also verify the `Cf-Access-Jwt-Assertion` JWT on every request (defence in depth), and the `workers.dev` URL must be disabled or covered by Access so it cannot bypass the login.
- **Language**: TypeScript throughout. Tooling: Wrangler, Vitest (with `@cloudflare/vitest-pool-workers`).

### Sources — v1 (decided), in build order

The team is US-based, so US government sources take priority.

| # | Source | Role in the briefing | Access |
|---|---|---|---|
| 1 | CISA KEV catalog | "Actively exploited" section | Public JSON |
| 2 | FIRST EPSS | Enrichment: exploit-probability score per CVE | Public API |
| 2 | NVD CVE API 2.0 | Enrichment: CVSS, description, affected products for CVEs already in the briefing (do not ingest every new CVE) | Public; optional free API key for higher rate limits |
| 3 | CISA advisories (cybersecurity + ICS) | "Advisories" section | RSS |
| 3 | BleepingComputer, The Record, SANS ISC diary | "Headlines" section | RSS |
| 4 | ransomware.live | "Ransomware activity" section | Public API (check free-tier terms) |

All RSS feeds go through one shared parser/adapter. Each step must leave a working, usable briefing.

### Later (not in v1)

- GitHub Security Advisories and vendor PSIRTs (Microsoft, Cisco, Fortinet…): after a product watchlist exists.
- abuse.ch (URLhaus, ThreatFox, MalwareBazaar): IOC-level, better suited to detection tooling; needs auth key.

Always check a source's terms of use and rate limits before adding it, and respect them in the fetch schedule.

## Normalised item shape

Every adapter returns `NormalisedItem` ([src/sources/types.ts](src/sources/types.ts)), stored in the `items` table ([migrations/](migrations/)): `id` (`<source>:<native id>`), `source`, `type` (vuln | advisory | ioc | incident | news), `title`, `summary`, `url`, `publishedAt`, `severity` (normalised or null), `cves[]`, `vendors[]`, `products[]`, `tags[]`, and source-specific `details`. The DB adds `first_seen_at` / `updated_at`; upserts only write rows whose content changed. Cross-source dedup (on CVE ID and canonical URL) happens when building the briefing, not at ingest.

## Briefing rules

- Team time zone is America/New_York. "New" = published on or after the previous business day (Mon → Fri).
- Default window: last 7 days (`?days=1..30` on `/` and `/api/briefing`).
- "Actively exploited" ranking: new items first, then EPSS desc, CVSS desc, date added desc.

## Enrichment rules

- CVEs from items published in the last 30 days are enriched (stored in `cve_enrichment`, joined by CVE ID).
- EPSS: refreshed when older than 20 h; batched 100 per request.
- NVD: one CVE per request, max 5 per run without `NVD_API_KEY` (secret), 30 with one. Never-checked CVEs first. Rechecked daily while unscored, weekly once scored. A 403/429 stops NVD for that run and is shown in the footer.
- CVSS choice: v3.1 > v4.0 > v3.0 > v2; within a version NVD's Primary score beats a CNA/ADP Secondary score. The CISA ADP UUID is labelled `CISA-ADP`.

## Conventions

- **Branches**: work on `dev`. `main` is protected: changes reach it only via pull request (`gh pr create --base main --head dev`). Never push to `main` directly or force-push.
- **Access check**: `DEV_BYPASS_ACCESS=true` (in `.dev.vars` only) skips the JWT check, and only for `localhost` requests. Never set it as a deployed var or secret. Every new route must sit behind `requireAccess` (it is applied to `*`).
- **Secrets**: API keys go in Wrangler secrets (`wrangler secret put`) and `.dev.vars` locally. `.dev.vars` must never be committed.
- **Source adapters**: one module per source, each exporting a fetch + normalise function, with a unit test against a saved fixture of real output. Adapters must fail independently: one broken feed must not break the briefing.
- **Fetching**: set a descriptive `User-Agent`, honour rate limits, and use conditional requests (ETag / If-Modified-Since) where supported.

## Commands

- `npm run dev` — local dev server at http://localhost:8787 (needs `.dev.vars`; copy `.dev.vars.example`)
- `npm run db:migrate:local` — apply D1 migrations to the local database (run once, and after adding a migration)
- `npm test` — Vitest inside the Workers runtime (`@cloudflare/vitest-plugin`; the old `vitest-pool-workers` package is deprecated)
- `npm run typecheck` — `tsc --noEmit`
- `npm run cf-typegen` — regenerate `worker-configuration.d.ts` after any change to `wrangler.jsonc`
- `npm run deploy` — apply pending D1 migrations to the remote database, then deploy. Run by the user: Claude's auto mode blocks production deploys.
- Trigger the cron locally (fetches real feeds): `curl localhost:8787/cdn-cgi/handler/scheduled`

## Layout

- `src/index.tsx` — Hono app (routes) and the `scheduled` handler
- `src/sources/` — one adapter per source (`kev.ts`), shared `http.ts` (User-Agent, conditional GET), `types.ts`
- `src/ingest.ts` — runs all adapters independently; `adapters` list registers sources
- `src/enrich/` — per-CVE enrichment after ingest: `epss.ts`, `nvd.ts` (CVSS + CISA SSVC), `index.ts` (what's due, rate-limit caps)
- `src/store.ts` — D1 access (item upserts, source_state)
- `src/briefing.ts` — builds the briefing from the DB; `src/dates.ts` — team-time-zone date helpers
- `migrations/` — D1 schema migrations
- `src/access.ts` — Cloudflare Access JWT verification middleware (fails closed)
- `src/env.ts` — binding/variable types (`Env` itself is generated by `wrangler types`)
- `src/views/` — Hono JSX components
- `public/` — static assets; served via `ASSETS` only after the Access check (`run_worker_first: true`)
- `test/` — Vitest tests; storage is NOT isolated automatically, so `test/apply-migrations.ts` runs `reset()` + migrations before each test; tests use `exports.default.fetch()` from `cloudflare:workers`. Adapters take an injected `fetcher`, so tests use `fakeFeed()` from `test/helpers.ts` instead of the network. Fixtures in `test/fixtures/` are trimmed copies of real feed output.

## Decisions

- Hosting: a single Cloudflare Worker with static assets (not Pages). Reason: needs Cron Triggers for ingestion, keeps cron + API + frontend in one deployable, and is Cloudflare's recommended path for new projects.
- v1 sources and build order: KEV → EPSS + NVD enrichment → RSS feeds (shared parser: CISA advisories, BleepingComputer, The Record, SANS ISC) → ransomware.live. Team is US-based; no non-US government feeds in v1.
- Web framework: Hono, with server-rendered pages (Hono JSX). Reason: one lightweight framework for API + UI on Workers; a read-mostly briefing doesn't need a client-side SPA.
- Access: Cloudflare Access in front of the site, plus JWT verification in the Worker. Reason: data is public, but the product watchlist reveals the team's stack.
- Production URL: https://sitrep.kueper.cloud (Worker custom domain; `workers.dev` and preview URLs disabled).
- Public GitHub repo: `ikueper73/sitrep`; `main` protected, `dev` for work.
