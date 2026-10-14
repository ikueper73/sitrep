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
| 3 | The Hacker News, The Record, SANS ISC diary | "Headlines" section | RSS |
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
- Advisories (CISA): same window as KEV. ICS advisories are collapsed into one group. "CISA Adds … to KEV" alerts are dropped (duplicate the KEV section).
- Headlines (news feeds): default "since the last standup" (previous business day, 00:00 Eastern); an explicit `?days=` widens them.
- CVEs mentioned by advisories/headlines are extracted, enriched, and marked "KEV" when in the catalog.

## CPU budget (Workers Free plan: 10 ms per invocation)

The whole cron run (all sources + enrichment) shares one 10 ms CPU budget. CISA's RSS is ~1.2 MB with full advisory text and no ETag, so it is parsed every hour: the RSS parser decodes only the first 2,500 chars of each description and searches the raw text for CVEs (~3 ms vs ~27 ms naive, measured in Node). KEV JSON parse is ~3 ms but only when the catalog changes. Check the dashboard CPU metric after adding sources; benchmark large feeds before adding them.

## UI

- Palette and type follow a corporate scheme the user picked: navy `#09244f`, blue `#006e96`, dark grey `#464747`, light grey `#f9f8f8`, lime accent `#d0df00`, green `#4f8309`; Barlow (body) and Barlow Condensed (headings, labels), loaded from Google Fonts. Colours, not logos or names. All colours are tokens on `:root`, with a navy dark mode.
- Each section is a `<details class="section">`, collapsed by default; its summary shows the count, "N new" and context, so the collapsed page is itself a summary.
- `app.js` adds standup controls: Next/Prev (one section open at a time), Expand/Collapse all, keys N/→, P/←, E, C. `/#<section-id>` opens that section (ids: exploited, advisories, headlines, ransomware). The page must keep working without JS.
- Screenshots: `chromium --headless=new --screenshot=… "http://localhost:8787/#advisories"` while `npm run dev` runs. Headless screenshots of a scrolled page show the sticky header mid-page; that's a capture artefact, not a bug.

## Product watchlist

- Source: the team's Jira Assets exports (software + vendor objects). They contain internal data (owners, costs, hosts) and stay outside the repo.
- `node scripts/watchlist-draft.mjs <software.csv> <vendors.csv>` builds `private/watchlist-draft.csv` for human review, with historical KEV match counts per entry.
- `private/` is gitignored and holds everything inventory-specific: the draft, and `private/watchlist-config.json` (curated match terms per app, resellers, in-house vendors). **Never commit inventory-derived names, hosts, resellers or the company name: the repo is public.** The watchlist itself will live only in D1, behind Access.
- Workflow: `node scripts/watchlist-draft.mjs <software.csv> <vendors.csv>` → review `private/watchlist-draft.csv` (the script refuses to overwrite it; `--force` to regenerate) → `npm run watchlist:sql` writes `private/watchlist-load.sql` (include = yes rows; replaces the previous import, keeps entries added on /watchlist) → `npm run watchlist:load:local`, or for production the user runs `npx wrangler d1 execute sitrep --remote --file private/watchlist-load.sql`.
- "Add to your stack" links (KEV items: exact vendor/product; ICS advisories: first title word guessed as vendor, flagged on the form) open `/watchlist?label=…&vendors=…&products=…&from=…#add`. GET only pre-fills; saving needs the form POST.
- Storage: `watchlist` table (migration 0003). `/watchlist` lists entries and adds/removes hand-added ones (POSTs require same-origin: Sec-Fetch-Site or Origin host). Imported entries are edited via the CSV, not the page.
- In the briefing: KEV items match on vendor + product; advisories and headlines match on text. Vendor-wide entries (no product terms) match titles only; entries with product terms match title + summary. Matches get a "Your stack" badge, sort first (by tier), and are counted per section and in the top bar.
- Matching (`src/watchlist/match.ts`, dependency-free so the Node script can import it): vendor alias + product phrase (whole words). Vendors with >= 3 KEV entries are matched per product; smaller vendors on vendor name alone. Generic product names are matched against KEV (vendor + product) but not against headline text.

## Enrichment rules

- CVEs from items published in the last 30 days are enriched (stored in `cve_enrichment`, joined by CVE ID).
- EPSS: refreshed when older than 20 h; batched 100 per request.
- NVD: one CVE per request, max 5 per run without `NVD_API_KEY` (secret), 30 with one. Never-checked CVEs first. Rechecked daily while unscored, weekly once scored. A 403/429 stops NVD for that run and is shown in the footer.
- CVSS choice: v3.1 > v4.0 > v3.0 > v2; within a version NVD's Primary score beats a CNA/ADP Secondary score. The CISA ADP UUID is labelled `CISA-ADP`.

## Conventions

- **Branches**: work on `dev` (check `git branch --show-current` before committing; the user may have `main` checked out after a deploy). `main` is protected: changes reach it only via pull request (`gh pr create --base main --head dev`), merged with a merge commit (not squash), then fast-forward `dev` to `main`. Never push to `main` directly or force-push.
- **Releases**: `main` is what runs in production. Try changes from `dev` locally; deploy (`npm run deploy`, run by the user) from `main` after merging.
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
- Stop a background dev server with `pkill -x workerd; pkill -f '[n]ode.*[w]rangler'` as a command of its own. `pkill -f` matches full command lines, including the shell running it: never put the unbracketed process name anywhere in the same command.

## Layout

- `src/index.tsx` — Hono app (routes) and the `scheduled` handler
- `src/sources/` — one adapter per source (`kev.ts`), shared `http.ts` (User-Agent, conditional GET), `types.ts`
- Feeds must be reachable from Cloudflare Workers: some sites behind Cloudflare block Worker requests (BleepingComputer returns 403 from Workers, 200 elsewhere). Respect such blocks; don't proxy or disguise requests. Prefer feeds not served via Cloudflare, and check the source footer after deploying a new feed.
- `src/sources/rss.ts` — shared RSS 2.0 parser (regex-based; Workers has no XML parser) and `rssAdapter()`; `feeds.ts` — per-feed config and filters
- `src/ingest.ts` — runs all adapters independently; `adapters` list registers sources
- `src/enrich/` — per-CVE enrichment after ingest: `epss.ts`, `nvd.ts` (CVSS + CISA SSVC), `index.ts` (what's due, rate-limit caps)
- `src/store.ts` — D1 access (item upserts, source_state)
- `src/briefing.ts` — builds the briefing from the DB; `src/dates.ts` — team-time-zone date helpers
- `migrations/` — D1 schema migrations
- `src/access.ts` — Cloudflare Access JWT verification middleware (fails closed)
- `src/env.ts` — binding/variable types (`Env` itself is generated by `wrangler types`)
- `src/views/` — Hono JSX components
- `public/` — static assets; served via `ASSETS` only after the Access check (`run_worker_first: true`). `style.css` (colour tokens for light/dark), `app.js` (standup step-through controls)
- `test/` — Vitest tests; storage is NOT isolated automatically, so `test/apply-migrations.ts` runs `reset()` + migrations before each test; tests use `exports.default.fetch()` from `cloudflare:workers`. Adapters take an injected `fetcher`, so tests use `fakeFeed()` from `test/helpers.ts` instead of the network. Fixtures in `test/fixtures/` are trimmed copies of real feed output.

## Decisions

- Hosting: a single Cloudflare Worker with static assets (not Pages). Reason: needs Cron Triggers for ingestion, keeps cron + API + frontend in one deployable, and is Cloudflare's recommended path for new projects.
- v1 sources and build order: KEV → EPSS + NVD enrichment → RSS feeds (shared parser: CISA advisories, The Hacker News, The Record, SANS ISC) → ransomware.live. Team is US-based; no non-US government feeds in v1.
- Web framework: Hono, with server-rendered pages (Hono JSX). Reason: one lightweight framework for API + UI on Workers; a read-mostly briefing doesn't need a client-side SPA.
- Access: Cloudflare Access in front of the site, plus JWT verification in the Worker. Reason: data is public, but the product watchlist reveals the team's stack.
- Production URL: https://sitrep.kueper.cloud (Worker custom domain; `workers.dev` and preview URLs disabled).
- ransomware.live via the PRO API (free key, `RANSOMWARE_LIVE_API_KEY`). Use is non-commercial (user-confirmed). T&C: poll no more than every 30 min, show "Source: Ransomware.live" with a link wherever its data appears, don't re-serve its data to third parties, and never commit its raw data (the repo is public; its test fixture is synthetic).
- Public GitHub repo: `ikueper73/sitrep`; `main` protected, `dev` for work.
