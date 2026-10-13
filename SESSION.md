# Session state

_Read this at the start of a session; update it before you stop. See [CLAUDE.md](CLAUDE.md)._

**Last updated:** 2026-10-13
**Branch:** `dev`

## Current state

- GitHub repo created (public), `main` protected, `dev` is the working branch.
- Worker scaffolded: Hono + TypeScript + Vitest, Access JWT middleware (fails closed, covers static assets), placeholder page and `/api/briefing`, hourly cron stub, D1 binding with placeholder ID. 6 tests passing.
- Decided: Cloudflare Workers + static assets (not Pages).
- Decided: Hono (server-rendered JSX) for API + UI; site behind Cloudflare Access with JWT verification in the Worker.
- Decided: v1 sources and build order (see CLAUDE.md → Sources). Team is US-based.

## Next steps

1. CISA KEV end to end: fetch → normalise → store (D1) → API → page.
2. Enrich CVEs with EPSS scores and NVD details.
3. Shared RSS adapter: CISA advisories, BleepingComputer, The Record, SANS ISC.
4. ransomware.live adapter.
5. Before first deploy: `wrangler d1 create sitrep` and put the real ID in `wrangler.jsonc`; set up Cloudflare Access (Zero Trust dashboard) before the first public deploy; fill `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD`; attach a custom domain (`workers_dev` and preview URLs are already off).

## Open questions

- Product watchlist (vendors/products in the team's stack to highlight) — revisit after KEV works.

## Log

- 2026-10-13: Repo and branches set up; CLAUDE.md and SESSION.md created.
- 2026-10-13: Chose Workers + static assets over Pages.
- 2026-10-13: Settled v1 sources and build order; team is US-based.
- 2026-10-13: Chose Hono + Cloudflare Access.
- 2026-10-13: Installed Node 24 (nvm); scaffolded the Worker project.
