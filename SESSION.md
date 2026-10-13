# Session state

_Read this at the start of a session; update it before you stop. See [CLAUDE.md](CLAUDE.md)._

**Last updated:** 2026-10-13
**Branch:** `dev`

## Current state

- GitHub repo created (public), `main` protected, `dev` is the working branch.
- Worker scaffolded: Hono + TypeScript + Vitest, Access JWT middleware (fails closed, covers static assets), placeholder page and `/api/briefing`, hourly cron stub, D1 binding with placeholder ID. 
- CISA KEV done end to end: hourly cron fetch (ETag/Last-Modified), D1 upsert (writes only changed rows), "Actively exploited" section on the page and in `/api/briefing`, source-status footer. Verified against the live feed locally. 24 tests passing.
- Remote D1 database `sitrep` created (ENAM, ID in `wrangler.jsonc`), migration 0001 applied remotely. Wrangler logged in to the Cloudflare account. Not yet deployed.
- Decided: Cloudflare Workers + static assets (not Pages).
- Decided: Hono (server-rendered JSX) for API + UI; site behind Cloudflare Access with JWT verification in the Worker.
- Decided: v1 sources and build order (see CLAUDE.md → Sources). Team is US-based.

## Next steps

1. Enrich CVEs with EPSS scores and NVD details.
2. Shared RSS adapter: CISA advisories, BleepingComputer, The Record, SANS ISC.
3. ransomware.live adapter.
4. Deploy (`npm run deploy`, run by the user — Claude's auto mode blocks production deploys), then set up Cloudflare Access (Zero Trust dashboard) before the first public deploy; fill `ACCESS_TEAM_DOMAIN` / `ACCESS_AUD`; attach a custom domain (`workers_dev` and preview URLs are already off).

## Open questions

- KEV JSON is ~1.8 MB. Parsing it may exceed the Workers Free plan's 10 ms CPU limit on the hourly cron; verify after first deploy (Workers Paid plan has no such issue). Fetches only parse when the ETag changed.
- Product watchlist (vendors/products in the team's stack to highlight) — revisit after KEV works.

## Log

- 2026-10-13: Repo and branches set up; CLAUDE.md and SESSION.md created.
- 2026-10-13: Chose Workers + static assets over Pages.
- 2026-10-13: Settled v1 sources and build order; team is US-based.
- 2026-10-13: Chose Hono + Cloudflare Access.
- 2026-10-13: Installed Node 24 (nvm); scaffolded the Worker project.
- 2026-10-13: CISA KEV adapter, D1 schema, briefing page.
- 2026-10-13: Created remote D1 database and applied migrations.
