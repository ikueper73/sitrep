# Session state

_Read this at the start of a session; update it before you stop. See [CLAUDE.md](CLAUDE.md)._

**Last updated:** 2026-10-13
**Branch:** `dev`

## Current state

- GitHub repo created (public), `main` protected, `dev` is the working branch.
- Worker scaffolded: Hono + TypeScript + Vitest, Access JWT middleware (fails closed, covers static assets), placeholder page and `/api/briefing`, hourly cron stub, D1 binding with placeholder ID. 
- CISA KEV done end to end: hourly cron fetch (ETag/Last-Modified), D1 upsert (writes only changed rows), "Actively exploited" section on the page and in `/api/briefing`, source-status footer. Verified against the live feed locally. 24 tests passing.
- **v1 released**: PR #1 merged `dev` → `main` (2026-10-13, merge commit d374eca); production matches `main`.
- BleepingComputer replaced by The Hacker News (FeedBurner): BleepingComputer returns 403 to requests from Cloudflare Workers (their block; not worked around). THN promos ([Webinar], Product Walkthrough) are filtered.
- UI polish on `dev`: collapsible sections with standup step-through (Next/Prev, keys, `/#section` links), new palette + Barlow fonts, light/dark. Federal due dates no longer shown in red (they bind US federal agencies, not the team).
- ransomware.live adapter on `dev`: PRO API, "Ransomware activity" section (since last standup, US victims first, top groups, required attribution). Without a key the source footer shows "API key not set". 65 tests. Verified locally with the user's key: 100/100 victims parsed (2026-10-13); /victims/recent covers ~1–2 days, so hourly polling + stored history is what covers weekends.
- RSS sources: CISA advisories (ICS collapsed, KEV-addition alerts dropped), The Hacker News (replaced BleepingComputer), The Record, SANS ISC (Stormcast dropped). New "Advisories" and "Headlines" sections; CVE mentions marked when in KEV. 56 tests; verified against live feeds.
- EPSS + NVD enrichment done on `dev` (not yet deployed): CVSS pill, EPSS likelihood, CISA SSVC "Automatable" badge; list ranked by exploit likelihood. Migration 0002 adds `cve_enrichment`; `npm run deploy` now applies migrations first. 37 tests passing; verified against the live APIs locally.
- **Deployed** to https://sitrep.kueper.cloud behind Cloudflare Access. First production cron (2026-10-13 12:00 UTC) stored all 1,739 KEV entries with no errors on the Workers Free plan. Deploys are run by the user (`npm run deploy`); Claude's auto mode blocks them.
- Cloudflare Access application created for sitrep.kueper.cloud (team `kueper.cloudflareaccess.com`); team domain and AUD in `wrangler.jsonc`.
- Custom domain `sitrep.kueper.cloud` configured in `wrangler.jsonc` (zone is on Cloudflare; goes live on next deploy).
- Remote D1 database `sitrep` created (ENAM, ID in `wrangler.jsonc`), migration 0001 applied remotely. Wrangler logged in to the Cloudflare account. 
- Decided: Cloudflare Workers + static assets (not Pages).
- Decided: Hono (server-rendered JSX) for API + UI; site behind Cloudflare Access with JWT verification in the Worker.
- Decided: v1 sources and build order (see CLAUDE.md → Sources). Team is US-based.

## Next steps

1. Watch the Workers dashboard CPU-time metric for the hourly cron now that all sources run together (Free plan limit: 10 ms per invocation).
2. Product watchlist: built on `dev` (not deployed). Loaded locally from the draft (109 entries). To go live: merge to main, `npm run deploy` (applies migration 0003), then the user runs `npm run watchlist:sql` and `npx wrangler d1 execute sitrep --remote --file private/watchlist-load.sql`. Known tuning: the vendor-wide "Hitachi" entry (a drive configuration tool) matches unrelated "Hitachi Energy" ICS advisories — give it a product term in the CSV. The 4 "review" rows (Windows, Exchange, NetScaler, Cisco IOS) are not loaded until marked yes.
3. Briefing improvements agreed 2026-10-15: (1) Today's focus — done on dev; (2) fewer, better headlines: merge duplicates across outlets, rank by relevance, cap ~10 with "show all"; (3) ransomware: highlight own sectors + a supplier list, collapse the rest; (4) optional "discussed" state with Jira link.

## Open questions

- **ransomware.live terms (checked 2026-10-13):**
  - The free keyless API (v2) is "personal use only, not for corporate or business use", rate-limited to 1 req/min, and frozen.
  - The PRO API (`https://api-pro.ransomware.live`, header `X-API-KEY`, free key from my.ransomware.live) is the supported route. `GET /victims/recent` returns the 100 most recent victims (`victim`, `group`, `attackdate`, `discovered`, `country`, `activity`, `website`, `press`, `permalink`).
  - T&C: no polling more often than every 30 min (hourly is fine); attribution "Source: Ransomware.live" with a link wherever the data is shown; no re-serving the data as an API or feed to third parties.
  - Commercial use needs prior written approval. **Decided 2026-10-13: the user confirmed sitrep's use is non-commercial.** Revisit if that changes.


## Log

- 2026-10-13: Repo and branches set up; CLAUDE.md and SESSION.md created.
- 2026-10-13: Chose Workers + static assets over Pages.
- 2026-10-13: Settled v1 sources and build order; team is US-based.
- 2026-10-13: Chose Hono + Cloudflare Access.
- 2026-10-13: Installed Node 24 (nvm); scaffolded the Worker project.
- 2026-10-13: CISA KEV adapter, D1 schema, briefing page.
- 2026-10-13: Created remote D1 database and applied migrations.
- 2026-10-13: Custom domain and Cloudflare Access configured.
- 2026-10-13: First production deploy; full KEV ingest fits the Free plan CPU limit.
- 2026-10-13: EPSS + NVD enrichment. Found that test storage isn't isolated per test; added reset() before each test. Set `dev.host` so the localhost dev bypass works with a custom-domain route.
- 2026-10-15: "Today's focus" box (improvement 1 of 4 agreed: focus box, fewer/better headlines, relevant ransomware section, optional discussed state).
- 2026-10-14: SitRep logo (radar mark + wordmark) top-left; compact top bar on phones.
- 2026-10-14: "Add to your stack" links on KEV items (exact vendor/product) and ICS advisories (vendor guessed from title) pre-fill the /watchlist form.
- 2026-10-14: Watchlist in the briefing (badge, sort-first, counts), /watchlist page, loader. Vendor-wide entries match headline titles only.
- 2026-10-14: Watchlist draft tooling; inventory-specific rules kept in gitignored `private/`.
- 2026-10-13: v1 merged to `main` (PR #1).
- 2026-10-13: Production showed BleepingComputer 403 (blocks Workers); swapped in The Hacker News.
- 2026-10-13: UI polish: collapsible sections, step-through controls, new palette/fonts.
- 2026-10-13: ransomware.live adapter (non-commercial use confirmed by the user; PRO API; synthetic fixture only, per T&C).
- 2026-10-13: Shared RSS parser + 4 feeds. CISA feed parse optimized from ~27 ms to ~3 ms CPU (decode description head only).
