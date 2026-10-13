# sitrep

A one-page security briefing for a daily SecOps standup. sitrep collects threat intel from public sources every hour and shows what changed since the last standup, ranked so the most urgent items come first. It runs as a single Cloudflare Worker behind Cloudflare Access.

## What's on the page

The page has four sections. Each one is collapsible, and its collapsed header shows a count and how many items are new, so the collapsed page works as a one-screen overview.

| Section | Contents | Window |
|---|---|---|
| **Actively exploited** | New entries in CISA's Known Exploited Vulnerabilities catalog, with EPSS exploit likelihood, CVSS severity and CISA's "Automatable" assessment. Ranked by exploit likelihood. | Last 7 days |
| **Advisories** | CISA cybersecurity advisories and alerts. ICS advisories are grouped separately. CVEs that are in KEV are highlighted. | Last 7 days |
| **Headlines** | Security news from The Hacker News, The Record and SANS ISC diaries. | Since the last standup |
| **Ransomware activity** | Victims newly posted on ransomware leak sites, with victims in the team's country listed first and the most active groups summarised. | Since the last standup |

"Since the last standup" means since midnight at the start of the previous business day in the team's time zone, so on a Monday it covers the whole weekend. Add `?days=1` to `?days=30` to the URL to widen every section.

For running the standup, the top bar has **Next** and **Prev** buttons that open one section at a time, plus **Expand all** and **Collapse all**. Keyboard shortcuts: `N` or `→` next, `P` or `←` previous, `E` expand all, `C` collapse all. A link like `/#ransomware` opens straight to that section; the other section ids are `exploited`, `advisories` and `headlines`.

The same data is available as JSON at `/api/briefing`, also behind Access.

## Data sources

| Source | Used for | Access |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerabilities | Public JSON |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability per CVE | Public API |
| [NVD](https://nvd.nist.gov/developers/vulnerabilities) | CVSS score and CISA SSVC data per CVE | Public API; a free API key raises the rate limit |
| [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | Advisories section | RSS |
| [The Hacker News](https://thehackernews.com), [The Record](https://therecord.media), [SANS ISC](https://isc.sans.edu) | Headlines section | RSS |
| [Ransomware.live](https://www.ransomware.live) | Ransomware activity section | PRO API, free key required |

**Ransomware.live terms.** Its data is free for non-commercial use; commercial use needs written approval from its owner. Its terms also require visible attribution (the page shows "Source: Ransomware.live"), no polling more often than every 30 minutes, and no re-publishing of its raw data. Read the [terms](https://www.ransomware.live/t&c) before you deploy your own copy. Without a key, that section stays empty and the rest of the page works normally.

## How it works

- **One Cloudflare Worker** built with [Hono](https://hono.dev). Pages are rendered on the server with Hono JSX; a small script adds the standup controls, and the page works without it.
- **Hourly Cron Trigger** fetches every source, normalises items into one shape and stores them in **Cloudflare D1**. Sources run independently: a failing source is shown in the page footer and doesn't affect the others. Sources that support it are fetched with conditional requests, so unchanged feeds cost almost nothing.
- **Enrichment** then adds EPSS and NVD data to every CVE mentioned in the last 30 days, refetching only stale data and respecting NVD's rate limit.
- **Cloudflare Access** guards the site. The Worker also verifies the Access JWT on every request, static files included, and rejects all requests if Access isn't configured. The `workers.dev` and preview URLs are disabled so they can't bypass the login.
- The whole hourly run is designed to fit the **Workers Free plan** (10 ms CPU per invocation).

## Running your own copy

### Prerequisites

- Node.js 22 or later (24 recommended)
- A Cloudflare account with a domain on Cloudflare (for the custom domain and Access)
- Optional: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) and a [Ransomware.live PRO key](https://my.ransomware.live)

### Local development

```bash
npm install
cp .dev.vars.example .dev.vars     # enables the localhost-only login bypass
npm run db:migrate:local
npm run dev                        # http://localhost:8787
```

The local database starts empty. To fetch real data, trigger the hourly job by hand:

```bash
curl localhost:8787/cdn-cgi/handler/scheduled
```

API keys for local runs go in `.dev.vars`, which is gitignored (see `.dev.vars.example`).

### Deploying

`wrangler.jsonc` contains the values for the original deployment. Replace them with your own:

1. **Log in:** `npx wrangler login`
2. **Create the database:** `npx wrangler d1 create sitrep`, then put the returned ID in `d1_databases[0].database_id`.
3. **Set your domain:** change the `routes` pattern to your hostname, e.g. `sitrep.example.com`.
4. **Set up Cloudflare Access:** in the Zero Trust dashboard, create a self-hosted application for that hostname with a policy listing who may log in. Put your team domain (`<team>.cloudflareaccess.com`) in `ACCESS_TEAM_DOMAIN` and the application's AUD tag in `ACCESS_AUD`. Do this before the first deploy, so the site is never reachable without a login.
5. **Add secrets** (optional, but the ransomware section needs its key):
   ```bash
   npx wrangler secret put NVD_API_KEY
   npx wrangler secret put RANSOMWARE_LIVE_API_KEY
   ```
6. **Deploy:** `npm run deploy`. This applies pending database migrations first.

Data appears after the first hourly run, at the top of the next hour.

### Adapting to your team

- **Time zone:** `TEAM_TIME_ZONE` in `src/dates.ts` (default `America/New_York`) decides when "today" and "since the last standup" begin.
- **Country:** `TEAM_COUNTRY` in `src/briefing.ts` (default `US`) decides which ransomware victims are listed first.
- **News feeds:** add or remove RSS feeds in `src/sources/feeds.ts`. Some sites behind Cloudflare block requests from Workers (BleepingComputer does), so after adding a feed, deploy and check that the page footer shows it without errors.

## Commands

| Command | What it does |
|---|---|
| `npm run dev` | Local dev server |
| `npm test` | Tests, run inside the Workers runtime |
| `npm run typecheck` | TypeScript check |
| `npm run cf-typegen` | Regenerate binding types after changing `wrangler.jsonc` |
| `npm run db:migrate:local` | Apply database migrations locally |
| `npm run deploy` | Apply migrations to the remote database, then deploy |

## Project layout

```
src/
  index.tsx         routes and the hourly scheduled handler
  access.ts         Cloudflare Access JWT verification
  ingest.ts         runs all sources independently
  enrich/           EPSS and NVD enrichment
  sources/          one adapter per source, plus the shared RSS parser
  briefing.ts       builds the briefing from the database
  views/            page components (Hono JSX)
public/             stylesheet and the standup controls script
migrations/         D1 schema
test/               Vitest tests and fixtures
```

Test fixtures are trimmed copies of real feed output, except Ransomware.live's, which is synthetic because its terms forbid publishing its raw data.

`CLAUDE.md` holds detailed design notes and conventions; `SESSION.md` tracks current work in progress.
