#!/usr/bin/env node
// Turns a reviewed watchlist draft into SQL for the D1 database.
//
//   node scripts/watchlist-load.mjs [private/watchlist-draft.csv] [private/watchlist-load.sql]
//   npx wrangler d1 execute sitrep --local  --file private/watchlist-load.sql   # local dev
//   npx wrangler d1 execute sitrep --remote --file private/watchlist-load.sql   # production
//
// Only rows with include = "yes" are loaded. Imported rows replace the previous
// import; entries added by hand on /watchlist (source = 'manual') are kept.
// The SQL file describes the team's stack: it stays in private/ (gitignored).

import { readFileSync, writeFileSync } from "node:fs";
import { parseCsv } from "./lib/csv.mjs";

const [inPath = "private/watchlist-draft.csv", outPath = "private/watchlist-load.sql"] = process.argv.slice(2);

const list = (cell) => (cell ?? "").split(";").map((x) => x.trim()).filter(Boolean);
const sql = (v) => (v === null ? "NULL" : typeof v === "number" ? String(v) : `'${String(v).replace(/'/g, "''")}'`);

const rows = parseCsv(readFileSync(inPath, "utf8"));
const now = new Date().toISOString();
const statements = ["DELETE FROM watchlist WHERE source = 'import';"];
let loaded = 0;
const problems = [];

for (const [i, r] of rows.entries()) {
  if (r.include?.trim().toLowerCase() !== "yes") continue;
  const vendors = list(r.vendors);
  if (!vendors.length) {
    problems.push(`line ${i + 2}: "${r.label}" has no vendor, skipped`);
    continue;
  }
  const tier = [1, 2, 3].includes(Number(r.tier)) ? Number(r.tier) : 3;
  statements.push(
    `INSERT INTO watchlist (label, vendors, products, tier, match_headlines, apps, source, created_at, updated_at) VALUES (${[
      sql(r.label || vendors[0]),
      sql(JSON.stringify(vendors)),
      sql(JSON.stringify(list(r.products))),
      tier,
      r.match_headlines?.trim().toLowerCase() === "no" ? 0 : 1,
      sql(JSON.stringify(list(r.apps))),
      sql("import"),
      sql(now),
      sql(now),
    ].join(", ")});`,
  );
  loaded++;
}

writeFileSync(outPath, statements.join("\n") + "\n");
for (const p of problems) console.error(`warning: ${p}`);
console.error(`wrote ${loaded} entries to ${outPath}`);
