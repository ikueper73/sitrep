#!/usr/bin/env node
// Builds a draft product watchlist from the Jira Assets software and vendor
// exports, for a human to review before it is loaded into the database.
//
//   node scripts/watchlist-draft.mjs <software.csv> <vendors.csv> [out.csv] [--force]
//
// Refuses to overwrite an existing draft (it holds review edits) unless --force.
//
// The exports contain internal data (owners, costs, hostnames). They are only
// read here; nothing from them is written into the repo. The draft goes to
// private/ (gitignored) and keeps only names, vendor, tier and match terms.
//
// Inventory-specific rules (curated match terms for named apps, resellers,
// in-house vendors) live in private/watchlist-config.json, also gitignored,
// because they reveal the stack. This file holds only generic logic.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { matchVendorProduct, normalize, vendorMatches } from "../src/watchlist/match.ts";
import { parseCsv, toCsv } from "./lib/csv.mjs";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const args = process.argv.slice(2);
const force = args.includes("--force");
const [softwarePath, vendorsPath, outPath = "private/watchlist-draft.csv"] = args.filter((a) => a !== "--force");
const CONFIG_PATH = "private/watchlist-config.json";
if (!softwarePath || !vendorsPath) {
  console.error("usage: node scripts/watchlist-draft.mjs <software.csv> <vendors.csv> [out.csv] [--force]");
  process.exit(1);
}
// The draft is reviewed and edited by hand: never overwrite it silently.
if (existsSync(outPath) && !force) {
  console.error(`${outPath} exists and may contain review edits. Pass --force to overwrite, or give another output path.`);
  process.exit(1);
}


// ---------- Normalising inventory names ----------

const TIER = { "ISS-35030": 1, "ISS-35031": 2, "ISS-35032": 3 };

/**
 * private/watchlist-config.json (optional):
 *   notAVendor:   vendor names that are resellers/placeholders; the real vendor comes from the app name
 *   inHouse:      vendor names of in-house software (skipped: advisories and news won't name it)
 *   genericNames: extra product names too generic for headline matching
 *   curated:      { "<normalized app name>": { vendors?: string[], products: string[] } }
 */
const config = existsSync(CONFIG_PATH) ? JSON.parse(readFileSync(CONFIG_PATH, "utf8")) : {};
if (!existsSync(CONFIG_PATH)) console.error(`note: ${CONFIG_PATH} not found; using generic rules only`);

const NOT_A_VENDOR = new Set(["none", "not in list", "n a", ...(config.notAVendor ?? [])].map(normalize));
const IN_HOUSE = new Set((config.inHouse ?? []).map(normalize));

// Vendors with at least this many KEV entries are matched per product;
// smaller vendors are matched on the vendor name alone (one row per vendor).
const PER_PRODUCT_MIN_KEV = 3;

// Extra names feeds use for a vendor.
const VENDOR_ALIASES = {
  vmware: ["VMware", "Broadcom"],
  citrix: ["Citrix", "Cloud Software Group"],
  delinea: ["Delinea", "Thycotic"],
  zoho: ["Zoho", "ManageEngine"],
  "igor pavlov": ["7-Zip", "Igor Pavlov"],
  "amazon web services": ["Amazon", "AWS"],
};

function cleanVendor(name) {
  let n = name.split(/\s+dba\s+/i).pop();
  n = n.replace(/\((?:f\/?k\/?a|fka|formerly|now)[^)]*\)/gi, "").replace(/\(([^)]*)\)/g, "");
  n = n.replace(/,?\s*\b(Inc\.?|LLC|L\.?P\.?|Ltd\.?|Limited|Corp\.?|Corporation|GmbH|S\.?p\.?A\.?|plc|Pty|Co\.?)\s*$/gi, "");
  n = n.replace(/,?\s*\b(Inc\.?|LLC|Systems|Technologies|Software|Holdings)\s*$/gi, "");
  return n.replace(/[,\s]+$/, "").trim();
}

// Words that describe packaging, not the product.
const NOISE = new Set(["for", "windows", "desktop", "client", "console", "app", "application", "agent", "enterprise",
  "professional", "pro", "standard", "basic", "full", "host", "online", "plus", "suite", "tools", "tool",
  "production", "legacy", "x64", "and", "the", "global", "lease", "m365"]);

// Names too generic to match headline text on their own.
const GENERIC = new Set(
  ["access", "loop", "photos", "studio", "firewall", "fabric", "sentinel", "defender", "copilot", "planner",
    "whiteboard", "to do", "azure", "git", "linux", "python", "go", "platform", "portal", "simulation",
    ...(config.genericNames ?? [])].map(normalize),
);

function productTerms(appName, vendor) {
  let n = appName.replace(/\(([^)]*)\)/g, " $1 ");
  for (const w of vendor.split(/\s+/)) n = n.replace(new RegExp(`^\\s*${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i"), "");
  const words = normalize(n)
    .split(" ")
    .filter((w) => w && !NOISE.has(w) && !/^(v?\d+(\.\d+)*|20\d\d(sp\d+)?|r\d|sp\d+|\d+[a-z]{1,2})$/.test(w));
  const term = words.join(" ");
  return term ? [term] : [];
}

// Match terms for apps whose inventory name differs from how advisories name
// them, keyed by normalized app name. Inventory-specific: see config.
const CURATED = config.curated ?? {};

// Infrastructure that rarely appears in an application inventory but often in
// KEV. Marked "review": the team confirms what it actually runs.
const SUGGESTED = [
  { label: "Microsoft Windows (clients and servers)", vendors: ["Microsoft"], products: ["windows", "win32k"], tier: 1 },
  { label: "Microsoft Exchange Server (on-premises)", vendors: ["Microsoft"], products: ["exchange server"], tier: 1 },
  { label: "Citrix NetScaler ADC / Gateway", vendors: ["Citrix", "Cloud Software Group"], products: ["netscaler", "adc", "gateway"], tier: 1 },
  { label: "Cisco IOS / IOS XE (network devices)", vendors: ["Cisco"], products: ["ios"], tier: 1 },
];

// ---------- Build ----------

const apps = parseCsv(readFileSync(softwarePath, "utf8")).filter((a) => a.Status === "2");
const vendors = new Map(parseCsv(readFileSync(vendorsPath, "utf8")).map((v) => [v.Key, v]));

console.error("fetching KEV catalog for match statistics…");
const kev = (await (await fetch(KEV_URL)).json()).vulnerabilities;
const kevVendors = [...new Set(kev.map((k) => k.vendorProject.trim()))];
const kevCount = new Map();
for (const k of kev) kevCount.set(normalize(k.vendorProject), (kevCount.get(normalize(k.vendorProject)) ?? 0) + 1);
const kevEntriesFor = (names) => Math.max(0, ...names.map((n) => kevCount.get(normalize(n)) ?? 0));
const yearAgo = new Date(Date.now() - 365 * 864e5).toISOString().slice(0, 10);

const entries = new Map(); // dedupe on vendor + terms

function add(entry, source) {
  const key = `${normalize(entry.vendors[0])}|${entry.products.map(normalize).sort().join(";")}`;
  const existing = entries.get(key);
  if (existing) {
    existing.tier = Math.min(existing.tier, entry.tier);
    existing.apps.push(...entry.apps);
    existing.appNames.push(...entry.appNames);
    existing.notes = [...new Set([...existing.notes, ...entry.notes])];
    existing.headlines &&= entry.headlines;
    return;
  }
  entries.set(key, { ...entry, source });
}

for (const app of apps) {
  const v = vendors.get(app.Vendor);
  const name = app["Application Name"];
  const tier = TIER[app["Software Criticality"]] ?? 3;
  const notes = [];
  let vendor = v ? cleanVendor(v.Name) : "";
  if (IN_HOUSE.has(normalize(vendor))) continue;
  if (!vendor || NOT_A_VENDOR.has(normalize(vendor))) {
    // Reseller or no vendor: take the first word of the app name if a KEV vendor has that name.
    const first = name.split(/\s+/)[0];
    vendor = kevVendors.find((k) => normalize(k) === normalize(first)) ?? "";
  }
  if (v && ["33", "34"].includes(v.Status)) notes.push("vendor marked retired in Jira");

  const curated = CURATED[normalize(name)];
  const vendorNames = curated?.vendors ?? (vendor ? VENDOR_ALIASES[normalize(vendor)] ?? [vendor] : []);
  if (!vendorNames.length) continue; // no vendor at all: nothing reliable to match on

  const perProduct = curated || kevEntriesFor(vendorNames) >= PER_PRODUCT_MIN_KEV;
  const products = curated?.products ?? (perProduct ? productTerms(name, vendor) : []);
  // Generic names are fine for KEV (vendor + product), but would misfire on headline text.
  const generic = products.some((p) => GENERIC.has(p)) || (!products.length && vendorNames.some((n) => GENERIC.has(normalize(n))));
  if (generic) notes.push("generic name: KEV matching only");

  add(
    { label: perProduct ? name : vendorNames[0], vendors: vendorNames, products, tier, apps: [app.Key], appNames: [name], notes, headlines: !generic },
    "inventory",
  );
}
for (const s of SUGGESTED) add({ ...s, apps: [], appNames: [], notes: ["suggested: confirm you run it"], headlines: true }, "suggested");

// KEV statistics per entry, and the default include decision.
const rows = [];
for (const e of entries.values()) {
  const kevVendor = kevVendors.find((k) => vendorMatches(e, k)) ?? "";
  const hits = kevVendor ? kev.filter((k) => matchVendorProduct([e], k.vendorProject, k.product).length) : [];
  const recent = hits.filter((k) => k.dateAdded >= yearAgo);
  let include;
  if (e.source === "suggested") include = "review";
  else if (hits.length > 0 || (kevVendor && e.tier <= 2) || e.tier === 1) include = "yes";
  else include = "no";
  rows.push({
    include,
    tier: e.tier,
    label: e.label,
    apps: [...new Set(e.appNames)].join("; "),
    headlines: e.headlines ? "yes" : "no",
    vendors: e.vendors.join("; "),
    products: e.products.join("; "),
    kevVendor,
    kevAllTime: hits.length,
    kevLast12m: recent.length,
    example: [...new Set(hits.slice(-3).map((k) => `${k.vendorProject} ${k.product}`))].join(" | "),
    jira: e.apps.join(" "),
    notes: e.notes.join("; "),
  });
}

const order = { yes: 0, review: 1, no: 2 };
rows.sort((a, b) => order[a.include] - order[b.include] || a.tier - b.tier || b.kevAllTime - a.kevAllTime || a.label.localeCompare(b.label));

const header = ["include", "tier", "label", "apps", "vendors", "products", "match_headlines", "kev_vendor", "kev_matches_all_time", "kev_matches_last_12m", "example_kev_matches", "jira_keys", "notes"];
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, toCsv([header, ...rows.map((r) => [r.include, r.tier, r.label, r.apps, r.vendors, r.products, r.headlines, r.kevVendor, r.kevAllTime, r.kevLast12m, r.example, r.jira, r.notes])]));

const count = (k) => rows.filter((r) => r.include === k).length;
console.error(`wrote ${rows.length} entries to ${outPath}: ${count("yes")} yes, ${count("review")} review, ${count("no")} no`);
