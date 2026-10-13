import { conditionalGet } from "./http";
import type { NormalisedItem, SourceAdapter } from "./types";

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** One entry of the CISA KEV catalog, as published. */
export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  forensicTriage?: string;
  notes: string;
  cwes?: string[];
}

interface KevCatalog {
  catalogVersion: string;
  vulnerabilities: unknown[];
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isKevEntry(v: unknown): v is KevEntry {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.cveID === "string" &&
    CVE_RE.test(e.cveID) &&
    typeof e.dateAdded === "string" &&
    DATE_RE.test(e.dateAdded) &&
    typeof e.vulnerabilityName === "string"
  );
}

const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");

export function normaliseKevEntry(e: KevEntry): NormalisedItem {
  const tags: string[] = [];
  if (str(e.knownRansomwareCampaignUse) === "Known") tags.push("ransomware");
  if (str(e.forensicTriage) === "Yes") tags.push("forensic-triage");

  return {
    id: `kev:${e.cveID}`,
    source: "kev",
    type: "vuln",
    title: str(e.vulnerabilityName),
    summary: str(e.shortDescription) || null,
    url: `https://nvd.nist.gov/vuln/detail/${e.cveID}`,
    publishedAt: e.dateAdded,
    severity: null, // filled in later from NVD
    cves: [e.cveID],
    vendors: str(e.vendorProject) ? [str(e.vendorProject)] : [],
    products: str(e.product) ? [str(e.product)] : [],
    tags,
    details: {
      requiredAction: str(e.requiredAction),
      dueDate: DATE_RE.test(str(e.dueDate)) ? str(e.dueDate) : null,
      knownRansomwareCampaignUse: str(e.knownRansomwareCampaignUse) || "Unknown",
      forensicTriage: str(e.forensicTriage) || null,
      notes: str(e.notes),
      cwes: Array.isArray(e.cwes) ? e.cwes.filter((c) => typeof c === "string") : [],
    },
  };
}

/** Parses a KEV catalog, skipping (and counting) malformed entries. */
export function parseKevCatalog(json: unknown): {
  version: string | null;
  items: NormalisedItem[];
  skipped: number;
} {
  const catalog = json as Partial<KevCatalog> | null;
  if (!catalog || !Array.isArray(catalog.vulnerabilities)) {
    throw new Error("KEV catalog has no vulnerabilities array");
  }
  const items: NormalisedItem[] = [];
  let skipped = 0;
  for (const entry of catalog.vulnerabilities) {
    if (isKevEntry(entry)) items.push(normaliseKevEntry(entry));
    else skipped++;
  }
  return { version: typeof catalog.catalogVersion === "string" ? catalog.catalogVersion : null, items, skipped };
}

export const kev: SourceAdapter = {
  id: "kev",
  name: "CISA KEV",
  async fetch(fetcher, state) {
    const res = await conditionalGet(fetcher, KEV_URL, state);
    if (!res) return { status: "not-modified" };
    const { version, items, skipped } = parseKevCatalog(await res.response.json());
    if (skipped > 0) console.warn(`kev: skipped ${skipped} malformed entries`);
    return { status: "ok", items, validators: res.validators, version };
  },
};
