import { USER_AGENT } from "../sources/http";
import type { Fetcher } from "../sources/types";

export const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export interface NvdInfo {
  status: string | null;
  cvss: {
    score: number;
    severity: string;
    version: string;
    vector: string;
    source: string;
  } | null;
  ssvc: {
    exploitation: string | null;
    automatable: string | null;
    technicalImpact: string | null;
  } | null;
}

// CVSS 3.1 first: it's the version most teams triage by and NVD's own default.
// Within a version, NVD's own (Primary) score beats a CNA's (Secondary) score.
const CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"] as const;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null;
const asArray = (v: unknown): Obj[] => (Array.isArray(v) ? v.filter(isObj) : []);

// NVD identifies some scorers by UUID. This one is CISA's "Vulnrichment" ADP.
const KNOWN_SOURCES: Record<string, string> = {
  "nvd@nist.gov": "nvd",
  "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA-ADP",
};

function v2Severity(score: number): string {
  return score >= 7 ? "high" : score >= 4 ? "medium" : "low";
}

function pickCvss(metrics: Obj): NvdInfo["cvss"] {
  for (const key of CVSS_PREFERENCE) {
    const entries = asArray(metrics[key]).filter((m) => isObj(m.cvssData));
    const chosen = entries.find((m) => m.type === "Primary") ?? entries[0];
    if (!chosen) continue;
    const data = chosen.cvssData as Obj;
    const score = Number(data.baseScore);
    if (!Number.isFinite(score)) continue;
    // v2 keeps baseSeverity outside cvssData, and sometimes omits it.
    const rawSeverity = data.baseSeverity ?? chosen.baseSeverity;
    const severity = typeof rawSeverity === "string" ? rawSeverity.toLowerCase() : v2Severity(score);
    const raw = String(chosen.source ?? "unknown");
    const source = KNOWN_SOURCES[raw] ?? raw;
    return {
      score,
      severity,
      version: String(data.version ?? key.replace("cvssMetricV", "")),
      vector: String(data.vectorString ?? ""),
      source,
    };
  }
  return null;
}

function pickSsvc(metrics: Obj): NvdInfo["ssvc"] {
  // Keyed by SSVC version (currently ssvcV203); take whichever is present.
  const key = Object.keys(metrics).find((k) => k.startsWith("ssvc"));
  const entry = key ? asArray(metrics[key])[0] : undefined;
  const options = isObj(entry?.ssvcData) ? asArray(entry.ssvcData.options) : [];
  if (options.length === 0) return null;
  const merged: Obj = Object.assign({}, ...options);
  const str = (v: unknown) => (typeof v === "string" ? v.toLowerCase() : null);
  return {
    exploitation: str(merged.exploitation),
    automatable: str(merged.automatable),
    technicalImpact: str(merged.technicalImpact),
  };
}

/** Parses an NVD CVE API 2.0 response for a single CVE; null if NVD has no record. */
export function parseNvd(json: unknown): NvdInfo | null {
  if (!isObj(json) || !Array.isArray(json.vulnerabilities)) throw new Error("NVD response has no vulnerabilities array");
  const cve = asArray(json.vulnerabilities)[0]?.cve;
  if (!isObj(cve)) return null;
  const metrics = isObj(cve.metrics) ? cve.metrics : {};
  return {
    status: typeof cve.vulnStatus === "string" ? cve.vulnStatus : null,
    cvss: pickCvss(metrics),
    ssvc: pickSsvc(metrics),
  };
}

export class NvdRateLimitError extends Error {}

export async function fetchNvd(fetcher: Fetcher, cve: string, apiKey?: string): Promise<NvdInfo | null> {
  const headers: Record<string, string> = { "User-Agent": USER_AGENT, Accept: "application/json" };
  if (apiKey) headers.apiKey = apiKey;
  const res = await fetcher(`${NVD_URL}?cveId=${encodeURIComponent(cve)}`, { headers });
  // NVD signals rate limiting with 403 or 429.
  if (res.status === 403 || res.status === 429) throw new NvdRateLimitError(`NVD rate limit (${res.status})`);
  if (!res.ok) throw new Error(`NVD request for ${cve} failed: ${res.status} ${res.statusText}`);
  return parseNvd(await res.json());
}
