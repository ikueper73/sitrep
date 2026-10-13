import { USER_AGENT } from "../sources/http";
import type { Fetcher } from "../sources/types";

export const EPSS_URL = "https://api.first.org/data/v1/epss";
/** The API's default page size; also keeps the query string well under URL length limits. */
export const EPSS_BATCH = 100;

export interface EpssScore {
  epss: number;
  percentile: number;
  date: string;
}

/** Parses an EPSS API response. CVEs EPSS doesn't know are simply absent. */
export function parseEpss(json: unknown): Map<string, EpssScore> {
  const data = (json as { data?: unknown } | null)?.data;
  if (!Array.isArray(data)) throw new Error("EPSS response has no data array");
  const scores = new Map<string, EpssScore>();
  for (const row of data as Record<string, unknown>[]) {
    const epss = Number(row?.epss);
    const percentile = Number(row?.percentile);
    if (typeof row?.cve !== "string" || !Number.isFinite(epss) || !Number.isFinite(percentile)) continue;
    scores.set(row.cve, { epss, percentile, date: typeof row.date === "string" ? row.date : "" });
  }
  return scores;
}

/** Fetches EPSS scores for up to EPSS_BATCH CVEs in one request. */
export async function fetchEpss(fetcher: Fetcher, cves: string[]): Promise<Map<string, EpssScore>> {
  if (cves.length === 0) return new Map();
  if (cves.length > EPSS_BATCH) throw new Error(`fetchEpss: at most ${EPSS_BATCH} CVEs per call`);
  const url = `${EPSS_URL}?cve=${cves.join(",")}`;
  const res = await fetcher(url, { headers: { "User-Agent": USER_AGENT, Accept: "application/json" } });
  if (!res.ok) throw new Error(`EPSS request failed: ${res.status} ${res.statusText}`);
  return parseEpss(await res.json());
}
