import epssFixture from "./fixtures/epss.json";
import kevFixture from "./fixtures/kev.json";
import nvdBind from "./fixtures/nvd-CVE-2015-5477.json";
import nvdVcenter from "./fixtures/nvd-CVE-2026-59310.json";
import type { Fetcher } from "../src/sources/types";

export { epssFixture, kevFixture, nvdBind, nvdVcenter };

const EMPTY_NVD = { resultsPerPage: 0, startIndex: 0, totalResults: 0, format: "NVD_CVE", version: "2.0", vulnerabilities: [] };

/**
 * A fake fetch for the EPSS and NVD APIs, backed by the real-data fixtures.
 * EPSS answers only for the CVEs requested; NVD knows the two fixture CVEs.
 */
export function fakeEnrichmentApis(opts: { nvdStatus?: number } = {}): Fetcher & { calls: Request[] } {
  const calls: Request[] = [];
  const nvd: Record<string, unknown> = { "CVE-2015-5477": nvdBind, "CVE-2026-59310": nvdVcenter };
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    calls.push(req);
    const url = new URL(req.url);
    if (url.hostname === "api.first.org") {
      const wanted = new Set(url.searchParams.get("cve")!.split(","));
      return Response.json({ ...epssFixture, data: epssFixture.data.filter((d) => wanted.has(d.cve)) });
    }
    if (url.hostname === "services.nvd.nist.gov") {
      if (opts.nvdStatus) return new Response("rate limited", { status: opts.nvdStatus });
      return Response.json(nvd[url.searchParams.get("cveId")!] ?? EMPTY_NVD);
    }
    return new Response("unexpected host", { status: 500 });
  };
  return Object.assign(fetcher, { calls });
}

/** A fake fetch that serves `body` with an ETag and honours If-None-Match. */
export function fakeFeed(body: unknown, etag = '"v1"'): Fetcher & { calls: Request[] } {
  const calls: Request[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    calls.push(req);
    if (req.headers.get("If-None-Match") === etag) return new Response(null, { status: 304 });
    return Response.json(body, { headers: { ETag: etag, "Last-Modified": "Thu, 08 Oct 2026 20:09:19 GMT" } });
  };
  return Object.assign(fetcher, { calls });
}

export const failingFeed: Fetcher = async () => new Response("upstream down", { status: 503 });
