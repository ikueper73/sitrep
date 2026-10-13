import type { FetchState, Fetcher } from "./types";

export const USER_AGENT = "sitrep/0.1 (+https://github.com/ikueper73/sitrep)";

/**
 * GET with a descriptive User-Agent and conditional-request headers.
 * Returns null on 304 Not Modified; throws on any other non-2xx response.
 */
export async function conditionalGet(
  fetcher: Fetcher,
  url: string,
  state: FetchState,
  accept = "application/json",
): Promise<{ response: Response; validators: FetchState } | null> {
  const headers = new Headers({ "User-Agent": USER_AGENT, Accept: accept });
  if (state.etag) headers.set("If-None-Match", state.etag);
  if (state.lastModified) headers.set("If-Modified-Since", state.lastModified);

  const response = await fetcher(url, { headers });
  if (response.status === 304) return null;
  if (!response.ok) {
    throw new Error(`GET ${url} failed: ${response.status} ${response.statusText}`);
  }
  return {
    response,
    validators: {
      etag: response.headers.get("ETag"),
      lastModified: response.headers.get("Last-Modified"),
    },
  };
}
