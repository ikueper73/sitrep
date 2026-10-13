import kevFixture from "./fixtures/kev.json";
import type { Fetcher } from "../src/sources/types";

export { kevFixture };

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
