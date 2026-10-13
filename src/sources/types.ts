export type ItemType = "vuln" | "advisory" | "ioc" | "incident" | "news";
export type Severity = "critical" | "high" | "medium" | "low";

/** The common shape every source adapter normalises into. */
export interface NormalisedItem {
  id: string;
  source: string;
  type: ItemType;
  title: string;
  summary: string | null;
  url: string | null;
  publishedAt: string;
  severity: Severity | null;
  cves: string[];
  vendors: string[];
  products: string[];
  tags: string[];
  details: Record<string, unknown>;
}

/** Conditional-request validators remembered between fetches. */
export interface FetchState {
  etag: string | null;
  lastModified: string | null;
}

export type FetchResult =
  | { status: "not-modified" }
  | { status: "ok"; items: NormalisedItem[]; validators: FetchState; version: string | null };

export type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface SourceAdapter {
  id: string;
  name: string;
  fetch(fetcher: Fetcher, state: FetchState): Promise<FetchResult>;
}
