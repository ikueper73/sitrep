/**
 * Watchlist matching: does a KEV entry (vendor + product) concern something in
 * the team's stack? Kept free of imports so the import script
 * (scripts/watchlist-draft.mjs) can load it directly with Node.
 */

export interface WatchEntry {
  /** Display name, e.g. "Cisco Secure Client (AnyConnect)". */
  label: string;
  /** Vendor names as they may appear in feeds, e.g. ["Cisco"]. */
  vendors: string[];
  /**
   * Product terms; a KEV product matches if it contains any term as whole
   * words. Empty means "any product of this vendor".
   */
  products: string[];
  /** 1 = business critical … 3 = low. */
  tier: number;
  /** False for generic names: match KEV (vendor + product) but not free text. Default true. */
  matchText?: boolean;
}

/** Lowercase, strip accents and punctuation, collapse whitespace. */
export function normalize(s: string): string {
  return s
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/\+\+/g, "pp") // notepad++ → notepadpp
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function containsPhrase(haystack: string, phrase: string): boolean {
  if (!phrase) return false;
  return ` ${haystack} `.includes(` ${phrase} `);
}

/** "hitachi" matches KEV's "Hitachi Vantara"; "microsoft" matches "Microsoft". */
export function vendorMatches(entry: WatchEntry, vendor: string): boolean {
  const v = normalize(vendor);
  return entry.vendors.some((alias) => {
    const a = normalize(alias);
    return a === v || containsPhrase(v, a) || containsPhrase(a, v);
  });
}

export function productMatches(entry: WatchEntry, product: string): boolean {
  if (entry.products.length === 0) return true;
  const p = normalize(product);
  return entry.products.some((term) => containsPhrase(p, normalize(term)));
}

/** Entries that a KEV-style (vendor, product) pair concerns. */
export function matchVendorProduct(entries: WatchEntry[], vendor: string, product: string): WatchEntry[] {
  return entries.filter((e) => vendorMatches(e, vendor) && productMatches(e, product));
}

/**
 * Entries that a piece of free text (a headline or advisory title + summary)
 * concerns: a vendor name must appear, plus one of the product phrases when the
 * entry has any. Entries with matchText === false are skipped.
 */
export function matchText(entries: WatchEntry[], text: string): WatchEntry[] {
  const t = normalize(text);
  if (!t) return [];
  return entries.filter(
    (e) =>
      e.matchText !== false &&
      e.vendors.some((v) => containsPhrase(t, normalize(v))) &&
      (e.products.length === 0 || e.products.some((p) => containsPhrase(t, normalize(p)))),
  );
}
