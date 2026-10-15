import type { Advisory, ExploitedVuln, Headline, SourceStatus, StackMatch } from "./briefing";

/**
 * "Today's focus": the few things worth raising first at the standup. Fixed,
 * explainable rules over data the briefing already has; no new sources.
 */

export type FocusKind = "act" | "news" | "watch" | "check";

export interface FocusItem {
  kind: FocusKind;
  /** One-line headline for the standup. */
  text: string;
  /** Short supporting detail, e.g. which watchlist entry matched. */
  detail: string;
  /** In-page anchor of the item, e.g. "#kev-CVE-2026-1234"; null if there is none. */
  href: string | null;
}

export interface Focus {
  items: FocusItem[];
  /** Candidates beyond the cap, still visible in the sections below. */
  more: number;
}

export const FOCUS_LIMIT = 5;

const KIND_ORDER: Record<FocusKind, number> = { act: 0, news: 1, watch: 2, check: 3 };

function stackDetail(stack: StackMatch[]): string {
  const [first, ...rest] = stack;
  if (!first) return "";
  return `Your stack: ${first.label} (tier ${first.tier})${rest.length ? ` +${rest.length} more` : ""}`;
}

interface Candidate extends FocusItem {
  tier: number;
  epss: number;
}

export function buildFocus(input: {
  exploited: ExploitedVuln[];
  advisories: Advisory[];
  headlines: Headline[];
  sources: SourceStatus[];
}): Focus {
  const candidates: Candidate[] = [];

  for (const v of input.exploited) {
    if (!v.isNew) continue;
    const product = `${v.vendor} ${v.product}`.trim();
    if (v.stack.length) {
      candidates.push({
        kind: "act",
        text: `Newly exploited in your stack: ${v.cve} · ${product}`,
        detail: stackDetail(v.stack),
        href: `#${v.anchor}`,
        tier: v.stack[0]!.tier,
        epss: v.epss?.score ?? 0,
      });
    } else if (v.ransomware) {
      candidates.push({
        kind: "watch",
        text: `Newly exploited, used by ransomware: ${v.cve} · ${product}`,
        detail: "Not on your watchlist — check whether you run it",
        href: `#${v.anchor}`,
        tier: 9,
        epss: v.epss?.score ?? 0,
      });
    }
  }

  for (const a of input.advisories) {
    if (!a.isNew || !a.stack.length) continue;
    candidates.push({
      kind: "act",
      text: `CISA advisory for your stack: ${a.title}`,
      detail: stackDetail(a.stack),
      href: `#${a.anchor}`,
      tier: a.stack[0]!.tier,
      epss: 0,
    });
  }

  for (const h of input.headlines) {
    if (!h.isNew || !h.stack.length) continue;
    candidates.push({
      kind: "news",
      text: h.title,
      detail: `${h.sourceName} · ${stackDetail(h.stack)}`,
      href: `#${h.anchor}`,
      tier: h.stack[0]!.tier,
      epss: 0,
    });
  }

  for (const s of input.sources) {
    if (!s.error) continue;
    candidates.push({
      kind: "check",
      text: `${s.name} is failing — its section may be out of date`,
      detail: s.error,
      href: null,
      tier: 9,
      epss: 0,
    });
  }

  candidates.sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || a.tier - b.tier || b.epss - a.epss);
  const items = candidates.slice(0, FOCUS_LIMIT).map(({ kind, text, detail, href }) => ({ kind, text, detail, href }));
  return { items, more: Math.max(0, candidates.length - FOCUS_LIMIT) };
}
