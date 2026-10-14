import type { WatchItem } from "../watchlist/store";
import { Layout } from "./Layout";

const TIER_NAMES: Record<number, string> = { 1: "Tier 1 · business critical", 2: "Tier 2 · important", 3: "Tier 3 · other" };

function Entry({ e }: { e: WatchItem }) {
  return (
    <li class="watch-entry">
      <div class="watch-head">
        <span class="watch-label">{e.label}</span>
        {e.source === "manual" && <span class="badge badge-kind">Added here</span>}
        {!e.matchText && (
          <span class="badge badge-kind" title="Generic name: matched against KEV vendor + product only, not headline text">
            KEV only
          </span>
        )}
        {e.source === "manual" && (
          <form method="post" action={`/watchlist/${e.id}/delete`} class="inline-form">
            <button type="submit" class="link-button" title="Remove from the watchlist">
              Remove
            </button>
          </form>
        )}
      </div>
      <p class="meta">
        Vendor: {e.vendors.join(", ")}
        {" · "}
        {e.products.length ? <>Products: {e.products.join(", ")}</> : "any product of this vendor"}
      </p>
      {e.apps.length > 0 && <p class="meta">Apps: {e.apps.join(", ")}</p>}
    </li>
  );
}

/** Values for the add form, e.g. from an "Add to your stack" link in the briefing. */
export interface Prefill {
  label: string;
  vendors: string;
  products: string;
  /** What the values came from, e.g. a CVE ID or an advisory title. */
  from: string;
  /** True when vendor/product were guessed (ICS advisory titles). */
  guessed: boolean;
}

export function WatchlistPage({ items, notice, prefill }: { items: WatchItem[]; notice?: string; prefill?: Prefill }) {
  const header = (
    <header class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <span class="brand-name">sitrep</span>
          <span class="brand-date">Watchlist</span>
        </div>
        <p class="topbar-summary">
          {items.length} entries · <a class="topbar-link" href="/">Back to the briefing</a>
        </p>
      </div>
    </header>
  );
  return (
    <Layout title="sitrep · Watchlist" header={header}>
      {notice && <p class="notice">{notice}</p>}

      <section class="section-static" id="add">
        <h2>Add an entry</h2>
        {prefill && (
          <p class={prefill.guessed ? "prefill-note warn" : "prefill-note"}>
            Pre-filled from <strong>{prefill.from}</strong>.{" "}
            {prefill.guessed
              ? "Vendor and product were guessed from the advisory title: check where the vendor name ends."
              : "Check the values, choose a tier, then add."}
          </p>
        )}
        <form method="post" action="/watchlist" class="watch-form">
          <label>
            Name{" "}
            <input name="label" required maxlength={120} placeholder="e.g. Fortinet FortiGate firewalls" value={prefill?.label} autofocus={!!prefill} />
          </label>
          <label>
            Vendor names <input name="vendors" required maxlength={200} placeholder="e.g. Fortinet" value={prefill?.vendors} />
            <small>Separate several with “;”, as advisories may name the vendor differently.</small>
          </label>
          <label>
            Product terms <input name="products" maxlength={300} placeholder="e.g. FortiOS; FortiGate" value={prefill?.products} />
            <small>Leave empty to match any product of the vendor.</small>
          </label>
          <label>
            Tier
            <select name="tier">
              <option value="1">1 · business critical</option>
              <option value="2">2 · important</option>
              <option value="3" selected>
                3 · other
              </option>
            </select>
          </label>
          <label class="check">
            <input type="checkbox" name="match_headlines" value="yes" checked /> Also match headline text (turn off for
            generic names)
          </label>
          <button type="submit" class="primary-button">
            Add to watchlist
          </button>
        </form>
      </section>

      {[1, 2, 3].map((tier) => {
        const group = items.filter((i) => i.tier === tier);
        if (group.length === 0) return null;
        return (
          <details class="section" open={tier === 1}>
            <summary>
              <span class="section-title">{TIER_NAMES[tier]}</span>
              <span class="section-count">{group.length}</span>
            </summary>
            <div class="section-body">
              <ul class="watch-list">
                {group.map((e) => (
                  <Entry e={e} />
                ))}
              </ul>
            </div>
          </details>
        );
      })}

      {items.length === 0 && (
        <p class="muted">
          The watchlist is empty. Load a reviewed draft (see CLAUDE.md) or add entries above.
        </p>
      )}
    </Layout>
  );
}
