import type { Child } from "hono/jsx";
import {
  type Advisory,
  type Briefing,
  type ExploitedVuln,
  type Headline,
  type RansomwareVictim,
  type SourceStatus,
  type StackMatch,
  TEAM_COUNTRY,
} from "../briefing";
import { formatDate, TEAM_TIME_ZONE } from "../dates";
import { Layout } from "./Layout";

function formatTime(iso: string): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: TEAM_TIME_ZONE,
    timeZoneName: "short",
  }).format(new Date(iso));
}

function formatPercent(p: number): string {
  const pct = p * 100;
  return pct >= 10 ? `${pct.toFixed(0)}%` : pct >= 1 ? `${pct.toFixed(1)}%` : `${pct.toFixed(2)}%`;
}

function ordinal(n: number): string {
  const s = n % 100 >= 11 && n % 100 <= 13 ? "th" : ({ 1: "st", 2: "nd", 3: "rd" } as Record<number, string>)[n % 10] ?? "th";
  return `${n}${s}`;
}

function CvssPill({ cvss }: { cvss: NonNullable<ExploitedVuln["cvss"]> }) {
  const sev = cvss.severity || "none";
  const scoredBy = cvss.source === "nvd" ? "NVD" : cvss.source === "CISA-ADP" ? "CISA (ADP)" : `CNA (${cvss.source})`;
  return (
    <span class={`badge sev-${sev}`} title={`CVSS ${cvss.version}, scored by ${scoredBy}`}>
      {cvss.score.toFixed(1)} {sev.toUpperCase()}
    </span>
  );
}

function EpssTag({ epss }: { epss: NonNullable<ExploitedVuln["epss"]> }) {
  const pctile = Math.floor(epss.percentile * 100);
  return (
    <span
      class={epss.score >= 0.1 ? "epss epss-high" : "epss"}
      title={`FIRST EPSS: ${formatPercent(epss.score)} probability of exploitation activity in the next 30 days (${ordinal(pctile)} percentile)`}
    >
      EPSS {formatPercent(epss.score)}
    </span>
  );
}

/** "Your stack" badge; the tooltip lists the matched watchlist entries. */
function StackBadge({ stack }: { stack: StackMatch[] }) {
  if (stack.length === 0) return null;
  const title = `Matches your watchlist: ${stack.map((m) => `${m.label} (tier ${m.tier})`).join(", ")}`;
  return (
    <span class={`badge badge-stack tier-${stack[0]!.tier}`} title={title}>
      Your stack{stack[0]!.tier === 1 ? " · T1" : ""}
    </span>
  );
}

function stackCount(items: { stack: StackMatch[] }[]): number {
  return items.filter((i) => i.stack.length > 0).length;
}

function VulnCard({ v }: { v: ExploitedVuln }) {
  return (
    <li class={`card${v.isNew ? " new" : ""}${v.stack.length ? " in-stack" : ""}`}>
      <div class="card-head">
        <StackBadge stack={v.stack} />
        {v.isNew && <span class="badge badge-new">New</span>}
        <a class="cve" href={v.url ?? undefined} target="_blank" rel="noopener noreferrer">
          {v.cve}
        </a>
        <span class="vendor">
          {v.vendor} {v.product}
        </span>
        {v.cvss && <CvssPill cvss={v.cvss} />}
        {v.epss && <EpssTag epss={v.epss} />}
        {v.ransomware && <span class="badge badge-ransomware">Ransomware use</span>}
        {v.automatable && (
          <span class="badge badge-automatable" title="CISA SSVC: exploitation can be automated">
            Automatable
          </span>
        )}
      </div>
      <p class="card-title">{v.name}</p>
      {v.description && <p class="card-desc">{v.description}</p>}
      <p class="meta">
        Added {formatDate(v.dateAdded)}
        {v.dueDate && (
          <>
            {" · "}
            <span title="CISA's remediation deadline for US federal agencies">
              Federal due date {formatDate(v.dueDate)}
            </span>
          </>
        )}
      </p>
      {v.requiredAction && (
        <details>
          <summary>Required action</summary>
          <p>{v.requiredAction}</p>
        </details>
      )}
    </li>
  );
}

function count(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

function shortTime(iso: string): string {
  return new Intl.DateTimeFormat("en-US", {
    weekday: "short",
    hour: "numeric",
    minute: "2-digit",
    timeZone: TEAM_TIME_ZONE,
  }).format(new Date(iso));
}

/** CVE mentions, with the ones in KEV highlighted. */
function CveList({ cves, kevCves, max = 6 }: { cves: string[]; kevCves: string[]; max?: number }) {
  if (cves.length === 0) return null;
  const kev = new Set(kevCves);
  // KEV CVEs first so they survive the cut.
  const ordered = [...cves].sort((a, b) => Number(kev.has(b)) - Number(kev.has(a)));
  return (
    <p class="cve-list">
      {ordered.slice(0, max).map((c) => (
        <a
          class={kev.has(c) ? "cve-chip in-kev" : "cve-chip"}
          href={`https://nvd.nist.gov/vuln/detail/${c}`}
          target="_blank"
          rel="noopener noreferrer"
          title={kev.has(c) ? "In CISA KEV: known exploited" : undefined}
        >
          {c}
          {kev.has(c) && " · KEV"}
        </a>
      ))}
      {cves.length > max && <span class="muted"> +{cves.length - max} more</span>}
    </p>
  );
}

function AdvisoryCard({ a }: { a: Advisory }) {
  const label = a.kind === "alert" ? "Alert" : a.kind === "advisory" ? "Advisory" : "Notice";
  return (
    <li class={`card${a.isNew ? " new" : ""}${a.stack.length ? " in-stack" : ""}`}>
      <div class="card-head">
        <StackBadge stack={a.stack} />
        {a.isNew && <span class="badge badge-new">New</span>}
        <span class="badge badge-kind">{label}</span>
        <a class="card-link" href={a.url ?? undefined} target="_blank" rel="noopener noreferrer">
          {a.title}
        </a>
      </div>
      {a.summary && <p class="card-desc">{a.summary}</p>}
      <CveList cves={a.cves} kevCves={a.kevCves} />
      <p class="meta">Published {formatDate(a.publishedAt)}</p>
    </li>
  );
}

function IcsList({ items }: { items: Advisory[] }) {
  if (items.length === 0) return null;
  const newCount = items.filter((a) => a.isNew).length;
  return (
    <details class="ics">
      <summary>
        {count(items.length, "ICS advisory", "ICS advisories")}
        {newCount > 0 && ` (${newCount} new)`}
      </summary>
      <ul class="compact">
        {items.map((a) => (
          <li>
            <StackBadge stack={a.stack} />
            {a.isNew && <span class="badge badge-new">New</span>}{" "}
            <a href={a.url ?? undefined} target="_blank" rel="noopener noreferrer">
              {a.title}
            </a>{" "}
            <span class="muted">
              · {formatDate(a.publishedAt)}
              {a.cves.length > 0 && ` · ${count(a.cves.length, "CVE", "CVEs")}`}
            </span>
            {a.kevCves.length > 0 && <span class="badge badge-ransomware"> KEV</span>}
          </li>
        ))}
      </ul>
    </details>
  );
}

function HeadlineItem({ h }: { h: Headline }) {
  return (
    <li class={h.stack.length ? "headline in-stack" : "headline"}>
      <div>
        <StackBadge stack={h.stack} />{" "}
        <a class="card-link" href={h.url ?? undefined} target="_blank" rel="noopener noreferrer">
          {h.title}
        </a>
      </div>
      <p class="meta">
        {h.sourceName} · {shortTime(h.publishedAt)}
      </p>
      {h.summary && <p class="card-desc">{h.summary}</p>}
      <CveList cves={h.cves} kevCves={h.kevCves} />
    </li>
  );
}

const MAX_VICTIMS = 40;

function VictimItem({ v }: { v: RansomwareVictim }) {
  return (
    <li class={v.country === TEAM_COUNTRY ? "victim home" : "victim"}>
      <a class="card-link" href={v.url ?? undefined} target="_blank" rel="noopener noreferrer">
        {v.victim}
      </a>{" "}
      <span class="badge badge-group">{v.group}</span>
      <span class="muted">
        {v.country && ` · ${v.country}`}
        {v.sector && ` · ${v.sector}`}
        {` · ${shortTime(v.discoveredAt)}`}
      </span>
      {v.press && (
        <>
          {" · "}
          <a href={v.press} target="_blank" rel="noopener noreferrer">
            press
          </a>
        </>
      )}
    </li>
  );
}

function SourceLine({ s }: { s: SourceStatus }) {
  if (!s.lastSuccessAt && !s.error) return <li>{s.name}: not fetched yet</li>;
  return (
    <li class={s.error ? "source-error" : undefined}>
      {s.name}
      {s.version && ` (catalog ${s.version})`}
      {s.lastSuccessAt && `: checked ${formatTime(s.lastSuccessAt)}`}
      {s.lastChangedAt && `, last changed ${formatTime(s.lastChangedAt)}`}
      {s.error && ` · last attempt failed: ${s.error}`}
    </li>
  );
}

/** A collapsible briefing section. The summary row stays informative while collapsed. */
function Section({
  id,
  title,
  total,
  fresh,
  inStack,
  meta,
  children,
}: {
  id: string;
  title: string;
  total: number;
  fresh?: number;
  inStack?: number;
  meta: Child;
  children: Child;
}) {
  return (
    <details class="section" id={id}>
      <summary>
        <span class="section-title">{title}</span>
        <span class="section-count" title="Items in this section">
          {total}
        </span>
        {inStack !== undefined && inStack > 0 && <span class="badge badge-stack">{inStack} in your stack</span>}
        {fresh !== undefined && fresh > 0 && <span class="badge badge-new">{fresh} new</span>}
        <span class="section-meta">{meta}</span>
      </summary>
      <div class="section-body">{children}</div>
    </details>
  );
}

function Toolbar() {
  return (
    <div class="toolbar" role="toolbar" aria-label="Step through sections">
      <button type="button" data-action="prev" title="Previous section (P or ←)">
        ‹ Prev
      </button>
      <button type="button" data-action="next" class="primary" title="Next section (N or →)">
        Next ›
      </button>
      <span class="toolbar-position" aria-live="polite"></span>
      <span class="toolbar-spacer"></span>
      <button type="button" data-action="expand" title="Expand all (E)">
        Expand all
      </button>
      <button type="button" data-action="collapse" title="Collapse all (C)">
        Collapse all
      </button>
    </div>
  );
}

export function BriefingPage({ b }: { b: Briefing }) {
  const newExploited = b.exploited.filter((v) => v.isNew).length;
  const ics = b.advisories.filter((a) => a.kind === "ics");
  const advisories = b.advisories.filter((a) => a.kind !== "ics");
  const newAdvisories = advisories.filter((a) => a.isNew).length;
  const newHeadlines = b.headlines.filter((h) => h.isNew).length;
  const rw = b.ransomware.summary;

  const header = (
    <header class="topbar">
      <div class="topbar-inner">
        <div class="brand">
          <span class="brand-name">sitrep</span>
          <span class="brand-date">{formatDate(b.today)}</span>
        </div>
        <p class="topbar-summary">
          Since {formatDate(b.newSince)}: {count(newExploited, "new exploited vulnerability", "new exploited vulnerabilities")}
          {" · "}
          {count(newAdvisories, "new advisory", "new advisories")}
          {" · "}
          {count(newHeadlines, "headline", "headlines")}
          {" · "}
          {count(rw.total, "ransomware victim", "ransomware victims")}
          {b.watchlistSize > 0 && (
            <>
              {" · "}
              <a class="topbar-link" href="/watchlist">
                {stackCount([...b.exploited, ...b.advisories, ...b.headlines])} in your stack
              </a>
            </>
          )}
        </p>
        <Toolbar />
      </div>
    </header>
  );

  return (
    <Layout title={`sitrep · ${formatDate(b.today)}`} header={header}>
      <Section
        id="exploited"
        title="Actively exploited"
        total={b.exploited.length}
        fresh={newExploited}
        inStack={stackCount(b.exploited)}
        meta={<>CISA KEV since {formatDate(b.windowStart)} · ranked by exploit likelihood</>}
      >
        {b.exploited.length === 0 ? (
          <p class="muted">Nothing added to the KEV catalog in this window.</p>
        ) : (
          <ul class="cards">
            {b.exploited.map((v) => (
              <VulnCard v={v} />
            ))}
          </ul>
        )}
      </Section>

      <Section
        id="advisories"
        title="Advisories"
        total={advisories.length}
        fresh={newAdvisories}
        inStack={stackCount(b.advisories)}
        meta={
          <>
            CISA since {formatDate(b.windowStart)}
            {ics.length > 0 && ` · plus ${count(ics.length, "ICS advisory", "ICS advisories")}`}
          </>
        }
      >
        {advisories.length === 0 && ics.length === 0 ? (
          <p class="muted">No CISA advisories in this window.</p>
        ) : (
          <>
            {advisories.length > 0 ? (
              <ul class="cards">
                {advisories.map((a) => (
                  <AdvisoryCard a={a} />
                ))}
              </ul>
            ) : (
              <p class="muted">No cybersecurity advisories or alerts in this window.</p>
            )}
            <IcsList items={ics} />
          </>
        )}
      </Section>

      <Section
        id="headlines"
        title="Headlines"
        total={b.headlines.length}
        fresh={newHeadlines}
        inStack={stackCount(b.headlines)}
        meta={<>News since {shortTime(b.headlinesSince)}</>}
      >
        {b.headlines.length === 0 ? (
          <p class="muted">No headlines in this window.</p>
        ) : (
          <ul class="headlines">
            {b.headlines.map((h) => (
              <HeadlineItem h={h} />
            ))}
          </ul>
        )}
      </Section>

      <Section
        id="ransomware"
        title="Ransomware activity"
        total={rw.total}
        meta={
          <>
            {rw.inTeamCountry > 0 && <strong class="home-count">{rw.inTeamCountry} in the {TEAM_COUNTRY}</strong>}
            {rw.inTeamCountry > 0 && " · "}
            Leak-site posts since {shortTime(b.headlinesSince)}
          </>
        }
      >
        <p class="attribution">
          Source:{" "}
          <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer">
            Ransomware.live
          </a>
        </p>
        {rw.total === 0 ? (
          <p class="muted">No new victims posted in this window.</p>
        ) : (
          <>
            <p>
              {count(rw.total, "victim", "victims")} posted
              {rw.inTeamCountry > 0 && (
                <>
                  , <strong>{rw.inTeamCountry} in the {TEAM_COUNTRY}</strong>
                </>
              )}
              . Most active:{" "}
              {rw.topGroups.map((g, i) => (
                <>
                  {i > 0 && ", "}
                  <span class="badge badge-group">{g.group}</span> {g.count}
                </>
              ))}
            </p>
            <ul class="victims">
              {b.ransomware.victims.slice(0, MAX_VICTIMS).map((v) => (
                <VictimItem v={v} />
              ))}
            </ul>
            {b.ransomware.victims.length > MAX_VICTIMS && (
              <p class="muted">
                +{b.ransomware.victims.length - MAX_VICTIMS} more on{" "}
                <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer">
                  Ransomware.live
                </a>
              </p>
            )}
          </>
        )}
      </Section>

      <footer class="sources-footer">
        <h2>Sources</h2>
        <ul class="sources">
          {b.sources.map((s) => (
            <SourceLine s={s} />
          ))}
        </ul>
      </footer>
    </Layout>
  );
}
