import type { Briefing, ExploitedVuln, SourceStatus } from "../briefing";
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

function VulnCard({ v, today }: { v: ExploitedVuln; today: string }) {
  const overdue = v.dueDate !== null && v.dueDate < today;
  return (
    <li class={v.isNew ? "card new" : "card"}>
      <div class="card-head">
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
            <span class={overdue ? "overdue" : undefined}>
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

export function BriefingPage({ b }: { b: Briefing }) {
  const newCount = b.exploited.filter((v) => v.isNew).length;
  return (
    <Layout title={`sitrep · ${formatDate(b.today)}`}>
      <header>
        <h1>sitrep · {formatDate(b.today)}</h1>
        <p class="muted">
          {newCount === 1 ? "1 new exploited vulnerability" : `${newCount} new exploited vulnerabilities`} since{" "}
          {formatDate(b.newSince)}
        </p>
      </header>

      <section>
        <h2>
          Actively exploited{" "}
          <span class="muted">· CISA KEV, added since {formatDate(b.windowStart)}, ranked by exploit likelihood</span>
        </h2>
        {b.exploited.length === 0 ? (
          <p class="muted">Nothing added to the KEV catalog in this window.</p>
        ) : (
          <ul class="cards">
            {b.exploited.map((v) => (
              <VulnCard v={v} today={b.today} />
            ))}
          </ul>
        )}
      </section>

      <footer>
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
