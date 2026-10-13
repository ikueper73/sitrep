import {
  type Advisory,
  type Briefing,
  type ExploitedVuln,
  type Headline,
  type RansomwareVictim,
  type SourceStatus,
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
    <li class={a.isNew ? "card new" : "card"}>
      <div class="card-head">
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
    <li class="headline">
      <div>
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

export function BriefingPage({ b }: { b: Briefing }) {
  const newCount = b.exploited.filter((v) => v.isNew).length;
  const ics = b.advisories.filter((a) => a.kind === "ics");
  const advisories = b.advisories.filter((a) => a.kind !== "ics");
  const newAdvisories = advisories.filter((a) => a.isNew).length;
  return (
    <Layout title={`sitrep · ${formatDate(b.today)}`}>
      <header>
        <h1>sitrep · {formatDate(b.today)}</h1>
        <p class="muted">
          Since {formatDate(b.newSince)}: {count(newCount, "new exploited vulnerability", "new exploited vulnerabilities")}
          {" · "}
          {count(newAdvisories, "new advisory", "new advisories")}
          {" · "}
          {count(b.headlines.filter((h) => h.isNew).length, "headline", "headlines")}
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

      <section>
        <h2>
          Advisories <span class="muted">· CISA, since {formatDate(b.windowStart)}</span>
        </h2>
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
      </section>

      <section>
        <h2>
          Headlines <span class="muted">· since {shortTime(b.headlinesSince)}</span>
        </h2>
        {b.headlines.length === 0 ? (
          <p class="muted">No headlines in this window.</p>
        ) : (
          <ul class="headlines">
            {b.headlines.map((h) => (
              <HeadlineItem h={h} />
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>
          Ransomware activity{" "}
          <span class="muted">
            · leak-site posts since {shortTime(b.headlinesSince)} · Source:{" "}
            <a href="https://www.ransomware.live" target="_blank" rel="noopener noreferrer">
              Ransomware.live
            </a>
          </span>
        </h2>
        {b.ransomware.summary.total === 0 ? (
          <p class="muted">No new victims posted in this window.</p>
        ) : (
          <>
            <p>
              {count(b.ransomware.summary.total, "victim", "victims")} posted
              {b.ransomware.summary.inTeamCountry > 0 && <>, <strong>{b.ransomware.summary.inTeamCountry} in the {TEAM_COUNTRY}</strong></>}
              . Most active:{" "}
              {b.ransomware.summary.topGroups.map((g, i) => (
                <>
                  {i > 0 && ", "}
                  {g.group} ({g.count})
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
