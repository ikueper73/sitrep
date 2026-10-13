// The team is US-based; "today" and "since the last standup" use US Eastern time.
export const TEAM_TIME_ZONE = "America/New_York";

/** Calendar date (YYYY-MM-DD) of `now` in the team's time zone. */
export function teamDate(now: Date, timeZone = TEAM_TIME_ZONE): string {
  // en-CA formats as YYYY-MM-DD.
  return new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(now);
}

export function addDays(date: string, days: number): string {
  const d = new Date(`${date}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

export function weekday(date: string): number {
  return new Date(`${date}T00:00:00Z`).getUTCDay(); // 0 = Sunday
}

/** The business day before `date`: Monday → Friday, Sunday → Friday, Saturday → Friday. */
export function previousBusinessDay(date: string): string {
  let d = addDays(date, -1);
  while (weekday(d) === 0 || weekday(d) === 6) d = addDays(d, -1);
  return d;
}

export function formatDate(date: string): string {
  return new Intl.DateTimeFormat("en-US", { weekday: "short", month: "short", day: "numeric", timeZone: "UTC" }).format(
    new Date(`${date.slice(0, 10)}T00:00:00Z`),
  );
}

function offsetMinutes(at: Date, timeZone: string): number {
  const name =
    new Intl.DateTimeFormat("en-US", { timeZone, timeZoneName: "longOffset" })
      .formatToParts(at)
      .find((p) => p.type === "timeZoneName")?.value ?? "GMT";
  const m = name.match(/GMT([+-])(\d{2}):(\d{2})/);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
}

/** The UTC instant (ISO) of midnight at the start of `date` in the team's time zone. */
export function teamMidnightUtc(date: string, timeZone = TEAM_TIME_ZONE): string {
  const utcMidnight = new Date(`${date}T00:00:00Z`);
  const offset = offsetMinutes(utcMidnight, timeZone);
  return new Date(utcMidnight.getTime() - offset * 60_000).toISOString();
}
