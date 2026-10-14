/**
 * SitRep logo: the favicon's radar mark (without its tile, for use on the navy
 * top bar) plus the wordmark. The wordmark is live text in Barlow Condensed so
 * it stays crisp and uses the already-loaded web font.
 */
export function Logo({ subtitle }: { subtitle?: string }) {
  return (
    <a class="brand" href="/" aria-label="SitRep: back to the briefing">
      <svg class="brand-mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
        <circle cx="32" cy="32" r="27" fill="none" stroke="#ffffff" stroke-opacity="0.25" stroke-width="2" />
        <circle cx="32" cy="32" r="21" fill="none" stroke="#ffffff" stroke-opacity="0.75" stroke-width="4.5" />
        <path d="M32 32 L32 11 A21 21 0 0 1 53 32 Z" fill="#d0df00" />
        <circle cx="20.5" cy="42.5" r="6" fill="#ff6b5b" />
        <circle cx="32" cy="32" r="3.5" fill="#ffffff" />
      </svg>
      <span class="brand-word">
        Sit<span class="brand-word-accent">Rep</span>
      </span>
      {subtitle && <span class="brand-date">{subtitle}</span>}
    </a>
  );
}
