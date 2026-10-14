const compactFormatter = new Intl.NumberFormat('en-US', {
  notation: 'compact',
  maximumFractionDigits: 1,
});

export function formatNumber(value: number): string {
  return value.toLocaleString('en-US');
}

/** 1234 → "1,234", 250000 → "250K". */
export function formatCompact(value: number): string {
  return value < 10_000 ? formatNumber(value) : compactFormatter.format(value);
}

/** HH:MM:SS in the viewer's locale clock. */
export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return `${date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} ${date.toLocaleTimeString('en-GB', { hour12: false })}`;
}

export function relativeTime(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Compact time-ago for feed gutters: "43s", "3m", "1h", "2d" — never a suffix word. */
export function timeAgoCompact(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

/** FNV-1a seeds; six rounds yield 24 hex chars of actor ID per source IP. */
const ACTOR_SEEDS = [0x811c9dc5, 0x01000193, 0x9dc5811c, 0x1b873593, 0x85ebca6b, 0xc2b2ae35];

/** Stable 24-lowercase-hex actor ID derived from a source IP (same IP ⇒ same hash). */
export function actorHash(ip: string): string {
  let out = '';
  for (const seed of ACTOR_SEEDS) {
    let hash = seed >>> 0;
    for (let index = 0; index < ip.length; index += 1) {
      hash ^= ip.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    out += hash.toString(16).padStart(8, '0');
  }
  return out.slice(0, 24);
}

/** Flag emoji from an ISO-3166 alpha-2 code; white flag when unknown. */
export function flagEmoji(countryCode: string | null | undefined): string {
  if (!countryCode || !/^[a-zA-Z]{2}$/.test(countryCode)) return '🏳️';
  return String.fromCodePoint(
    ...[...countryCode.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65),
  );
}

export function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}
