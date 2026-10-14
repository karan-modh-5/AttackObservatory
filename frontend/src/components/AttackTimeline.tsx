import type { Event } from '../api/types';
import { truncate } from '../lib/format';

/** KIND chip colors, matching the reference AUTH FAIL / CLIENT / COMMAND chips. */
const KIND_CHIP: Record<string, { label: string; className: string }> = {
  failed_password: { label: 'AUTH FAIL', className: 'border-warn/50 text-warn' },
  client_version: { label: 'CLIENT', className: 'border-[#a78bfa]/50 text-[#a78bfa]' },
  connect: { label: 'CONNECT', className: 'border-[#a78bfa]/50 text-[#a78bfa]' },
  command: { label: 'COMMAND', className: 'border-lime/50 text-lime' },
  file_download: { label: 'FETCH', className: 'border-warn/50 text-warn' },
  file_upload: { label: 'FETCH', className: 'border-warn/50 text-warn' },
  accepted: { label: 'AUTH OK', className: 'border-pos/50 text-pos' },
};

function relativeShort(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

/** Dim description line under each timeline entry. */
function describe(event: Event): string {
  switch (event.event_kind) {
    case 'connect':
      return 'new SSH session opened';
    case 'client_version':
      return 'client banner announced';
    case 'failed_password':
      return `attempted login as ${event.username ?? 'unknown'}`;
    case 'accepted':
      return `accepted password for ${event.username ?? 'unknown'}`;
    case 'file_download':
      return `downloaded ${truncate(event.payload ?? 'remote file', 72)}`;
    case 'file_upload':
      return `uploaded ${truncate(event.payload ?? 'file', 72)}`;
    default:
      return `ran ${truncate(event.payload ?? 'a command', 72)}`;
  }
}

/** Vertical live timeline: dotted rail, kind chip, green IP, dim description. */
export function AttackTimeline({ events }: { events: Event[] }) {
  // SSH intel context: only cowrie (SSH/Telnet) events belong on this timeline.
  const recent = events.filter((event) => event.honeypot === 'cowrie').slice(0, 12);
  return (
    <div>
      {recent.length === 0 ? (
        <p className="rounded border border-dashed border-edge px-3 py-6 text-center font-mono text-[11px] text-dim">
          no attacks in the last hour
        </p>
      ) : (
        <ol className="relative space-y-4 border-l border-edge pl-5">
          {recent.map((event) => {
            const kind = KIND_CHIP[event.event_kind ?? ''] ?? {
              label: (event.event_kind ?? 'EVENT').toUpperCase(),
              className: 'border-edge text-dim',
            };
            return (
              <li key={event.id} className="relative">
                <span className="absolute -left-[25px] top-1 h-2 w-2 rounded-full border-2 border-edge bg-panel" />
                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                  <span className="text-dim">{relativeShort(event.timestamp)}</span>
                  <span className={`rounded border px-1.5 py-px text-[9px] tracking-[0.5px] ${kind.className}`}>
                    {kind.label}
                  </span>
                  <span className="text-pos">{event.source_ip ?? 'unknown'}</span>
                  {event.username !== null && event.username !== '' && (
                    <span className="text-ink">as {event.username}</span>
                  )}
                </div>
                <p className="mt-1 font-mono text-[11px] text-dim">{describe(event)}</p>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
