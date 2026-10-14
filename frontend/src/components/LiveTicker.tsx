import { useLiveFeed } from '../api/ws';
import { flagEmoji, relativeTime } from '../lib/format';
import { SEVERITY_DOT } from './SeverityBadge';

/** Scrolling strip of the newest attacks arriving over the websocket. */
export function LiveTicker() {
  const { events } = useLiveFeed({ max: 24 });

  if (events.length === 0) {
    return (
      <div className="panel px-4 py-2.5 font-mono text-[11px] text-dim">
        Waiting for live events — the ticker fills as attacks stream in…
      </div>
    );
  }

  const strip = [...events, ...events];
  return (
    <div className="panel flex items-center overflow-hidden">
      <span className="z-10 flex shrink-0 items-center gap-1.5 border-r border-edge px-3 py-2 font-mono text-[10px] uppercase tracking-[0.6px] text-neg">
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neg opacity-75" />
          <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neg" />
        </span>
        live
      </span>
      <div className="group relative min-w-0 flex-1 overflow-hidden">
        <div className="flex w-max animate-ticker items-center gap-8 px-5 py-2 group-hover:[animation-play-state:paused]">
          {strip.map((event, index) => (
            <span
              key={`${event.id}-${index}`}
              className="flex items-center gap-2 whitespace-nowrap font-mono text-[11px] text-dim"
            >
              <span className={`h-1 w-1 rounded-full ${SEVERITY_DOT[event.severity]}`} />
              <span className="text-pos">{event.attack_type.toLowerCase()}</span>
              <span className="text-neg">{event.source_ip ?? '—'}</span>
              <span>{flagEmoji(event.country)}</span>
              <span>{relativeTime(event.timestamp)}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
