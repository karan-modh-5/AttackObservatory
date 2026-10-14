import { useEffect, useMemo, useRef, useState } from 'react';
import { Pause, Play, ScrollText } from 'lucide-react';
import { useLiveFeed } from '../api/ws';
import type { WsStatus } from '../api/ws';
import { useApi } from '../api/hooks';
import type { Event, EventsResponse } from '../api/types';
import { SeverityBadge } from '../components/SeverityBadge';
import { flagEmoji, formatTime } from '../lib/format';

function dedupeNewestFirst(events: Event[]): Event[] {
  const seen = new Set<number>();
  const result: Event[] = [];
  for (const event of events) {
    if (seen.has(event.id)) continue;
    seen.add(event.id);
    result.push(event);
  }
  return result;
}

const STATUS_META: Record<WsStatus, { label: string; className: string }> = {
  open: { label: 'live', className: 'border-pos/40 text-pos' },
  connecting: { label: 'connecting', className: 'border-warn/40 text-warn' },
  reconnecting: { label: 'reconnecting', className: 'border-warn/40 text-warn' },
  closed: { label: 'disconnected', className: 'border-neg/40 text-neg' },
};

const COLUMNS = ['time', 'source ip', 'country', 'service', 'attack type', 'severity'] as const;

export function LiveFeed() {
  const [pauseOnScroll, setPauseOnScroll] = useState(true);
  const [pausedRows, setPausedRows] = useState<Event[] | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const pausedRef = useRef(false);

  const { events: liveEvents, status, attempt } = useLiveFeed({ max: 100 });
  const { data } = useApi<EventsResponse>('/events', { limit: 50 });

  useEffect(() => {
    pausedRef.current = pausedRows !== null;
  }, [pausedRows]);

  const paused = pausedRows !== null;

  const initialRows = useMemo(
    () => (data ? [...data.items].sort((a, b) => b.timestamp.localeCompare(a.timestamp)) : []),
    [data],
  );
  const merged = useMemo(
    () => dedupeNewestFirst([...liveEvents, ...initialRows]).slice(0, 100),
    [liveEvents, initialRows],
  );
  const rows = pausedRows ?? merged;

  const newCount = useMemo(() => {
    if (pausedRows === null) return 0;
    const ids = new Set(pausedRows.map((row) => row.id));
    return merged.filter((row) => !ids.has(row.id)).length;
  }, [merged, pausedRows]);

  const pause = () => setPausedRows(merged);

  const handleScroll = () => {
    if (!pauseOnScroll || pausedRef.current) return;
    const element = scrollRef.current;
    if (element !== null && element.scrollTop > 2) pause();
  };

  const statusLabel =
    status === 'reconnecting' && attempt > 0 ? `reconnecting · ${attempt}` : STATUS_META[status].label;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">live feed</h2>
        <span
          className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.6px] ${STATUS_META[status].className}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full bg-current ${status === 'open' ? 'animate-pulse' : ''}`} />
          {statusLabel}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPauseOnScroll((value) => !value)}
            className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
              pauseOnScroll
                ? 'border-lime/60 text-lime'
                : 'border-edge text-dim hover:text-ink'
            }`}
          >
            <ScrollText className="h-3 w-3" />
            pause on scroll
          </button>
          <button
            type="button"
            onClick={() => (paused ? setPausedRows(null) : pause())}
            className="inline-flex items-center gap-1.5 rounded border border-edge px-2.5 py-1 font-mono text-[11px] text-dim transition-colors hover:border-lime/60 hover:text-lime"
          >
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? 'resume' : 'pause'}
          </button>
        </div>
      </div>

      <section className="panel overflow-hidden">
        {paused && (
          <div className="flex items-center justify-between border-b border-warn/30 bg-warn/5 px-3.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.6px] text-warn">
            <span>
              updates paused{newCount > 0 ? ` · ${newCount} new event${newCount === 1 ? '' : 's'}` : ''}
            </span>
            <button
              type="button"
              onClick={() => setPausedRows(null)}
              className="font-semibold underline-offset-2 hover:underline"
            >
              resume
            </button>
          </div>
        )}
        <div ref={scrollRef} onScroll={handleScroll} className="max-h-[70vh] overflow-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="sticky top-0 z-10 bg-panel">
              <tr className="border-b border-edge">
                {COLUMNS.map((column) => (
                  <th
                    key={column}
                    scope="col"
                    className="whitespace-nowrap px-3.5 py-2 text-[10px] font-medium uppercase tracking-[0.6px] text-dim"
                  >
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((event) => (
                <tr key={event.id} className="border-b border-edge/40 last:border-0 hover:bg-white/[0.02]">
                  <td className="whitespace-nowrap px-3.5 py-[7px] text-[11px] text-dim">
                    {formatTime(event.timestamp)}
                  </td>
                  <td className="whitespace-nowrap px-3.5 py-[7px] text-[11px] text-neg">
                    {event.source_ip ?? '—'}
                  </td>
                  <td className="whitespace-nowrap px-3.5 py-[7px] text-[11px] text-dim">
                    {flagEmoji(event.country)}
                    <span className="ml-1">{event.country ?? '—'}</span>
                  </td>
                  <td className="whitespace-nowrap px-3.5 py-[7px] text-[11px] uppercase text-dim">
                    {event.service}
                  </td>
                  <td className="whitespace-nowrap px-3.5 py-[7px] text-[11px] text-pos">
                    {event.attack_type.toLowerCase()}
                  </td>
                  <td className="px-3.5 py-[7px]">
                    <SeverityBadge severity={event.severity} />
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="px-4 py-16 text-center text-[11px] text-dim">
                    Waiting for events — rows appear the moment attacks stream in…
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <p className="font-mono text-[10px] text-dim">
        showing {rows.length} of at most 100 most recent events · seeded from /events and merged with the live
        stream
      </p>
    </div>
  );
}
