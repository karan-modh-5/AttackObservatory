import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useApi } from '../api/hooks';
import { useLiveFeed } from '../api/ws';
import type {
  EventsResponse,
  Event,
  Honeypot,
  MapPoints,
  NetworkStats,
  OverviewStats,
  ReadinessResponse,
  Timeseries,
} from '../api/types';
import { GlobeCanvas } from '../components/GlobeCanvas';
import type { GlobePulse } from '../components/GlobeCanvas';
import { Panel } from '../components/Panel';
import { SourceList } from '../components/SourceList';
import {
  ThreatGauge,
  breakdownFrom,
  threatScore,
} from '../components/ThreatGauge';
import { actorHash, formatNumber, relativeTime, timeAgoCompact } from '../lib/format';

const HONEYPOTS: Honeypot[] = ['cowrie', 'snare', 'tanner', 'heralding', 'suricata'];

function HHMMSS(date: Date): string {
  return date.toLocaleTimeString('en-GB', { hour12: false });
}

/** True when the event carries an executed command worth its own block. */
function isCommand(event: Event): boolean {
  if (event.event_kind === 'command') return true;
  // Older REST rows may lack event_kind: treat non-URL payloads as commands.
  return event.event_kind === undefined && event.payload !== null && !event.payload.startsWith('http');
}

/** Reference-style live feed row: time gutter, ip/user/kind line, command block, actor hash. */
function FeedRow({ event }: { event: Event }): JSX.Element {
  const ip = event.source_ip ?? '—';
  return (
    <div className="grid grid-cols-[52px_minmax(0,1fr)] gap-x-[10px] px-3.5 py-1.5 font-mono text-[11px] leading-snug">
      <span className="row-span-2 text-dim">{timeAgoCompact(event.timestamp)}</span>
      <span className="min-w-0 break-all">
        <span className="text-pos">{ip}</span> <span className="text-warn">{event.username ?? '?'}</span>{' '}
        <span className="text-ink">{event.event_kind ?? 'connect'}</span>
      </span>
      {isCommand(event) && event.payload !== null && (
        <span className="col-start-2 mt-[3px] break-all leading-[1.35] text-pos">{event.payload}</span>
      )}
      <span className="col-start-2 mt-0.5 text-[10px] text-dim">actor {actorHash(ip)}</span>
    </div>
  );
}

/** Telemetry header box: identity, source/origin/updated meta, globe/intel nav. */
const SENSOR_ORIGIN =
  (import.meta.env.VITE_SENSOR_ORIGIN as string | undefined) ?? 'your VPS';

function TelemetryHeader(): JSX.Element {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return (
    <section className="panel px-3.5 py-3">
      <div className="flex items-center gap-2">
        <span className="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-lime" />
        <h1 className="font-mono text-[13px] font-bold text-ink">observatory telemetry</h1>
      </div>
      <div className="mt-2.5 space-y-1 font-mono text-[11px] text-dim">
        <p>
          source <strong className="font-semibold text-ink">fluent-bit + duckdb</strong>
        </p>
        <p>
          origin <strong className="font-semibold text-ink">{SENSOR_ORIGIN}</strong>
        </p>
        <p>
          updated <strong className="font-semibold text-ink">{HHMMSS(now)}</strong>
        </p>
      </div>
      <nav className="mt-3 flex gap-2">
        <span className="rounded border border-lime/60 px-2.5 py-1 font-mono text-[10px] text-lime">
          [ globe ]
        </span>
        <Link
          to="/ssh"
          className="rounded border border-edge px-2.5 py-1 font-mono text-[10px] text-dim transition-colors hover:border-lime/50 hover:text-lime"
        >
          [ intel ]
        </Link>
      </nav>
    </section>
  );
}

/** Tiny summary cell inside the SUMMARY panel. */
function MiniStat({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="rounded border border-edge bg-base/70 px-2.5 py-2">
      <p className="font-mono text-[17px] font-semibold leading-none text-lime">{value}</p>
      <p className="mt-1.5 font-mono text-[9px] uppercase tracking-[0.6px] text-dim">{label}</p>
    </div>
  );
}

/** SVG area sparkline for the EVENTS / HOUR strip. */
function HourSparkline({ values }: { values: number[] }): JSX.Element | null {
  if (values.length < 2) {
    return <div className="h-16" />;
  }
  const max = Math.max(1, ...values);
  const coords = values.map((value, index) => {
    const x = (index / (values.length - 1)) * 100;
    const y = 96 - (value / max) * 88;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-16 w-full" aria-hidden>
      <polygon points={`0,100 ${coords.join(' ')} 100,100`} fill="rgba(209, 254, 23, 0.12)" />
      <polyline
        points={coords.join(' ')}
        fill="none"
        stroke="#d1fe17"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export function AttackMap() {
  const overview = useApi<OverviewStats>('/stats/overview');
  const mapData = useApi<MapPoints>('/map/points');
  const recent = useApi<EventsResponse>('/events', { limit: 6 });
  // Backfill: the feed shows recent SSH history immediately on load (the
  // reference console is never empty), then live WS events prepend on top.
  const feedSeed = useApi<EventsResponse>('/events', { limit: 14, honeypot: 'cowrie' });
  const network = useApi<NetworkStats>('/network/stats', { days: 7 });
  const readiness = useApi<ReadinessResponse>('/health/ready');
  const hourly = useApi<Timeseries>('/stats/timeseries', { days: 1, interval: 'hour' });

  const pulsesRef = useRef<GlobePulse[]>([]);
  const onEvent = useCallback((event: Event) => {
    if (event.lat === null || event.lon === null) return;
    const pulse: GlobePulse = { id: event.id, lat: event.lat, lon: event.lon, at: Date.now() };
    pulsesRef.current = [...pulsesRef.current.slice(-40), pulse];
  }, []);
  const { events, status } = useLiveFeed({ max: 14, onEvent });

  const feedEvents = useMemo(() => {
    const seed = (feedSeed.data?.items ?? []).filter((event) => event.honeypot === 'cowrie');
    const merged: Event[] = [];
    const seen: Record<number, true> = {};
    for (const event of [...events, ...seed]) {
      if (seen[event.id]) continue;
      seen[event.id] = true;
      merged.push(event);
    }
    return merged.slice(0, 14);
  }, [events, feedSeed.data]);

  const points = useMemo(() => mapData.data?.points ?? [], [mapData.data]);
  const highlights = useMemo(() => {
    const totalWeight = Math.max(
      1,
      points.reduce((sum, point) => sum + point.weight, 0),
    );
    return [...points]
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3)
      .filter((point) => point.country !== null)
      .map((point) => ({
        label: `${point.country} ${((point.weight / totalWeight) * 100).toFixed(1)}%`,
        lat: point.lat,
        lon: point.lon,
      }));
  }, [points]);

  const lastEventByHoneypot = useMemo(() => {
    const latest = new Map<Honeypot, string>();
    for (const event of recent.data?.items ?? []) {
      if (!latest.has(event.honeypot)) latest.set(event.honeypot, event.timestamp);
    }
    return latest;
  }, [recent.data]);

  const breakdown = useMemo(
    () => breakdownFrom(overview.data, hourly.data?.by_type.length ?? 0),
    [overview.data, hourly.data],
  );
  const score = threatScore(breakdown);

  const peakPerHour = Math.max(0, ...(hourly.data?.points ?? []).map((point) => point.total));
  const sensorHost = window.location.hostname;
  const geoipDownloading = readiness.data?.geoip === 'downloading';

  return (
    <div className="grid gap-4 xl:grid-cols-[240px_minmax(0,1fr)_300px]">
      {/* Left column */}
      <div className="space-y-4">
        <TelemetryHeader />

        <Panel title="summary" bodyClassName="grid grid-cols-2 gap-2 p-3">
          <MiniStat label="events" value={overview.data !== null ? formatNumber(overview.data.total_attacks) : '—'} />
          <MiniStat
            label="unique attackers"
            value={overview.data !== null ? formatNumber(overview.data.unique_attackers) : '—'}
          />
          <MiniStat label="countries" value={overview.data !== null ? formatNumber(overview.data.countries) : '—'} />
          <MiniStat
            label="credentials"
            value={overview.data !== null ? formatNumber(overview.data.credentials_captured) : '—'}
          />
        </Panel>

        <Panel title="honeypot">
          <div className="divide-y divide-edge/50">
            {HONEYPOTS.map((honeypot) => {
              const lastEvent = lastEventByHoneypot.get(honeypot);
              return (
                <div key={honeypot} className="flex items-center gap-2 px-3.5 py-[7px]">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-pos" />
                  <span className="font-mono text-[11px] text-ink">{honeypot}</span>
                  <span className="font-mono text-[9px] uppercase tracking-[0.6px] text-pos">active</span>
                  <span className="ml-auto font-mono text-[10px] text-dim">
                    {lastEvent !== undefined ? relativeTime(lastEvent) : '—'}
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="threat level">
          <div className="flex justify-center pt-2">
            <ThreatGauge score={score} size={200} />
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 px-3.5 pb-3 font-mono text-[10px]">
            <span className="text-dim">volume</span>
            <span className="text-right text-ink">{breakdown.volume}/25</span>
            <span className="text-dim">intrusion</span>
            <span className="text-right text-ink">{breakdown.intrusion}/25</span>
            <span className="text-dim">diversity</span>
            <span className="text-right text-ink">{breakdown.diversity}/25</span>
            <span className="text-dim">exposure</span>
            <span className="text-right text-ink">{breakdown.exposure}/25</span>
          </div>
          <p className="border-t border-edge px-3.5 py-2 font-mono text-[10px] text-dim">
            last 24h · {formatNumber(overview.data?.last_24h ?? 0)} events ·{' '}
            {formatNumber(overview.data?.unique_attackers ?? 0)} attackers
          </p>
        </Panel>
      </div>

      {/* Center column: globe + hourly sparkline */}
      <div className="space-y-4">
        <Panel
          title={`sensor ${sensorHost}`}
          right={
            <div className="flex items-center gap-3">
              {geoipDownloading && (
                <span className="font-mono text-[10px] text-warn">loading geolocation databases…</span>
              )}
              {mapData.error !== null && (
                <span className="font-mono text-[10px] text-neg">map data: {mapData.error}</span>
              )}
              <span className="font-mono text-[10px] text-dim">
                {formatNumber(points.length)} origins
              </span>
            </div>
          }
          bodyClassName="relative h-[420px] xl:h-[560px]"
        >
          <GlobeCanvas
            points={points}
            highlights={highlights}
            sensorLabel={`LIVE ${sensorHost}`}
            pulsesRef={pulsesRef}
          />
        </Panel>

        <Panel
          title="events / hour"
          right={
            <span className="font-mono text-[10px] text-lime">
              peak: {formatNumber(peakPerHour)}/h
            </span>
          }
          bodyClassName="px-3.5 pb-3 pt-2"
        >
          <HourSparkline values={(hourly.data?.points ?? []).map((point) => point.total)} />
        </Panel>
      </div>

      {/* Right column */}
      <div className="space-y-4">
        <Panel title="top source ips">
          <SourceList sources={network.data?.top_sources ?? []} maxRows={7} />
        </Panel>

        <Panel
          title="live feed"
          right={
            <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.6px] text-dim">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  status === 'open' ? 'bg-pos animate-pulse' : status === 'closed' ? 'bg-neg' : 'bg-warn'
                }`}
              />
              {status}
            </span>
          }
          bodyClassName="max-h-[420px] overflow-y-auto"
        >
          {feedEvents.length === 0 && (
            <p className="px-3.5 py-6 font-mono text-[11px] text-dim">
              waiting for attacks — events stream in live…
            </p>
          )}
          <div className="divide-y divide-dotted divide-edge/40">
            {feedEvents.map((event) => (
              <FeedRow key={event.id} event={event} />
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
