import { useEffect, useMemo, useState } from 'react';
import { useApi } from '../api/hooks';
import { useLiveFeed } from '../api/ws';
import type {
  ActorRow,
  ActorsResponse,
  Event,
  EventsResponse,
  HeatmapResponse,
  OverviewStats,
  PayloadsResponse,
  ReadinessResponse,
  SshStats,
} from '../api/types';
import { ActivityHeatmap } from '../components/ActivityHeatmap';
import { AttackTimeline } from '../components/AttackTimeline';
import { GeographyBars } from '../components/GeographyBars';
import { Panel } from '../components/Panel';
import { RankBars } from '../components/RankBars';
import {
  ThreatGauge,
  breakdownFrom,
  threatLabel,
  threatScore,
} from '../components/ThreatGauge';
import { WINDOW_DAYS, WindowChips } from '../components/WindowChips';
import type { WindowKey } from '../components/WindowChips';
import { countryName } from '../lib/countries';
import { formatNumber, truncate } from '../lib/format';

/** Flat stat tile with a controllable accent color, reference-style. */
function IntelTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: 'lime' | 'pos';
}) {
  return (
    <div className="rounded border border-edge bg-panel px-4 py-3.5">
      <p
        className={`font-mono text-[24px] font-semibold leading-none ${
          accent === 'lime' ? 'text-lime' : 'text-pos'
        }`}
      >
        {value}
      </p>
      <p className="panel-title mt-2.5">{label}</p>
    </div>
  );
}

/** PASSWORDS | USERNAMES twin list, mirroring the reference TOP CREDENTIALS panel. */
function CredentialColumns({ stats }: { stats: SshStats }) {
  const columns: Array<{ title: string; rows: Array<{ name: string; count: number }> }> = [
    { title: 'passwords', rows: stats.top_passwords },
    { title: 'usernames', rows: stats.top_usernames },
  ];
  return (
    <div className="grid grid-cols-2 gap-6">
      {columns.map((column) => (
        <div key={column.title}>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.6px] text-dim">
            {column.title}
          </p>
          {column.rows.length === 0 ? (
            <p className="rounded border border-dashed border-edge px-3 py-6 text-center font-mono text-[11px] text-dim">
              none captured
            </p>
          ) : (
            <ul className="space-y-px">
              {column.rows.slice(0, 8).map((row) => (
                <li
                  key={column.title + row.name}
                  className="flex items-baseline justify-between gap-3 border-b border-edge/60 px-1 py-[5px] font-mono text-[12px]"
                >
                  <span className="truncate text-ink" title={row.name}>
                    {row.name}
                  </span>
                  <span className="shrink-0 text-dim">{row.count}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

/** Brute-force radar: color encodes the actor's classified threat tier, not rank.
 *  deploy (breached / ran commands) = red · active credential attacks = amber · probe-only = dim. */
const IS_CREDENTIAL_ATTACK_PLAYBOOK: Record<string, true> = {
  default_credential_spray: true,
  fast_dictionary: true,
  service_account_enum: true,
};

function radarTier(actor: ActorRow): { ip: string; bar: string; rate: string } {
  if (actor.intent === 'deploy') return { ip: 'text-neg', bar: 'bg-neg', rate: 'text-neg' };
  if (IS_CREDENTIAL_ATTACK_PLAYBOOK[actor.playbook ?? '']) {
    return { ip: 'text-warn', bar: 'bg-warn', rate: 'text-warn' };
  }
  return { ip: 'text-ink', bar: 'bg-dim/40', rate: 'text-dim' };
}

function BruteForceRadar({ actors, days }: { actors: ActorRow[]; days: number }) {
  const rows = [...actors].sort((a, b) => b.events - a.events).slice(0, 8);
  if (rows.length === 0) {
    return (
      <p className="rounded border border-dashed border-edge px-3 py-8 text-center font-mono text-[11px] text-dim">
        no ssh sources for this period
      </p>
    );
  }
  const max = Math.max(1, ...rows.map((row) => row.events));
  const hours = Math.max(1, days * 24);
  return (
    <div>
      <div className="mb-2 flex items-center gap-3 font-mono text-[9px] uppercase tracking-[0.5px] text-dim">
        <span className="text-neg">■ deploy</span>
        <span className="text-warn">■ credential attack</span>
        <span>■ probe</span>
      </div>
      <ul className="space-y-[7px]">
        {rows.map((actor) => {
          const tier = radarTier(actor);
          const rate = actor.events / hours;
          return (
            <li key={actor.ip} className="flex items-center gap-3">
              <span
                className={`w-[132px] shrink-0 truncate font-mono text-[12px] ${tier.ip}`}
                title={`${actor.ip} · ${actor.playbook ?? 'unknown'} · ${actor.intent}`}
              >
                {actor.ip}
              </span>
              <span className="h-[5px] min-w-0 flex-1 overflow-hidden rounded-[2px] bg-white/5">
                <span
                  className={`block h-full transition-[width] duration-500 ${tier.bar}`}
                  style={{ width: `${Math.max(2, (actor.events / max) * 100)}%` }}
                />
              </span>
              <span className={`w-[52px] shrink-0 text-right font-mono text-[11px] ${tier.rate}`}>
                {rate >= 10 ? rate.toFixed(0) : rate.toFixed(1)}/h
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** '2d 3h' style humanized uptime from seconds. */
function humanUptime(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/** Humanized byte size: B / KB / MB, reference format like '36.06 MB'. */
function humanBytes(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(2)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
  return `${bytes} B`;
}

/** Short relative stamp used in tables, like '14h' or '2m'. */
function agoShort(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

/** Shared 10px uppercase dim column header row. Sticky inside scrollable panels. */
function Th({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={`sticky top-0 z-10 bg-panel px-3 py-2 text-left font-mono text-[10px] font-medium uppercase tracking-[0.6px] text-dim ${className}`}>
      {children}
    </th>
  );
}

const ACTOR_ROW =
  'border-b border-edge/60 px-3 py-2 align-baseline font-mono text-[11px]';

export function SshAnalytics() {
  const [win, setWin] = useState<WindowKey>('24h');
  const days = WINDOW_DAYS[win];
  const hours = Math.min(days * 24, 168);

  const overview = useApi<OverviewStats>('/stats/overview');
  const stats = useApi<SshStats>('/ssh/stats', { days });
  const actors = useApi<ActorsResponse>('/ssh/actors', { days });
  const heatmap = useApi<HeatmapResponse>('/ssh/heatmap', { hours });
  const payloads = useApi<PayloadsResponse>('/ssh/payloads', { limit: 100 });
  const readiness = useApi<ReadinessResponse>('/health/ready');
  const commands = useApi<EventsResponse>('/events', { honeypot: 'cowrie', limit: 30 });
  const live = useLiveFeed({ max: 12 });

  const loading = stats.loading && actors.loading;
  const reload = (): void => {
    overview.reload();
    stats.reload();
    actors.reload();
    heatmap.reload();
    payloads.reload();
    readiness.reload();
    commands.reload();
  };

  // Ticking 'UPDATED' tile: anchored to the last successful fetch.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const [lastFetch, setLastFetch] = useState<number | null>(null);
  useEffect(() => {
    if (stats.data !== null) setLastFetch(Date.now());
  }, [stats.data]);
  const updatedLabel =
    lastFetch === null ? '—' : `${Math.max(0, Math.floor((now - lastFetch) / 1000))}s ago`;

  const breakdown = useMemo(
    () => breakdownFrom(overview.data, stats.data?.event_kinds?.length ?? 0),
    [overview.data, stats.data],
  );
  const score = threatScore(breakdown);
  const level = threatLabel(score);

  const recentCommands = useMemo(
    () =>
      (commands.data?.items ?? [])
        .filter((event: Event) => event.payload !== null && event.payload !== '')
        .slice(0, 15),
    [commands.data],
  );

  const wsOpen = live.status === 'open';

  return (
    <div className="space-y-4">
      {/* 1. Header row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">
          ssh intel
        </h2>
        <div className="flex items-center gap-3">
          <WindowChips value={win} onChange={setWin} />
          <button
            type="button"
            onClick={reload}
            className="font-mono text-[11px] uppercase tracking-[0.6px] text-dim transition-colors hover:text-lime"
          >
            {loading ? 'syncing…' : '↻ refresh'}
          </button>
        </div>
      </div>

      {(stats.error ?? actors.error) !== null && (
        <p className="rounded border border-neg/30 bg-neg/5 px-3.5 py-2 font-mono text-[11px] text-neg">
          {stats.error ?? actors.error}
        </p>
      )}

      {/* 2. Stat strip */}
      <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <IntelTile
          label="events (ssh)"
          accent="lime"
          value={overview.data !== null ? formatNumber(overview.data.ssh_events) : '—'}
        />
        <IntelTile
          label="actors"
          accent="pos"
          value={actors.data !== null ? formatNumber(actors.data.actors.length) : '—'}
        />
        <IntelTile
          label="unique ips"
          accent="lime"
          value={overview.data !== null ? formatNumber(overview.data.ssh_unique_ips) : '—'}
        />
        <IntelTile
          label="uptime"
          accent="pos"
          value={readiness.data !== null ? humanUptime(readiness.data.uptime_seconds) : '—'}
        />
        <IntelTile label="updated" accent="lime" value={updatedLabel} />
      </div>

      {/* 3. Threat level + attack geography */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="threat level">
          <div className="flex justify-center py-3">
            <ThreatGauge score={score} size={230} />
          </div>
          <p className="-mt-2 mb-2 text-center font-mono text-[11px] tracking-[1px] text-ink">
            {level}
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 border-t border-edge px-4 py-3 font-mono text-[10px]">
            <span className="text-dim">volume</span>
            <span className="text-right text-ink">{breakdown.volume}/25</span>
            <span className="text-dim">intrusion</span>
            <span className="text-right text-ink">{breakdown.intrusion}/25</span>
            <span className="text-dim">diversity</span>
            <span className="text-right text-ink">{breakdown.diversity}/25</span>
            <span className="text-dim">weaponization</span>
            <span className="text-right text-ink">{breakdown.exposure}/25</span>
          </div>
          <p className="border-t border-edge px-4 py-2 font-mono text-[10px] text-dim">
            last 24h · {formatNumber(overview.data?.last_24h ?? 0)} events ·{' '}
            {formatNumber(overview.data?.unique_attackers ?? 0)} IPs
          </p>
        </Panel>

        <Panel title="attack geography" bodyClassName="p-3.5">
          <GeographyBars data={actors.data?.geography ?? []} maxRows={10} />
        </Panel>
      </div>

      {/* 4. Top credentials + brute-force radar */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="top credentials" bodyClassName="p-3.5">
          {stats.data !== null ? (
            <CredentialColumns stats={stats.data} />
          ) : (
            <p className="rounded border border-dashed border-edge px-3 py-8 text-center font-mono text-[11px] text-dim">
              loading…
            </p>
          )}
        </Panel>

        <Panel title="brute-force radar" bodyClassName="p-3.5">
          {stats.data !== null ? (
            <BruteForceRadar actors={actors.data?.actors ?? []} days={days} />
          ) : (
            <p className="rounded border border-dashed border-edge px-3 py-8 text-center font-mono text-[11px] text-dim">
              loading…
            </p>
          )}
        </Panel>
      </div>

      {/* 5. Activity heatmap */}
      <Panel title={`activity heatmap (${Math.min(hours, 72)}h · by event kind)`} bodyClassName="p-3.5">
        <ActivityHeatmap data={heatmap.data} />
      </Panel>

      {/* 6. Event kinds + playbooks */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="event kinds (events, all-time)" bodyClassName="p-3.5">
          <RankBars data={stats.data?.event_kinds ?? []} maxRows={8} />
        </Panel>
        <Panel title="playbooks (actors, all-time)" bodyClassName="p-3.5">
          <RankBars data={actors.data?.playbooks ?? []} maxRows={8} />
        </Panel>
      </div>

      {/* 7. Intent + sources */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="intent (actors, all-time)" bodyClassName="p-3.5">
          <RankBars data={actors.data?.intents ?? []} maxRows={8} />
        </Panel>
        <Panel title="sources (events, all-time)" bodyClassName="p-3.5">
          <RankBars data={actors.data?.sources ?? []} maxRows={8} />
        </Panel>
      </div>

      {/* 8. Threat actors table */}
      <Panel title="threat actors" bodyClassName="max-h-[420px] overflow-auto">
        <table className="w-full min-w-[880px] border-collapse">
          <thead>
            <tr className="border-b border-edge">
              <Th>ip / id</Th>
              <Th>location</Th>
              <Th>playbook</Th>
              <Th>intent</Th>
              <Th className="text-right">events</Th>
              <Th className="text-right">probe</Th>
              <Th>last cmd</Th>
              <Th>last seen</Th>
            </tr>
          </thead>
          <tbody>
            {(actors.data?.actors ?? []).slice(0, 14).map((actor) => (
              <tr key={actor.ip} className="border-b border-edge/60">
                <td className={`${ACTOR_ROW} whitespace-nowrap text-pos`}>{actor.ip}</td>
                <td className={`${ACTOR_ROW} min-w-0 text-dim`} title={countryName(actor.country)}>
                  <span className="shrink-0">{(actor.country ?? '??').toUpperCase()}</span>
                  <span className="truncate">{actor.city ?? countryName(actor.country)}</span>
                </td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-ink`}>{actor.playbook ?? '—'}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-ink`}>{actor.intent ?? '—'}</td>
                <td className={`${ACTOR_ROW} text-right whitespace-nowrap text-lime`}>
                  {formatNumber(actor.events)}
                </td>
                <td className={`${ACTOR_ROW} text-right whitespace-nowrap text-lime`}>
                  {formatNumber(actor.probes)}
                </td>
                <td className={`${ACTOR_ROW} max-w-[280px] text-ink`}>
                  {actor.last_cmd === null ? '—' : truncate(actor.last_cmd, 40)}
                </td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-dim`}>{agoShort(actor.last_seen)}</td>
              </tr>
            ))}
            {(actors.data?.actors ?? []).length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-8 text-center font-mono text-[11px] text-dim">
                  no actors tracked in this window
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Panel>

      {/* 9. Recent commands executed */}
      <Panel title="recent commands executed" bodyClassName="max-h-[360px] overflow-auto">
        <table className="w-full min-w-[640px] border-collapse">
          <thead>
            <tr className="border-b border-edge">
              <Th>time</Th>
              <Th>ip</Th>
              <Th>user</Th>
              <Th>kind</Th>
              <Th>command</Th>
            </tr>
          </thead>
          <tbody>
            {recentCommands.map((event) => (
              <tr key={event.id} className="border-b border-edge/60">
                <td className={`${ACTOR_ROW} whitespace-nowrap text-dim`}>{agoShort(event.timestamp)}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-pos`}>{event.source_ip ?? '—'}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-ink`}>{event.username ?? '—'}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-ink`}>
                  {event.event_kind ?? 'command'}
                </td>
                <td className={`${ACTOR_ROW} text-pos`}>{truncate(event.payload ?? '', 90)}</td>
              </tr>
            ))}
            {recentCommands.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center font-mono text-[11px] text-dim">
                  no commands captured in this window
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Panel>

      {/* 10. Payload capture (live) */}
      <Panel
        title="payload capture (live)"
        right={
          <span className="rounded border border-pos/50 px-2 py-px font-mono text-[10px] tracking-[0.5px] text-pos">
            LIVE
          </span>
        }
        bodyClassName="p-0"
      >
        <div className="grid gap-3 px-3.5 pb-4 pt-3.5 sm:grid-cols-2 xl:grid-cols-4">
          <IntelTile
            label="tracked urls"
            accent="pos"
            value={payloads.data !== null ? formatNumber(payloads.data.stats.tracked_urls) : '—'}
          />
          <IntelTile
            label="saved to evidence"
            accent="pos"
            value={payloads.data !== null ? formatNumber(payloads.data.stats.saved) : '—'}
          />
          <IntelTile
            label="fetching now"
            accent="lime"
            value={payloads.data !== null ? formatNumber(payloads.data.stats.fetching_now) : '—'}
          />
          <IntelTile
            label="evidence on disk"
            accent="pos"
            value={payloads.data !== null ? humanBytes(payloads.data.stats.bytes_on_disk) : '—'}
          />
        </div>
        <div className="max-h-[300px] overflow-auto border-t border-edge">
          <table className="w-full min-w-[920px] border-collapse">
          <thead>
            <tr className="border-b border-edge">
              <Th>time</Th>
              <Th>status</Th>
              <Th>url / target</Th>
              <Th className="text-right">size</Th>
              <Th>sha256</Th>
              <Th>source ip</Th>
              <Th>origin</Th>
            </tr>
          </thead>
          <tbody>
            {(payloads.data?.items ?? []).slice(0, 20).map((item) => (
              <tr key={item.sha256 + item.time} className="border-b border-edge/60">
                <td className={`${ACTOR_ROW} whitespace-nowrap text-dim`}>{agoShort(item.time)}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap`}>
                  <span className="rounded border border-pos/50 px-1.5 py-px text-[9px] tracking-[0.5px] text-pos">
                    FETCHED
                  </span>
                </td>
                <td className={`${ACTOR_ROW} max-w-[260px] text-pos`} title={item.url}>
                  {truncate(item.url, 40)}
                </td>
                <td className={`${ACTOR_ROW} text-right whitespace-nowrap text-pos`}>
                  {humanBytes(item.size_bytes)}
                </td>
                <td className={`${ACTOR_ROW} max-w-[220px] text-dim`} title={item.sha256}>
                  {truncate(item.sha256, 32)}
                </td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-pos`}>{item.source_ip ?? '—'}</td>
                <td className={`${ACTOR_ROW} whitespace-nowrap text-dim`}>{item.origin}</td>
              </tr>
            ))}
            {(payloads.data?.items ?? []).length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center font-mono text-[11px] text-dim">
                  no payloads captured yet
                </td>
              </tr>
            )}
          </tbody>
          </table>
        </div>
      </Panel>

      {/* 11. Live attack timeline */}
      <Panel
        title="live attack timeline"
        right={
          <span
            className={`rounded border px-2 py-px font-mono text-[10px] tracking-[0.5px] ${
              wsOpen ? 'border-pos/50 text-pos' : 'border-edge text-dim'
            }`}
          >
            {wsOpen ? 'LIVE' : 'IDLE'}
          </span>
        }
        bodyClassName="p-3.5"
      >
        <p className="mb-3 text-right font-mono text-[10px] text-dim">
          last hour · {live.events.length} events
        </p>
        <AttackTimeline events={live.events} />
      </Panel>
    </div>
  );
}
