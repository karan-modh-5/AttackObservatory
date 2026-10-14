import { useMemo } from 'react';
import { useApi } from '../api/hooks';
import type { MapPoints, NetworkStats, OverviewStats, Timeseries } from '../api/types';
import { LiveTicker } from '../components/LiveTicker';
import { Panel } from '../components/Panel';
import { RankBars } from '../components/RankBars';
import { SourceList } from '../components/SourceList';
import { StatTile } from '../components/StatTile';
import {
  ThreatGauge,
  breakdownFrom,
  threatLabel,
  threatScore,
} from '../components/ThreatGauge';
import { flagEmoji, formatNumber } from '../lib/format';

export function Overview() {
  const overview = useApi<OverviewStats>('/stats/overview');
  // 365d reaches the retention horizon — the closest an int-days API gets to all-time.
  const series = useApi<Timeseries>('/stats/timeseries', { days: 365, interval: 'day' });
  const geo = useApi<MapPoints>('/map/points', { days: 30 });
  const network = useApi<NetworkStats>('/network/stats', { days: 30 });

  const breakdown = useMemo(
    () => breakdownFrom(overview.data, series.data?.by_type.length ?? 0),
    [overview.data, series.data],
  );
  const score = threatScore(breakdown);
  const level = threatLabel(score);

  const countries = useMemo(
    () =>
      (geo.data?.top_countries ?? []).map((country) => ({
        name: `${flagEmoji(country.name)} ${country.name}`,
        count: country.count,
      })),
    [geo.data],
  );
  const eventTypes = useMemo(
    () => (series.data?.by_type ?? []).map((entry) => ({ name: entry.attack_type, count: entry.count })),
    [series.data],
  );

  const stats = overview.data;

  return (
    <div className="space-y-4">
      {/* Stat strip */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        <StatTile
          label="events"
          value={stats !== null ? formatNumber(stats.total_attacks) : '—'}
          sub={stats !== null ? `last 24h ${formatNumber(stats.last_24h)}` : undefined}
        />
        <StatTile label="unique attackers" value={stats !== null ? formatNumber(stats.unique_attackers) : '—'} />
        <StatTile label="countries" value={stats !== null ? formatNumber(stats.countries) : '—'} />
        <StatTile label="credentials" value={stats !== null ? formatNumber(stats.credentials_captured) : '—'} />
        <StatTile label="commands" value={stats !== null ? formatNumber(stats.commands_executed) : '—'} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="threat level">
          <div className="flex justify-center py-3">
            <ThreatGauge score={score} size={230} />
          </div>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 border-t border-edge px-4 py-3 font-mono text-[10px]">
            <span className="text-dim">volume</span>
            <span className="text-right text-ink">{breakdown.volume}/25</span>
            <span className="text-dim">intrusion</span>
            <span className="text-right text-ink">{breakdown.intrusion}/25</span>
            <span className="text-dim">diversity</span>
            <span className="text-right text-ink">{breakdown.diversity}/25</span>
            <span className="text-dim">exposure</span>
            <span className="text-right text-ink">{breakdown.exposure}/25</span>
          </div>
          <p className="border-t border-edge px-4 py-2 font-mono text-[10px] text-dim">
            last 24h · {formatNumber(stats?.last_24h ?? 0)} events · {formatNumber(stats?.unique_attackers ?? 0)}{' '}
            attackers · {level.toLowerCase()}
          </p>
        </Panel>

        <Panel title="attack geography" bodyClassName="p-3.5">
          <RankBars data={countries} maxRows={9} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="event types (events, all-time)" bodyClassName="p-3.5">
          <RankBars data={eventTypes} maxRows={9} />
        </Panel>

        <Panel title="top attacker ips">
          <SourceList sources={network.data?.top_sources ?? []} maxRows={9} />
        </Panel>
      </div>

      <LiveTicker />
    </div>
  );
}
