import { useState } from 'react';
import { useApi } from '../api/hooks';
import type { NetworkSource, NetworkStats } from '../api/types';
import { DataTable } from '../components/DataTable';
import type { Column } from '../components/DataTable';
import { CountPie } from '../lib/chart';
import { Panel } from '../components/Panel';
import { RankBars } from '../components/RankBars';
import { StatTile } from '../components/StatTile';
import { WINDOW_DAYS, WindowChips } from '../components/WindowChips';
import type { WindowKey } from '../components/WindowChips';
import { flagEmoji, formatNumber } from '../lib/format';

const SOURCE_COLUMNS: Array<Column<NetworkSource>> = [
  {
    key: 'name',
    header: 'Source IP',
    render: (row) => <span className="break-all text-neg">{row.name}</span>,
    sortValue: (row) => row.name,
  },
  {
    key: 'country',
    header: 'Country',
    render: (row) => (
      <span className="whitespace-nowrap text-dim">
        {flagEmoji(row.country)} <span>{row.country ?? '—'}</span>
      </span>
    ),
    sortValue: (row) => row.country ?? '',
  },
  {
    key: 'count',
    header: 'Alerts',
    align: 'right',
    render: (row) => <span className="text-lime">{formatNumber(row.count)}</span>,
    sortValue: (row) => row.count,
  },
];

export function NetworkAnalytics() {
  const [win, setWin] = useState<WindowKey>('30d');
  const { data, error, loading, reload } = useApi<NetworkStats>('/network/stats', {
    days: WINDOW_DAYS[win],
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">
          network analytics
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

      {error !== null && (
        <p className="rounded border border-neg/30 bg-neg/5 px-3.5 py-2 font-mono text-[11px] text-neg">
          {error}
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="total alerts" value={data !== null ? formatNumber(data.total_alerts) : '—'} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="top signatures" bodyClassName="p-3.5">
          <RankBars data={data?.signatures ?? []} maxRows={8} />
        </Panel>

        <Panel title="protocols" bodyClassName="p-3.5">
          <CountPie data={(data?.protocols ?? []).map((entry) => ({ label: entry.name, count: entry.count }))} />
        </Panel>

        <Panel title="top sources" className="xl:col-span-2" bodyClassName="max-h-[420px] overflow-auto p-3.5 pt-1">
          <DataTable
            columns={SOURCE_COLUMNS}
            rows={data?.top_sources ?? []}
            rowKey={(row) => row.name}
            emptyTitle="No alerts for this period"
            initialSort={{ key: 'count', dir: 'desc' }}
          />
        </Panel>
      </div>
    </div>
  );
}
