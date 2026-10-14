import { useState } from 'react';
import { useApi } from '../api/hooks';
import type { CredentialStats } from '../api/types';
import { DataTable } from '../components/DataTable';
import type { Column } from '../components/DataTable';
import { Panel } from '../components/Panel';
import { RankBars } from '../components/RankBars';
import { StatTile } from '../components/StatTile';
import { WINDOW_DAYS, WindowChips } from '../components/WindowChips';
import type { WindowKey } from '../components/WindowChips';
import { formatNumber } from '../lib/format';

interface ReusePair {
  username: string;
  password: string;
  count: number;
}

const REUSE_COLUMNS: Array<Column<ReusePair>> = [
  {
    key: 'username',
    header: 'Username',
    render: (row) => <span className="break-all text-ink/85">{row.username}</span>,
    sortValue: (row) => row.username,
  },
  {
    key: 'password',
    header: 'Password',
    render: (row) => <span className="break-all text-warn/90">{row.password}</span>,
    sortValue: (row) => row.password,
  },
  {
    key: 'count',
    header: 'Reuses',
    align: 'right',
    render: (row) => <span className="text-lime">{formatNumber(row.count)}</span>,
    sortValue: (row) => row.count,
  },
];

export function CredentialAnalytics() {
  const [win, setWin] = useState<WindowKey>('30d');
  const { data, error, loading, reload } = useApi<CredentialStats>('/credentials/stats', {
    days: WINDOW_DAYS[win],
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">
          credential analytics
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
        <StatTile
          label="unique credential pairs"
          value={data !== null ? formatNumber(data.unique_pairs) : '—'}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="top usernames" bodyClassName="p-3.5">
          <RankBars data={data?.top_usernames ?? []} maxRows={8} />
        </Panel>

        <Panel title="top passwords" bodyClassName="p-3.5">
          <RankBars data={data?.top_passwords ?? []} maxRows={8} />
        </Panel>

        <Panel title="by service" bodyClassName="p-3.5">
          <RankBars data={data?.by_service ?? []} maxRows={8} />
        </Panel>

        <Panel title="credential reuse pairs" bodyClassName="max-h-[420px] overflow-auto p-3.5 pt-1">
          <DataTable
            columns={REUSE_COLUMNS}
            rows={data?.reuse_pairs ?? []}
            rowKey={(row) => `${row.username}:${row.password}`}
            emptyTitle="No reuse pairs for this period"
            initialSort={{ key: 'count', dir: 'desc' }}
          />
        </Panel>
      </div>
    </div>
  );
}
