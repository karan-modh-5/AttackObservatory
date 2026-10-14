import { useState } from 'react';
import { useApi } from '../api/hooks';
import type { WebStats } from '../api/types';
import { CountPie } from '../lib/chart';
import { Panel } from '../components/Panel';
import { RankBars } from '../components/RankBars';
import { StatTile } from '../components/StatTile';
import { WINDOW_DAYS, WindowChips } from '../components/WindowChips';
import type { WindowKey } from '../components/WindowChips';
import { formatNumber } from '../lib/format';

export function WebAnalytics() {
  const [win, setWin] = useState<WindowKey>('30d');
  const { data, error, loading, reload } = useApi<WebStats>('/web/stats', { days: WINDOW_DAYS[win] });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">
          web analytics
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
        <StatTile label="scanner events" value={data !== null ? formatNumber(data.scanner_events) : '—'} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="top urls" bodyClassName="p-3.5">
          <RankBars data={data?.top_urls ?? []} maxRows={8} />
        </Panel>

        <Panel title="attack types" bodyClassName="p-3.5">
          <CountPie
            data={(data?.attack_types ?? []).map((entry) => ({ label: entry.attack_type, count: entry.count }))}
          />
        </Panel>

        <Panel title="top user agents" bodyClassName="p-3.5">
          <RankBars data={data?.top_user_agents ?? []} maxRows={8} />
        </Panel>

        <Panel title="exploit payloads" bodyClassName="p-3.5">
          <RankBars data={data?.exploit_payloads ?? []} maxRows={8} />
        </Panel>
      </div>
    </div>
  );
}
