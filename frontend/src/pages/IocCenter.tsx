import { useState } from 'react';
import { useApi } from '../api/hooks';
import { api } from '../api/client';
import type { IocData, IocEntry } from '../api/types';
import { DataTable } from '../components/DataTable';
import type { Column } from '../components/DataTable';
import { Panel } from '../components/Panel';
import { WINDOW_DAYS, WindowChips } from '../components/WindowChips';
import type { WindowKey } from '../components/WindowChips';
import { flagEmoji, formatNumber, relativeTime } from '../lib/format';

type TabKey = 'ips' | 'urls' | 'domains' | 'hashes';

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: 'ips', label: 'ip addresses' },
  { key: 'urls', label: 'urls' },
  { key: 'domains', label: 'domains' },
  { key: 'hashes', label: 'hashes' },
];

/** /ioc/export expects singular type names (contract §4). */
const EXPORT_TYPE: Record<TabKey, string> = {
  ips: 'ip',
  urls: 'url',
  domains: 'domain',
  hashes: 'hash',
};

const INDICATOR_COLUMN: Column<IocEntry> = {
  key: 'value',
  header: 'Indicator',
  render: (row) => <span className="break-all text-ink/85">{row.value}</span>,
  sortValue: (row) => row.value,
};

const HITS_COLUMN: Column<IocEntry> = {
  key: 'hits',
  header: 'Hits',
  align: 'right',
  render: (row) => <span className="text-lime">{formatNumber(row.hits)}</span>,
  sortValue: (row) => row.hits,
};

const IP_COLUMNS: Array<Column<IocEntry>> = [
  INDICATOR_COLUMN,
  {
    key: 'country',
    header: 'Country',
    render: (row) => (
      <span className="whitespace-nowrap text-dim">
        {flagEmoji(row.country ?? null)} <span>{row.country ?? '—'}</span>
      </span>
    ),
    sortValue: (row) => row.country ?? '',
  },
  {
    key: 'asn',
    header: 'ASN',
    render: (row) => <span className="text-dim">{row.asn ?? '—'}</span>,
    sortValue: (row) => row.asn ?? '',
  },
  HITS_COLUMN,
  {
    key: 'last_seen',
    header: 'Last Seen',
    render: (row) => (
      <span className="whitespace-nowrap text-dim">{row.last_seen ? relativeTime(row.last_seen) : '—'}</span>
    ),
    sortValue: (row) => row.last_seen ?? '',
  },
];

const SIMPLE_COLUMNS: Array<Column<IocEntry>> = [INDICATOR_COLUMN, HITS_COLUMN];

export function IocCenter() {
  const [win, setWin] = useState<WindowKey>('7d');
  const [tab, setTab] = useState<TabKey>('ips');
  const [exporting, setExporting] = useState<'csv' | 'json' | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const { data, error, loading, reload } = useApi<IocData>('/ioc', { days: WINDOW_DAYS[win] });

  const handleExport = async (format: 'csv' | 'json') => {
    if (exporting !== null) return;
    setExporting(format);
    setExportError(null);
    try {
      const blob = await api.getBlob('/ioc/export', { format, types: EXPORT_TYPE[tab], days: WINDOW_DAYS[win] });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      anchor.href = url;
      anchor.download = `ioc_${stamp}.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setExporting(null);
    }
  };

  const columns = tab === 'ips' ? IP_COLUMNS : SIMPLE_COLUMNS;
  const rows = data !== null ? data[tab] : [];
  const activeTab = TABS.find((candidate) => candidate.key === tab) ?? TABS[0];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[13px] font-semibold uppercase tracking-[0.6px] text-ink">ioc center</h2>
        <div className="flex flex-wrap items-center gap-3">
          <WindowChips value={win} onChange={setWin} />
          <button
            type="button"
            onClick={reload}
            className="font-mono text-[11px] uppercase tracking-[0.6px] text-dim transition-colors hover:text-lime"
          >
            {loading ? 'syncing…' : '↻ refresh'}
          </button>
          <button
            type="button"
            onClick={() => handleExport('csv')}
            disabled={exporting !== null}
            className="font-mono text-[11px] text-lime underline-offset-2 transition-colors hover:underline disabled:opacity-40"
          >
            {exporting === 'csv' ? '… preparing' : '↓ download csv'}
          </button>
          <button
            type="button"
            onClick={() => handleExport('json')}
            disabled={exporting !== null}
            className="font-mono text-[11px] text-lime underline-offset-2 transition-colors hover:underline disabled:opacity-40"
          >
            {exporting === 'json' ? '… preparing' : '↓ download json'}
          </button>
        </div>
      </div>

      {error !== null && (
        <p className="rounded border border-neg/30 bg-neg/5 px-3.5 py-2 font-mono text-[11px] text-neg">
          {error}
        </p>
      )}

      {exportError !== null && (
        <p className="rounded border border-neg/30 bg-neg/5 px-3.5 py-2 font-mono text-[11px] text-neg">
          export failed: {exportError}
        </p>
      )}

      <div className="flex flex-wrap gap-1.5">
        {TABS.map((candidate) => {
          const active = candidate.key === tab;
          return (
            <button
              key={candidate.key}
              type="button"
              onClick={() => setTab(candidate.key)}
              className={`inline-flex items-center gap-2 rounded border px-3 py-1.5 font-mono text-[11px] transition-colors ${
                active ? 'border-lime/60 text-lime' : 'border-edge text-dim hover:text-ink'
              }`}
            >
              <span className={`h-1 w-1 rounded-full ${active ? 'bg-lime' : 'bg-edge'}`} />
              {candidate.label}
              <span className="text-[10px] text-dim">
                {data !== null ? formatNumber(data[candidate.key].length) : '—'}
              </span>
            </button>
          );
        })}
      </div>

      <Panel title={activeTab.label} right={<span className="font-mono text-[10px] text-dim">window {win}</span>}>
        <div className="max-h-[60vh] overflow-auto p-3.5 pt-1">
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(row) => row.value}
            emptyTitle={`No ${activeTab.label} for this period`}
            initialSort={{ key: 'hits', dir: 'desc' }}
          />
        </div>
      </Panel>
    </div>
  );
}
