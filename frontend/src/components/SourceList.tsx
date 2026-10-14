import type { NetworkSource } from '../api/types';
import { flagEmoji, formatNumber } from '../lib/format';

interface SourceListProps {
  sources: NetworkSource[];
  maxRows?: number;
}

/** Reference-style TOP SOURCE IPS listing: red mono IP, gray location, lime hits. */
export function SourceList({ sources, maxRows = 8 }: SourceListProps) {
  const rows = sources.slice(0, maxRows);
  if (rows.length === 0) {
    return (
      <p className="px-3.5 py-8 text-center font-mono text-[11px] text-dim">No sources for this period</p>
    );
  }
  return (
    <div>
      <div className="grid grid-cols-[minmax(0,1fr)_64px_56px] gap-x-2 border-b border-edge/60 px-3.5 py-1.5 font-mono text-[9px] uppercase tracking-[0.6px] text-dim">
        <span>ip</span>
        <span>loc</span>
        <span className="text-right">hits</span>
      </div>
      <div className="divide-y divide-edge/50">
        {rows.map((source) => (
          <div
            key={source.name}
            className="grid grid-cols-[minmax(0,1fr)_64px_56px] items-center gap-x-2 px-3.5 py-[5px]"
          >
            <span className="truncate font-mono text-[11px] text-pos" title={source.name}>
              {source.name}
            </span>
            <span className="truncate font-mono text-[10px] text-dim">
              {source.country === null ? '—' : `${flagEmoji(source.country)} ${source.country}`}
            </span>
            <span className="text-right font-mono text-[11px] text-lime">{formatNumber(source.count)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
