import type { NameCount } from '../api/types';

interface RankBarsProps {
  data: NameCount[];
  maxRows?: number;
  /** Tailwind background class for the bar fill. */
  barClassName?: string;
  /** Tailwind text class for the right-aligned value. */
  valueClassName?: string;
  emptyLabel?: string;
}

/** Reference-style ranking: thin 4px bar, mono name left, value right-aligned. */
export function RankBars({
  data,
  maxRows = 8,
  barClassName = 'bg-lime',
  valueClassName = 'text-lime',
  emptyLabel = 'No data for this period',
}: RankBarsProps) {
  const rows = data.slice(0, maxRows);
  if (rows.length === 0) {
    return (
      <p className="rounded border border-dashed border-edge px-3 py-8 text-center font-mono text-[11px] text-dim">
        {emptyLabel}
      </p>
    );
  }
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <div key={row.name} className="flex items-center gap-3">
          <span className="w-28 shrink-0 truncate font-mono text-[11px] text-dim sm:w-36" title={row.name}>
            {row.name}
          </span>
          <span className="h-1 min-w-0 flex-1 overflow-hidden rounded-full bg-white/5">
            <span
              className={`block h-full rounded-full transition-[width] duration-500 ${barClassName}`}
              style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }}
            />
          </span>
          <span className={`w-14 shrink-0 text-right font-mono text-[11px] ${valueClassName}`}>
            {row.count.toLocaleString('en-US')}
          </span>
        </div>
      ))}
    </div>
  );
}
