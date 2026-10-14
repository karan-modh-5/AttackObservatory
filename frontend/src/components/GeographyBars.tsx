import type { NameCount } from '../api/types';
import { countryName } from '../lib/countries';

/**
 * ATTACK GEOGRAPHY list: two-letter country chip, truncated country name,
 * thin lime bar, right-aligned mono count — reference rows like
 * `NL The Nether… ▬▬▬▬ 18,976`.
 */
export function GeographyBars({ data, maxRows = 10 }: { data: NameCount[]; maxRows?: number }) {
  const rows = data.slice(0, maxRows);
  if (rows.length === 0) {
    return (
      <p className="rounded border border-dashed border-edge px-3 py-8 text-center font-mono text-[11px] text-dim">
        No geography data for this period
      </p>
    );
  }
  const max = Math.max(1, ...rows.map((row) => row.count));
  return (
    <div className="space-y-[7px]">
      {rows.map((row) => {
        const code = row.name.toUpperCase();
        return (
          <div key={row.name} className="flex items-center gap-2.5">
            <span className="w-[22px] shrink-0 border border-edge px-0.5 text-center font-mono text-[9px] text-dim">
              {code}
            </span>
            <span className="w-[92px] shrink-0 truncate font-mono text-[11px] text-ink" title={countryName(row.name)}>
              {countryName(row.name)}
            </span>
            <span className="h-[5px] min-w-0 flex-1 overflow-hidden rounded-[2px] bg-white/5">
              <span
                className="block h-full bg-lime transition-[width] duration-500"
                style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }}
              />
            </span>
            <span className="w-14 shrink-0 text-right font-mono text-[11px] text-lime">
              {row.count.toLocaleString('en-US')}
            </span>
          </div>
        );
      })}
    </div>
  );
}
