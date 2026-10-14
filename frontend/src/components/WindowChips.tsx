export type WindowKey = '1h' | '24h' | '7d' | '30d';

export const WINDOW_KEYS: WindowKey[] = ['1h', '24h', '7d', '30d'];

/** The API window is day-granular (int days ≥ 1), so 1h rides the 1-day window. */
export const WINDOW_DAYS: Record<WindowKey, number> = { '1h': 1, '24h': 1, '7d': 7, '30d': 30 };

/** Bucket size for /stats/timeseries given a window chip. */
export const WINDOW_INTERVAL: Record<WindowKey, 'hour' | 'day'> = {
  '1h': 'hour',
  '24h': 'hour',
  '7d': 'day',
  '30d': 'day',
};

interface WindowChipsProps {
  value: WindowKey;
  onChange: (key: WindowKey) => void;
  className?: string;
}

/** Reference-style window chips: 1h 24h 7d 30d, active = lime text + lime border. */
export function WindowChips({ value, onChange, className = '' }: WindowChipsProps) {
  return (
    <div className={`inline-flex items-center gap-1 ${className}`}>
      {WINDOW_KEYS.map((key) => (
        <button
          key={key}
          type="button"
          onClick={() => onChange(key)}
          aria-pressed={key === value}
          className={`rounded border px-2 py-0.5 font-mono text-[11px] transition-colors ${
            key === value ? 'border-lime/60 text-lime' : 'border-edge text-dim hover:text-ink'
          }`}
        >
          {key}
        </button>
      ))}
    </div>
  );
}
