import type { HeatmapResponse } from '../api/types';

/** Per-kind hue: intensity scales with the count relative to that row's max. */
const KIND_COLOR: Record<string, string> = {
  accepted: '#40d986',
  failed_password: '#d1fe17',
  command: '#3d4a3a',
  connect: '#a78bfa',
  client_version: '#898a8b',
  file_download: '#ffb454',
  file_upload: '#ffb454',
};

function cellStyle(kind: string, count: number, rowMax: number): React.CSSProperties {
  if (count <= 0) return { backgroundColor: 'rgba(247, 247, 248, 0.04)' };
  const base = KIND_COLOR[kind] ?? '#d1fe17';
  const intensity = 0.25 + 0.75 * Math.min(1, count / Math.max(1, rowMax));
  const r = parseInt(base.slice(1, 3), 16);
  const g = parseInt(base.slice(3, 5), 16);
  const b = parseInt(base.slice(5, 7), 16);
  return { backgroundColor: `rgba(${r}, ${g}, ${b}, ${intensity.toFixed(2)})` };
}

/** Cell label under the column for the hour axis, printed every 12 buckets. */
function hourLabel(iso: string): string {
  const date = new Date(iso);
  return `${String(date.getHours()).padStart(2, '0')}:00`;
}

/** Full-width 72h × event-kind CSS-grid heatmap with a dim hour axis. */
export function ActivityHeatmap({ data }: { data: HeatmapResponse | null }) {
  if (data === null || data.hours.length === 0 || data.kinds.length === 0) {
    return (
      <p className="rounded border border-dashed border-edge px-3 py-10 text-center font-mono text-[11px] text-dim">
        No heatmap data for this period
      </p>
    );
  }
  const columns = data.hours.length;
  const template = `84px repeat(${columns}, minmax(0, 1fr))`;
  return (
    <div className="overflow-x-auto pb-1">
      <div className="min-w-[720px]">
        {data.kinds.map((kind, k) => {
          const row = data.matrix[k] ?? [];
          const rowMax = Math.max(1, ...row);
          return (
            <div key={kind} className="grid items-center gap-[2px]" style={{ gridTemplateColumns: template }}>
              <span className="truncate pr-2 text-right font-mono text-[10px] text-dim" title={kind}>
                {kind}
              </span>
              {data.hours.map((hour, h) => {
                const count = row[h] ?? 0;
                return (
                  <div
                    key={hour}
                    title={`${kind} · ${hourLabel(hour)} · ${count}`}
                    className="aspect-square rounded-[1px]"
                    style={cellStyle(kind, count, rowMax)}
                  />
                );
              })}
            </div>
          );
        })}
        <div className="grid gap-[2px] pt-1.5" style={{ gridTemplateColumns: template }}>
          <span />
          {data.hours.map((hour, h) => (
            <span key={hour} className="text-center font-mono text-[9px] text-dim">
              {h % 12 === 0 ? hourLabel(hour) : ''}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
