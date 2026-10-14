import type { CSSProperties, ReactNode } from 'react';
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { TooltipProps } from 'recharts';

export const PALETTE = [
  '#d1fe17',
  '#40d986',
  '#ffb454',
  '#ff5449',
  '#a3ff5e',
  '#57e6a0',
  '#ffd27a',
  '#ff8a7a',
  '#c8ff45',
  '#2fbf6b',
  '#b0b2b4',
  '#6f7173',
];

const TOOLTIP_STYLE: CSSProperties = {
  backgroundColor: 'rgba(19, 21, 25, 0.96)',
  border: '1px solid #24272c',
  borderRadius: 6,
  padding: '6px 10px',
  fontSize: 11,
  fontFamily: '"JetBrains Mono", monospace',
};

export function ChartTooltip({
  active,
  payload,
  label,
}: TooltipProps<number, string>): ReactNode | null {
  if (active !== true || !payload || payload.length === 0) return null;
  return (
    <div style={TOOLTIP_STYLE}>
      {label !== undefined && label !== '' && (
        <p className="mb-1 max-w-[280px] truncate text-dim">{String(label)}</p>
      )}
      <div className="space-y-0.5">
        {payload.map((entry, index) => (
          <p key={index} className="flex items-center justify-between gap-4 text-ink">
            <span className="max-w-[240px] truncate text-dim">{entry.name ?? 'Count'}</span>
            <span className="font-mono text-lime">
              {typeof entry.value === 'number' ? entry.value.toLocaleString('en-US') : String(entry.value ?? '')}
            </span>
          </p>
        ))}
      </div>
    </div>
  );
}

function EmptyChart(): ReactNode {
  return (
    <div className="flex h-36 items-center justify-center rounded border border-dashed border-edge font-mono text-[11px] text-dim">
      No data for this period
    </div>
  );
}

export interface PieSlice {
  label: string;
  count: number;
}

interface CountPieProps {
  data: PieSlice[];
  height?: number;
  colors?: string[];
}

/** Donut pie for categorical breakdowns (attack types, protocols, …). */
export function CountPie({ data, height = 260, colors = PALETTE }: CountPieProps) {
  if (data.length === 0) return <EmptyChart />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="label"
          innerRadius="55%"
          outerRadius="85%"
          paddingAngle={3}
          stroke="#131519"
          strokeWidth={2}
        >
          {data.map((slice, index) => (
            <Cell key={slice.label} fill={colors[index % colors.length]} />
          ))}
        </Pie>
        <Tooltip content={<ChartTooltip />} />
        <Legend
          iconType="circle"
          iconSize={7}
          formatter={(value: unknown) => {
            const text = String(value);
            return <span className="font-mono text-[10px] text-dim">{text}</span>;
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
