import type { Severity } from '../api/types';

/** Flat text tone per contract §2 severity values. */
const TONE: Record<Severity, string> = {
  info: 'text-dim',
  low: 'text-pos',
  medium: 'text-lime',
  high: 'text-warn',
  critical: 'text-neg',
};

export const SEVERITY_DOT: Record<Severity, string> = {
  info: 'bg-dim',
  low: 'bg-pos',
  medium: 'bg-lime',
  high: 'bg-warn',
  critical: 'bg-neg',
};

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded border border-edge px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.6px] ${TONE[severity]}`}
    >
      <span className={`h-1 w-1 rounded-full ${SEVERITY_DOT[severity]}`} />
      {severity}
    </span>
  );
}
