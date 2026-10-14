interface StatTileProps {
  label: string;
  /** Preformatted display value (mono, rendered large). */
  value: string;
  /** Optional small sub-label under the tile caption. */
  sub?: string;
  className?: string;
}

/** Flat stat tile: big JetBrains Mono number over a 10px uppercase label. */
export function StatTile({ label, value, sub, className = '' }: StatTileProps) {
  return (
    <div className={`rounded border border-edge bg-panel px-4 py-3.5 ${className}`}>
      <p className="font-mono text-[24px] font-semibold leading-none text-lime">{value}</p>
      <p className="panel-title mt-2.5">{label}</p>
      {sub !== undefined && <p className="mt-0.5 font-mono text-[10px] text-dim">{sub}</p>}
    </div>
  );
}
