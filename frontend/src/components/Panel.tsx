import type { ReactNode } from 'react';

interface PanelProps {
  title?: string;
  /** Small right-aligned content for the panel header (labels, counts). */
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}

/** Flat ShardLure panel: #131519 body, 1px #24272c edge, 6px radius. */
export function Panel({ title, right, children, className = '', bodyClassName = '' }: PanelProps) {
  return (
    <section className={`panel ${className}`}>
      {title !== undefined && (
        <header className="flex items-center justify-between gap-2 border-b border-edge px-3.5 py-2.5">
          <h2 className="panel-title">{title}</h2>
          {right}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}
