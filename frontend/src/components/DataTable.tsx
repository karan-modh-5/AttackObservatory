import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, Inbox } from 'lucide-react';

export interface Column<T> {
  key: keyof T & string;
  header: string;
  render?: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number;
  align?: 'left' | 'right';
  className?: string;
}

export type SortDir = 'asc' | 'desc';

export interface SortState<T> {
  key: keyof T & string;
  dir: SortDir;
}

interface DataTableProps<T> {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T) => string;
  emptyTitle?: string;
  emptyHint?: string;
  initialSort?: SortState<T>;
}

/** Generic sortable mono table with a styled empty state. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  emptyTitle = 'Nothing here yet',
  emptyHint,
  initialSort,
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState<T> | null>(initialSort ?? null);

  const sortedRows = useMemo(() => {
    if (sort === null) return rows;
    const column = columns.find((candidate) => candidate.key === sort.key);
    const select = column?.sortValue;
    if (select === undefined) return rows;
    const factor = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = select(a);
      const vb = select(b);
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * factor;
      return String(va).localeCompare(String(vb)) * factor;
    });
  }, [rows, columns, sort]);

  const toggleSort = (key: keyof T & string): void => {
    setSort((prev) => {
      if (prev?.key !== key) return { key, dir: 'asc' };
      if (prev.dir === 'asc') return { key, dir: 'desc' };
      return null;
    });
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left font-mono text-xs">
        <thead>
          <tr className="border-b border-edge">
            {columns.map((col) => {
              const active = sort?.key === col.key;
              const SortIcon = !col.sortValue
                ? null
                : active
                  ? sort.dir === 'asc'
                    ? ArrowUp
                    : ArrowDown
                  : ArrowUpDown;
              return (
                <th
                  key={col.key}
                  scope="col"
                  className={`px-4 py-2 text-[10px] font-medium uppercase tracking-[0.6px] text-dim ${
                    col.align === 'right' ? 'text-right' : ''
                  } ${col.className ?? ''}`}
                >
                  {col.sortValue ? (
                    <button
                      type="button"
                      onClick={() => toggleSort(col.key)}
                      className={`inline-flex items-center gap-1 transition-colors hover:text-ink ${
                        active ? 'text-lime' : ''
                      }`}
                    >
                      {col.header}
                      {SortIcon !== null && <SortIcon className="h-3 w-3" />}
                    </button>
                  ) : (
                    col.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center">
                <div className="flex flex-col items-center gap-2 text-dim">
                  <Inbox className="h-7 w-7 opacity-50" />
                  <p className="text-xs text-dim">{emptyTitle}</p>
                  {emptyHint !== undefined && <p className="text-[11px] text-dim/70">{emptyHint}</p>}
                </div>
              </td>
            </tr>
          ) : (
            sortedRows.map((row) => (
              <tr key={rowKey(row)} className="border-b border-edge/50 transition-colors last:border-0 hover:bg-white/[0.02]">
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={`px-4 py-2 text-ink/85 ${col.align === 'right' ? 'text-right' : ''} ${
                      col.className ?? ''
                    }`}
                  >
                    {col.render
                      ? col.render(row)
                      : row[col.key] === null || row[col.key] === undefined
                        ? '—'
                        : String(row[col.key])}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
