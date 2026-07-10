// DataTable + Pagination — the list-page workhorses. Pages pass column configs
// and rows; the table owns the header/hover/empty/loading chrome so every list
// looks identical. All colors are semantic tokens → dark-mode native.
import { useEffect } from 'react'
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from 'lucide-react'
import { cn, useTranslation } from '@mxid/shared'
import type { ReactNode } from 'react'
import { EmptyState } from './index'

export interface Column<T> {
  key: string
  title: ReactNode
  align?: 'left' | 'right' | 'center'
  width?: string
  render?: (row: T, index: number) => ReactNode
  // sortable marks the header clickable; the table is CONTROLLED — it calls
  // onSort(key) and the parent decides how to reorder / refetch.
  sortable?: boolean
}

const ALIGN = { left: 'text-left', right: 'text-right', center: 'text-center' } as const

export interface SortState {
  key: string
  dir: 'asc' | 'desc'
}

interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string | number
  loading?: boolean
  emptyText?: ReactNode
  onRowClick?: (row: T) => void
  selectable?: boolean
  selectedKeys?: Set<string | number>
  onToggleRow?: (key: string | number, row: T) => void
  onToggleAll?: (checked: boolean) => void
  // Controlled sort: pass the active sort + a handler to enable sortable headers.
  sort?: SortState
  onSort?: (key: string) => void
  // Number of shimmer rows to show while loading (defaults to 5). Skeleton rows
  // preserve the column layout instead of collapsing to a centred spinner.
  skeletonRows?: number
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  emptyText,
  onRowClick,
  selectable,
  selectedKeys,
  onToggleRow,
  onToggleAll,
  sort,
  onSort,
  skeletonRows = 5,
}: DataTableProps<T>) {
  const { t } = useTranslation()
  const safeRows = Array.isArray(rows) ? rows : []
  const colCount = columns.length + (selectable ? 1 : 0)
  const allSelected =
    safeRows.length > 0 && selectedKeys != null && safeRows.every((r) => selectedKeys.has(rowKey(r)))

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-muted text-left text-xs font-medium uppercase tracking-wider text-faint">
            {selectable && (
              <th style={{ width: 40 }} className="px-4 py-3 text-center">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-primary"
                  checked={allSelected}
                  onChange={() => onToggleAll?.(!allSelected)}
                  aria-label={t('common.selectAll')}
                />
              </th>
            )}
            {columns.map((col) => {
              const sortable = col.sortable && onSort
              const active = sort?.key === col.key
              return (
                <th
                  key={col.key}
                  style={col.width ? { width: col.width } : undefined}
                  aria-sort={active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                  className={cn('px-6 py-3', ALIGN[col.align ?? 'left'])}
                >
                  {sortable ? (
                    <button
                      type="button"
                      onClick={() => onSort(col.key)}
                      className={cn(
                        'inline-flex items-center gap-1 font-medium uppercase tracking-wider hover:text-ink',
                        active ? 'text-ink' : 'text-faint',
                      )}
                    >
                      {col.title}
                      {active ? (
                        sort!.dir === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                      ) : (
                        <ChevronsUpDown className="h-3 w-3 opacity-60" />
                      )}
                    </button>
                  ) : (
                    col.title
                  )}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            Array.from({ length: skeletonRows }).map((_, i) => (
              <tr key={`sk-${i}`} className="border-b border-border/60 last:border-0">
                {selectable && (
                  <td className="px-4 py-3">
                    <div className="h-4 w-4 animate-pulse rounded bg-surface-muted" />
                  </td>
                )}
                {columns.map((col) => (
                  <td key={col.key} className={cn('px-6 py-3', ALIGN[col.align ?? 'left'])}>
                    <div className="h-4 animate-pulse rounded bg-surface-muted" style={{ width: `${40 + ((i * 7 + col.key.length * 5) % 45)}%` }} />
                  </td>
                ))}
              </tr>
            ))
          ) : safeRows.length === 0 ? (
            <tr>
              <td colSpan={colCount}>
                <EmptyState>{emptyText ?? t('common.noData')}</EmptyState>
              </td>
            </tr>
          ) : (
            safeRows.map((row, i) => {
              const key = rowKey(row)
              return (
                <tr
                  key={key}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    'border-b border-border/60 transition-colors last:border-0 hover:bg-surface-muted',
                    onRowClick && 'cursor-pointer',
                  )}
                >
                  {selectable && (
                    <td className="px-4 py-3 text-center" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        className="h-4 w-4 accent-primary"
                        checked={selectedKeys?.has(key) ?? false}
                        onChange={() => onToggleRow?.(key, row)}
                        aria-label={t('common.selectRow')}
                      />
                    </td>
                  )}
                  {columns.map((col) => (
                    <td key={col.key} className={cn('px-6 py-3', ALIGN[col.align ?? 'left'])}>
                      {col.render ? col.render(row, i) : ((row as Record<string, ReactNode>)[col.key])}
                    </td>
                  ))}
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}

const PAGER_BTN =
  'inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted transition-colors hover:bg-surface-muted hover:text-ink disabled:opacity-40 disabled:hover:bg-transparent'

export function Pagination({
  page,
  pageSize,
  total,
  onChange,
  onPageSizeChange,
  pageSizeOptions = [10, 20, 50, 100],
}: {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
  // Opt-in page-size selector; omit to keep the plain prev/next pager.
  onPageSizeChange?: (size: number) => void
  pageSizeOptions?: number[]
}) {
  const { t } = useTranslation()
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  // Snap back into range when the data shrinks (e.g. page=3 but only 1 page
  // left after a filter) so the list never renders empty on a valid dataset.
  useEffect(() => {
    if (total > 0 && page > totalPages) onChange(totalPages)
  }, [page, totalPages, total, onChange])

  return (
    <div className="flex items-center justify-end gap-3 px-6 py-3 text-sm">
      {onPageSizeChange && (
        <select
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value))}
          aria-label={t('common.rowsPerPage')}
          className="rounded-control border border-border bg-surface px-2 py-1 text-muted outline-none focus:border-primary"
        >
          {pageSizeOptions.map((n) => (
            <option key={n} value={n}>
              {t('common.pageSize', { n })}
            </option>
          ))}
        </select>
      )}
      <span className="text-muted">{t('common.totalItems', { count: total })}</span>
      <button
        type="button"
        className={PAGER_BTN}
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        aria-label={t('common.prevPage')}
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <span className="tabular-nums text-muted">{t('common.pageOf', { page, pages: totalPages })}</span>
      <button
        type="button"
        className={PAGER_BTN}
        disabled={page >= totalPages}
        onClick={() => onChange(page + 1)}
        aria-label={t('common.nextPage')}
      >
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  )
}
