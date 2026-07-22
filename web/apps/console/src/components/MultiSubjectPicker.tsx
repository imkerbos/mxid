import { useEffect, useRef, useState } from 'react'
import { Loader2, X, Search, Check } from 'lucide-react'
import { userApi, groupApi, orgApi, permissionApi, cn, useTranslation, AccessPolicySubjectType } from '@mxid/shared'
import type { OrgNode } from '@mxid/shared'

// Subject types that support multi-select (public is a single global rule and
// is handled outside this picker).
export type MultiSubjectType = 'user' | 'group' | 'org' | 'role'

export interface SubjectOption {
  id: string
  label: string
  secondary?: string
}

interface Props {
  subjectType: MultiSubjectType
  /** Ids already attached to the policy — shown but not selectable. */
  excludeIds: Set<string>
  /** Currently picked options (multi). */
  selected: SubjectOption[]
  onChange: (opts: SubjectOption[]) => void
  placeholder?: string
}

function flattenOrgs(nodes: OrgNode[], acc: SubjectOption[] = []): SubjectOption[] {
  for (const n of nodes) {
    acc.push({ id: n.id, label: n.name, secondary: n.code })
    if (n.children?.length) flattenOrgs(n.children, acc)
  }
  return acc
}

/**
 * MultiSubjectPicker — searchable multi-select for access-policy subjects.
 * Users/groups search server-side (?search= / ?keyword=); orgs/roles load once
 * and filter client-side. Subjects already on the policy (excludeIds) render
 * disabled with an "added" hint so the admin sees why they can't re-pick them.
 */
export default function MultiSubjectPicker({ subjectType, excludeIds, selected, onChange, placeholder }: Props) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [options, setOptions] = useState<SubjectOption[]>([])
  // Client-side cache for the tree/role types (no keyword endpoint).
  const [localCache, setLocalCache] = useState<SubjectOption[] | null>(null)
  const boxRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  // Reset when the subject type flips (parent also clears `selected`).
  useEffect(() => {
    setQuery('')
    setOptions([])
    setLocalCache(null)
    setOpen(false)
  }, [subjectType])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    const handle = setTimeout(async () => {
      setLoading(true)
      try {
        let opts: SubjectOption[] = []
        if (subjectType === AccessPolicySubjectType.User) {
          const data = await userApi.list({ search: query, page: 1, page_size: 20 })
          opts = data.items.map((u) => ({ id: u.id, label: u.display_name || u.username, secondary: u.email || u.username }))
        } else if (subjectType === AccessPolicySubjectType.Group) {
          const data = await groupApi.list({ keyword: query, page: 1, page_size: 20 })
          opts = data.items.map((g) => ({ id: g.id, label: g.name, secondary: g.code }))
        } else {
          let all = localCache
          if (!all) {
            if (subjectType === AccessPolicySubjectType.Org) {
              const tree = await orgApi.tree()
              all = flattenOrgs(tree)
            } else {
              const r = await permissionApi.listRoles({ page: 1, page_size: 200 })
              all = r.items.map((role: { id: string; name: string; code: string }) => ({ id: role.id, label: role.name, secondary: role.code }))
            }
            if (!cancelled) setLocalCache(all)
          }
          const q = query.trim().toLowerCase()
          opts = (q ? all.filter((o) => o.label.toLowerCase().includes(q) || (o.secondary || '').toLowerCase().includes(q)) : all).slice(0, 30)
        }
        if (!cancelled) setOptions(opts)
      } catch {
        if (!cancelled) setOptions([])
      } finally {
        if (!cancelled) setLoading(false)
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [query, subjectType, open, localCache])

  const selectedIds = new Set(selected.map((s) => s.id))
  const toggle = (o: SubjectOption) => {
    if (excludeIds.has(o.id)) return
    if (selectedIds.has(o.id)) onChange(selected.filter((s) => s.id !== o.id))
    else onChange([...selected, o])
  }

  return (
    <div ref={boxRef} className="relative">
      {selected.length > 0 && (
        <div className="mb-2 flex flex-wrap gap-1.5">
          {selected.map((o) => (
            <span key={o.id} className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">
              {o.label}
              <button type="button" onClick={() => toggle(o)} className="rounded-full hover:bg-primary/20" aria-label={t('common.remove')}>
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="flex items-center rounded-lg border border-border px-3 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/20">
        <Search className="h-4 w-4 shrink-0 text-faint" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => setOpen(true)}
          placeholder={placeholder || t('permissions.subjectPicker.placeholder')}
          className="w-full bg-transparent px-2 py-2 text-sm outline-none"
        />
        {loading && <Loader2 className="h-4 w-4 shrink-0 animate-spin text-faint" />}
      </div>
      {open && (
        <div className="absolute z-20 mt-1 max-h-60 w-full overflow-auto rounded-lg border border-border bg-surface py-1 shadow-lg">
          {options.length === 0 ? (
            <p className="px-3 py-4 text-center text-xs text-faint">
              {loading ? t('common.loading') : t('permissions.subjectPicker.noResults')}
            </p>
          ) : (
            options.map((o) => {
              const isExcluded = excludeIds.has(o.id)
              const isSelected = selectedIds.has(o.id)
              return (
                <button
                  key={o.id}
                  type="button"
                  disabled={isExcluded}
                  onClick={() => toggle(o)}
                  className={cn(
                    'flex w-full items-center gap-2 px-3 py-2 text-left',
                    isExcluded ? 'cursor-not-allowed opacity-50' : 'hover:bg-surface-muted',
                  )}
                >
                  <span className={cn('flex h-4 w-4 shrink-0 items-center justify-center rounded border', isSelected ? 'border-primary bg-primary text-white' : 'border-border')}>
                    {isSelected && <Check className="h-3 w-3" />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm text-ink">{o.label}</span>
                    {o.secondary && <span className="block text-xs text-faint">{o.secondary} · #{o.id}</span>}
                  </span>
                  {isExcluded && <span className="shrink-0 text-xs text-faint">{t('apps.access.alreadyAdded')}</span>}
                </button>
              )
            })
          )}
        </div>
      )}
    </div>
  )
}
