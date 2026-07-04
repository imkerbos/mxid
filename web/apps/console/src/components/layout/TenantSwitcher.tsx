// TenantSwitcher — sits in the sidebar. Full-width button that matches the
// dark sidebar theme. Dropdown anchored left+right within the 256px sidebar
// gutter so labels never get clipped.
import { useCallback, useEffect, useState } from 'react'
import { Building2, ChevronsUpDown, Check } from 'lucide-react'
import {
  tenantApi,
  getActiveTenantID,
  setActiveTenantID,
  cn,
  useTranslation,
} from '@mxid/shared'
import type { Tenant } from '@mxid/shared'

export default function TenantSwitcher() {
  const { t } = useTranslation()
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [open, setOpen] = useState(false)
  const [activeID, setActiveID] = useState<string | null>(() => getActiveTenantID())

  const load = useCallback(async () => {
    try {
      const list = await tenantApi.list()
      setTenants(list ?? [])
      // Defensive: if the localStorage active tenant points to a tenant
      // that no longer exists (e.g. deleted while user was logged in,
      // or stale from a previous DB reset), clear it so subsequent
      // requests fall back to the session tenant instead of returning
      // empty lists with a phantom X-Tenant-ID header.
      const stored = getActiveTenantID()
      if (stored && !(list ?? []).some((t) => String(t.id) === stored)) {
        setActiveTenantID(null)
        setActiveID(null)
        // Reload once so all open queries re-fire without the stale header.
        window.location.reload()
      }
    } catch {
      setTenants([])
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // No tenants at all → hide entirely. Otherwise always show the current
  // tenant; the dropdown only opens when there's more than one to switch to.
  if (tenants.length === 0) return null

  const active = tenants.find((t) => String(t.id) === (activeID ?? '')) ?? tenants[0]
  const canSwitch = tenants.length > 1

  const pick = (t: Tenant) => {
    const id = String(t.id)
    setActiveTenantID(id)
    setActiveID(id)
    setOpen(false)
    window.location.reload()
  }

  return (
    <div className="relative w-full">
      <button
        onClick={() => canSwitch && setOpen((o) => !o)}
        disabled={!canSwitch}
        className="flex w-full items-center justify-between gap-2 rounded-lg border border-white/10 bg-surface/5 px-3 py-2 text-sm text-white/90 transition-colors hover:bg-surface/10 disabled:cursor-default disabled:hover:bg-surface/5"
        title={canSwitch ? t('nav.switchTenant') : t('nav.currentTenant')}
      >
        <div className="flex min-w-0 items-center gap-2">
          <Building2 className="h-4 w-4 shrink-0 text-white/60" />
          <span className="truncate font-medium">{active?.name ?? t('nav.defaultTenant')}</span>
        </div>
        {canSwitch && <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-white/40" />}
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute left-0 right-0 z-50 mt-1 rounded-lg border border-white/10 bg-sidebar py-1 shadow-2xl">
            {tenants.map((t) => {
              const isActive = String(t.id) === String(active?.id ?? '')
              return (
                <button
                  key={t.id}
                  onClick={() => pick(t)}
                  className={cn(
                    'flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm transition-colors',
                    isActive
                      ? 'bg-primary/20 text-white'
                      : 'text-white/80 hover:bg-surface/5 hover:text-white',
                  )}
                >
                  <div className="min-w-0">
                    <div className="truncate font-medium">{t.name}</div>
                    <div className="truncate text-xs text-white/40">{t.code}</div>
                  </div>
                  {isActive && <Check className="h-3.5 w-3.5 shrink-0 text-primary" />}
                </button>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
