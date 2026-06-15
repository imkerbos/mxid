import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * useTabParam — persist a single tab/view selection into ?key=value.
 *
 * Refresh-safe: the active tab survives full page reloads and is shareable
 * via copy-paste. When the param is missing or not in `allowed`, the hook
 * returns `defaultValue` (and does NOT eagerly write it — the URL stays
 * clean until the user actively changes the tab).
 *
 * Generic over a literal union so consumers get static typing on tab keys.
 */
export function useTabParam<T extends string>(
  key: string,
  defaultValue: T,
  allowed: readonly T[],
): [T, (next: T) => void] {
  const [params, setParams] = useSearchParams()
  const raw = params.get(key)
  const value = (allowed as readonly string[]).includes(raw ?? '')
    ? (raw as T)
    : defaultValue

  const set = useCallback(
    (next: T) => {
      const sp = new URLSearchParams(params)
      if (next === defaultValue) {
        sp.delete(key)
      } else {
        sp.set(key, next)
      }
      setParams(sp, { replace: true })
    },
    [key, defaultValue, params, setParams],
  )

  return [value, set]
}
