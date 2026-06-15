import { useEffect, useState } from 'react'
import { systemApi, type SystemInfo } from '../api/system'

// Edition info, cached process-wide so route navigations don't refetch.
export type LicenseState = 'ce' | 'ee' | 'expired' | 'invalid' | 'mismatch'

export interface Edition {
  edition: 'ce' | 'ee'
  state: LicenseState
  features: string[]
  isEE: boolean
  has: (feature: string) => boolean
}

const CE: Edition = { edition: 'ce', state: 'ce', features: [], isEE: false, has: () => false }

function build(info: SystemInfo | null): Edition {
  const edition = (info?.edition === 'ee' ? 'ee' : 'ce') as 'ce' | 'ee'
  const features = info?.features ?? []
  const state = (info?.license_state ?? edition) as LicenseState
  return {
    edition,
    state,
    features,
    isEE: edition === 'ee',
    has: (f) => features.includes(f),
  }
}

let cached: Edition | null = null
let inflight: Promise<Edition> | null = null

function fetchOnce(): Promise<Edition> {
  if (cached) return Promise.resolve(cached)
  if (inflight) return inflight
  inflight = systemApi
    .info()
    .then((info) => {
      cached = build(info)
      return cached
    })
    .catch(() => CE)
    .finally(() => {
      inflight = null
    })
  return inflight
}

// useEdition returns the live edition + a feature gate. Defaults to CE until the
// fetch resolves, so EE UI stays hidden during load (fail-closed).
export function useEdition(): Edition {
  const [e, setE] = useState<Edition>(cached ?? CE)
  useEffect(() => {
    let alive = true
    fetchOnce().then((next) => {
      if (alive) setE(next)
    })
    return () => {
      alive = false
    }
  }, [])
  return e
}
