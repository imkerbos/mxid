// useSSE — React hook wrapping native EventSource for the portal /events
// stream. Lifetime: tied to the component that calls it. Reconnects on
// disconnect with exponential backoff (browser's default isn't enough
// behind some proxies that 504 idle conns).
//
// Usage:
//   useSSE({
//     'apps_updated': () => refetchApps(),
//     'tenants_updated': () => refetchTenants(),
//   })
//
// Only mounts ONE EventSource per browser tab even if multiple
// components subscribe; events fan out to all registered handlers.

import { useEffect } from 'react'

type Handler = (payload: unknown) => void
type HandlerMap = Record<string, Handler>

let source: EventSource | null = null
let backoff = 1000
let listeners: HandlerMap[] = []

function ensureSource() {
  if (source) return source
  source = new EventSource('/api/v1/portal/events', { withCredentials: true })

  source.addEventListener('open', () => {
    backoff = 1000
  })

  // We can't catch arbitrary `event:` types via addEventListener('message')
  // — the SSE spec dispatches by event name. So we register a handler per
  // KNOWN event type. Adding a new event type requires editing this list.
  const KNOWN_EVENTS = ['hello', 'ping', 'apps_updated', 'tenants_updated', 'profile_updated']
  for (const name of KNOWN_EVENTS) {
    source.addEventListener(name, (ev) => {
      const data = parseData((ev as MessageEvent).data)
      for (const m of listeners) {
        const h = m[name]
        if (h) h(data)
      }
    })
  }

  source.addEventListener('error', () => {
    // Browser's auto-reconnect kicks in but can spin tightly on persistent
    // failures; throttle with manual close + reopen via timer.
    if (!source) return
    source.close()
    source = null
    setTimeout(ensureSource, backoff)
    backoff = Math.min(backoff * 2, 30_000)
  })

  return source
}

function parseData(s: string): unknown {
  try {
    return JSON.parse(s)
  } catch {
    return s
  }
}

export function useSSE(handlers: HandlerMap) {
  useEffect(() => {
    ensureSource()
    listeners.push(handlers)
    return () => {
      listeners = listeners.filter((l) => l !== handlers)
      if (listeners.length === 0 && source) {
        // Keep the connection open even when no listeners — reconnecting
        // is expensive (auth check etc). Optional cleanup left to GC.
      }
    }
  }, [handlers])
}
