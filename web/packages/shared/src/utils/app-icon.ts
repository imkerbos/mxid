// App icon utilities — shared between console and portal so the same
// `builtin:<slug>` / `/static/...` / `https://...` value renders identically
// in both places.
//
// The icon library itself lives in the console (where the picker is) — this
// shared module only knows how to PARSE the value and render the FALLBACK.
// Each frontend resolves builtin slugs against its own library; portal can
// stick with the fallback if it doesn't ship one.

export const BUILTIN_PREFIX = 'builtin:'

export type IconValueKind = 'none' | 'builtin' | 'url'

export interface ParsedIconValue {
  kind: IconValueKind
  // For builtin kind, the slug after the prefix (consumer looks it up).
  slug?: string
  // For url kind, the original string.
  url?: string
}

export function parseAppIcon(value: string | null | undefined): ParsedIconValue {
  if (!value) return { kind: 'none' }
  if (value.startsWith(BUILTIN_PREFIX)) {
    return { kind: 'builtin', slug: value.slice(BUILTIN_PREFIX.length) }
  }
  return { kind: 'url', url: value }
}

// isRenderableAsImage tells callers using a plain <img src=...> whether
// they can pass the value through directly. Useful in legacy components
// that don't (yet) want to depend on a full icon-picker library.
export function isRenderableAsImage(value: string | null | undefined): boolean {
  return parseAppIcon(value).kind === 'url'
}
