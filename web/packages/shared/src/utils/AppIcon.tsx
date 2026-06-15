// AppIcon — renders an app.icon column value uniformly across console + portal.
//
// Supports three value forms:
//   - "builtin:<slug>" → inline SVG from the brand library (no network)
//   - "/static/..." or "https://..." → <img src>
//   - "" / null → letter avatar built from `fallbackName.charAt(0)`
//
// Why one component shared between both apps: console and portal would
// otherwise drift on which forms they render — admins pick a builtin icon,
// it works in console preview, breaks in portal. Single source of truth.
import { parseAppIcon } from './app-icon'
import { resolveIcon, type BuiltinIcon } from './app-icon-library'

export function AppIcon({
  value,
  fallbackName = '',
  size = 40,
  className,
}: {
  value: string | null | undefined
  fallbackName?: string
  size?: number
  className?: string
}) {
  const parsed = parseAppIcon(value)

  if (parsed.kind === 'builtin') {
    const ic = resolveIcon(value)
    if (ic) return <BrandSvg icon={ic} size={size} className={className} />
    // Builtin slug unknown — fall through to letter fallback.
  }

  if (parsed.kind === 'url' && parsed.url) {
    return (
      <img
        src={parsed.url}
        alt={fallbackName || 'app icon'}
        style={{ width: size, height: size }}
        className={`shrink-0 rounded-lg object-contain ${className ?? ''}`}
      />
    )
  }

  // Letter fallback.
  const letter = (fallbackName || '?').charAt(0).toUpperCase()
  return (
    <div
      className={`flex shrink-0 items-center justify-center rounded-lg bg-gray-100 font-semibold text-gray-500 ${className ?? ''}`}
      style={{ width: size, height: size, fontSize: size * 0.45 }}
    >
      {letter}
    </div>
  )
}

function BrandSvg({
  icon,
  size,
  className,
}: {
  icon: BuiltinIcon
  size: number
  className?: string
}) {
  return (
    <div
      className={`flex shrink-0 items-center justify-center rounded-lg ${className ?? ''}`}
      style={{ width: size, height: size, backgroundColor: icon.color + '1A' }}
    >
      <svg viewBox="0 0 24 24" width={size * 0.6} height={size * 0.6} fill={icon.color}>
        <path d={icon.path} />
      </svg>
    </div>
  )
}
