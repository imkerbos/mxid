// Shared "sign in with <IdP>" button row for the portal + console login pages.
// Centralizes the brand styling so both surfaces stay visually consistent and
// any beautification lands in one place.
import type { PublicIDP } from '../api/externalidp'

interface Brand {
  // `mark` is a self-contained brand SVG (with its own background) rendered
  // as-is. When set it wins over badge+glyph. Used for official logos.
  mark?: React.ReactNode
  // Tailwind classes for the brand-colored icon badge (used when no mark).
  badge?: string
  // Inline glyph rendered inside the badge.
  glyph?: React.ReactNode
}

// Official Lark / Feishu mark — blue (#3370ff) disc + white bird. Vendored
// verbatim from the aegis-icons brand set (simple-icons drops ByteDance logos
// for trademark reasons), used here for nominative "Sign in with Lark".
const LarkMark = (
  <svg viewBox="0 0 1024 1024" className="h-7 w-7 rounded-full shadow-sm" aria-hidden>
    <circle cx="512" cy="512" r="512" fill="#3370ff" />
    <path
      fill="#fff"
      d="M452.66 735.98c129.21-.05 240.96-73.62 296.01-181.49-28.47 55.36-88.93 81.63-149.06 66.88-34.65-8.89-68.49-21.04-101.43-34.95-88.52-38.05-168.71-94.13-234.5-164.53-2.65-2.92-7.95-.95-7.87 3.1l.14 213.29v17.31c0 10.06 4.96 19.44 13.3 25.03a328.727 328.727 0 0 0 183.41 55.37v-.02Zm89.96-222.18-.08.08a705.434 705.434 0 0 0-194.67-217.69 4.554 4.554 0 0 1 2.71-8.21h241.67c9.13 0 17.78 4.13 23.52 11.24a330.672 330.672 0 0 1 59.66 114.96c-30.57 9.47-58.51 25.96-80.81 48.28-7.65 7.52-15.59 15.38-23.27 23-8.6 8.53-17.5 17.35-26.05 25.72l-.07.07-.07.07c-.83.84-1.68 1.67-2.54 2.48Zm-55.3 55.67c22.18-13.01 42.79-28.57 61.47-46.28l1.38-1.38c.96-.9 1.9-1.83 2.83-2.77 16.22-15.89 33.15-32.84 49.36-48.76 53.08-53.16 136.95-68.88 205.83-40.1l-7.52 8.74c-12.15 14.11-22.3 29.94-30.16 47.04l-6.3 12.56c-8.01 15.97-24.68 49.19-25.58 50.92-8.74 16.48-20.4 30.55-33.74 40.68l-.13.1c-1.85 1.45-3.84 2.81-5.96 4.26-18.58 12.7-42.04 19.7-66.07 19.7-7.53 0-15.09-.68-22.47-2.02-2.72-.54-5.29-1.04-7.85-1.66-22.19-5.75-45.25-13.11-68.54-21.88-10.76-4.05-22.21-8.68-34.06-13.76l-12.5-5.38Z"
    />
  </svg>
)
const TeamsGlyph = (
  <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4">
    <path d="M13 7a3 3 0 1 0-3-3 3 3 0 0 0 3 3Zm7 1h-5v7a4 4 0 0 1-4 4H8.6A5 5 0 0 0 13 22a5 5 0 0 0 5-5v-1h2a2 2 0 0 0 2-2v-4a2 2 0 0 0-2-2ZM4 9h7a1 1 0 0 1 1 1v6a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4v-6a1 1 0 0 1 1-1Z" />
  </svg>
)

const BRANDS: Record<string, Brand> = {
  lark: { mark: LarkMark },
  feishu: { mark: LarkMark },
  teams: { badge: 'bg-[#5059C9] text-white', glyph: TeamsGlyph },
}

function brandFor(type: string): Brand {
  return BRANDS[type] ?? { badge: 'bg-slate-500 text-white', glyph: <span className="text-xs font-bold">{type.slice(0, 1).toUpperCase()}</span> }
}

interface Props {
  idps: PublicIDP[]
  hrefFor: (idp: PublicIDP) => string
  dividerLabel: string
}

export function ExternalIdpButtons({ idps, hrefFor, dividerLabel }: Props) {
  if (!idps.length) return null
  return (
    <div className="mt-6">
      <div className="mb-4 flex items-center gap-3 text-xs text-white/40">
        <div className="h-px flex-1 bg-white/10" />
        <span className="uppercase tracking-wider">{dividerLabel}</span>
        <div className="h-px flex-1 bg-white/10" />
      </div>
      <div className={idps.length === 1 ? 'grid grid-cols-1 gap-3' : 'grid grid-cols-2 gap-3'}>
        {idps.map((idp) => {
          const brand = brandFor(idp.type)
          return (
            <a
              key={idp.id}
              href={hrefFor(idp)}
              className="group flex items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-medium text-white/90 shadow-sm transition-all hover:-translate-y-0.5 hover:border-white/20 hover:bg-white/10 hover:shadow-md"
            >
              <span className="flex h-7 w-7 shrink-0 items-center justify-center transition-transform group-hover:scale-105">
                {idp.icon ? (
                  <img src={idp.icon} alt="" className="h-7 w-7 rounded-lg object-contain" />
                ) : brand.mark ? (
                  brand.mark
                ) : (
                  <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${brand.badge} shadow-sm`}>
                    {brand.glyph}
                  </span>
                )}
              </span>
              <span className="truncate">{idp.name}</span>
            </a>
          )
        })}
      </div>
    </div>
  )
}
