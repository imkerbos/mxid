// IconPicker — picks an icon for an app via three modes:
//   1. Built-in library    (BUILTIN_ICONS grid)
//   2. Upload local file   (POST /api/v1/console/upload/app-icon, max 200KB)
//   3. Manual URL          (typed in)
//
// Output value is the string stored in App.icon:
//   "builtin:<slug>"   for library
//   "/static/..."      for upload
//   "https://..."      for manual URL
import { useRef, useState } from 'react'
import { Upload, Globe, Library, X, Loader2 } from 'lucide-react'
import {
  client,
  cn,
  BUILTIN_ICONS,
  BUILTIN_PREFIX,
  parseAppIcon,
  resolveIcon,
  AppIcon,
  useTranslation,
} from '@mxid/shared'

type Mode = 'builtin' | 'upload' | 'url'

export function IconPicker({
  value,
  onChange,
}: {
  value: string
  onChange: (v: string) => void
}) {
  const { t } = useTranslation()
  const parsed = parseAppIcon(value)
  const initialMode: Mode =
    parsed.kind === 'builtin' ? 'builtin' : parsed.kind === 'url' ? 'url' : 'builtin'
  const [mode, setMode] = useState<Mode>(initialMode)
  const [urlInput, setUrlInput] = useState(parsed.kind === 'url' ? parsed.url ?? '' : '')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const pickBuiltin = (slug: string) => {
    onChange(`${BUILTIN_PREFIX}${slug}`)
  }

  const setURL = (u: string) => {
    setUrlInput(u)
    onChange(u)
  }

  const clear = () => {
    onChange('')
    setUrlInput('')
    setUploadError(null)
  }

  const handleUpload = async (file: File) => {
    setUploading(true)
    setUploadError(null)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await client.post<{ data: { url: string } }>('/upload/app-icon', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      const url = res.data.data.url
      onChange(url)
      setMode('url')
      setUrlInput(url)
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } }).response?.data?.message
      setUploadError(msg ?? t('iconPicker.uploadFailed'))
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-3">
      {/* ─── Preview row ─── */}
      <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-muted px-3 py-2.5">
        <AppIcon value={value} size={40} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-xs font-medium text-ink">
            {previewLabel(value, t)}
          </div>
          <div className="truncate font-mono text-[11px] text-faint">{value || t('iconPicker.emptyValue')}</div>
        </div>
        {!!value && (
          <button
            type="button"
            onClick={clear}
            title={t('iconPicker.clearTitle')}
            className="rounded-md p-1.5 text-faint hover:bg-surface hover:text-red-500"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* ─── Mode tabs ─── */}
      <div className="flex gap-1 rounded-lg bg-surface-muted p-1">
        <ModeButton active={mode === 'builtin'} onClick={() => setMode('builtin')} icon={Library} label={t('iconPicker.modeBuiltin')} />
        <ModeButton active={mode === 'upload'} onClick={() => setMode('upload')} icon={Upload} label={t('iconPicker.modeUpload')} />
        <ModeButton active={mode === 'url'} onClick={() => setMode('url')} icon={Globe} label={t('iconPicker.modeUrl')} />
      </div>

      {/* ─── Mode panel ─── */}
      {mode === 'builtin' && (
        <BuiltinGrid
          selectedSlug={parsed.kind === 'builtin' ? parsed.slug : undefined}
          onPick={pickBuiltin}
        />
      )}

      {mode === 'upload' && (
        <div>
          <input
            ref={fileRef}
            type="file"
            accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleUpload(f)
              e.target.value = ''
            }}
          />
          <button
            type="button"
            disabled={uploading}
            onClick={() => fileRef.current?.click()}
            className={cn(
              'flex w-full flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-border py-8 text-sm text-muted transition-colors',
              uploading ? 'cursor-wait bg-surface-muted' : 'hover:border-primary hover:bg-primary/5',
            )}
          >
            {uploading ? (
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            ) : (
              <Upload className="h-6 w-6 text-faint" />
            )}
            <span>{uploading ? t('iconPicker.uploading') : t('iconPicker.uploadHint')}</span>
            <span className="text-xs text-faint">{t('iconPicker.uploadFormatHint')}</span>
          </button>
          {uploadError && <p className="mt-2 text-xs text-red-500">{uploadError}</p>}
        </div>
      )}

      {mode === 'url' && (
        <div>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setURL(e.target.value)}
            placeholder={t('iconPicker.urlPlaceholder')}
            className="w-full rounded-lg border border-border px-3 py-2 text-sm font-mono outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
          <p className="mt-1 text-xs text-faint">{t('iconPicker.urlHint')}</p>
        </div>
      )}
    </div>
  )
}

// IconPreview kept for backwards compat with callers that imported it from
// this file; new code should import { AppIcon } from '@mxid/shared'.
export const IconPreview = AppIcon

function previewLabel(value: string, t: (k: string, opts?: Record<string, unknown>) => string): string {
  const parsed = parseAppIcon(value)
  if (parsed.kind === 'builtin') {
    const ic = resolveIcon(value)
    return t('iconPicker.builtinLabel', { name: ic?.name ?? t('iconPicker.builtinUnknown') })
  }
  if (parsed.kind === 'url') {
    if (parsed.url?.startsWith('/static/')) return t('iconPicker.uploaded')
    return t('iconPicker.externalUrl')
  }
  return t('iconPicker.notSelected')
}

/* ──────────────── Helpers ──────────────── */

function ModeButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean
  onClick: () => void
  icon: typeof Library
  label: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
        active ? 'bg-surface text-ink shadow-sm' : 'text-muted hover:text-ink',
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </button>
  )
}

function BuiltinGrid({
  selectedSlug,
  onPick,
}: {
  selectedSlug?: string
  onPick: (slug: string) => void
}) {
  const { t } = useTranslation()
  const [filter, setFilter] = useState('')
  const filtered = filter.trim()
    ? BUILTIN_ICONS.filter((i) =>
        i.name.toLowerCase().includes(filter.toLowerCase()) ||
        i.slug.toLowerCase().includes(filter.toLowerCase()),
      )
    : BUILTIN_ICONS

  return (
    <div>
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder={t('iconPicker.searchPlaceholder')}
        className="mb-2 w-full rounded-lg border border-border px-3 py-1.5 text-xs outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
      />
      <div className="grid max-h-64 grid-cols-6 gap-2 overflow-y-auto rounded-lg border border-border p-2">
        {filtered.map((ic) => (
          <button
            key={ic.slug}
            type="button"
            onClick={() => onPick(ic.slug)}
            title={ic.name}
            className={cn(
              'flex flex-col items-center gap-1 rounded-lg p-1.5 transition-colors',
              selectedSlug === ic.slug
                ? 'bg-primary/10 ring-2 ring-primary'
                : 'hover:bg-surface-muted',
            )}
          >
            <AppIcon value={`${BUILTIN_PREFIX}${ic.slug}`} size={32} />
            <span className="truncate text-[10px] text-muted">{ic.name}</span>
          </button>
        ))}
        {filtered.length === 0 && (
          <p className="col-span-6 py-6 text-center text-xs text-faint">{t('iconPicker.noMatch')}</p>
        )}
      </div>
    </div>
  )
}
