// ImageUpload — picks a brand asset (logo / favicon) either by uploading a file
// or by typing an external URL.
//
// Uploads go to POST /api/v1/console/upload/brand-logo, which stores the bytes
// in the database (mxid_upload) and returns the public serve URL
// "/static/app-icons/<id>.<ext>". The stored value is always just that string,
// so an admin can equally paste a CDN URL and nothing downstream cares.
//
// Deliberately simpler than IconPicker: brand assets have no built-in library
// to choose from, so there are only two modes.
import { useRef, useState } from 'react'
import { Upload, Globe, X, Loader2, ImageOff } from 'lucide-react'
import { client, cn, useTranslation } from '@mxid/shared'
import { toast, extractMessage } from './ui/toast'

type Mode = 'upload' | 'url'

export function ImageUpload({
  value,
  onChange,
  disabled,
}: {
  value: string
  onChange: (v: string) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<Mode>('upload')
  const [urlInput, setUrlInput] = useState(value)
  const [uploading, setUploading] = useState(false)
  // Tracks a preview that failed to load, so a bad URL reads as "broken image"
  // rather than a silently blank box.
  const [broken, setBroken] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const setURL = (u: string) => {
    setUrlInput(u)
    setBroken(false)
    onChange(u)
  }

  const clear = () => {
    setUrlInput('')
    setBroken(false)
    onChange('')
  }

  const handleUpload = async (file: File) => {
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await client.post<{ data: { url: string } }>('/upload/brand-logo', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      const url = res.data.data.url
      setUrlInput(url)
      setBroken(false)
      onChange(url)
      toast.success(t('imageUpload.uploaded'))
    } catch (e) {
      toast.error(t('imageUpload.uploadFailed'), extractMessage(e))
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-3">
      {/* ─── Preview row ─── */}
      <div className="flex items-center gap-3 rounded-lg border border-border bg-surface-muted px-3 py-2.5">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-border bg-surface">
          {value && !broken ? (
            <img
              src={value}
              alt=""
              className="h-full w-full object-contain"
              onError={() => setBroken(true)}
              onLoad={() => setBroken(false)}
            />
          ) : (
            <ImageOff className="h-4 w-4 text-faint" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-xs font-medium text-ink">
            {broken ? t('imageUpload.broken') : value ? t('imageUpload.current') : t('imageUpload.none')}
          </div>
          <div className="truncate font-mono text-[11px] text-faint">
            {value || t('imageUpload.emptyValue')}
          </div>
        </div>
        {!!value && !disabled && (
          <button
            type="button"
            onClick={clear}
            title={t('imageUpload.clear')}
            className="shrink-0 rounded-md p-1.5 text-faint hover:bg-surface hover:text-red-500"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* ─── Mode tabs ─── */}
      <div className="flex gap-1 rounded-lg bg-surface-muted p-1">
        <ModeButton
          active={mode === 'upload'}
          onClick={() => setMode('upload')}
          icon={Upload}
          label={t('imageUpload.modeUpload')}
          disabled={disabled}
        />
        <ModeButton
          active={mode === 'url'}
          onClick={() => setMode('url')}
          icon={Globe}
          label={t('imageUpload.modeUrl')}
          disabled={disabled}
        />
      </div>

      {mode === 'upload' ? (
        <div>
          <input
            ref={fileRef}
            type="file"
            accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) void handleUpload(f)
              // Reset so re-picking the same file fires onChange again.
              e.target.value = ''
            }}
          />
          <button
            type="button"
            disabled={uploading || disabled}
            onClick={() => fileRef.current?.click()}
            className={cn(
              'flex w-full flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-border py-8 text-sm text-muted transition-colors',
              uploading ? 'cursor-wait bg-surface-muted' : 'hover:border-primary hover:bg-primary/5',
              disabled && 'cursor-not-allowed opacity-50 hover:border-border hover:bg-transparent',
            )}
          >
            {uploading ? (
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            ) : (
              <Upload className="h-6 w-6 text-faint" />
            )}
            <span>{uploading ? t('imageUpload.uploading') : t('imageUpload.uploadHint')}</span>
            <span className="text-xs text-faint">{t('imageUpload.formatHint')}</span>
          </button>
        </div>
      ) : (
        <div>
          <input
            type="text"
            value={urlInput}
            disabled={disabled}
            onChange={(e) => setURL(e.target.value)}
            placeholder={t('imageUpload.urlPlaceholder')}
            className="w-full rounded-lg border border-border px-3 py-2 font-mono text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20 disabled:opacity-50"
          />
          <p className="mt-1 text-xs text-faint">{t('imageUpload.urlHint')}</p>
        </div>
      )}
    </div>
  )
}

function ModeButton({
  active,
  onClick,
  icon: Icon,
  label,
  disabled,
}: {
  active: boolean
  onClick: () => void
  icon: React.ComponentType<{ className?: string }>
  label: string
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
        active ? 'bg-surface text-ink shadow-sm' : 'text-muted hover:text-ink',
        disabled && 'cursor-not-allowed opacity-50',
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </button>
  )
}
