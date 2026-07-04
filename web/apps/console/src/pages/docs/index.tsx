// Docs — in-console integration guides. Lists guides on the left, renders
// the selected guide's steps on the right. Content lives in `guides.ts`
// (static data) so adding a new guide is a one-file change.
//
// Why in-console (not a separate docs site or README files):
//  - Admins already authenticated here — no extra browser tab / login.
//  - Issuer URL auto-substituted from window.location.origin, so copy-paste
//    works for whatever domain the user actually deploys to (saves a class
//    of "copied localhost into prod config" bugs).
//  - Multi-tenant context: app_code examples reflect the actual app codes
//    on this MXID install over time (future enhancement — for now static).

import { useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { Check, Copy, ExternalLink, Search } from 'lucide-react'
import { cn, systemApi, useTranslation } from '@mxid/shared'
import type { SystemInfo } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { Input, Tag } from '../../components/ui'
import {
  ISSUER_PLACEHOLDER,
  PORTAL_PLACEHOLDER,
  CONSOLE_PLACEHOLDER,
  type Guide,
  type Protocol,
} from './types'
import { GUIDES as GUIDES_ZH } from './guides.zh'
import { GUIDES as GUIDES_EN } from './guides.en'

// Picks the active guide bundle by i18n language. zh-CN is canonical;
// en-US is a parallel translation.
function pickGuides(lang: string): Guide[] {
  if (lang.startsWith('zh')) return GUIDES_ZH
  return GUIDES_EN
}

function useProtocolLabel(): Record<Protocol, string> {
  const { t } = useTranslation()
  return {
    oidc: 'OIDC',
    saml: 'SAML 2.0',
    cas: 'CAS 3.0',
    deploy: t('docs.protocolDeploy'),
  }
}

const PROTOCOL_COLOR: Record<Protocol, string> = {
  oidc: 'bg-emerald-100 text-emerald-700',
  saml: 'bg-blue-100 text-blue-700',
  cas: 'bg-amber-100 text-amber-700',
  deploy: 'bg-purple-100 text-purple-700',
}

// Fallback issuer used only before /system/info resolves (or on error).
// Keep it obvious so admins notice if the fetch is broken.
const FALLBACK_ISSUER = 'https://id.example.com'

export default function DocsPage() {
  const { t, i18n } = useTranslation()
  const PROTOCOL_LABEL = useProtocolLabel()
  const guides = useMemo(() => pickGuides(i18n.language), [i18n.language])
  const [query, setQuery] = useState('')
  const [selectedSlug, setSelectedSlug] = useState<string>(guides[0]?.slug ?? '')
  const [protoFilter, setProtoFilter] = useState<Protocol | 'all'>('all')
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null)

  useEffect(() => {
    systemApi.info().then(setSysInfo).catch(() => setSysInfo(null))
  }, [])

  const issuer = sysInfo?.issuer_url || FALLBACK_ISSUER
  const portal = sysInfo?.portal_url || issuer
  const consoleURL = sysInfo?.console_url || issuer
  const substitute = useMemo(
    () => (input: string) =>
      input
        .replaceAll(ISSUER_PLACEHOLDER, issuer)
        .replaceAll(PORTAL_PLACEHOLDER, portal)
        .replaceAll(CONSOLE_PLACEHOLDER, consoleURL),
    [issuer, portal, consoleURL],
  )

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return guides.filter((g) => {
      if (protoFilter !== 'all' && g.protocol !== protoFilter) return false
      if (!q) return true
      return (
        g.app.toLowerCase().includes(q) ||
        g.summary.toLowerCase().includes(q) ||
        g.tags.some((t) => t.toLowerCase().includes(q))
      )
    })
  }, [guides, query, protoFilter])

  const selected = useMemo(
    () => guides.find((g) => g.slug === selectedSlug) ?? guides[0],
    [guides, selectedSlug],
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('docs.title')}
        description={t('docs.subtitle')}
      />

      <div className="grid grid-cols-12 gap-6">
        {/* ───── Left rail: search + filter + list ───── */}
        <aside className="col-span-12 md:col-span-4 xl:col-span-3">
          <div className="space-y-3 rounded-xl border border-border bg-surface p-4">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('docs.searchPlaceholder')}
                className="pl-9"
              />
            </div>

            <div className="flex flex-wrap gap-1.5">
              {(['all', 'oidc', 'saml', 'cas', 'deploy'] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setProtoFilter(p)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                    protoFilter === p
                      ? 'bg-primary text-white'
                      : 'bg-surface-muted text-muted hover:bg-surface-muted',
                  )}
                >
                  {p === 'all' ? t('docs.allFilter') : PROTOCOL_LABEL[p as Protocol]}
                </button>
              ))}
            </div>

            <div className="space-y-1 pt-1">
              {filtered.map((g) => (
                <GuideRow
                  key={g.slug}
                  guide={g}
                  active={g.slug === selected?.slug}
                  onClick={() => setSelectedSlug(g.slug)}
                />
              ))}
              {filtered.length === 0 && (
                <p className="px-2 py-6 text-center text-sm text-faint">{t('docs.noMatch')}</p>
              )}
            </div>
          </div>
        </aside>

        {/* ───── Right pane: selected guide ───── */}
        <main className="col-span-12 md:col-span-8 xl:col-span-9">
          {selected ? (
            <GuideView
              guide={selected}
              issuer={issuer}
              portal={portal}
              consoleURL={consoleURL}
              substitute={substitute}
            />
          ) : null}
        </main>
      </div>
    </div>
  )
}

/* ───────────────────────────────────────────────── */

function GuideRow({
  guide,
  active,
  onClick,
}: {
  guide: Guide
  active: boolean
  onClick: () => void
}) {
  const PROTOCOL_LABEL = useProtocolLabel()
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full rounded-lg px-3 py-2.5 text-left transition-colors',
        active ? 'bg-primary/10 ring-1 ring-primary/30' : 'hover:bg-surface-muted',
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className={cn('truncate text-sm font-medium', active ? 'text-primary' : 'text-ink')}>
          {guide.app}
        </span>
        <span
          className={cn(
            'shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
            PROTOCOL_COLOR[guide.protocol],
          )}
        >
          {PROTOCOL_LABEL[guide.protocol]}
        </span>
      </div>
      <p className="mt-0.5 line-clamp-2 text-xs text-muted">{guide.summary}</p>
    </button>
  )
}

function GuideView({
  guide,
  issuer,
  portal,
  consoleURL,
  substitute,
}: {
  guide: Guide
  issuer: string
  portal: string
  consoleURL: string
  substitute: (s: string) => string
}) {
  const { t } = useTranslation()
  const PROTOCOL_LABEL = useProtocolLabel()
  return (
    <motion.article
      key={guide.slug}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
      className="space-y-6 rounded-xl border border-border bg-surface p-6"
    >
      <header className="space-y-2 border-b border-border pb-4">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wider',
              PROTOCOL_COLOR[guide.protocol],
            )}
          >
            {PROTOCOL_LABEL[guide.protocol]}
          </span>
          <span className="text-xs text-faint">
            {t('docs.difficulty')}{'⭐'.repeat(guide.difficulty)}
          </span>
        </div>
        <h2 className="text-2xl font-bold text-ink">{guide.app}</h2>
        <p className="text-sm text-muted">{guide.summary}</p>
        <div className="flex flex-wrap gap-1.5 pt-1">
          {guide.tags.map((t) => (
            <Tag key={t}>{t}</Tag>
          ))}
        </div>
      </header>

      <div className="space-y-1 rounded-lg border border-info/20 bg-info/10 px-3 py-2 text-xs text-ink">
        <div>
          <span className="inline-block w-20 font-mono text-info">{'{{ISSUER}}'}</span>
          <code className="rounded bg-surface px-1.5 py-0.5 font-mono">{issuer}</code>
        </div>
        <div>
          <span className="inline-block w-20 font-mono text-info">{'{{PORTAL}}'}</span>
          <code className="rounded bg-surface px-1.5 py-0.5 font-mono">{portal}</code>
        </div>
        <div>
          <span className="inline-block w-20 font-mono text-info">{'{{CONSOLE}}'}</span>
          <code className="rounded bg-surface px-1.5 py-0.5 font-mono">{consoleURL}</code>
        </div>
      </div>

      <section className="space-y-5">
        {guide.steps.map((step, idx) => (
          <StepBlock
            key={idx}
            index={idx + 1}
            title={step.title}
            body={step.body}
            substitute={substitute}
          />
        ))}
      </section>

      {guide.notes && guide.notes.length > 0 && (
        <section className="space-y-2 rounded-lg border border-warning/20 bg-warning/10 p-4">
          <h3 className="text-sm font-semibold text-warning">{t('docs.notes')}</h3>
          <ul className="space-y-1 text-sm text-muted">
            {guide.notes.map((n, i) => (
              <li key={i} className="flex gap-2">
                <span className="select-none">•</span>
                <span>{n}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <footer className="flex items-center gap-2 border-t border-border pt-4 text-xs text-faint">
        <ExternalLink className="h-3.5 w-3.5" />
        {t('docs.footer')}
      </footer>
    </motion.article>
  )
}

/* ───────────────────────────────────────────────── */

function StepBlock({
  index,
  title,
  body,
  substitute,
}: {
  index: number
  title: string
  body: string
  substitute: (s: string) => string
}) {
  return (
    <div className="space-y-2">
      <h3 className="flex items-center gap-2 text-base font-semibold text-ink">
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary text-xs font-bold text-white">
          {index}
        </span>
        {title.replace(/^\d+\.\s*/, '')}
      </h3>
      <div className="prose-sm pl-8">
        <RenderBody text={body} substitute={substitute} />
      </div>
    </div>
  )
}

// Minimal renderer: split body by fenced ``` blocks, format inline `code` and
// **bold**. Avoid pulling in a full markdown lib for a few static documents.
function RenderBody({ text, substitute }: { text: string; substitute: (s: string) => string }) {
  const substituted = substitute(text)
  const parts = substituted.split(/```(\w*)\n([\s\S]*?)```/g)
  // parts pattern: [pre, lang, code, pre, lang, code, ..., pre]
  const blocks: { kind: 'text' | 'code'; content: string; lang?: string }[] = []
  for (let i = 0; i < parts.length; i++) {
    if (i % 3 === 0) {
      if (parts[i]) blocks.push({ kind: 'text', content: parts[i] })
    } else if (i % 3 === 1) {
      blocks.push({ kind: 'code', lang: parts[i] || '', content: parts[i + 1] })
      i++ // skip the code chunk that's already consumed
    }
  }
  return (
    <div className="space-y-3 text-sm leading-relaxed text-ink">
      {blocks.map((b, i) =>
        b.kind === 'code' ? (
          <CodeBlock key={i} code={b.content} lang={b.lang} />
        ) : (
          <InlineText key={i} text={b.content} />
        ),
      )}
    </div>
  )
}

function InlineText({ text }: { text: string }) {
  // Split paragraphs on blank lines; render `code` and **bold** inline.
  const paragraphs = text.split(/\n{2,}/).filter((p) => p.trim() !== '')
  return (
    <>
      {paragraphs.map((p, i) => (
        <p key={i} className="whitespace-pre-wrap">
          {renderInline(p)}
        </p>
      ))}
    </>
  )
}

function renderInline(text: string) {
  const out: React.ReactNode[] = []
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[1]
    if (tok.startsWith('**')) {
      out.push(
        <strong key={out.length} className="font-semibold text-ink">
          {tok.slice(2, -2)}
        </strong>,
      )
    } else {
      out.push(
        <code
          key={out.length}
          className="rounded bg-surface-muted px-1.5 py-0.5 font-mono text-[12.5px] text-rose-600"
        >
          {tok.slice(1, -1)}
        </code>,
      )
    }
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

function CodeBlock({ code, lang }: { code: string; lang?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="group relative overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
      {lang && (
        <div className="border-b border-gray-800 px-3 py-1 text-[10px] uppercase tracking-wider text-faint">
          {lang}
        </div>
      )}
      <button
        onClick={copy}
        className="absolute right-2 top-2 hidden items-center gap-1 rounded-md bg-gray-700 px-2 py-1 text-xs text-white opacity-0 transition-opacity hover:bg-gray-600 group-hover:flex group-hover:opacity-100"
        title={t('docs.copyTitle')}
      >
        {copied ? (
          <>
            <Check className="h-3 w-3" /> {t('docs.copied')}
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" /> {t('docs.copy')}
          </>
        )}
      </button>
      <pre className="overflow-x-auto p-3 text-[12.5px] leading-relaxed text-gray-100">
        <code>{code.trimEnd()}</code>
      </pre>
    </div>
  )
}
