#!/usr/bin/env node
// Every literal t('...') key must exist in BOTH locales.
//
// A missing key does not throw — i18next renders the key itself, so the screen
// silently fills with "account.password.forceTitle" instead of text. That
// shipped: the forced-password-change screen asked for `account.password.*`
// while the locale namespace is `account.pwd`, and every label on it — the one
// screen a locked-out administrator has to use — rendered as a raw key. Nobody
// noticed until a customer sent a screenshot.
//
// Only literal keys are checked. Keys built by interpolation
// (t(`apps.protocolFields.${p}.label`)) are invisible to any static check;
// those are covered by keeping whole prefix subtrees when pruning, per CLAUDE.md.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const LOCALES = [
  'web/packages/shared/src/i18n/locales/zh-CN.ts',
  'web/packages/shared/src/i18n/locales/en-US.ts',
]
const SCAN = ['web/packages/shared/src', 'web/apps/console/src', 'web/apps/portal/src']

// Collect the dotted key paths a locale file defines. The files are plain
// nested object literals, so tracking brace depth and the key that opened each
// level is enough — no TS parse needed.
function localeKeys(file) {
  const src = readFileSync(join(root, file), 'utf8')
  const keys = new Set()
  // Character-level scan rather than line-level: the locales mix multi-line
  // blocks with single-line ones (`theme: { toLight: '..', toDark: '..' }`),
  // and a line-based reader silently misses every key inside the latter — which
  // would make this check report keys as missing that are perfectly present.
  const stack = []
  let i = 0
  while (i < src.length) {
    const ch = src[i]
    if (ch === '/' && src[i + 1] === '/') {
      i = src.indexOf('\n', i) + 1 || src.length
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      // skip the string literal whole, honouring escapes
      const quote = ch
      i++
      while (i < src.length && src[i] !== quote) i += src[i] === '\\' ? 2 : 1
      i++
      continue
    }
    if (ch === '}') {
      stack.pop()
      i++
      continue
    }
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(\{|['"`])/.exec(src.slice(i, i + 200))
    if (m && (i === 0 || /[\s{,]/.test(src[i - 1]))) {
      if (m[2] === '{') {
        stack.push(m[1])
        i += m[0].length
      } else {
        keys.add([...stack, m[1]].join('.'))
        i += m[0].length - 1 // leave the quote for the string skipper above
      }
      continue
    }
    i++
  }
  return keys
}

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (/\.(ts|tsx)$/.test(p) && !/\.(test|spec)\./.test(p)) yield p
  }
}

const defined = LOCALES.map((f) => ({ file: f, keys: localeKeys(f) }))
const missing = []

for (const base of SCAN) {
  for (const file of walk(join(root, base))) {
    const src = readFileSync(file, 'utf8')
    for (const m of src.matchAll(/\bt\(\s*'([a-zA-Z][\w.]*)'/g)) {
      const key = m[1]
      if (!key.includes('.')) continue // not a namespaced message key
      const absent = defined.filter((d) => !d.keys.has(key)).map((d) => d.file.split('/').pop())
      if (absent.length) {
        const line = src.slice(0, m.index).split('\n').length
        missing.push(`${relative(root, file)}:${line}  ${key}  (missing in ${absent.join(', ')})`)
      }
    }
  }
}

if (missing.length) {
  console.error(
    'i18n keys used in code but absent from a locale — these render as the raw key on screen:\n  ' +
      missing.join('\n  '),
  )
  process.exit(1)
}
console.log(`✓ verify-i18n-keys: every literal t() key resolves in both locales`)
