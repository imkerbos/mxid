#!/usr/bin/env node
// Frontend error text must come from extractMessage.
//
// It is the one place that knows the two shapes a rejected request arrives in
// (ApiError with a numeric .code, or a raw axios error with the code buried at
// response.data.code), localizes the codes that have a fixed sentence, and —
// since the traceId was threaded through — turns a 500 into something an
// operator can act on. Reading response.data.message or err.message by hand
// skips all of it: the code-specific translation is lost, and a 500 degrades to
// axios' "Request failed with status code 500" with no request id to quote.
//
// Thirty-six sites across twenty-three files had drifted that way.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const SCAN = ['web/packages/shared/src', 'web/apps/console/src', 'web/apps/portal/src']
// The extractor itself, and the interceptor that builds ApiError from the wire.
const ALLOW = ['ui/toast.tsx', 'api/client.ts']

const BYPASS = /response\?\.data\?\.message|\b(err|e|error)\s+instanceof Error\s*\?\s*\1\.message/

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (/\.(ts|tsx)$/.test(p) && !/\.(test|spec)\./.test(p)) yield p
  }
}

const findings = []
for (const base of SCAN) {
  for (const file of walk(join(root, base))) {
    const rel = relative(root, file)
    if (ALLOW.some((a) => rel.endsWith(a))) continue
    const lines = readFileSync(file, 'utf8').split('\n')
    lines.forEach((line, i) => {
      if (BYPASS.test(line) && !line.includes('//error:ok')) {
        findings.push(`${rel}:${i + 1}  ${line.trim().slice(0, 90)}`)
      }
    })
  }
}

if (findings.length) {
  console.error(
    'error text read by hand instead of through extractMessage — the localized\n' +
      'code message and the traceId are both lost this way:\n  ' +
      findings.join('\n  '),
  )
  process.exit(1)
}
console.log('✓ verify-error-extraction: every error message goes through extractMessage')
