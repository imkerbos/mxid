#!/usr/bin/env node
// verify-csp-hash: the CSP script-src hashes in the nginx config must match the
// inline scripts the SPAs actually ship.
//
// Both apps carry one inline script in index.html — the FOUC theme guard, which
// applies the persisted theme before React mounts. The production CSP allows it
// by hash rather than by 'unsafe-inline', which is what makes that policy worth
// having: an injected inline script has no matching hash and is refused.
//
// The cost of that is a coupling with no compiler behind it. Edit the guard and
// the stored hash stops matching, so the browser refuses the script. Measured
// consequence: the app still mounts and works — the main bundle is loaded by
// src and unaffected — but the theme flashes on every load, and the CSP carries
// an allowance that matches nothing. Silent, cosmetic, and permanent until
// someone notices. Hence this check.
//
// Checks the SOURCE index.html and, when a build is present, the BUILT one too:
// nginx serves the build, and a bundler that ever decides to minify inline
// scripts would break the match without the source changing.

import { readFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const NGINX_CONF = 'deploy/nginx/prod.conf'
const APPS = ['console', 'portal']

// Pulls the bodies of inline <script> tags — those without a src attribute.
const INLINE_SCRIPT = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g

function inlineScriptHashes(html, label) {
  const out = []
  for (const [, body] of html.matchAll(INLINE_SCRIPT)) {
    out.push({ label, hash: createHash('sha256').update(body, 'utf8').digest('base64') })
  }
  return out
}

const conf = readFileSync(join(root, NGINX_CONF), 'utf8')

// Every sha256-... allowed anywhere in the file's script-src directives.
const allowed = new Set([...conf.matchAll(/'sha256-([A-Za-z0-9+/=]+)'/g)].map((m) => m[1]))
if (allowed.size === 0) {
  console.error(`✗ verify-csp-hash: no 'sha256-...' found in ${NGINX_CONF}.\n` +
    `  Either the CSP lost its script-src hash (inline scripts will be refused), or the\n` +
    `  policy moved and this check no longer knows where to look.`)
  process.exit(1)
}

const problems = []
const seen = []

for (const app of APPS) {
  for (const rel of [`web/apps/${app}/index.html`, `web/apps/${app}/dist/index.html`]) {
    const path = join(root, rel)
    // The build is optional: a clean checkout has no dist/.
    if (!existsSync(path)) {
      if (!rel.includes('/dist/')) problems.push(`${rel} is missing`)
      continue
    }
    const found = inlineScriptHashes(readFileSync(path, 'utf8'), rel)
    if (found.length === 0) {
      // No inline script is fine — it just means the hash is no longer needed.
      continue
    }
    for (const { label, hash } of found) {
      seen.push(hash)
      if (!allowed.has(hash)) {
        problems.push(
          `${label} ships an inline script whose hash is not allowed by the CSP.\n` +
            `    expected in ${NGINX_CONF}:  'sha256-${hash}'\n` +
            `    currently allowed:         ${[...allowed].map((h) => `'sha256-${h}'`).join(', ')}\n` +
            `    The browser will refuse this script. Update the CSP with the hash above.`
        )
      }
    }
  }
}

// A hash allowed by the CSP that no app ships is dead weight, and usually the
// other half of the same mistake — someone updated one entrypoint's policy and
// not the other.
for (const h of allowed) {
  if (!seen.includes(h)) {
    problems.push(
      `${NGINX_CONF} allows 'sha256-${h}', which matches no inline script in either app.\n` +
        `    Remove it, or restore the script it was allowing.`
    )
  }
}

if (problems.length) {
  console.error('✗ verify-csp-hash: CSP script-src hashes are out of sync\n')
  for (const p of problems) console.error('  - ' + p)
  process.exit(1)
}

console.log(
  `✓ verify-csp-hash: ${seen.length} inline script${seen.length === 1 ? '' : 's'} across ` +
    `${APPS.length} apps all allowed by the CSP`
)
