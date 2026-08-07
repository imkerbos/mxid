#!/usr/bin/env node
// Every app mounts <Toaster /> exactly once, and mounts it at the app root.
//
// toast.* is a pub-sub: the call publishes, a mounted <Toaster /> renders. A
// toast raised from a screen the Toaster does not cover is not a degraded
// notification — it is silence.
//
// Both apps had it inside MainLayout, and both render real screens OUTSIDE that
// layout: the portal's /step-up page and forced MFA-enrollment gate, the
// console's login screen and forced password-change gate. A failed step-up on
// /step-up therefore reported nothing at all — the button simply appeared dead,
// which is how the bug was found. Mounting at the root is what makes rule 8
// ("every write gives toast feedback") true everywhere rather than in the
// subtree someone happened to check.
//
// Exactly one is equally load-bearing in the other direction: two Toasters
// subscribe to the same queue, so every toast would render twice.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const APPS = ['web/apps/console/src', 'web/apps/portal/src']
const MOUNT = /<Toaster\s*\/>/g

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (/\.(ts|tsx)$/.test(p) && !/\.(test|spec)\./.test(p)) yield p
  }
}

const findings = []
for (const base of APPS) {
  const mounts = []
  for (const file of walk(join(root, base))) {
    const rel = relative(root, file)
    const hits = (readFileSync(file, 'utf8').match(MOUNT) || []).length
    for (let i = 0; i < hits; i++) mounts.push(rel)
  }
  const app = `${base}/App.tsx`
  if (mounts.length === 0) {
    findings.push(`${base}: no <Toaster /> anywhere — every toast in this app is silent`)
  } else if (mounts.length > 1) {
    findings.push(`${base}: ${mounts.length} <Toaster /> mounts (${mounts.join(', ')}) — toasts would render once per mount`)
  } else if (mounts[0] !== app) {
    findings.push(
      `${base}: <Toaster /> is mounted in ${mounts[0]}, not App.tsx — screens rendered outside that component (forced-enrollment / password-change gates, /step-up, login) raise toasts nobody displays`,
    )
  }
}

if (findings.length) {
  console.error('✗ verify-toaster-mount:\n' + findings.map((f) => '  ' + f).join('\n'))
  process.exit(1)
}
console.log(`✓ verify-toaster-mount: ${APPS.length} apps mount <Toaster /> exactly once, at the app root`)
