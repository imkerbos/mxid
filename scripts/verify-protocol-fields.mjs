#!/usr/bin/env node
// verify-protocol-fields: every protocol-config field the console renders must
// correspond to a key the engine actually reads.
//
// Six fields once sat in the OIDC tab that no engine code read. Four had no
// backend key at all; two were spelled differently from the struct tag
// (id_token_lifetime vs id_token_ttl, token_endpoint_auth_method vs
// token_endpoint_auth_mode). Operators set them, the console reported success,
// and nothing happened — for years, because nothing compared the two lists.
//
// This is that comparison. It reads the console's field descriptors and the Go
// struct tags for each protocol, and fails when the console offers a key the
// backend does not read.
//
// Not covered: form-fill, whose config struct lives in the private EE repo and
// is absent from a CE checkout.

import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

// Go files whose json struct tags define the accepted keys for each protocol.
const BACKEND_SOURCES = {
  oidc: [
    'internal/protocol/oidcop/client.go',
    'internal/protocol/oidclogout/service.go',
  ],
  saml: ['internal/protocol/saml/config.go'],
  cas: ['internal/protocol/cas/config.go'],
}

// Protocols the console renders that this check cannot verify, with the reason.
const UNVERIFIABLE = { form: 'config struct lives in the EE repo (features/formfill)' }

const CONSOLE_PAGE = 'web/apps/console/src/pages/apps/index.tsx'

function backendKeys(files) {
  const keys = new Set()
  for (const rel of files) {
    const path = join(root, rel)
    if (!existsSync(path)) throw new Error(`backend source missing: ${rel}`)
    const src = readFileSync(path, 'utf8')
    for (const m of src.matchAll(/`json:"([a-z0-9_]+)[",]/g)) keys.add(m[1])
  }
  return keys
}

// Protocol blocks expected in the console's descriptor map. Listed explicitly
// so a renamed or deleted block fails loudly — a parser that silently matches
// nothing reports success, which is worse than no check at all. (The first
// version of this script did exactly that: it began scanning mid-line, so the
// `oidc:` header never matched its own indentation and all ten OIDC fields went
// unchecked while the output still said OK.)
const EXPECTED_PROTOCOLS = ['oidc', 'saml', 'cas', 'form']

// Walk the console's protocolConfigFields descriptors, tracking which protocol
// block each `key:` belongs to.
function consoleFields() {
  const lines = readFileSync(join(root, CONSOLE_PAGE), 'utf8').split('\n')
  const byProtocol = {}
  let protocol = null
  for (const line of lines) {
    const header = line.match(/^\s{4}([a-z_]+): \[\s*$/)
    if (header && EXPECTED_PROTOCOLS.includes(header[1])) {
      protocol = header[1]
      byProtocol[protocol] ??= []
      continue
    }
    if (!protocol) continue
    if (/^\s{4}\],/.test(line)) {
      protocol = null
      continue
    }
    const key = line.match(/key: '([a-z0-9_]+)'/)
    if (key) byProtocol[protocol].push(key[1])
  }

  const missing = EXPECTED_PROTOCOLS.filter((p) => !byProtocol[p]?.length)
  if (missing.length) {
    throw new Error(
      `no fields parsed for protocol(s) ${missing.join(', ')} in ${CONSOLE_PAGE} — ` +
        `the descriptor layout changed and this check is no longer reading it`
    )
  }
  return byProtocol
}

const fields = consoleFields()
const problems = []
let checked = 0

for (const [protocol, keys] of Object.entries(fields)) {
  if (UNVERIFIABLE[protocol]) continue
  const sources = BACKEND_SOURCES[protocol]
  if (!sources) {
    problems.push(`protocol "${protocol}" has console fields but no backend source mapping in this script`)
    continue
  }
  const allowed = backendKeys(sources)
  for (const key of keys) {
    checked++
    if (!allowed.has(key)) {
      problems.push(
        `${protocol}: console field "${key}" matches no json tag in ${sources.join(', ')} — ` +
          `the engine will never read it, so setting it in the console does nothing`
      )
    }
  }
}

// Second edge: the onboarding templates write protocol_config too, and their
// keys have to reach the engine just as the console form's do. Checking only
// the form left this one open — the form and the engine agreed on
// token_endpoint_auth_mode while the templates, the create path and the OIDC
// registration metadata all said token_endpoint_auth_method. The guard was
// green the whole time, and every public client created from a template was
// read as confidential and refused with invalid_client.
//
// Keys that are deliberately informational (consumed by the console or the docs
// rather than the engine) go in TEMPLATE_NON_ENGINE with the reason.
const TEMPLATE_DIR = 'internal/domain/app/templates'
const TEMPLATE_NON_ENGINE = {
  access_token_lifetime: 'documented for the RP; the engine takes its own default',
  refresh_token_lifetime: 'documented for the RP; the engine takes its own default',
  id_token_signing_alg: 'advertised in discovery, not per-app configurable',
  subject_type: 'stored on the app row, not in protocol_config',
}

function templateProblems() {
  const dir = join(root, TEMPLATE_DIR)
  if (!existsSync(dir)) return []
  const allowed = backendKeys(BACKEND_SOURCES.oidc)
  const found = []
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue
    const tpl = JSON.parse(readFileSync(join(dir, name), 'utf8'))
    if (tpl.protocol !== 'oidc') continue
    for (const key of Object.keys(tpl.defaults ?? {})) {
      if (allowed.has(key) || TEMPLATE_NON_ENGINE[key]) continue
      found.push(
        `template ${name}: defaults key "${key}" matches no json tag in ` +
          `${BACKEND_SOURCES.oidc.join(', ')} — an app onboarded from this ` +
          `template carries a setting the engine never reads`
      )
    }
  }
  return found
}

problems.push(...templateProblems())

if (problems.length) {
  console.error('✗ verify-protocol-fields: console offers settings the backend ignores\n')
  for (const p of problems) console.error('  - ' + p)
  console.error('\nEither correct the key to the one the engine reads, wire the setting up, or remove the field.')
  process.exit(1)
}

const skipped = Object.entries(UNVERIFIABLE)
  .filter(([p]) => fields[p]?.length)
  .map(([p, why]) => `${p} (${why})`)
console.log(
  `✓ verify-protocol-fields: ${checked} console fields all map to engine keys` +
    (skipped.length ? `; not checked: ${skipped.join(', ')}` : '')
)
