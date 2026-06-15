// Built-in brand icons for common IAM-integrated apps.
//
// Sourced from `simple-icons` npm package — authoritative SVG paths +
// official brand hex. We re-export only a curated subset (~40 brands) so
// the IconPicker UI stays browsable and bundle size stays small (~30KB
// for the slice we use).
//
// Stored format in DB: `builtin:<slug>` (e.g. "builtin:grafana"). The slug
// is simple-icons' own slug; if simple-icons removes/renames a brand the
// admin will see a fallback letter and can switch to upload mode.
//
// Brands NOT in simple-icons (trademark removals: Slack, AWS, Azure, Lark,
// Feishu, DingTalk) fall back to the upload mode. A handful of high-value
// targets (JumpServer) have hand-crafted SVGs in CUSTOM_ICONS below so the
// icon picker still surfaces them.

import { parseAppIcon } from './app-icon'
import * as si from 'simple-icons'

export interface BuiltinIcon {
  slug: string
  name: string
  // Single SVG path. simple-icons normalizes everything to a 24x24 viewbox.
  path: string
  color: string
  category: 'iam' | 'devops' | 'collab' | 'storage' | 'cloud' | 'observability' | 'misc'
}

// Generic placeholder for `builtin:<unknown>` strings (e.g. icon removed
// from a future simple-icons release). Keeps the UI from crashing.
export const FALLBACK_ICON: BuiltinIcon = {
  slug: 'fallback',
  name: 'App',
  path: 'M3 3h18v18H3V3zm2 2v14h14V5H5zm3 3h8v2H8V8zm0 4h8v2H8v-2zm0 4h5v2H8v-2z',
  color: '#64748b',
  category: 'misc',
}

// pick wraps simple-icons access with a category tag. Throws at startup if
// simple-icons doesn't ship the requested slug — better to crash here than
// silently swallow into the UI.
function pick(slug: string, category: BuiltinIcon['category'], nameOverride?: string): BuiltinIcon {
  const key = 'si' + slug.charAt(0).toUpperCase() + slug.slice(1)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ic = (si as any)[key] as { title: string; path: string; hex: string; slug: string } | undefined
  if (!ic) {
    // Don't throw — leave a visibly-broken placeholder so we notice in dev.
    return { ...FALLBACK_ICON, slug, name: slug }
  }
  return {
    slug: ic.slug,
    name: nameOverride ?? ic.title,
    path: ic.path,
    color: '#' + ic.hex,
    category,
  }
}

// Hand-crafted icons for brands simple-icons doesn't ship. Keep entries
// minimal — single path, 24x24 viewbox, brand-official hex. Adding more is
// a deliberate maintenance burden (no upstream updates, no normalisation),
// so reserve this for brands actively integrated by users.
const CUSTOM_ICONS: BuiltinIcon[] = [
  {
    slug: 'jumpserver',
    name: 'JumpServer',
    // Filled circle ("J" cut out) — recognisable as the JumpServer mark in
    // the icon picker grid at 16-24px without needing multi-path strokes.
    path: 'M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm2.5 5.5h2.25v9.75a4.25 4.25 0 1 1-8.5 0v-1.5h2.25v1.5a2 2 0 1 0 4 0V5.5z',
    color: '#FB6203',
    category: 'iam',
  },
]

export const BUILTIN_ICONS: BuiltinIcon[] = [
  // ─── IAM / SSO ───
  pick('okta', 'iam'),
  pick('keycloak', 'iam'),
  pick('auth0', 'iam'),
  ...CUSTOM_ICONS.filter((i) => i.category === 'iam'),

  // ─── Atlassian ───
  pick('jira', 'collab'),
  pick('confluence', 'collab'),

  // ─── DevOps ───
  pick('grafana', 'observability'),
  pick('gitlab', 'devops'),
  pick('github', 'devops'),
  pick('gitea', 'devops'),
  pick('jenkins', 'devops'),
  pick('harbor', 'devops'),
  pick('argo', 'devops'),
  pick('spinnaker', 'devops'),
  pick('rancher', 'devops'),
  pick('helm', 'devops'),
  pick('traefikproxy', 'devops', 'Traefik'),
  pick('consul', 'devops'),
  pick('vault', 'devops', 'HashiCorp Vault'),
  pick('vmware', 'devops'),
  pick('kubernetes', 'devops'),
  pick('docker', 'devops'),
  pick('nginx', 'devops'),

  // ─── Collab / Communication ───
  pick('discord', 'collab'),
  pick('telegram', 'collab'),
  pick('zoom', 'collab'),
  pick('wechat', 'collab'),
  pick('notion', 'collab'),
  pick('figma', 'collab'),
  pick('linear', 'collab'),
  pick('clickup', 'collab'),
  pick('obsidian', 'collab'),

  // ─── Storage / Data ───
  pick('nextcloud', 'storage'),
  pick('minio', 'storage'),
  pick('postgresql', 'storage'),
  pick('mysql', 'storage'),
  pick('redis', 'storage'),
  pick('mongodb', 'storage'),
  pick('etcd', 'storage'),
  pick('apachecassandra', 'storage', 'Cassandra'),
  pick('clickhouse', 'storage'),

  // ─── Cloud ───
  pick('googlecloud', 'cloud'),
  pick('alibabacloud', 'cloud'),

  // ─── Observability ───
  pick('prometheus', 'observability'),
  pick('elasticsearch', 'observability'),
  pick('kibana', 'observability'),
  pick('sentry', 'observability'),
  pick('datadog', 'observability'),
  pick('newrelic', 'observability'),
  pick('splunk', 'observability'),
  pick('pagerduty', 'observability'),

  // ─── Misc ───
  pick('apachekafka', 'misc', 'Kafka'),
  pick('rabbitmq', 'misc'),
  pick('apacheairflow', 'misc', 'Airflow'),
  pick('natsdotio', 'misc', 'NATS'),
]

// Map for O(1) lookup by slug.
const BY_SLUG = new Map(BUILTIN_ICONS.map((i) => [i.slug, i]))

export function getBuiltinIcon(slug: string): BuiltinIcon | undefined {
  return BY_SLUG.get(slug)
}

// resolveIcon resolves an app.icon column value to a BuiltinIcon when the
// value is `builtin:<slug>`; otherwise returns undefined (caller renders
// URL via <img> or falls back to a placeholder).
export function resolveIcon(value: string | null | undefined): BuiltinIcon | undefined {
  const p = parseAppIcon(value)
  if (p.kind === 'builtin' && p.slug) return getBuiltinIcon(p.slug)
  return undefined
}
