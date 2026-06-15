// Shared type + placeholder definitions for integration guides.
//
// Per-language content lives in guides.<lang>.ts files. The page
// (index.tsx) picks the right one based on the active i18n language.

export type Protocol = 'oidc' | 'saml' | 'cas' | 'deploy'

export interface GuideStep {
  title: string
  body: string // markdown-ish: supports ``` code blocks, `inline`, **bold**
}

export interface Guide {
  slug: string
  app: string
  protocol: Protocol
  difficulty: 1 | 2 | 3
  tags: string[]
  summary: string
  steps: GuideStep[]
  notes?: string[]
}

// MXID deployment URL placeholders. Replaced at render time using
// /api/v1/system/info:
//   {{ISSUER}}  — protocol endpoint root (OIDC iss / SAML EntityID)
//   {{PORTAL}}  — end-user login base URL
//   {{CONSOLE}} — admin console base URL
// In a single-domain prod deploy all three are the same origin; in dev
// they map to :10050 / :3501 / :3500 (or to the unified nginx :3500).
export const ISSUER_PLACEHOLDER = '{{ISSUER}}'
export const PORTAL_PLACEHOLDER = '{{PORTAL}}'
export const CONSOLE_PLACEHOLDER = '{{CONSOLE}}'
