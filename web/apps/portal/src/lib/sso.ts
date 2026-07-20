// Shared SSO-resume helper for the portal.
//
// When an SP sends the user to /login mid-handshake (CAS / SAML / OIDC) and the
// user is already authenticated, the SPA resumes the handshake by hard-
// navigating back to the backend protocol endpoint, which then issues the
// ticket / code and 302s to the original service. Used by both App.tsx's
// RedirectIfAuth (mount-time) and the login page (after a fresh login).
//
// It carries a redirect-loop tripwire: a half-cleared session (e.g. a CAS
// single-logout that drops only the protocol session but leaves the portal
// session) would otherwise bounce forever between /login and the protocol
// endpoint. The tripwire caps identical resumes in a short window and, once
// tripped, refuses to redirect so the caller can land the user on the portal.

const GUARD_KEY = 'mxid_sso_resume_guard'
const GUARD_MAX = 3
const GUARD_WINDOW_MS = 15000

// allowResume returns false when the same target has been resumed GUARD_MAX
// times within GUARD_WINDOW_MS — i.e. we are looping. The count persists in
// sessionStorage because every resume is a full-page navigation that reloads
// this SPA.
function allowResume(targetKey: string): boolean {
  const now = Date.now()
  let g: { key: string; n: number; t: number } | null = null
  try {
    g = JSON.parse(sessionStorage.getItem(GUARD_KEY) || 'null')
  } catch {
    g = null
  }
  if (g && g.key === targetKey && now - g.t < GUARD_WINDOW_MS) {
    if (g.n >= GUARD_MAX) {
      sessionStorage.removeItem(GUARD_KEY)
      return false
    }
    sessionStorage.setItem(GUARD_KEY, JSON.stringify({ key: targetKey, n: g.n + 1, t: now }))
  } else {
    sessionStorage.setItem(GUARD_KEY, JSON.stringify({ key: targetKey, n: 1, t: now }))
  }
  return true
}

// clearResumeGuard resets the tripwire. Call it once the user reaches a stable
// authenticated state so a later legitimate SSO isn't counted against a stale
// run.
export function clearResumeGuard(): void {
  try {
    sessionStorage.removeItem(GUARD_KEY)
  } catch {
    // ignore
  }
}

// safeSameOriginURL returns raw only if it is a same-origin http(s) URL (or a
// single-slash-rooted relative path); anything else (cross-origin, javascript:,
// //evil, userinfo) yields '' so a tampered return_to can't open-redirect.
export function safeSameOriginURL(raw: string | null): string {
  if (!raw) return ''
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return ''
  }
  if (raw.startsWith('//') || raw.startsWith('/\\') || raw.startsWith('\\')) return ''
  if (raw.startsWith('/')) return raw.includes('\\') ? '' : raw
  try {
    const u = new URL(raw, window.location.origin)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    if (u.username || u.password) return ''
    if (u.origin !== window.location.origin) return ''
    return u.href
  } catch {
    return ''
  }
}

// resumeSSOIfAny inspects the URL for an in-flight protocol handshake
// (?protocol=cas|saml plus app_code, or a return_to for OIDC / generic) and,
// when present, fires a hard navigation back to the backend protocol endpoint.
// Returns true when it took over navigation. Returns false when there is
// nothing to resume OR the loop tripwire fired (caller should then land the
// user on the portal instead of hanging).
export function resumeSSOIfAny(sp: URLSearchParams): boolean {
  const protocol = sp.get('protocol')
  const appCode = sp.get('app_code')
  const service = sp.get('service')

  let url = ''
  let key = ''
  if (protocol === 'cas' && appCode && service) {
    url = `/protocol/cas/${appCode}/login?service=${encodeURIComponent(service)}`
    key = `cas:${appCode}`
  } else if (protocol === 'saml' && appCode) {
    const rid = sp.get('request_id') ?? ''
    const rs = sp.get('relay_state') ?? ''
    url = `/protocol/saml/${appCode}/resume?request_id=${encodeURIComponent(rid)}&relay_state=${encodeURIComponent(rs)}`
    key = `saml:${appCode}`
  } else {
    // OIDC (and any generic flow) hands back the full backend URL to resume in
    // return_to (e.g. /protocol/oidc/authorize?...).
    const rt = safeSameOriginURL(sp.get('return_to'))
    if (rt) {
      url = rt
      key = `rt:${rt}`
    }
  }

  if (!url) {
    clearResumeGuard()
    return false
  }
  if (!allowResume(key)) {
    // Loop tripwire hit: the backend keeps bouncing us back to /login without
    // completing the handshake. Stop; the caller drops the user on the portal.
    return false
  }
  window.location.replace(url)
  return true
}
