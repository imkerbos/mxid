// Post-login return-path helpers.
//
// When a session expires mid-navigation we bounce the user to /login and want to
// drop them back where they were once they re-authenticate. The path travels in
// router location state (not the query string) so it never leaks into logs or
// referrers, but it is still attacker-influencable in principle — a crafted
// link can seed history state — so every value is re-validated before use.

// currentReturnPath snapshots where the user is right now, for stashing in the
// login redirect's location state. Read straight off window.location rather
// than a captured useLocation() value so global (non-React) handlers such as
// the `mxid:unauthorized` listener never redirect to a stale route.
export function currentReturnPath(): string {
  const { pathname, search, hash } = window.location
  return pathname + search + hash
}

// safeReturnPath narrows an untrusted return path to a same-origin route, or
// falls back. Rejected:
//   - anything not starting with "/"        → absolute URLs (https://evil.com)
//   - "//host" and "/\host"                 → protocol-relative, browsers treat
//                                             these as cross-origin (open redirect)
//   - the auth routes themselves            → would bounce straight back here
export function safeReturnPath(raw: unknown, fallback: string): string {
  if (typeof raw !== 'string' || raw === '') return fallback
  if (raw[0] !== '/') return fallback
  if (raw[1] === '/' || raw[1] === '\\') return fallback
  // Backslashes are normalised to "/" by some browsers, so "/\/evil.com" and
  // friends must not survive the checks above by hiding deeper in the string.
  if (raw.includes('\\')) return fallback
  const path = raw.split(/[?#]/)[0]
  if (path === '/login' || path.startsWith('/login/')) return fallback
  return raw
}
