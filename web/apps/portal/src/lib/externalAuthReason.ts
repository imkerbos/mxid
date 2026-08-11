// Maps the external-IdP callback's ?reason= slug to an i18n key.
//
// The backend (mxid-ee/features/externalidp/portal_handler.go, authFailureSlug)
// puts a STABLE SLUG here — never the originating error's own text. An earlier
// round of this feature put url.QueryEscape(err.Error()) straight into the
// redirect: a wrapped database error flowed unfiltered into the browser's
// address bar, its history, and server access logs. The frontend side of that
// fix is this file — match slugs, never raw strings, and never render a slug
// value directly (an opaque token like "external_auth_failed" means nothing to
// a user; the caller supplies its own generic sentence for anything unmapped).
//
// This ?reason= query param is shared by two different callers with two
// different generic fallbacks:
//   - the login page's ?err=external (an ordinary third-party sign-in failed,
//     or — rarer — a bind round-trip whose portal session didn't survive it)
//   - the security page's ?bindErr=... (App.tsx's RedirectIfAuth forwards a
//     still-authenticated bind failure here instead of silently dropping it)
// so only the three conflicts meaningful in EITHER context are mapped here;
// each caller supplies its own text for a reason this map doesn't know and for
// its own bind-specific guard slugs (bind_session_mismatch, bind_unconfigured).
const KNOWN_REASON_KEYS: Record<string, string> = {
  external_id_taken: 'errors.externalIDTaken',
  identity_already_bound: 'errors.identityAlreadyBound',
  external_user_deleted: 'errors.externalUserDeleted',
}

// externalAuthReasonKey resolves a backend reason slug to an i18n key, or null
// when it isn't one of the three conflicts above — including the backend's own
// generic fallback slug and any bind-specific guard slug. The caller decides
// what to say for null (a generic message appropriate to its own context).
export function externalAuthReasonKey(reason: string): string | null {
  return KNOWN_REASON_KEYS[reason] ?? null
}
